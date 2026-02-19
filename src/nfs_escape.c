/*
 * Copyright (C)  2025-2026 John Cartwright <johnc@grok.org.uk>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by John Cartwright.
 * 4. The name John Cartwright may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * nfs_escape.c - Export boundary escape probing (low-level primitives)
 *
 * NFS exports typically restrict access to a subtree. For example, if
 * /export/home is exported, the server should block access above it.
 * However, some server configurations leak parent directory information:
 *
 *   - LOOKUP ".." may return the real parent FH (not blocked)
 *   - READDIRPLUS may include ".." entry with FH (even when LOOKUP blocked)
 *
 * This module provides primitive escape probing operations:
 *
 *   probe_parent()          - Try LOOKUP/READDIRPLUS for single parent
 *   nfs_probe_escape_one()  - Single-level probe with full diagnostics
 *   nfs_probe_escape()      - Multi-level probe, returns parent FH chain
 *
 * Higher-level strategies (using alternate exports) are in pathctx.c,
 * which calls these primitives as Phase 1 of its three-phase approach.
 *
 * Results are cached in parent_cache to avoid redundant probes when
 * multiple exports share parent directories.
 *
 * Security note: This is a diagnostic/pentesting feature. Well-configured
 * servers block parent access at export boundaries (RFC 1813 Section 4).
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "nfs.h"
#include "nfs_escape.h"
#include "nfs_util.h"
#include "nfscli.h"

/*
 * Parent FH cache - avoids redundant LOOKUP ".." calls during escape probing.
 * When probing multiple exports, we often encounter the same directories.
 * Caching FH → parent FH mappings eliminates redundant network calls.
 */
#define PARENT_CACHE_SIZE 64

struct parent_cache_entry {
    struct nfs_fh fh;     /* Child FH */
    struct nfs_fh parent; /* Parent FH (or same as fh if at ceiling) */
    int valid;            /* Entry is valid */
    int is_ceiling;       /* True if this FH is at ceiling (parent == self) */
};

static struct parent_cache_entry parent_cache[PARENT_CACHE_SIZE];
static int parent_cache_initialized = 0;

static void
parent_cache_init(void)
{
    if (!parent_cache_initialized) {
        memset(parent_cache, 0, sizeof(parent_cache));
        parent_cache_initialized = 1;
    }
}

/*
 * Hash function for parent cache (simple polynomial hash).
 * Uses multiplier 31 (common prime, used by Java String.hashCode).
 */
static unsigned int
parent_cache_hash(const struct nfs_fh *fh)
{
    unsigned int hash = 0;
    uint32_t i;

    for (i = 0; i < fh->len; i++)
        hash = hash * 31 + fh->data[i];
    return hash % PARENT_CACHE_SIZE;
}

/* Returns 0 if found (parent filled in), -1 if not in cache, -2 if at ceiling */
int
nfs_parent_cache_lookup(const struct nfs_fh *fh, struct nfs_fh *parent)
{
    unsigned int idx;

    parent_cache_init();
    idx = parent_cache_hash(fh);

    if (parent_cache[idx].valid && nfs_fh_equal(&parent_cache[idx].fh, fh)) {
        /* Always fill parent if available (for diagnostics even at ceiling) */
        if (parent_cache[idx].parent.len > 0)
            nfs_fh_copy(parent, &parent_cache[idx].parent);
        else
            parent->len = 0;
        if (parent_cache[idx].is_ceiling)
            return -2; /* At ceiling */
        return 0;
    }
    return -1;         /* Not in cache */
}

void
nfs_parent_cache_add(const struct nfs_fh *fh, const struct nfs_fh *parent, int is_ceiling)
{
    unsigned int idx;

    parent_cache_init();
    idx = parent_cache_hash(fh);

    nfs_fh_copy(&parent_cache[idx].fh, fh);
    if (parent)
        nfs_fh_copy(&parent_cache[idx].parent, parent);
    parent_cache[idx].is_ceiling = is_ceiling;
    parent_cache[idx].valid = 1;
}

/*
 * Clear the parent FH cache.
 * Called by cache management commands.
 */
void
nfs_parent_cache_clear(void)
{
    memset(parent_cache, 0, sizeof(parent_cache));
}

/*
 * Get parent cache statistics.
 */
size_t
nfs_parent_cache_count(void)
{
    size_t count = 0;
    int i;

    for (i = 0; i < PARENT_CACHE_SIZE; i++) {
        if (parent_cache[i].valid)
            count++;
    }
    return count;
}

/*
 * Mark an FH as being at ceiling (cannot go higher).
 * Used to pre-seed the cache for root exports ("/").
 */
void
nfs_parent_cache_mark_ceiling(const struct nfs_fh *fh)
{
    nfs_parent_cache_add(fh, NULL, 1);
}

/*
 * Try to get parent FH using LOOKUP ".."
 * Returns 0 on success, -1 on failure or blocked
 */
static int
probe_lookup(struct nfsctx *ctx, const struct nfs_fh *fh, struct nfs_fh *parent)
{
    struct nfs_lookup_res res;

    memset(&res, 0, sizeof(res));
    if (nfs_lookup(ctx, fh, "..", &res) < 0)
        return -1;

    /* Check if blocked (same FH returned) */
    if (nfs_fh_equal(&res.fh, fh))
        return -1;

    nfs_fh_copy(parent, &res.fh);
    return 0;
}

/*
 * Try to get parent FH via READDIRPLUS (v3 only, may leak blocked parents)
 * Returns 0 on success, -1 on failure or blocked
 */
static int
probe_readdirplus(struct nfsctx *ctx, const struct nfs_fh *fh, struct nfs_fh *parent)
{
    struct nfs_dir dir;
    int found = 0;
    size_t i;

    if (ctx->proto.nfs_version < 3)
        return -1;

    nfs_dir_init(&dir);
    if (nfs_readdirplus(ctx, fh, &dir, NFS_READDIRPLUS_FULL) < 0) {
        nfs_dir_free(&dir);
        return -1;
    }

    /* Find ".." entry */
    for (i = 0; i < dir.count; i++) {
        if (strcmp(dir.entries[i].name, "..") == 0) {
            if (dir.entries[i].has_fh) {
                /* Check if blocked */
                if (!nfs_fh_equal(&dir.entries[i].fh, fh)) {
                    nfs_fh_copy(parent, &dir.entries[i].fh);
                    found = 1;
                }
            }
            break;
        }
    }

    nfs_dir_free(&dir);
    return found ? 0 : -1;
}

/*
 * Try all methods to get parent FH
 * Returns 0 on success, -1 if no method worked (at ceiling or blocked)
 */
static int
probe_parent(struct nfsctx *ctx, const struct nfs_fh *fh, struct nfs_fh *parent)
{
    int cache_result;

    /* Check cache first - avoids redundant RPCs when probing multiple exports */
    cache_result = nfs_parent_cache_lookup(fh, parent);
    if (cache_result == 0)
        return 0;  /* Found in cache */
    if (cache_result == -2)
        return -1; /* Known to be at ceiling */

    /* Try LOOKUP first (cheapest) */
    if (probe_lookup(ctx, fh, parent) == 0) {
        nfs_parent_cache_add(fh, parent, 0);
        return 0;
    }

    /* v3 fallback: READDIRPLUS returns ".." with FH, may leak blocked parents.
     * (Note: v3 READDIR does NOT return FHs - only fileid/name/cookie) */
    if (ctx->proto.nfs_version >= 3) {
        if (probe_readdirplus(ctx, fh, parent) == 0) {
            nfs_parent_cache_add(fh, parent, 0);
            return 0;
        }
    }

    /* At ceiling - cache this so we don't retry */
    nfs_parent_cache_add(fh, NULL, 1);
    return -1;
}

/*
 * Single-level escape probe with full diagnostics.
 * Always tries both methods (READDIRPLUS and LOOKUP) for diagnostic output.
 * Updates parent cache with results.
 */
int
nfs_probe_escape_one(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_fh *parent, struct nfs_escape_diag *diag)
{
    struct nfs_escape_diag local_diag;
    struct nfs_lookup_res lu_res;
    struct nfs_dir dir;
    int cache_result;
    int saved_quiet;
    size_t i;

    if (ctx == NULL || fh == NULL || parent == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Use local diag if caller doesn't want diagnostics */
    if (diag == NULL)
        diag = &local_diag;
    memset(diag, 0, sizeof(*diag));

    /* Check cache first */
    cache_result = nfs_parent_cache_lookup(fh, parent);
    if (cache_result == 0) {
        /* Found in cache - but check if it's actually blocked */
        if (nfs_fh_equal(parent, fh)) {
            /* Parent equals current FH - blocked at ceiling */
            if (ctx->proto.nfs_version >= 3) {
                diag->rdp_tried = 1;
                nfs_fh_copy(&diag->rdp_fh, parent);
                diag->rdp_got_fh = 1;
                diag->rdp_blocked = 1;
            }
            diag->lu_tried = 1;
            nfs_fh_copy(&diag->lu_fh, parent);
            diag->lu_got_fh = 1;
            diag->lu_blocked = 1;
            return 0;
        }
        diag->lu_tried = 1;
        diag->lu_got_fh = 1;
        diag->used_lu = 1;
        nfs_fh_copy(&diag->lu_fh, parent);
        return 1;
    }
    if (cache_result == -2) {
        /* Known ceiling - populate diag for consistent UI output */
        if (ctx->proto.nfs_version >= 3) {
            diag->rdp_tried = 1;
            if (parent->len > 0) {
                nfs_fh_copy(&diag->rdp_fh, parent);
                diag->rdp_got_fh = 1;
                diag->rdp_blocked = 1;
            }
        }
        diag->lu_tried = 1;
        if (parent->len > 0) {
            nfs_fh_copy(&diag->lu_fh, parent);
            diag->lu_got_fh = 1;
            diag->lu_blocked = 1;
        }
        return 0;
    }

    /* Suppress errors during probing */
    saved_quiet = ctx->quiet;
    ctx->quiet = 1;

    /* Try READDIRPLUS (v3 only) - always try for diagnostics */
    if (ctx->proto.nfs_version >= 3) {
        diag->rdp_tried = 1;
        nfs_dir_init(&dir);
        if (nfs_readdirplus(ctx, fh, &dir, NFS_READDIRPLUS_FULL) == 0) {
            for (i = 0; i < dir.count; i++) {
                if (strcmp(dir.entries[i].name, "..") == 0 &&
                    dir.entries[i].has_fh) {
                    nfs_fh_copy(&diag->rdp_fh, &dir.entries[i].fh);
                    diag->rdp_got_fh = 1;
                    diag->rdp_blocked = nfs_fh_equal(&diag->rdp_fh, fh);
                    break;
                }
            }
            nfs_dir_free(&dir);
        }
    }

    /* Try LOOKUP - always try for diagnostics */
    diag->lu_tried = 1;
    memset(&lu_res, 0, sizeof(lu_res));
    if (nfs_lookup(ctx, fh, "..", &lu_res) == 0) {
        nfs_fh_copy(&diag->lu_fh, &lu_res.fh);
        diag->lu_got_fh = 1;
        diag->lu_blocked = nfs_fh_equal(&diag->lu_fh, fh);
    }

    ctx->quiet = saved_quiet;

    /*
     * Pick best result - prefer one that isn't blocked.
     * Try READDIRPLUS first (often leaks when LOOKUP is blocked).
     */
    if (diag->rdp_got_fh && !diag->rdp_blocked) {
        nfs_fh_copy(parent, &diag->rdp_fh);
        diag->used_rdp = 1;
        nfs_parent_cache_add(fh, parent, 0);
        return 1;
    }
    if (diag->lu_got_fh && !diag->lu_blocked) {
        nfs_fh_copy(parent, &diag->lu_fh);
        diag->used_lu = 1;
        nfs_parent_cache_add(fh, parent, 0);
        return 1;
    }

    /* Both methods blocked or failed - at ceiling */
    nfs_parent_cache_add(fh, NULL, 1);
    return 0;
}

/*
 * Probe escape path from start_fh up to ceiling.
 *
 * Tries LOOKUP, READDIR, READDIRPLUS to climb above export root.
 * Stops when:
 *   - All methods fail or return blocked (same FH)
 *   - We've climbed max_depth levels (if max_depth > 0)
 *   - We've climbed too many levels (safety limit)
 *
 * max_depth: Maximum levels to climb. Use 0 or negative for no limit.
 *            For an export like "/sbin", pass 1 (depth to root).
 *            This avoids the redundant ceiling-detection LOOKUP.
 *
 * Returns array of parent FHs from immediate parent to ceiling.
 */
#define PROBE_MAX_DEPTH 128

int
nfs_probe_escape(struct nfsctx *ctx, const struct nfs_fh *start_fh,
    int max_depth, struct nfs_fh **parents, int *count)
{
    struct nfs_fh *result = NULL;
    struct nfs_fh current;
    struct nfs_fh parent;
    int depth = 0;
    size_t capacity = 8;
    int limit;
    int saved_quiet;

    if (!ctx || !start_fh || !parents || !count) {
        errno = EINVAL;
        return -1;
    }

    *parents = NULL;
    *count = 0;

    /* Determine effective limit */
    limit = (max_depth > 0) ? max_depth : PROBE_MAX_DEPTH;

    /* Allocate initial result array */
    result = malloc(capacity * sizeof(struct nfs_fh));
    if (!result) {
        errno = ENOMEM;
        return -1;
    }

    /* Start from given FH */
    nfs_fh_copy(&current, start_fh);

    /*
     * Suppress NFS errors during probing - hitting the ceiling (ENOENT
     * from LOOKUP "..") is expected and shouldn't confuse the user.
     */
    saved_quiet = ctx->quiet;
    ctx->quiet = 1;

    /* Probe upward until blocked, at ceiling, or reached max depth */
    while (depth < limit) {
        if (probe_parent(ctx, &current, &parent) < 0) {
            /* Can't go higher - at ceiling */
            break;
        }

        /* Grow array if needed */
        if ((size_t)depth >= capacity) {
            size_t new_cap;
            struct nfs_fh *new_result;
            if (capacity > SIZE_MAX / 2 / sizeof(struct nfs_fh)) {
                ctx->quiet = saved_quiet;
                free(result);
                errno = ENOMEM;
                return -1;
            }
            new_cap = capacity * 2;
            new_result = realloc(result, new_cap * sizeof(struct nfs_fh));
            if (!new_result) {
                ctx->quiet = saved_quiet;
                free(result);
                errno = ENOMEM;
                return -1;
            }
            result = new_result;
            capacity = new_cap;
        }

        /* Add to result */
        nfs_fh_copy(&result[depth], &parent);
        depth++;

        /* Move up for next iteration */
        nfs_fh_copy(&current, &parent);
    }

    /* Restore quiet setting */
    ctx->quiet = saved_quiet;

    /*
     * If we stopped due to max_depth limit (not ceiling detection),
     * mark the last parent as ceiling to prevent future probes.
     */
    if (depth > 0 && max_depth > 0 && depth >= max_depth) {
        nfs_parent_cache_add(&result[depth - 1], NULL, 1);
    }

    *parents = result;
    *count = depth;
    return 0;
}
