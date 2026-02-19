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
 * pathctx.c - Path-based NFS navigation and export traversal
 *
 * Provides Unix-like path resolution over NFS exports. Key capabilities:
 *
 *   - Path resolution: "/foo/bar" → file handle chain via LOOKUPs
 *   - Cross-export navigation: seamless cd between /export/a and /export/b
 *   - Parent directory tracking: cd .. works even across export boundaries
 *
 * Export Boundary Escape (three-phase approach):
 *
 *   Phase 1: Direct escape via nfs_probe_escape() (in nfs_escape.c)
 *     - LOOKUP ".." from export root
 *     - READDIRPLUS to get ".." FH (often leaks when LOOKUP blocked)
 *
 *   Phase 2: Covering export probe (probe_via_covering_exports)
 *     - If export is /export/home, try mounting /export or /
 *     - Walk down from covering export to build parent FH chain
 *     - Example: /export/home blocked → mount / → LOOKUP export → home
 *
 *   Phase 3: Cross-export escape (probe_via_escapable_export)
 *     - Find ANY export that can escape (e.g., / or /tmp)
 *     - Use its ceiling as filesystem root
 *     - Build path from that root down to current location
 *
 * Mount Management:
 *   - path_mount structures track each mounted export
 *   - ceiling_fh marks the highest reachable directory (filesystem root)
 *   - Mounts are auto-added when navigating to new exports
 *
 * Uses nfs_cache for LOOKUP results, nfs_escape for parent probing.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "mount.h"
#include "nfs.h"
#include "nfs_escape.h"
#include "nfscli.h"
#include "pathctx.h"

/*
 * Path utilities
 */

int
path_is_absolute(const char *path)
{
    return path != NULL && path[0] == '/';
}

const char *
path_basename(const char *path)
{
    const char *slash;

    if (path == NULL)
        return NULL;
    slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

int
path_dirname(const char *path, char *out, size_t len)
{
    const char *slash;
    size_t dirlen;

    if (path == NULL || out == NULL || len == 0)
        return -1;

    slash = strrchr(path, '/');
    if (slash == NULL) {
        out[0] = '.';
        out[1] = '\0';
        return 0;
    }

    if (slash == path) {
        out[0] = '/';
        out[1] = '\0';
        return 0;
    }

    dirlen = (size_t)(slash - path);
    if (dirlen >= len)
        dirlen = len - 1;
    memcpy(out, path, dirlen);
    out[dirlen] = '\0';
    return 0;
}

/*
 * Remove last component from path in-place.
 * "/foo/bar" -> "/foo", "/foo" -> "/", "/" -> "/"
 */
static void
path_remove_last_component(char *path)
{
    char *last_slash = strrchr(path, '/');
    if (last_slash && last_slash != path)
        *last_slash = '\0';
    else if (last_slash == path)
        path[1] = '\0';
}

int
path_join(const char *dir, const char *name, char *out, size_t len)
{
    size_t dirlen;
    int n;

    if (out == NULL || len == 0)
        return -1;

    if (dir == NULL || dir[0] == '\0') {
        n = snprintf(out, len, "%s", name ? name : "");
        return (n < 0 || (size_t)n >= len) ? -1 : 0;
    }

    if (name == NULL || name[0] == '\0') {
        n = snprintf(out, len, "%s", dir);
        return (n < 0 || (size_t)n >= len) ? -1 : 0;
    }

    /* Handle absolute name */
    if (name[0] == '/') {
        n = snprintf(out, len, "%s", name);
        return (n < 0 || (size_t)n >= len) ? -1 : 0;
    }

    dirlen = strlen(dir);
    if (dir[dirlen - 1] == '/')
        n = snprintf(out, len, "%s%s", dir, name);
    else
        n = snprintf(out, len, "%s/%s", dir, name);

    return (n < 0 || (size_t)n >= len) ? -1 : 0;
}

int
path_count_components(const char *path)
{
    int count = 0;
    const char *p;

    if (path == NULL)
        return 0;

    for (p = path; *p != '\0'; p++) {
        if (*p == '/' && p[1] != '\0' && p[1] != '/')
            count++;
    }

    /* Count first component if path doesn't start with / */
    if (path[0] != '\0' && path[0] != '/')
        count++;

    return count;
}

/*
 * Return length of path truncated to n components.
 * "/a/b/c" with n=2 returns 4 (length of "/a/b").
 * "/home" with n=1 returns 5 (length of "/home").
 * n=0 returns 1 (for "/").
 */
size_t
path_prefix_len(const char *path, int n)
{
    const char *p;
    int count = 0;

    if (path == NULL || path[0] != '/')
        return 0;

    if (n <= 0)
        return 1; /* Just "/" */

    /* Skip leading slash, then find end of nth component */
    p = path + 1;
    while (*p) {
        /* Skip slashes */
        while (*p == '/')
            p++;
        if (*p == '\0')
            break;

        /* Found start of a component */
        count++;

        /* Skip to end of component */
        while (*p && *p != '/')
            p++;

        /* If we've counted n components, return current position */
        if (count >= n)
            return (size_t)(p - path);
    }

    /* Return full path length if fewer than n components */
    return (size_t)(p - path);
}

/*
 * Normalize a path: resolve ., .., and multiple slashes.
 * Input and output may be the same buffer.
 */
int
path_normalize(const char *in, char *out, size_t len)
{
    char *components[PATH_MAX / 2];
    char stack_buf[NFS_MAXPATHLEN + 1];
    char *buf, *p, *saveptr;
    int ncomp = 0;
    int is_absolute;
    size_t pos, in_len;
    int i;
    int heap_alloc = 0;

    if (in == NULL || out == NULL || len == 0)
        return -1;

    /* Use stack buffer for typical paths, heap for very long ones */
    in_len = strlen(in);
    if (in_len < sizeof(stack_buf)) {
        memcpy(stack_buf, in, in_len + 1);
        buf = stack_buf;
    } else {
        buf = strdup(in);
        if (buf == NULL)
            return -1;
        heap_alloc = 1;
    }

    is_absolute = (in[0] == '/');

    /* Split into components */
    for (p = strtok_r(buf, "/", &saveptr);
        p != NULL;
        p = strtok_r(NULL, "/", &saveptr)) {

        if (p[0] == '\0' || strcmp(p, ".") == 0)
            continue;

        if (strcmp(p, "..") == 0) {
            if (ncomp > 0 && strcmp(components[ncomp - 1], "..") != 0)
                ncomp--;
            else if (!is_absolute)
                components[ncomp++] = p;
            continue;
        }

        components[ncomp++] = p;
    }

    /* Rebuild path */
    pos = 0;
    if (is_absolute && pos < len - 1)
        out[pos++] = '/';

    for (i = 0; i < ncomp && pos < len - 1; i++) {
        if (i > 0 && pos < len - 1)
            out[pos++] = '/';
        size_t clen = strlen(components[i]);
        if (pos + clen >= len)
            clen = len - pos - 1;
        memcpy(out + pos, components[i], clen);
        pos += clen;
    }

    if (pos == 0 && len > 0) {
        out[0] = is_absolute ? '/' : '.';
        pos = 1;
    }
    out[pos] = '\0';

    if (heap_alloc)
        free(buf);
    return 0;
}

/*
 * Mount management
 */

static struct path_mount *
mount_alloc(const char *export_path, const struct nfs_fh *root_fh)
{
    struct path_mount *mnt;

    mnt = calloc(1, sizeof(*mnt));
    if (mnt == NULL)
        return NULL;

    mnt->export_path = strdup(export_path);
    if (mnt->export_path == NULL) {
        free(mnt);
        return NULL;
    }
    mnt->export_path_len = strlen(export_path);

    nfs_fh_copy(&mnt->root_fh, root_fh);
    nfs_fh_copy(&mnt->ceiling_fh, root_fh);
    mnt->depth = path_count_components(export_path);

    return mnt;
}

static void
mount_free(struct path_mount *mnt)
{
    if (mnt) {
        free(mnt->export_path);
        free(mnt);
    }
}

/*
 * Initialize path context with an export
 */
int
pathctx_init(struct pathctx *ctx, struct nfsctx *nfs,
    const char *export_path, const struct nfs_fh *root_fh)
{
    struct path_mount *mnt;

    if (ctx == NULL || nfs == NULL || export_path == NULL || root_fh == NULL) {
        errno = EINVAL;
        return -1;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->nfs = nfs;

    /* Create initial mount */
    mnt = mount_alloc(export_path, root_fh);
    if (mnt == NULL)
        return -1;

    ctx->mounts = mnt;
    ctx->mount_count = 1;
    ctx->cwd_mount = mnt;

    /* Set initial position */
    nfs_fh_copy(&ctx->cwd_fh, root_fh);
    nfs_fh_copy(&ctx->home_fh, root_fh);
    nfs_fh_copy(&ctx->prev_fh, root_fh);
    snprintf(ctx->cwd_path, sizeof(ctx->cwd_path), "%s", export_path);

    /* Probe for escape on initial mount */
    pathctx_probe_escape(ctx, mnt);

    return 0;
}

void
pathctx_destroy(struct pathctx *ctx)
{
    struct path_mount *mnt, *next;

    if (ctx == NULL)
        return;

    for (mnt = ctx->mounts; mnt != NULL; mnt = next) {
        next = mnt->next;
        mount_free(mnt);
    }

    memset(ctx, 0, sizeof(*ctx));
}

int
pathctx_mount(struct pathctx *ctx, const char *export_path,
    const struct nfs_fh *root_fh)
{
    struct path_mount *mnt, *p, *candidate;
    size_t export_len, len, best_len;

    if (ctx == NULL || export_path == NULL || root_fh == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Check for existing mount */
    for (p = ctx->mounts; p != NULL; p = p->next) {
        if (strcmp(p->export_path, export_path) == 0) {
            /*
             * Already mounted - verify FH matches.
             * If FH changed, the mount is stale.
             */
            if (!nfs_fh_equal(&p->root_fh, root_fh)) {
                errno = ESTALE;
                return -1;
            }
            return 0; /* Already mounted with same FH */
        }
    }

    mnt = mount_alloc(export_path, root_fh);
    if (mnt == NULL)
        return -1;

    /*
     * Find parent mount (longest existing path that is a proper prefix).
     * This avoids path manipulation at lookup time.
     */
    mnt->parent = NULL;
    export_len = strlen(export_path);
    best_len = 0;
    for (candidate = ctx->mounts; candidate != NULL; candidate = candidate->next) {
        len = candidate->export_path_len;
        if (len < export_len &&
            strncmp(candidate->export_path, export_path, len) == 0 &&
            (export_path[len] == '/' || len == 1) && /* "/" matches all */
            len > best_len) {
            mnt->parent = candidate;
            best_len = len;
        }
    }

    /* Add to list */
    mnt->next = ctx->mounts;
    ctx->mounts = mnt;
    ctx->mount_count++;

    /*
     * Probe for escape on this mount.
     * This sets mnt->escaped and may set ctx->has_ceiling if we
     * reach true root. Essential for proper path resolution.
     */
    pathctx_probe_escape(ctx, mnt);

    return 0;
}

/*
 * Unmount an export.
 * Removes mount from list and frees resources.
 * Updates parent pointers for any child mounts.
 */
int
pathctx_unmount(struct pathctx *ctx, const char *export_path)
{
    struct path_mount **pp;
    struct path_mount *mnt, *child;

    if (ctx == NULL || export_path == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Find and remove from list */
    for (pp = &ctx->mounts; *pp != NULL; pp = &(*pp)->next) {
        if (strcmp((*pp)->export_path, export_path) == 0) {
            mnt = *pp;
            *pp = mnt->next;
            ctx->mount_count--;

            /*
             * Update parent pointers for any child mounts.
             * Children of this mount should now point to this mount's parent.
             */
            for (child = ctx->mounts; child != NULL; child = child->next) {
                if (child->parent == mnt)
                    child->parent = mnt->parent;
            }

            /* Update cwd_mount if it was pointing to this mount */
            if (ctx->cwd_mount == mnt)
                ctx->cwd_mount = mnt->parent ? mnt->parent : ctx->mounts;

            mount_free(mnt);
            return 0;
        }
    }

    errno = ENOENT;
    return -1;
}

struct path_mount *
pathctx_find_mount(struct pathctx *ctx, const char *path)
{
    struct path_mount *mnt, *best = NULL;
    size_t best_len = 0;

    if (ctx == NULL || path == NULL)
        return NULL;

    /* Find longest matching mount */
    for (mnt = ctx->mounts; mnt != NULL; mnt = mnt->next) {
        size_t len = mnt->export_path_len;
        if (strncmp(path, mnt->export_path, len) == 0) {
            if (path[len] == '\0' || path[len] == '/') {
                if (len > best_len) {
                    best = mnt;
                    best_len = len;
                }
            }
        }
    }

    return best;
}

/*
 * Try to reach a path via covering exports.
 * E.g., for /export/home, try to get FH via /export or / exports.
 * Returns 1 if ceiling_fh was set, 0 otherwise.
 */
static int
probe_via_covering_exports(struct pathctx *ctx, struct path_mount *mnt)
{
    char parent_path[PATH_MAX];
    char *last_slash;
    const char *covering_export;
    uint8_t exp_fh[NFS_FHSIZE_MAX];
    int exp_fhlen;
    struct nfs_fh parent_fh;
    struct nfs_fh highest_fh;
    struct nfs_lookup_res res;
    char comp[NAME_MAX + 1];
    const char *remainder, *next;
    size_t len;
    int saved_quiet;
    int found_ceiling = 0;
    size_t parent_len;

    snprintf(parent_path, sizeof(parent_path), "%s", mnt->export_path);
    parent_len = strlen(parent_path);

    /* Walk up the path, finding parents via alternate exports */
    while (parent_len > 1) {
        /* Remove last component to get parent path */
        last_slash = strrchr(parent_path, '/');
        if (!last_slash || last_slash == parent_path) {
            if (parent_path[0] == '/' && parent_path[1] != '\0') {
                parent_path[1] = '\0'; /* Truncate to "/" */
                parent_len = 1;
            } else {
                break;
            }
        } else {
            *last_slash = '\0';
            parent_len = last_slash - parent_path;
        }

        /* Find an export that covers this parent path */
        covering_export = mount_exports_find_best(ctx->nfs, parent_path);
        if (!covering_export)
            continue;

        /* Mount the covering export */
        exp_fhlen = mount_mnt_cached(ctx->nfs, covering_export,
            exp_fh, sizeof(exp_fh), MNT_CACHE_UMNT);
        if (exp_fhlen < 0)
            continue;

        /* Build FH for parent by LOOKUPs from export root */
        parent_fh.len = exp_fhlen;
        memcpy(parent_fh.data, exp_fh, exp_fhlen);

        /* If parent_path is longer than covering_export, do LOOKUPs */
        size_t cover_len = strlen(covering_export);
        if (parent_len > cover_len) {
            remainder = parent_path + cover_len;
            while (*remainder == '/')
                remainder++;

            saved_quiet = ctx->nfs->quiet;
            ctx->nfs->quiet = 1;
            while (*remainder) {
                next = strchr(remainder, '/');
                len = next ? (size_t)(next - remainder) : strlen(remainder);
                if (len > NAME_MAX)
                    len = NAME_MAX;
                memcpy(comp, remainder, len);
                comp[len] = '\0';

                if (nfs_lookup(ctx->nfs, &parent_fh, comp, &res) < 0)
                    break;
                nfs_fh_copy(&parent_fh, &res.fh);
                remainder = next ? next + 1 : "";
                while (*remainder == '/')
                    remainder++;
            }
            ctx->nfs->quiet = saved_quiet;
        }

        /* Track highest parent we've found */
        nfs_fh_copy(&highest_fh, &parent_fh);
        found_ceiling = 1;

        /* Add to parent cache */
        nfs_parent_cache_add(&mnt->root_fh, &parent_fh, 0);

        if (strcmp(parent_path, "/") == 0) {
            /* Reached root */
            nfs_parent_cache_mark_ceiling(&parent_fh);
            break;
        }
    }

    if (found_ceiling) {
        mnt->escaped = 1;
        nfs_fh_copy(&mnt->ceiling_fh, &highest_fh);
        if (strcmp(parent_path, "/") == 0 && !ctx->has_ceiling) {
            nfs_fh_copy(&ctx->ceiling_fh, &highest_fh);
            ctx->has_ceiling = 1;
        }
    }

    return found_ceiling;
}

/*
 * Try to find ANY export that can escape, then LOOKUP down to build
 * parent chain for the current mount.
 * Returns 1 if ceiling_fh was set, 0 otherwise.
 */
static int
probe_via_escapable_export(struct pathctx *ctx, struct path_mount *mnt)
{
    size_t exp_count, i;
    const char *try_export;
    uint8_t try_fh[NFS_FHSIZE_MAX];
    int try_fhlen;
    struct nfs_fh start_fh;
    struct nfs_fh *esc_parents = NULL;
    int esc_count = 0;
    struct nfs_fh root_fh;
    struct nfs_fh cur_fh;
    struct nfs_lookup_res res;
    const char *p, *comp_start;
    char comp[NAME_MAX + 1];
    size_t comp_len;
    int saved_quiet;
    int found = 0;

    /* Ensure exports are cached */
    (void)mount_exports_find_best(ctx->nfs, "/");
    exp_count = mount_exports_cache_count(ctx->nfs);

    for (i = 0; i < exp_count; i++) {
        try_export = mount_exports_cache_get(ctx->nfs, i);
        if (!try_export || strcmp(try_export, mnt->export_path) == 0)
            continue;

        /* Mount this export */
        try_fhlen = mount_mnt_cached(ctx->nfs, try_export,
            try_fh, sizeof(try_fh), MNT_CACHE_UMNT);
        if (try_fhlen < 0)
            continue;

        start_fh.len = try_fhlen;
        memcpy(start_fh.data, try_fh, try_fhlen);

        /* Try to escape from this export */
        esc_parents = NULL;
        esc_count = 0;
        if (nfs_probe_escape(ctx->nfs, &start_fh,
                path_count_components(try_export), &esc_parents, &esc_count) < 0 ||
            esc_count <= 0) {
            free(esc_parents);
            continue;
        }

        /* Got root FH - now LOOKUP down to our mount's parent */
        nfs_fh_copy(&root_fh, &esc_parents[esc_count - 1]);
        free(esc_parents);

        /* LOOKUP each component of mnt->export_path except the last */
        nfs_fh_copy(&cur_fh, &root_fh);
        p = mnt->export_path;
        if (*p == '/')
            p++;

        saved_quiet = ctx->nfs->quiet;
        ctx->nfs->quiet = 1;

        while (*p) {
            comp_start = p;
            while (*p && *p != '/')
                p++;
            comp_len = p - comp_start;

            /* Skip the last component (that's our mount root itself) */
            while (*p == '/')
                p++;
            if (*p == '\0')
                break; /* Don't LOOKUP the final component */

            if (comp_len > NAME_MAX)
                comp_len = NAME_MAX;
            memcpy(comp, comp_start, comp_len);
            comp[comp_len] = '\0';

            if (nfs_lookup(ctx->nfs, &cur_fh, comp, &res) < 0)
                break;
            nfs_fh_copy(&cur_fh, &res.fh);
        }

        ctx->nfs->quiet = saved_quiet;

        /* cur_fh is now the parent of our mount root */
        nfs_parent_cache_add(&mnt->root_fh, &cur_fh, 0);

        /* Set ceiling to root */
        mnt->escaped = 1;
        nfs_fh_copy(&mnt->ceiling_fh, &root_fh);
        nfs_parent_cache_mark_ceiling(&root_fh);

        if (!ctx->has_ceiling) {
            nfs_fh_copy(&ctx->ceiling_fh, &root_fh);
            ctx->has_ceiling = 1;
        }

        found = 1;
        break;
    }

    return found;
}

/*
 * Probe for root escape - try to climb above mount root to filesystem root.
 *
 * Three-phase approach:
 * 1. Direct escape via nfs_probe_escape() (LOOKUP ".." / READDIRPLUS)
 * 2. Covering export lookup - find parents via alternate exports
 * 3. Escapable export fallback - find ANY export that can escape to root
 *
 * When escape succeeds, sets the global ceiling_fh for absolute path lookups.
 * Special case: "/" export is already at filesystem root.
 */
int
pathctx_probe_escape(struct pathctx *ctx, struct path_mount *mnt)
{
    struct nfs_fh *parents = NULL;
    int count = 0;

    if (ctx == NULL || mnt == NULL)
        return -1;

    if (mnt->escaped)
        return 1; /* Already escaped */

    /*
     * Special case: "/" export is already at filesystem root.
     * No need to probe - just set ceiling to root_fh.
     */
    if (strcmp(mnt->export_path, "/") == 0) {
        mnt->escaped = 1;
        nfs_fh_copy(&mnt->ceiling_fh, &mnt->root_fh);
        nfs_parent_cache_mark_ceiling(&mnt->root_fh);
        if (!ctx->has_ceiling) {
            nfs_fh_copy(&ctx->ceiling_fh, &mnt->root_fh);
            ctx->has_ceiling = 1;
        }
        return 1;
    }

    /*
     * Phase 1: Direct escape via nfs_probe_escape().
     * This tries LOOKUP ".." and READDIRPLUS to climb up.
     */
    if (nfs_probe_escape(ctx->nfs, &mnt->root_fh, mnt->depth, &parents, &count) == 0 &&
        count > 0) {
        /* Escaped! Set ceiling to highest parent reached */
        mnt->escaped = 1;
        nfs_fh_copy(&mnt->ceiling_fh, &parents[count - 1]);

        if (count >= mnt->depth && !ctx->has_ceiling) {
            nfs_fh_copy(&ctx->ceiling_fh, &parents[count - 1]);
            ctx->has_ceiling = 1;
        }

        free(parents);
        return 1;
    }
    free(parents);

    /*
     * Phase 2: Covering export lookup.
     * Walk up export path, find covering exports, LOOKUP to reach parents.
     */
    if (probe_via_covering_exports(ctx, mnt))
        return 1;

    /*
     * Phase 3: Escapable export fallback.
     * Try ALL exports, find one that can escape, LOOKUP down to our parents.
     */
    if (probe_via_escapable_export(ctx, mnt))
        return 1;

    return 0;
}

/*
 * Core path resolution
 */

static int
resolve_internal(struct pathctx *ctx, const char *path, int flags,
    int symlink_hops, struct path_result *out);

/*
 * Check for export crossing - if resolved_path matches an export with
 * a different FH than what LOOKUP returned, return the export's FH.
 * Also handles child export climbing (e.g., reach /usr via /usr/bin export).
 *
 * Returns 1 if fh was updated, 0 if no change needed.
 */
static int
check_export_crossing(struct pathctx *ctx, const char *resolved_path,
    struct nfs_fh *fh)
{
    uint8_t export_fh[NFS_FHSIZE_MAX];
    uint8_t child_fh[NFS_FHSIZE_MAX];
    struct nfs_fh check_fh, climb_fh;
    struct nfs_lookup_res lookup_res;
    struct mount_export_iter iter;
    const char *child_export;
    const char *exp;
    int export_fhlen, child_fhlen;
    int target_depth, child_depth;
    int levels_up, climb_ok;
    int saved_quiet;
    int found_exact = 0;
    size_t i, target_len;
    int k;

    /* Check if this path is in FH cache */
    if (mount_fh_cache_lookup(ctx->nfs, resolved_path,
            export_fh, &export_fhlen) == 0) {
        found_exact = 1;
    } else {
        /* Check exports list for exact match */
        i = 0;
        while ((exp = mount_exports_cache_get(ctx->nfs, i++)) != NULL) {
            if (strcmp(exp, resolved_path) == 0) {
                found_exact = 1;
                break;
            }
        }

        if (found_exact) {
            /* It's an export but not cached - mount it */
            export_fhlen = mount_mnt_cached(ctx->nfs, resolved_path,
                export_fh, sizeof(export_fh), MNT_CACHE_UMNT);
            if (export_fhlen < 0)
                return 0;
        }
    }

    if (!found_exact) {
        /*
         * Not an export itself - check if we can reach it via child export.
         * E.g., if resolved_path="/usr" and export="/usr/bin" exists,
         * mount /usr/bin and climb up with LOOKUP ".." to reach /usr.
         */
        target_depth = path_count_components(resolved_path);
        if (target_depth < 0)
            return 0;

        mount_export_iter_init(&iter, resolved_path);
        while ((child_export = mount_export_iter_next(ctx->nfs, &iter)) != NULL) {
            child_depth = path_count_components(child_export);
            climb_ok = 1;

            if (child_depth <= target_depth)
                continue; /* Not a child */

            /* Check if export is under our target path */
            target_len = strlen(resolved_path);
            if (strncmp(child_export, resolved_path, target_len) != 0)
                continue;
            if (target_len > 1 && child_export[target_len] != '/')
                continue;

            /* Mount the child export */
            child_fhlen = mount_mnt_cached(ctx->nfs, child_export,
                child_fh, sizeof(child_fh), MNT_CACHE_UMNT);
            if (child_fhlen < 0)
                continue;

            /* Climb up from child export to target path */
            levels_up = child_depth - target_depth;
            climb_fh.len = child_fhlen;
            memcpy(climb_fh.data, child_fh, child_fhlen);

            saved_quiet = ctx->nfs->quiet;
            ctx->nfs->quiet = 1;
            for (k = 0; k < levels_up && climb_ok; k++) {
                memset(&lookup_res, 0, sizeof(lookup_res));
                if (nfs_lookup(ctx->nfs, &climb_fh, "..", &lookup_res) < 0) {
                    climb_ok = 0;
                } else {
                    nfs_fh_copy(&climb_fh, &lookup_res.fh);
                }
            }
            ctx->nfs->quiet = saved_quiet;

            if (climb_ok) {
                memcpy(export_fh, climb_fh.data, climb_fh.len);
                export_fhlen = climb_fh.len;
                found_exact = 1;
                break;
            }
        }

        if (!found_exact)
            return 0;
    }

    /* Compare file handles */
    check_fh.len = export_fhlen;
    memcpy(check_fh.data, export_fh, export_fhlen);

    if (nfs_fh_equal(fh, &check_fh))
        return 0; /* Same FH, no crossing */

    /* Different FH - switch to export's FH */
    nfs_fh_copy(fh, &check_fh);
    return 1;
}

/*
 * Core path resolution with inline symlink handling.
 *
 * Handles symlinks during path walking, not just at the end.
 * This correctly resolves paths like /foo/link/bar where link is a symlink.
 * Uses resolved_path for proper relative symlink context.
 */
static int
resolve_internal(struct pathctx *ctx, const char *path, int flags,
    int symlink_hops, struct path_result *out)
{
    char pathbuf[PATH_MAX];
    char resolved_path[PATH_MAX]; /* Track current resolved absolute path */
    char *p, *next;
    struct nfs_fh current_fh, prev_fh;
    struct nfs_lookup_res res;
    struct nfs_readlink_res linkres;
    const char *last_component = NULL;
    int have_prev = 0;
    int is_absolute;
    int follow = (flags & PATH_FOLLOW) != 0;
    int want_parent = (flags & PATH_WANT_PARENT) != 0;
    size_t resolved_len;

    memset(out, 0, sizeof(*out));

    /* Handle empty path */
    if (path == NULL || path[0] == '\0') {
        nfs_fh_copy(&out->fh, &ctx->cwd_fh);
        return 0;
    }

    /* Copy path for manipulation */
    if (snprintf(pathbuf, sizeof(pathbuf), "%s", path) >= (int)sizeof(pathbuf)) {
        errno = ENAMETOOLONG;
        return -1;
    }

restart_resolution:
    /* Check symlink limit (checked here for loop-based symlink handling) */
    if (symlink_hops > PATH_MAX_SYMLINK_HOPS) {
        errno = ELOOP;
        return -1;
    }

    is_absolute = path_is_absolute(pathbuf);

    /* Initialize resolved_path for export crossing and relative symlinks */
    if (is_absolute) {
        resolved_path[0] = '\0'; /* Will build from "/" */
    } else {
        snprintf(resolved_path, sizeof(resolved_path), "%s", ctx->cwd_path);
    }

    /* Determine starting point */
    if (is_absolute) {
        /*
         * Absolute path resolution strategy:
         * 1. If we have a global ceiling (reached true root via escape),
         *    use that as starting point and resolve full path from root.
         * 2. If no global ceiling, find matching mount and use its root/ceiling.
         */
        if (ctx->has_ceiling) {
            nfs_fh_copy(&current_fh, &ctx->ceiling_fh);
        } else {
            char normalized[PATH_MAX];
            struct path_mount *mnt;

            path_normalize(pathbuf, normalized, sizeof(normalized));
            mnt = pathctx_find_mount(ctx, normalized);
            if (mnt == NULL)
                mnt = ctx->mounts;
            if (mnt == NULL) {
                errno = ENOENT;
                return -1;
            }

            size_t norm_len = strlen(normalized);
            size_t mount_len = mnt->export_path_len;
            int path_is_above = 0;

            if (norm_len == 1 && normalized[0] == '/') {
                path_is_above = (mount_len > 1);
            } else if (norm_len < mount_len &&
                strncmp(normalized, mnt->export_path, norm_len) == 0 &&
                mnt->export_path[norm_len] == '/') {
                path_is_above = 1;
            }

            if (path_is_above) {
                nfs_fh_copy(&current_fh, &mnt->ceiling_fh);
            } else {
                nfs_fh_copy(&current_fh, &mnt->root_fh);
            }
        }
        /* Start after leading slash */
        p = pathbuf + 1;
        while (*p == '/')
            p++;
    } else {
        nfs_fh_copy(&current_fh, &ctx->cwd_fh);
        p = pathbuf;
    }

    /* Walk path components */
    while (*p) {
        char component[NAME_MAX + 1];
        size_t comp_len;
        int has_more;

        /* Skip leading slashes */
        while (*p == '/')
            p++;
        if (*p == '\0')
            break;

        /* Find end of component */
        next = p;
        while (*next && *next != '/')
            next++;
        has_more = (*next != '\0');

        /* Extract component */
        comp_len = (size_t)(next - p);
        if (comp_len > NAME_MAX)
            comp_len = NAME_MAX;
        memcpy(component, p, comp_len);
        component[comp_len] = '\0';

        /* Handle NAMEI_PARENT: stop at parent, return basename */
        if (want_parent && !has_more) {
            snprintf(out->basename, sizeof(out->basename), "%s", component);
            nfs_fh_copy(&out->parent_fh, &current_fh);
            out->has_parent = 1;

            /* Try to look up the target (may not exist for create) */
            memset(&res, 0, sizeof(res));
            if (nfs_lookup(ctx->nfs, &current_fh, component, &res) == 0) {
                nfs_fh_copy(&out->fh, &res.fh);
                if (res.has_obj_attr) {
                    out->attr = res.obj_attr;
                    out->has_attr = 1;
                }
            } else {
                /* Target doesn't exist - return parent info only */
                nfs_fh_copy(&out->fh, &current_fh);
            }
            return 0;
        }

        /* Save for parent tracking */
        nfs_fh_copy(&prev_fh, &current_fh);
        have_prev = 1;
        last_component = p; /* Point into pathbuf */

        /* Lookup component */
        memset(&res, 0, sizeof(res));
        if (nfs_lookup(ctx->nfs, &current_fh, component, &res) < 0) {
            /* Save parent info even on failure (for create) */
            if (want_parent) {
                nfs_fh_copy(&out->parent_fh, &prev_fh);
                snprintf(out->basename, sizeof(out->basename), "%s", component);
                out->has_parent = 1;
            }
            return -1;
        }

        nfs_fh_copy(&current_fh, &res.fh);
        if (res.has_obj_attr) {
            out->attr = res.obj_attr;
            out->has_attr = 1;
        }

        /*
         * Update resolved_path for export crossing and relative symlinks.
         */
        if (strcmp(component, ".") == 0) {
            /* Current dir - no change */
        } else if (strcmp(component, "..") == 0) {
            /* Parent dir - remove last component */
            path_remove_last_component(resolved_path);
        } else {
            /* Regular component - append */
            resolved_len = strlen(resolved_path);
            if (resolved_len == 0 || (resolved_len == 1 && resolved_path[0] == '/')) {
                /* Start fresh: "/<component>" */
                if (comp_len + 2 <= sizeof(resolved_path)) {
                    resolved_path[0] = '/';
                    memcpy(resolved_path + 1, component, comp_len + 1);
                }
            } else if (resolved_len + comp_len + 2 <= sizeof(resolved_path)) {
                /* Append: "/<component>" */
                resolved_path[resolved_len] = '/';
                memcpy(resolved_path + resolved_len + 1, component, comp_len + 1);
            }

            /* Check for export crossing */
            check_export_crossing(ctx, resolved_path, &current_fh);
        }

        /*
         * Get attrs if needed for symlink detection.
         * Must happen BEFORE symlink check - NFSv2 LOOKUP doesn't return attrs,
         * and NFSv3 servers may omit post-op attrs.
         */
        if (!out->has_attr && (has_more || follow)) {
            if (nfs_getattr(ctx->nfs, &current_fh, &out->attr) == 0)
                out->has_attr = 1;
        }

        /*
         * Handle symlinks inline.
         * Follow if there's more path remaining, or if FOLLOW flag set.
         *
         * Instead of recursing, we rebuild pathbuf and goto restart_resolution.
         * This avoids deep stack usage from symlink chains.
         */
        if (out->has_attr && out->attr.type == NFS_FTYPE_LNK &&
            (has_more || follow)) {
            int n;

            /* Read symlink target */
            memset(&linkres, 0, sizeof(linkres));
            if (nfs_readlink(ctx->nfs, &current_fh, &linkres) < 0)
                return -1;

            /* Handle symlink target - build new path directly in pathbuf */
            if (linkres.target[0] == '/') {
                /* Absolute symlink */
                if (has_more) {
                    n = snprintf(pathbuf, sizeof(pathbuf), "%s/%s",
                        linkres.target, next + 1);
                } else {
                    n = snprintf(pathbuf, sizeof(pathbuf), "%s", linkres.target);
                }
            } else {
                /*
                 * Relative symlink - resolve from symlink's parent.
                 * Get parent by removing last component from resolved_path.
                 */
                size_t parent_len;
                char *last_slash;

                /* Find parent (don't modify resolved_path) */
                last_slash = strrchr(resolved_path, '/');
                if (last_slash != NULL && last_slash != resolved_path)
                    parent_len = last_slash - resolved_path;
                else
                    parent_len = 1; /* root */

                /* Build full path: parent + "/" + target + remaining */
                if (parent_len == 1) {
                    if (has_more) {
                        n = snprintf(pathbuf, sizeof(pathbuf), "/%s/%s",
                            linkres.target, next + 1);
                    } else {
                        n = snprintf(pathbuf, sizeof(pathbuf), "/%s",
                            linkres.target);
                    }
                } else {
                    if (has_more) {
                        n = snprintf(pathbuf, sizeof(pathbuf), "%.*s/%s/%s",
                            (int)parent_len, resolved_path,
                            linkres.target, next + 1);
                    } else {
                        n = snprintf(pathbuf, sizeof(pathbuf), "%.*s/%s",
                            (int)parent_len, resolved_path, linkres.target);
                    }
                }
            }
            if (n < 0 || (size_t)n >= sizeof(pathbuf)) {
                errno = ENAMETOOLONG;
                return -1;
            }

            /* Reset state and restart resolution */
            symlink_hops++;
            have_prev = 0;
            last_component = NULL;
            memset(out, 0, sizeof(*out));
            goto restart_resolution;
        }

        /* Advance to next component */
        p = has_more ? next + 1 : next;
    }

    /* Store parent info */
    if (want_parent && have_prev && last_component) {
        nfs_fh_copy(&out->parent_fh, &prev_fh);
        size_t lc_len = 0;
        const char *lc = last_component;
        while (*lc && *lc != '/')
            lc_len++, lc++;
        if (lc_len > sizeof(out->basename) - 1)
            lc_len = sizeof(out->basename) - 1;
        memcpy(out->basename, last_component, lc_len);
        out->basename[lc_len] = '\0';
        out->has_parent = 1;
    }

    nfs_fh_copy(&out->fh, &current_fh);
    return 0;
}

int
path_resolve(struct pathctx *ctx, const char *path, int flags,
    struct path_result *out)
{
    if (ctx == NULL || out == NULL) {
        errno = EINVAL;
        return -1;
    }

    return resolve_internal(ctx, path, flags, 0, out);
}

/*
 * Navigation
 */

const char *
pathctx_pwd(struct pathctx *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->cwd_path;
}

const struct nfs_fh *
pathctx_cwd_fh(struct pathctx *ctx)
{
    if (ctx == NULL)
        return NULL;
    return &ctx->cwd_fh;
}

void
pathctx_set_home(struct pathctx *ctx)
{
    if (ctx == NULL)
        return;
    nfs_fh_copy(&ctx->home_fh, &ctx->cwd_fh);
}

int
pathctx_chdir(struct pathctx *ctx, const char *path)
{
    struct path_result res;
    char newpath[PATH_MAX];

    if (ctx == NULL || path == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Resolve path with symlink following */
    if (path_resolve(ctx, path, PATH_FOLLOW, &res) < 0)
        return -1;

    /* Check it's a directory */
    if (!res.has_attr) {
        if (nfs_getattr(ctx->nfs, &res.fh, &res.attr) < 0)
            return -1;
        res.has_attr = 1;
    }

    if (res.attr.type != NFS_FTYPE_DIR) {
        errno = ENOTDIR;
        return -1;
    }

    /* Save previous for cd - */
    nfs_fh_copy(&ctx->prev_fh, &ctx->cwd_fh);

    /* Update cwd */
    nfs_fh_copy(&ctx->cwd_fh, &res.fh);

    /* Update path string */
    if (path_is_absolute(path)) {
        path_normalize(path, newpath, sizeof(newpath));
    } else {
        char tmppath[PATH_MAX];
        path_join(ctx->cwd_path, path, tmppath, sizeof(tmppath));
        path_normalize(tmppath, newpath, sizeof(newpath));
    }

    /*
     * Check if the resolved path is at or above the mount point.
     * If we haven't escaped AND don't have global ceiling, clamp to mount's path.
     * If we have global ceiling access, allow any path (we can reach anywhere).
     */
    ctx->cwd_mount = pathctx_find_mount(ctx, newpath);
    if (ctx->cwd_mount == NULL)
        ctx->cwd_mount = ctx->mounts;

    if (ctx->cwd_mount != NULL && !ctx->cwd_mount->escaped && !ctx->has_ceiling) {
        size_t new_len = strlen(newpath);
        size_t mount_len = ctx->cwd_mount->export_path_len;
        if (new_len < mount_len &&
            strncmp(newpath, ctx->cwd_mount->export_path, new_len) == 0 &&
            (new_len == 1 || ctx->cwd_mount->export_path[new_len] == '/')) {
            /* Path is above mount and no escape - clamp to mount root */
            snprintf(ctx->cwd_path, sizeof(ctx->cwd_path), "%s",
                ctx->cwd_mount->export_path);
        } else {
            snprintf(ctx->cwd_path, sizeof(ctx->cwd_path), "%s", newpath);
        }
    } else {
        snprintf(ctx->cwd_path, sizeof(ctx->cwd_path), "%s", newpath);
    }

    return 0;
}

int
pathctx_chdir_prev(struct pathctx *ctx)
{
    struct nfs_fh tmp;

    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Swap cwd and prev */
    nfs_fh_copy(&tmp, &ctx->cwd_fh);
    nfs_fh_copy(&ctx->cwd_fh, &ctx->prev_fh);
    nfs_fh_copy(&ctx->prev_fh, &tmp);

    /* Path tracking is imperfect for cd - but works for FH */
    return 0;
}

int
pathctx_chdir_home(struct pathctx *ctx)
{
    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    nfs_fh_copy(&ctx->prev_fh, &ctx->cwd_fh);
    nfs_fh_copy(&ctx->cwd_fh, &ctx->home_fh);

    return 0;
}

/*
 * Tab completion - sophisticated path completion.
 *
 * Supports three modes:
 * - Basic mode (COMPLETION_BASIC): READDIR only, no attrs, no trailing slash
 *   Minimizes RPCs - good for NFSv2 over slow/expensive links.
 * - Enhanced mode v3: READDIRPLUS (1 RPC gives names + attrs + pre-cache)
 * - Enhanced mode v2: READDIR + filtered LOOKUPs for matching entries
 */

#define ADD_COMPLETION_RESULT(results, count, capacity, s)         \
    do {                                                           \
        if ((count) >= (capacity) - 1) {                           \
            char **tmp;                                            \
            if ((capacity) > SIZE_MAX / 2 / sizeof(char *))        \
                break;                                             \
            (capacity) *= 2;                                       \
            tmp = realloc((results), (capacity) * sizeof(char *)); \
            if (tmp == NULL)                                       \
                break;                                             \
            (results) = tmp;                                       \
        }                                                          \
        (results)[(count)++] = (s);                                \
    } while (0)

/*
 * Add matching exports to completion results.
 * Returns number of exports added.
 */
static size_t
complete_from_exports(struct nfsctx *nfs, const char *prefix, size_t prefix_len,
    char ***results, size_t *count, size_t *capacity)
{
    size_t i = 0, added = 0;
    const char *exp;
    char *result;
    size_t exp_len;

    while ((exp = mount_exports_cache_get(nfs, i++)) != NULL) {
        if (strncmp(exp, prefix, prefix_len) == 0) {
            /* Skip nested exports - only suggest at current level */
            const char *rest = exp + prefix_len;
            if (strchr(rest, '/') != NULL)
                continue;

            /* Return export with trailing slash */
            exp_len = strlen(exp);
            if (exp_len > SIZE_MAX - 2)
                continue;
            result = malloc(exp_len + 2);
            if (result) {
                memcpy(result, exp, exp_len);
                result[exp_len] = '/';
                result[exp_len + 1] = '\0';
                ADD_COMPLETION_RESULT(*results, *count, *capacity, result);
                added++;
            }
        }
    }
    return added;
}

/*
 * Check if entry duplicates an export (exports already added in Phase 1).
 */
static int
is_duplicate_export(struct nfsctx *nfs, const char *full)
{
    size_t j = 0, full_len = strlen(full);
    const char *exp;

    while ((exp = mount_exports_cache_get(nfs, j++)) != NULL) {
        if (full[full_len - 1] == '/') {
            if (strlen(exp) == full_len - 1 &&
                strncmp(exp, full, full_len - 1) == 0)
                return 1;
        }
    }
    return 0;
}

/*
 * For single completion result, check if it's a directory and add trailing slash.
 */
static void
complete_fixup_single_result(struct pathctx *ctx, char **results, int saved_quiet)
{
    size_t len = strlen(results[0]);
    int is_dir = 0;
    size_t j = 0;
    const char *exp;
    struct path_result check_res;

    if (len == 0 || results[0][len - 1] == '/')
        return;

    /* Check if any export implies this is a directory */
    while ((exp = mount_exports_cache_get(ctx->nfs, j++)) != NULL) {
        if (strlen(exp) > len &&
            strncmp(exp, results[0], len) == 0 &&
            exp[len] == '/') {
            is_dir = 1;
            break;
        }
    }

    /* If not determined from exports, do LOOKUP */
    if (!is_dir) {
        ctx->nfs->quiet = 1;
        if (path_resolve(ctx, results[0], PATH_FOLLOW, &check_res) == 0) {
            if (check_res.has_attr && check_res.attr.type == NFS_FTYPE_DIR) {
                is_dir = 1;
            } else if (!check_res.has_attr) {
                struct nfs_attr attr;
                if (nfs_getattr(ctx->nfs, &check_res.fh, &attr) == 0 &&
                    attr.type == NFS_FTYPE_DIR)
                    is_dir = 1;
            }
        }
        ctx->nfs->quiet = saved_quiet;
    }

    if (is_dir) {
        char *with_slash = malloc(len + 2);
        if (with_slash) {
            memcpy(with_slash, results[0], len);
            with_slash[len] = '/';
            with_slash[len + 1] = '\0';
            free(results[0]);
            results[0] = with_slash;
        }
    }
}

char **
pathctx_complete(struct pathctx *ctx, const char *prefix,
    int dirs_only, int files_only)
{
    char **results = NULL;
    size_t count = 0;
    size_t capacity = 32;
    char dirname_buf[PATH_MAX];
    const char *basename_prefix;
    size_t prefix_len;
    struct path_result dir_res;
    struct nfs_dir nfs_dir;
    size_t i, dir_prefix_len;
    const char *last_slash;
    int saved_quiet;
    int basic_mode;
    int enhanced_v2;
    int readdir_ok;

    if (ctx == NULL || prefix == NULL)
        return NULL;

    results = malloc(capacity * sizeof(char *));
    if (results == NULL)
        return NULL;

    prefix_len = strlen(prefix);

    /*
     * Determine completion mode.
     * Basic mode: READDIR only (names, no attrs, no trailing slash).
     * Enhanced v2: READDIR + filtered LOOKUPs (NFSv2 has no READDIRPLUS).
     * Enhanced v3: READDIRPLUS (has attrs already).
     */
    basic_mode = (ctx->nfs->completion == COMPLETION_BASIC);
    enhanced_v2 = (!basic_mode && ctx->nfs->proto.nfs_version == 2);

    /* Phase 1: Add matching exports (directories, skip if files_only) */
    if (prefix[0] == '/' && !files_only)
        complete_from_exports(ctx->nfs, prefix, prefix_len,
            &results, &count, &capacity);

    /*
     * Phase 2: Get directory entries from the path.
     * Split prefix into directory and filename prefix.
     */
    if (prefix[0] == '\0') {
        dirname_buf[0] = '\0';
        basename_prefix = "";
    } else {
        const char *slash = strrchr(prefix, '/');
        if (slash == NULL) {
            dirname_buf[0] = '\0';
            basename_prefix = prefix;
        } else if (slash == prefix) {
            dirname_buf[0] = '/';
            dirname_buf[1] = '\0';
            basename_prefix = slash + 1;
        } else {
            size_t dlen = (size_t)(slash - prefix);
            if (dlen >= sizeof(dirname_buf))
                dlen = sizeof(dirname_buf) - 1;
            memcpy(dirname_buf, prefix, dlen);
            dirname_buf[dlen] = '\0';
            basename_prefix = slash + 1;
        }
    }

    /* Cache basename_prefix length for the filter loop */
    size_t basename_prefix_len = strlen(basename_prefix);

    /* Calculate directory prefix length for building full paths */
    last_slash = strrchr(prefix, '/');
    dir_prefix_len = last_slash ? (size_t)(last_slash - prefix + 1) : 0;

    /* Suppress errors during completion */
    saved_quiet = ctx->nfs->quiet;
    ctx->nfs->quiet = 1;

    /* Resolve directory */
    memset(&dir_res, 0, sizeof(dir_res));
    if (dirname_buf[0] == '\0') {
        nfs_fh_copy(&dir_res.fh, &ctx->cwd_fh);
    } else {
        if (path_resolve(ctx, dirname_buf, PATH_FOLLOW, &dir_res) < 0)
            goto out;
    }

    /*
     * Read directory entries.
     * - Basic mode or enhanced v2: READDIR only (get names)
     * - Enhanced v3: READDIRPLUS (get names + attrs + FHs)
     */
    nfs_dir_init(&nfs_dir);
    if (basic_mode || enhanced_v2)
        readdir_ok = (nfs_readdir(ctx->nfs, &dir_res.fh, &nfs_dir) == 0);
    else
        readdir_ok = (nfs_readdirplus(ctx->nfs, &dir_res.fh, &nfs_dir, 0) == 0);

    if (!readdir_ok) {
        nfs_dir_free(&nfs_dir);
        goto out;
    }

    /* Filter entries */
    for (i = 0; i < nfs_dir.count; i++) {
        struct nfs_dirent *ent = &nfs_dir.entries[i];
        size_t name_len;
        int is_dir;
        char *full;

        /* Skip . and .. */
        if (strcmp(ent->name, ".") == 0 || strcmp(ent->name, "..") == 0)
            continue;

        /* Check prefix match */
        if (strncmp(ent->name, basename_prefix, basename_prefix_len) != 0)
            continue;

        /*
         * Enhanced v2 mode: do filtered LOOKUP for matching entries.
         * Only fetch attrs for entries that match the typed prefix,
         * minimizing RPCs compared to fetching attrs for everything.
         */
        if (enhanced_v2 && !ent->has_attr) {
            struct nfs_lookup_res lu;
            if (nfs_lookup(ctx->nfs, &dir_res.fh, ent->name, &lu) == 0) {
                if (lu.has_obj_attr) {
                    ent->attr = lu.obj_attr;
                    ent->has_attr = 1;
                }
                nfs_fh_copy(&ent->fh, &lu.fh);
                ent->has_fh = 1;
            }
        }

        /* Check type filter */
        is_dir = 0;
        if (!basic_mode && ent->has_attr) {
            is_dir = (ent->attr.type == NFS_FTYPE_DIR);

            if (dirs_only && !is_dir)
                continue;

            /* Skip special files (devices, FIFOs, sockets) if files_only */
            if (files_only) {
                int ftype = ent->attr.type;
                if (ftype == NFS_FTYPE_DIR)
                    continue;
                if (ftype == NFS_FTYPE_BLK || ftype == NFS_FTYPE_CHR ||
                    ftype == NFS_FTYPE_FIFO || ftype == NFS_FTYPE_SOCK)
                    continue;
            }

            /*
             * Pre-cache directory contents.
             * Speculatively READDIR any matching directories so
             * the next tab completion is instant.
             */
            if (is_dir && ent->has_fh) {
                struct nfs_dir subdir;
                nfs_dir_init(&subdir);
                if (nfs_readdir(ctx->nfs, &ent->fh, &subdir) == 0)
                    nfs_dir_free(&subdir); /* Cache populated as side effect */
            }
        }

        /* Build full path */
        name_len = strlen(ent->name);
        if (name_len > SIZE_MAX - dir_prefix_len - 2)
            continue;
        full = malloc(dir_prefix_len + name_len + 2);
        if (full == NULL)
            continue;

        if (dir_prefix_len > 0)
            memcpy(full, prefix, dir_prefix_len);
        memcpy(full + dir_prefix_len, ent->name, name_len);
        if (is_dir) {
            full[dir_prefix_len + name_len] = '/';
            full[dir_prefix_len + name_len + 1] = '\0';
        } else {
            full[dir_prefix_len + name_len] = '\0';
        }

        /* Skip if this duplicates an export (already added in Phase 1) */
        if (!is_duplicate_export(ctx->nfs, full)) {
            ADD_COMPLETION_RESULT(results, count, capacity, full);
        } else {
            free(full);
        }
    }

    nfs_dir_free(&nfs_dir);

out:
    ctx->nfs->quiet = saved_quiet;

    if (count == 0) {
        free(results);
        return NULL;
    }

    results[count] = NULL;

    /* Single result: check if it's a directory and add trailing slash */
    if (count == 1 && results[0] != NULL)
        complete_fixup_single_result(ctx, results, saved_quiet);

    return results;
}

void
pathctx_complete_free(char **list)
{
    char **p;

    if (list == NULL)
        return;

    for (p = list; *p != NULL; p++)
        free(*p);
    free(list);
}

/*
 * Walk a path from a starting FH using LOOKUP calls.
 * Does not require a pathctx - just does raw LOOKUPs.
 * Returns 0 on success with result in out_fh, -1 on error.
 */
int
path_walk(struct nfsctx *nfs, const struct nfs_fh *start_fh,
    const char *path, struct nfs_fh *out_fh)
{
    struct nfs_fh dir_fh;
    struct nfs_lookup_res lookup_res;
    char *pathcopy, *component, *saveptr;

    nfs_fh_copy(&dir_fh, start_fh);

    /* Make a copy for tokenization */
    pathcopy = strdup(path);
    if (pathcopy == NULL)
        return -1;

    /* Walk each path component */
    for (component = strtok_r(pathcopy, "/", &saveptr);
        component != NULL;
        component = strtok_r(NULL, "/", &saveptr)) {

        if (component[0] == '\0')
            continue; /* Skip empty components */

        if (nfs_lookup(nfs, &dir_fh, component, &lookup_res) < 0) {
            free(pathcopy);
            return -1;
        }

        nfs_fh_copy(&dir_fh, &lookup_res.fh);
    }

    free(pathcopy);
    nfs_fh_copy(out_fh, &dir_fh);
    return 0;
}
