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
 * nfs_escape.h - Export boundary escape probing
 *
 * Provides functionality to probe parent directories above an export root
 * using LOOKUP "..", READDIR, and READDIRPLUS. Includes a parent FH cache
 * to avoid redundant RPCs when probing multiple exports.
 */

#ifndef NFS_ESCAPE_H
#define NFS_ESCAPE_H

#include <stddef.h>

#include "nfs_types.h"

struct nfsctx;

/*
 * Diagnostic result from single-level escape probe.
 * Tracks what each method returned for detailed output (used by explore).
 */
struct nfs_escape_diag {
    /* READDIRPLUS result */
    struct nfs_fh rdp_fh;
    unsigned int rdp_tried : 1;   /* Attempted READDIRPLUS */
    unsigned int rdp_got_fh : 1;  /* Got ".." FH from READDIRPLUS */
    unsigned int rdp_blocked : 1; /* FH equals current dir (blocked) */

    /* LOOKUP result */
    struct nfs_fh lu_fh;
    unsigned int lu_tried : 1;   /* Attempted LOOKUP */
    unsigned int lu_got_fh : 1;  /* Got ".." FH from LOOKUP */
    unsigned int lu_blocked : 1; /* FH equals current dir (blocked) */

    /* Which method was used for the final result (if escaped) */
    unsigned int used_rdp : 1; /* Used READDIRPLUS result */
    unsigned int used_lu : 1;  /* Used LOOKUP result */
};

/*
 * Single-level escape probe with diagnostics.
 *
 * Tries to get parent FH one level up. Always tries both READDIRPLUS (v3)
 * and LOOKUP for diagnostic purposes, recording what each returned.
 *
 * Parameters:
 *   ctx      - NFS context
 *   fh       - Current file handle
 *   parent   - Output: parent FH (if escaped)
 *   diag     - Output: diagnostic info (may be NULL if not needed)
 *
 * Returns:
 *   1 = escaped successfully (parent filled, diag shows which method)
 *   0 = at ceiling (can't go higher)
 *  -1 = error
 */
int nfs_probe_escape_one(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_fh *parent, struct nfs_escape_diag *diag);

/*
 * Escape probing - discover parent directories above an export root
 *
 * Starting from start_fh, tries to climb up using LOOKUP "..",
 * falling back to READDIR/READDIRPLUS if blocked.
 *
 * Returns array of parent FHs from immediate parent up to ceiling.
 * Caller must free the returned array (but not the FHs within).
 *
 * Parameters:
 *   ctx       - NFS context
 *   start_fh  - Starting file handle (e.g., export root)
 *   max_depth - Maximum levels to climb (0 or negative = no limit).
 *               Use path_count_components() from pathctx.h.
 *   parents   - Output: array of parent FHs (caller frees with free())
 *   count     - Output: number of parents found
 *
 * Returns 0 on success, -1 on error.
 * On success, parents[0] is immediate parent, parents[count-1] is ceiling.
 * If count==0, start_fh is already at ceiling (can't go higher).
 */
int nfs_probe_escape(struct nfsctx *ctx, const struct nfs_fh *start_fh,
    int max_depth, struct nfs_fh **parents, int *count);

/*
 * Parent FH cache management - caches LOOKUP ".." results during escape probing
 */
void nfs_parent_cache_clear(void);
size_t nfs_parent_cache_count(void);
void nfs_parent_cache_mark_ceiling(const struct nfs_fh *fh);

/*
 * Look up parent FH in cache.
 * Returns 0 if found (parent filled), -1 if not in cache, -2 if at ceiling.
 */
int nfs_parent_cache_lookup(const struct nfs_fh *fh, struct nfs_fh *parent);

/*
 * Add parent FH to cache.
 * is_ceiling should be 1 if fh is at ceiling (parent == self), 0 otherwise.
 */
void nfs_parent_cache_add(const struct nfs_fh *fh, const struct nfs_fh *parent, int is_ceiling);

#endif /* NFS_ESCAPE_H */
