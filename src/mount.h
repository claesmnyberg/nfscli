/*
 * Copyright (C)  2023-2026 Claes M Nyberg <cmn@signedness.org>
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
 *      This product includes software developed by Claes M Nyberg and
 *      John Cartwright.
 * 4. The names Claes M Nyberg and John Cartwright may not be used to endorse
 *    or promote products derived from this software without specific prior written
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
 * mount.h - Mount protocol public API (RFC 1094 Appendix A, RFC 1813 Section 5)
 *
 * Unified mount protocol interface that dispatches to version-specific
 * implementations (v1 or v3) based on ctx->mount_version.
 *
 * Mount v1: RFC 1094 - used with NFS v2, fixed 32-byte file handles
 * Mount v3: RFC 1813 - used with NFS v3, variable file handles (up to 64 bytes)
 */

#ifndef MOUNT_H
#define MOUNT_H

#include "mount_types.h"
#include <stdint.h>

struct nfsctx;

/*
 * Mount a filesystem export.
 * Returns file handle length on success, -1 on error.
 * If fh is not NULL, allocates and returns the file handle (caller must free).
 */
int mount_mnt(struct nfsctx *ctx, const char *path, uint8_t **fh);

/*
 * Mount with caching - checks cache first, mounts if needed.
 * Unlike mount_mnt, writes directly to caller's buffer (no allocation).
 * Returns file handle length on success, -1 on error.
 *
 * Flags:
 *   MNT_CACHE_UMNT - Call UMNT immediately after successful mount to
 *                    remove this client from server's mount list.
 *                    The FH remains valid and cached for future use.
 */
#define MNT_CACHE_UMNT 0x01

int mount_mnt_cached(struct nfsctx *ctx, const char *path,
    uint8_t *fh_out, size_t fh_out_size, int flags);

/*
 * Get list of exported filesystems.
 * Returns 0 on success, -1 on error.
 * Caller must free the returned list with mount_export_free().
 */
int mount_get_exports(struct nfsctx *ctx, struct mount_export **exports);

/*
 * Get list of mounted clients.
 * Returns 0 on success, -1 on error.
 * Caller must free the returned list with mount_entry_free().
 */
int mount_dump_list(struct nfsctx *ctx, struct mount_entry **entries);

/*
 * Unmount a specific filesystem.
 * Returns 0 on success, -1 on error.
 */
int mount_umnt(struct nfsctx *ctx, const char *path);

/*
 * Unmount all filesystems.
 * Returns 0 on success, -1 on error.
 */
int mount_umntall(struct nfsctx *ctx);

/*
 * Mount daemon connectivity test (NULL procedure).
 * Returns 0 on success, -1 on error.
 */
int mount_null(struct nfsctx *ctx);

/*
 * Free an export list.
 */
void mount_export_free(struct mount_export *exports);

/*
 * Free a mount entry list.
 */
void mount_entry_free(struct mount_entry *entries);

/*
 * Convert mount error code to string.
 */
const char *mount_errstr(int err);

/*
 * Version selection helpers
 */
int set_mount_version(struct nfsctx *ctx, uint8_t version);
int set_highest_mount_version(struct nfsctx *ctx);
void init_mount_version(struct nfsctx *ctx);

/*
 * Exports cache management
 */
void mount_exports_cache_clear(struct nfsctx *ctx);
int mount_exports_cache(struct nfsctx *ctx, struct mount_export *exports);
size_t mount_exports_cache_count(struct nfsctx *ctx);
const char *mount_exports_cache_get(struct nfsctx *ctx, size_t index);
const char *mount_exports_find_best(struct nfsctx *ctx, const char *path);

/*
 * Export selection iterator for path-based traversal.
 *
 * Iterates exports in priority order for reaching a target path:
 *   Pass 0: Cached FHs with nearer paths (no MOUNT RPC needed)
 *   Pass 1: Cached FHs with farther paths (no MOUNT RPC needed)
 *   Pass 2: Uncached exports with nearer paths (requires MOUNT RPC)
 *   Pass 3: Uncached exports with farther paths (requires MOUNT RPC)
 *
 * "Nearer" means target path is a prefix of export path, so we can
 * descend into the export and climb back up to reach the target.
 */
struct mount_export_iter {
    const char *target_path;
    size_t path_len;
    int pass;
    size_t index;
};

void mount_export_iter_init(struct mount_export_iter *iter, const char *target_path);
const char *mount_export_iter_next(struct nfsctx *ctx, struct mount_export_iter *iter);

/*
 * Mount file handle cache management
 */
void mount_fh_cache_clear(struct nfsctx *ctx);
void mount_fh_cache_add(struct nfsctx *ctx, const char *path,
    const uint8_t *fh, int fhlen);
int mount_fh_cache_lookup(struct nfsctx *ctx, const char *path,
    uint8_t *fh_out, int *fhlen_out);
void mount_fh_cache_invalidate(struct nfsctx *ctx, const char *path);
size_t mount_fh_cache_count(struct nfsctx *ctx);
char **mount_fh_cache_query_handles(struct nfsctx *ctx, const char *prefix);

#endif /* MOUNT_H */
