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
 * nfs.h - Unified NFS API
 *
 * This header provides a single, version-independent API for NFS operations.
 * Functions automatically dispatch to the correct version (v2 or v3) based
 * on ctx->nfs_version.
 *
 * All functions use struct nfs_fh for file handles, which works for both
 * v2 (fixed 32-byte) and v3 (variable-length up to 64 bytes).
 */

#ifndef NFS_H
#define NFS_H

#include "nfs_types.h"
#include <stdint.h>

struct nfsctx;

/*
 * Unified NFS operations
 * These dispatch to v2 or v3 based on ctx->nfs_version
 */

/* Get file attributes */
int nfs_getattr(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_attr *out);

/* Set file attributes */
int nfs_setattr(struct nfsctx *ctx, const struct nfs_fh *fh,
    const struct nfs_sattr *sattr);

/* Lookup a name in a directory */
int nfs_lookup(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, struct nfs_lookup_res *out);

/* Read symbolic link target */
int nfs_readlink(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_readlink_res *out);

/* Read from a file */
int nfs_read(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint64_t offset, uint32_t count, struct nfs_read_res *out);

/* Write to a file (out may be NULL if result not needed) */
int nfs_write(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint64_t offset, const uint8_t *data, uint32_t count,
    struct nfs_write_res *out);

/* Create a regular file (create_mode: NFS_CREATE_UNCHECKED/GUARDED/EXCLUSIVE) */
int nfs_create(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, uint32_t mode, int create_mode,
    struct nfs_create_res *out);

/* Remove a file */
int nfs_remove(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name);

/* Rename a file */
int nfs_rename(struct nfsctx *ctx, const struct nfs_fh *srcfh,
    const char *srcname, const struct nfs_fh *dstfh, const char *dstname);

/* Create a hard link */
int nfs_link(struct nfsctx *ctx, const struct nfs_fh *fh,
    const struct nfs_fh *dirfh, const char *name);

/* Create a symbolic link */
int nfs_symlink(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, const char *target, uint32_t mode);

/* Create a directory */
int nfs_mkdir(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, uint32_t mode, struct nfs_create_res *out);

/* Remove a directory */
int nfs_rmdir(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name);

/* Read directory entries */
int nfs_readdir(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_dir *out);

/*
 * Read directory entries with attributes (v3: readdirplus, v2: emulated)
 * Flags:
 *   NFS_READDIRPLUS_FULL (0) - Get full data (FH, attrs) - default
 *   NFS_READDIRPLUS_NAMES - Names only (skip LOOKUPs in v2 emulation)
 */
#define NFS_READDIRPLUS_FULL  0
#define NFS_READDIRPLUS_NAMES 1

int nfs_readdirplus(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_dir *out, int flags);

/* Create a device node (v3 only, returns ENOTSUP for v2) */
int nfs_mknod(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, int type, uint32_t mode,
    uint32_t major, uint32_t minor, struct nfs_create_res *out);

/* Get filesystem statistics (v2: STATFS, v3: FSSTAT) */
int nfs_statfs(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_fsstat_res *out);

/* Get filesystem info (v3 only, returns ENOTSUP for v2) */
int nfs_fsinfo(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_fsinfo_res *out);

/* Check access permissions (v3 only, returns ENOTSUP for v2) */
int nfs_access(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint32_t access_mask, struct nfs_access_res *out);

/* Get path configuration (v3 only, returns ENOTSUP for v2) */
int nfs_pathconf(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_pathconf_res *out);

/* NFS connectivity test (NULL procedure) */
int nfs_null(struct nfsctx *ctx);

/* Commit cached writes to stable storage (NFSv3 only, returns ENOTSUP for v2) */
int nfs_commit(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint64_t offset, uint32_t count, struct nfs_commit_res *out);

/* Write to a file with explicit stability mode (NFSv3: configurable, v2: FILE_SYNC) */
int nfs_write_stable(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint64_t offset, const uint8_t *data, uint32_t count,
    int stability, struct nfs_write_res *out);

/*
 * Version selection helpers
 */
int set_nfs_version(struct nfsctx *ctx, uint8_t version);
int set_highest_nfs_version(struct nfsctx *ctx);
void init_nfs_version(struct nfsctx *ctx);
void update_nfs_ops(struct nfsctx *ctx);

/* Check if NFS service is available (probes if needed, returns 1=yes, 0=no) */
int nfs_service_available(struct nfsctx *ctx);

#endif /* NFS_H */
