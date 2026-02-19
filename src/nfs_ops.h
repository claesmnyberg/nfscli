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
 * nfs_ops.h - NFS operations vtable definitions
 *
 * Separate vtables for NFSv2 and NFSv3:
 * - NFSv2: Fixed 32-byte file handles, 32-bit offsets
 * - NFSv3: Variable-length file handles, 64-bit offsets
 *
 * All functions return data via output parameters, never print directly.
 */

#ifndef NFS_OPS_H
#define NFS_OPS_H

#include "nfs_types.h"
#include <stdint.h>

struct nfsctx;

/*
 * NFS protocol versions
 */
#define NFS_VERSION_2 2
#define NFS_VERSION_3 3

/*
 * NFSv2 procedure numbers (RFC 1094)
 */
#define NFSV2_PROC_NULL       0
#define NFSV2_PROC_GETATTR    1
#define NFSV2_PROC_SETATTR    2
#define NFSV2_PROC_ROOT       3 /* obsolete */
#define NFSV2_PROC_LOOKUP     4
#define NFSV2_PROC_READLINK   5
#define NFSV2_PROC_READ       6
#define NFSV2_PROC_WRITECACHE 7 /* obsolete */
#define NFSV2_PROC_WRITE      8
#define NFSV2_PROC_CREATE     9
#define NFSV2_PROC_REMOVE     10
#define NFSV2_PROC_RENAME     11
#define NFSV2_PROC_LINK       12
#define NFSV2_PROC_SYMLINK    13
#define NFSV2_PROC_MKDIR      14
#define NFSV2_PROC_RMDIR      15
#define NFSV2_PROC_READDIR    16
#define NFSV2_PROC_STATFS     17

/*
 * NFSv3 procedure numbers (RFC 1813)
 */
#define NFSV3_PROC_NULL        0
#define NFSV3_PROC_GETATTR     1
#define NFSV3_PROC_SETATTR     2
#define NFSV3_PROC_LOOKUP      3
#define NFSV3_PROC_ACCESS      4
#define NFSV3_PROC_READLINK    5
#define NFSV3_PROC_READ        6
#define NFSV3_PROC_WRITE       7
#define NFSV3_PROC_CREATE      8
#define NFSV3_PROC_MKDIR       9
#define NFSV3_PROC_SYMLINK     10
#define NFSV3_PROC_MKNOD       11
#define NFSV3_PROC_REMOVE      12
#define NFSV3_PROC_RMDIR       13
#define NFSV3_PROC_RENAME      14
#define NFSV3_PROC_LINK        15
#define NFSV3_PROC_READDIR     16
#define NFSV3_PROC_READDIRPLUS 17
#define NFSV3_PROC_FSSTAT      18
#define NFSV3_PROC_FSINFO      19
#define NFSV3_PROC_PATHCONF    20
#define NFSV3_PROC_COMMIT      21

/*
 * Unified NFS Operations - v3-style signatures for both versions
 *
 * This is the dispatch table used by nfs.c. For v2, wrapper functions
 * validate file handle lengths and truncate 64-bit offsets to 32-bit.
 */
struct nfs_ops {
    int (*getattr)(struct nfsctx *ctx,
        const struct nfs_fh *fh,
        struct nfs_attr *out);

    int (*setattr)(struct nfsctx *ctx,
        const struct nfs_fh *fh,
        const struct nfs_sattr *sattr,
        struct nfs_attr *out); /* Optional: returns new attributes */

    int (*lookup)(struct nfsctx *ctx,
        const struct nfs_fh *dirfh,
        const char *name,
        struct nfs_lookup_res *out);

    int (*readlink)(struct nfsctx *ctx,
        const struct nfs_fh *fh,
        struct nfs_readlink_res *out);

    int (*read)(struct nfsctx *ctx,
        const struct nfs_fh *fh,
        uint64_t offset,
        uint32_t count,
        struct nfs_read_res *out);

    int (*write)(struct nfsctx *ctx,
        const struct nfs_fh *fh,
        uint64_t offset,
        const uint8_t *data,
        uint32_t count,
        struct nfs_write_res *out);

    int (*create)(struct nfsctx *ctx,
        const struct nfs_fh *dirfh,
        const char *name,
        uint32_t mode,
        int create_mode,
        struct nfs_create_res *out);

    int (*remove)(struct nfsctx *ctx,
        const struct nfs_fh *dirfh,
        const char *name,
        struct nfs_wcc_data *out);

    int (*rename)(struct nfsctx *ctx,
        const struct nfs_fh *srcfh,
        const char *srcname,
        const struct nfs_fh *dstfh,
        const char *dstname,
        struct nfs_rename_res *out);

    int (*link)(struct nfsctx *ctx,
        const struct nfs_fh *fh,
        const struct nfs_fh *dirfh,
        const char *name,
        struct nfs_link_res *out);

    int (*symlink)(struct nfsctx *ctx,
        const struct nfs_fh *dirfh,
        const char *name,
        const char *target,
        uint32_t mode,
        struct nfs_symlink_res *out);

    int (*mkdir)(struct nfsctx *ctx,
        const struct nfs_fh *dirfh,
        const char *name,
        uint32_t mode,
        struct nfs_create_res *out);

    int (*rmdir)(struct nfsctx *ctx,
        const struct nfs_fh *dirfh,
        const char *name,
        struct nfs_wcc_data *out);

    int (*readdir)(struct nfsctx *ctx,
        const struct nfs_fh *fh,
        struct nfs_dir *out);

    int (*readdirplus)(struct nfsctx *ctx,
        const struct nfs_fh *fh,
        struct nfs_dir *out);

    int (*mknod)(struct nfsctx *ctx,
        const struct nfs_fh *dirfh,
        const char *name,
        int type,
        uint32_t mode,
        uint32_t major,
        uint32_t minor,
        struct nfs_create_res *out);

    int (*statfs)(struct nfsctx *ctx,
        const struct nfs_fh *fh,
        struct nfs_fsstat_res *out);

    int (*fsinfo)(struct nfsctx *ctx,
        const struct nfs_fh *fh,
        struct nfs_fsinfo_res *out);

    int (*access)(struct nfsctx *ctx,
        const struct nfs_fh *fh,
        uint32_t access_mask,
        struct nfs_access_res *out);

    int (*pathconf)(struct nfsctx *ctx,
        const struct nfs_fh *fh,
        struct nfs_pathconf_res *out);
};

/* Unified ops tables - v3-style signatures for dispatch */
extern struct nfs_ops nfsv2_unified_ops;
extern struct nfs_ops nfsv3_unified_ops;

#endif /* NFS_OPS_H */
