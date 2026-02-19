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
 * nfsv3.h - NFSv3 protocol definitions (RFC 1813)
 *
 * This file contains NFSv3-specific definitions:
 * - Wire format structures for XDR encoding/decoding
 * - Procedure numbers
 * - Error handling functions
 *
 * Key NFSv3 characteristics:
 * - Variable-length file handles (up to 64 bytes)
 * - 64-bit offsets and sizes
 * - Nanosecond timestamps
 *
 * Common types and error codes are in nfs_types.h.
 * NFSv2 definitions are in nfsv2.h.
 */

#ifndef NFSV3_H
#define NFSV3_H

#include <errno.h>
#include <stdint.h>

#include "nfs_types.h"

/*
 * NFSv3 wire format structures
 *
 * These are the on-the-wire XDR structures per RFC 1813.
 * All multi-byte values are in network byte order (big endian).
 */

/*
 * NFSv3 file attributes (fattr3) - wire format
 *
 * Returned by GETATTR, LOOKUP, etc.
 * Uses 64-bit fields for size, fileid, etc.
 * Per RFC 1813 Section 2.5.
 */
struct nfsv3_fattr {
    uint32_t type;
    uint32_t mode;
    uint32_t nlink;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    uint64_t used;
    uint32_t rdev_major; /* specdata3: major device number */
    uint32_t rdev_minor; /* specdata3: minor device number */
    uint64_t fsid;
    uint64_t fileid;
    uint32_t atime_sec;  /* nfstime3 */
    uint32_t atime_nsec;
    uint32_t mtime_sec;  /* nfstime3 */
    uint32_t mtime_nsec;
    uint32_t ctime_sec;  /* nfstime3 */
    uint32_t ctime_nsec;
} __attribute__((packed));

/*
 * NFSv3 set attributes (sattr3)
 *
 * Used by SETATTR, CREATE, MKDIR, SYMLINK.
 * Zero values typically mean "don't change" but see mode_value_follows.
 */
struct nfsv3_sattr {
    uint32_t mode_value_follows; /* 1 = set mode, 0 = don't change */
    uint32_t mode;
    uint32_t uid;                /* 0 = don't change */
    uint32_t gid;                /* 0 = don't change */
    uint32_t size;               /* 0 = don't change */
    uint32_t atime;              /* 0 = don't change */
    uint32_t mtime;              /* 0 = don't change */
} __attribute__((packed));

/* NFSv3 error functions are declared in nfs_common.h */

/* NFSv3 procedures */
struct nfsctx;
struct nfs_fh;
struct nfs_write_res;
struct nfs_commit_res;
int nfsv3_null(struct nfsctx *ctx);
int nfsv3_write_stable(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint64_t offset, const uint8_t *data, uint32_t count,
    int stability, struct nfs_write_res *out);
int nfsv3_commit(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint64_t offset, uint32_t count, struct nfs_commit_res *out);

#endif /* NFSV3_H */
