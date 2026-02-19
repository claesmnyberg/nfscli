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
 * nfsv2.h - NFSv2 protocol definitions (RFC 1094)
 *
 * This file contains NFSv2-specific definitions:
 * - Wire format structures for XDR encoding/decoding
 * - Procedure numbers
 * - Error codes (note: v2 uses different spellings/values in some cases)
 *
 * Key NFSv2 characteristics:
 * - Fixed 32-byte file handles
 * - 32-bit offsets and sizes
 * - Microsecond timestamps (not nanoseconds like v3)
 */

#ifndef NFSV2_H
#define NFSV2_H

#include "nfs_types.h" /* For NFSV2_FHSIZE and other common definitions */
#include <stdint.h>

/*
 * NFSv2 procedure numbers (RFC 1094)
 *
 * Note: Some procedure numbers differ from NFSv3!
 * For example, LOOKUP is 4 in v2 but 3 in v3.
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
 * NFSv2 error codes (RFC 1094)
 *
 * IMPORTANT differences from NFSv3:
 * - NFSERR_ACCES is v2 spelling (13) - v3 also has this
 * - NFSERR_WFLUSH (99) is v2 ONLY - does not exist in v3
 * - v2 does NOT have: XDEV, INVAL, MLINK, REMOTE, or 10001-10008 range
 */
#define NFSV2_OK             0
#define NFSV2ERR_PERM        1  /* Not owner */
#define NFSV2ERR_NOENT       2  /* No such file or directory */
#define NFSV2ERR_IO          5  /* I/O error */
#define NFSV2ERR_NXIO        6  /* No such device or address */
#define NFSV2ERR_ACCES       13 /* Permission denied (note spelling!) */
#define NFSV2ERR_EXIST       17 /* File exists */
#define NFSV2ERR_NODEV       19 /* No such device */
#define NFSV2ERR_NOTDIR      20 /* Not a directory */
#define NFSV2ERR_ISDIR       21 /* Is a directory */
#define NFSV2ERR_FBIG        27 /* File too large */
#define NFSV2ERR_NOSPC       28 /* No space left on device */
#define NFSV2ERR_ROFS        30 /* Read-only file system */
#define NFSV2ERR_NAMETOOLONG 63 /* File name too long */
#define NFSV2ERR_NOTEMPTY    66 /* Directory not empty */
#define NFSV2ERR_DQUOT       69 /* Disk quota exceeded */
#define NFSV2ERR_STALE       70 /* Stale file handle */
#define NFSV2ERR_WFLUSH      99 /* Write cache flushed - V2 ONLY */

/*
 * NFSv2 file types (RFC 1094)
 */
#define NFSV2_FTYPE_NON 0 /* non-file */
#define NFSV2_FTYPE_REG 1 /* regular file */
#define NFSV2_FTYPE_DIR 2 /* directory */
#define NFSV2_FTYPE_BLK 3 /* block special */
#define NFSV2_FTYPE_CHR 4 /* character special */
#define NFSV2_FTYPE_LNK 5 /* symbolic link */

/*
 * NFSv2 wire format structures
 *
 * These are the on-the-wire XDR structures per RFC 1094.
 * All multi-byte values are in network byte order (big endian).
 */

/*
 * NFSv2 time structure - seconds and microseconds
 * (NFSv3 uses nanoseconds instead)
 */
struct nfsv2_timeval {
    uint32_t seconds;
    uint32_t useconds;
} __attribute__((packed));

/*
 * NFSv2 file attributes (fattr)
 *
 * Returned by GETATTR, LOOKUP, READ, WRITE, CREATE, MKDIR, etc.
 * All fields are 32-bit (v3 uses 64-bit for size, fileid, etc.)
 */
struct nfsv2_fattr {
    uint32_t type;
    uint32_t mode;
    uint32_t nlink;
    uint32_t uid;
    uint32_t gid;
    uint32_t size;
    uint32_t blocksize;
    uint32_t rdev;
    uint32_t blocks;
    uint32_t fsid;
    uint32_t fileid;
    struct nfsv2_timeval atime;
    struct nfsv2_timeval mtime;
    struct nfsv2_timeval ctime;
} __attribute__((packed));

/*
 * NFSv2 set attributes (sattr)
 *
 * Used by SETATTR, CREATE, MKDIR, SYMLINK.
 * A value of 0xFFFFFFFF means "don't change this field".
 * For time fields, 0xFFFFFFFFFFFFFFFF means "don't change".
 */
struct nfsv2_sattr {
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t size;
    struct nfsv2_timeval atime;
    struct nfsv2_timeval mtime;
} __attribute__((packed));

/* NFSv2 error functions are declared in nfs_common.h */

/* NFSv2 procedures */
struct nfsctx;
int nfsv2_null(struct nfsctx *ctx);

/*
 * Check if an error code is valid for NFSv2
 * (returns 0 if it's a v3-only error)
 */
static inline int
nfsv2_err_valid(int err)
{
    switch (err) {
    case NFSV2_OK:
    case NFSV2ERR_PERM:
    case NFSV2ERR_NOENT:
    case NFSV2ERR_IO:
    case NFSV2ERR_NXIO:
    case NFSV2ERR_ACCES:
    case NFSV2ERR_EXIST:
    case NFSV2ERR_NODEV:
    case NFSV2ERR_NOTDIR:
    case NFSV2ERR_ISDIR:
    case NFSV2ERR_FBIG:
    case NFSV2ERR_NOSPC:
    case NFSV2ERR_ROFS:
    case NFSV2ERR_NAMETOOLONG:
    case NFSV2ERR_NOTEMPTY:
    case NFSV2ERR_DQUOT:
    case NFSV2ERR_STALE:
    case NFSV2ERR_WFLUSH:
        return 1;
    default:
        return 0;
    }
}

#endif /* NFSV2_H */
