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
 * nfs_util.c - Core NFS utilities (version-independent)
 */

#include <stdlib.h>
#include <string.h>

#include "nfs_util.h"
#include "str.h"

/*
 * Convert NFS error code to string.
 *
 * RFC 1094 Section 2.3.1 (NFSv2 stat)
 * RFC 1813 Section 2.6 (NFSv3 nfsstat3)
 *
 * NFS error codes map closely to Unix errno values. Most codes 1-70
 * correspond to standard Unix errors. v3 adds codes 10001-10008 for
 * NFS-specific conditions (BADHANDLE, NOT_SYNC, BAD_COOKIE, etc.).
 */
const char *
nfs_errstr(int err)
{
    switch (err) {
    case NFS_OK:
        return "OK";
    case NFSERR_PERM:
        return "Not owner";
    case NFSERR_NOENT:
        return "No such file or directory";
    case NFSERR_IO:
        return "I/O error";
    case NFSERR_NXIO:
        return "No such device or address";
    case NFSERR_ACCES:
        return "Permission denied";
    case NFSERR_EXIST:
        return "File exists";
    case NFSERR_XDEV:
        return "Cross-device link";
    case NFSERR_NODEV:
        return "No such device";
    case NFSERR_NOTDIR:
        return "Not a directory";
    case NFSERR_ISDIR:
        return "Is a directory";
    case NFSERR_INVAL:
        return "Invalid argument";
    case NFSERR_FBIG:
        return "File too large";
    case NFSERR_NOSPC:
        return "No space left on device";
    case NFSERR_ROFS:
        return "Read-only file system";
    case NFSERR_MLINK:
        return "Too many links";
    case NFSERR_NAMETOOLONG:
        return "File name too long";
    case NFSERR_NOTEMPTY:
        return "Directory not empty";
    case NFSERR_DQUOT:
        return "Disk quota exceeded";
    case NFSERR_STALE:
        return "Stale file handle";
    case NFSERR_REMOTE:
        return "Object is remote";
    case NFSERR_BADHANDLE:
        return "Invalid file handle";
    case NFSERR_NOT_SYNC:
        return "Synchronization mismatch";
    case NFSERR_BAD_COOKIE:
        return "Stale cookie";
    case NFSERR_NOTSUPP:
        return "Operation not supported";
    case NFSERR_TOOSMALL:
        return "Buffer or request too small";
    case NFSERR_SERVERFAULT:
        return "Server fault";
    case NFSERR_BADTYPE:
        return "Type not supported";
    case NFSERR_JUKEBOX:
        return "Request initiated, not completed";
    default:
        return "Unknown error";
    }
}

/*
 * Convert NFS error code to errno
 */
int
nfs_err2errno(int err)
{
    switch (err) {
    case NFS_OK:
        return 0;
    case NFSERR_PERM:
        return EPERM;
    case NFSERR_NOENT:
        return ENOENT;
    case NFSERR_IO:
        return EIO;
    case NFSERR_NXIO:
        return ENXIO;
    case NFSERR_ACCES:
        return EACCES;
    case NFSERR_EXIST:
        return EEXIST;
    case NFSERR_XDEV:
        return EXDEV;
    case NFSERR_NODEV:
        return ENODEV;
    case NFSERR_NOTDIR:
        return ENOTDIR;
    case NFSERR_ISDIR:
        return EISDIR;
    case NFSERR_INVAL:
        return EINVAL;
    case NFSERR_FBIG:
        return EFBIG;
    case NFSERR_NOSPC:
        return ENOSPC;
    case NFSERR_ROFS:
        return EROFS;
    case NFSERR_MLINK:
        return EMLINK;
    case NFSERR_NAMETOOLONG:
        return ENAMETOOLONG;
    case NFSERR_NOTEMPTY:
        return ENOTEMPTY;
    case NFSERR_DQUOT:
        return EDQUOT;
    case NFSERR_STALE:
        return ESTALE;
    case NFSERR_BADHANDLE:
        return EBADF;
    case NFSERR_NOTSUPP:
        return ENOTSUP;
    default:
        return EIO;
    }
}

/*
 * Add entry to directory listing, growing array as needed
 */
int
nfs_dir_add(struct nfs_dir *dir, const struct nfs_dirent *ent)
{
    if (dir->count >= dir->capacity) {
        size_t newcap;
        struct nfs_dirent *newents;

        if (dir->capacity == 0) {
            newcap = 64;
        } else if (dir->capacity > SIZE_MAX / 2 / sizeof(struct nfs_dirent)) {
            return -1;
        } else {
            newcap = dir->capacity * 2;
        }

        newents = realloc(dir->entries, newcap * sizeof(struct nfs_dirent));
        if (newents == NULL)
            return -1;

        dir->entries = newents;
        dir->capacity = newcap;
    }

    memcpy(&dir->entries[dir->count], ent, sizeof(struct nfs_dirent));
    dir->count++;
    return 0;
}

/*
 * Initialize file handle structure
 */
void
nfs_fh_init(struct nfs_fh *fh)
{
    memset(fh, 0, sizeof(*fh));
}

/*
 * Copy file handle
 */
void
nfs_fh_copy(struct nfs_fh *dst, const struct nfs_fh *src)
{
    memcpy(dst, src, sizeof(*dst));
}

/*
 * Compare file handles for equality
 */
int
nfs_fh_equal(const struct nfs_fh *a, const struct nfs_fh *b)
{
    if (a->len != b->len)
        return 0;
    return memcmp(a->data, b->data, a->len) == 0;
}

/*
 * Initialize file handle from raw buffer
 */
void
nfs_fh_from_buf(struct nfs_fh *fh, const uint8_t *data, uint32_t len)
{
    if (len > NFS_FHSIZE_MAX)
        len = NFS_FHSIZE_MAX;
    memset(fh, 0, sizeof(*fh));
    memcpy(fh->data, data, len);
    fh->len = len;
}

/*
 * Copy file handle to raw buffer
 * Returns number of bytes copied
 */
uint32_t
nfs_fh_to_buf(const struct nfs_fh *fh, uint8_t *data, size_t maxlen)
{
    uint32_t len = fh->len;
    if (len > maxlen)
        len = maxlen;
    memcpy(data, fh->data, len);
    return len;
}

/*
 * Parse hex string to file handle buffer.
 * Returns length on success, -1 on error.
 */
int
nfs_parse_fh(const char *hexstr, uint8_t *fh, size_t fhsize)
{
    int fhlen = str_hex2bin(hexstr, fh, fhsize);
    if (fhlen <= 0)
        return -1;
    return fhlen;
}

/*
 * Parse hex string directly into struct nfs_fh.
 * Returns 0 on success, -1 on error.
 */
int
nfs_parse_fh_arg(const char *hexstr, struct nfs_fh *fh)
{
    uint8_t buf[NFS_FHSIZE_MAX];
    int len;

    len = nfs_parse_fh(hexstr, buf, sizeof(buf));
    if (len < 0)
        return -1;
    nfs_fh_from_buf(fh, buf, (uint32_t)len);
    return 0;
}
