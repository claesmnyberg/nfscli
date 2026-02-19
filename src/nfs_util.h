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
 * nfs_util.h - Core NFS utilities (version-independent)
 *
 * Provides low-level NFS utility functions:
 * - File handle operations
 * - Directory listing management
 * - Error handling and conversion
 * - Path normalization
 * - XDR encoding/decoding helpers
 */

#ifndef NFS_UTIL_H
#define NFS_UTIL_H

#include "nfs_types.h"
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct nfsctx;

/*
 * Error handling - version independent
 */
const char *nfs_errstr(int err);
int nfs_err2errno(int err);

/*
 * NFS status check macro - checks reply status and handles errors.
 * _ctx: nfsctx pointer (for quiet flag)
 * _reply: pointer to reply struct (must have status field)
 * _cleanup: statement to execute before returning on error (use (void)0 for none)
 *
 * Prints an error message (unless quiet), sets errno, and returns -1 on failure.
 */
#define NFS_CHECK_STATUS_EX(_ctx, _reply, _cleanup)                             \
    do {                                                                        \
        uint32_t _nfs_status = ntohl((_reply)->status);                         \
        if (_nfs_status != NFS_OK) {                                            \
            if (!(_ctx)->quiet)                                                 \
                fprintf(stderr, "** NFS Error: %s\n", nfs_errstr(_nfs_status)); \
            errno = nfs_err2errno(_nfs_status);                                 \
            _cleanup;                                                           \
            return -1;                                                          \
        }                                                                       \
    } while (0)

#define NFS_CHECK_STATUS(_ctx, _reply) \
    NFS_CHECK_STATUS_EX(_ctx, _reply, (void)0)

/*
 * Directory listing management
 */
int nfs_dir_add(struct nfs_dir *dir, const struct nfs_dirent *ent);

/*
 * File handle utilities
 */
void nfs_fh_init(struct nfs_fh *fh);
void nfs_fh_copy(struct nfs_fh *dst, const struct nfs_fh *src);
int nfs_fh_equal(const struct nfs_fh *a, const struct nfs_fh *b);

/* Copy from raw buffer to nfs_fh */
void nfs_fh_from_buf(struct nfs_fh *fh, const uint8_t *data, uint32_t len);

/* Copy from nfs_fh to raw buffer, returns length */
uint32_t nfs_fh_to_buf(const struct nfs_fh *fh, uint8_t *data, size_t maxlen);

/* Parse hex string to file handle buffer, returns length or -1 on error */
int nfs_parse_fh(const char *hexstr, uint8_t *fh, size_t fhsize);

/* Parse hex string directly into struct nfs_fh, returns 0 or -1 on error */
int nfs_parse_fh_arg(const char *hexstr, struct nfs_fh *fh);

/*
 * NFS-specific XDR helpers
 *
 * Generic XDR primitives are in xdr.h. These are NFS-specific
 * because they use struct nfs_fh.
 */

/* Parse XDR opaque into nfs_fh (alignment-safe) */
static inline uint8_t *
xdr_parse_fh(uint8_t *pt, uint8_t *end, struct nfs_fh *fh)
{
    uint32_t len;

    if (pt + XDR_UNIT > end)
        return NULL;
    len = xdr_get_u32(pt);
    pt += XDR_UNIT;

    if (pt + len > end || len > NFS_FHSIZE_MAX)
        return NULL;

    fh->len = len;
    memcpy(fh->data, pt, len);
    return pt + XDR_ALIGN(len);
}

#endif /* NFS_UTIL_H */
