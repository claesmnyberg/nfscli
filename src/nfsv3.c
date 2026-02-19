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
 * nfsv3.c - NFSv3 protocol implementation (RFC 1813)
 *
 * Pure NFSv3 implementation using variable-length file handles (max 64 bytes)
 * and 64-bit offsets. All functions return data via output parameters and
 * never print directly.
 */

#include <stdlib.h>
#include <sys/time.h>

#include "nfs_ops.h"
#include "nfscli.h"
#include "nfsv3.h"
#include "print.h"
#include "rpc.h"

/*
 * Build NFSv3 sattr3 into buffer (variable length).
 *
 * RFC 1813 Section 2.5 - sattr3 structure
 *
 * Unlike NFSv2, NFSv3 sattr3 is variable-length:
 *   set_mode3:  bool set_it; [mode3 mode if TRUE]
 *   set_uid3:   bool set_it; [uid3 uid if TRUE]
 *   set_gid3:   bool set_it; [gid3 gid if TRUE]
 *   set_size3:  bool set_it; [size3 size if TRUE]
 *   set_atime:  time_how (0=DONT_CHANGE, 1=SET_TO_SERVER_TIME, 2=SET_TO_CLIENT_TIME)
 *               [nfstime3 if SET_TO_CLIENT_TIME]
 *   set_mtime:  same as atime
 *
 * Returns pointer past the written data.
 */
static uint8_t *
nfsv3_build_sattr3(uint8_t *pt, const struct nfs_sattr *sattr)
{
    /* mode */
    if (sattr->set_mode) {
        pt = xdr_build_u32(pt, 1);
        pt = xdr_build_u32(pt, sattr->mode);
    } else {
        pt = xdr_build_u32(pt, 0);
    }

    /* uid */
    if (sattr->set_uid) {
        pt = xdr_build_u32(pt, 1);
        pt = xdr_build_u32(pt, sattr->uid);
    } else {
        pt = xdr_build_u32(pt, 0);
    }

    /* gid */
    if (sattr->set_gid) {
        pt = xdr_build_u32(pt, 1);
        pt = xdr_build_u32(pt, sattr->gid);
    } else {
        pt = xdr_build_u32(pt, 0);
    }

    /* size (64-bit) */
    if (sattr->set_size) {
        pt = xdr_build_u32(pt, 1);
        pt = xdr_build_u64(pt, sattr->size);
    } else {
        pt = xdr_build_u32(pt, 0);
    }

    /* atime: 0=DONT_CHANGE, 1=SET_TO_SERVER_TIME, 2=SET_TO_CLIENT_TIME */
    pt = xdr_build_u32(pt, sattr->set_atime);
    if (sattr->set_atime == NFS_TIME_SET_TO_CLIENT) {
        pt = xdr_build_u32(pt, sattr->atime.sec);
        pt = xdr_build_u32(pt, sattr->atime.nsec);
    }

    /* mtime: same as atime */
    pt = xdr_build_u32(pt, sattr->set_mtime);
    if (sattr->set_mtime == NFS_TIME_SET_TO_CLIENT) {
        pt = xdr_build_u32(pt, sattr->mtime.sec);
        pt = xdr_build_u32(pt, sattr->mtime.nsec);
    }

    return pt;
}

/*
 * Calculate size of sattr3 encoding for buffer allocation
 */
static size_t
nfsv3_sattr3_size(const struct nfs_sattr *sattr)
{
    size_t size = 0;

    /* mode: 1 word for set_it, 1 word for value if set */
    size += XDR_UNIT + (sattr->set_mode ? XDR_UNIT : 0);
    /* uid */
    size += XDR_UNIT + (sattr->set_uid ? XDR_UNIT : 0);
    /* gid */
    size += XDR_UNIT + (sattr->set_gid ? XDR_UNIT : 0);
    /* size: 1 word for set_it, 2 words for 64-bit value if set */
    size += XDR_UNIT + (sattr->set_size ? 2 * XDR_UNIT : 0);
    /* atime: 1 word for time_how, 2 words for nfstime3 if client time */
    size += XDR_UNIT + (sattr->set_atime == NFS_TIME_SET_TO_CLIENT ? 2 * XDR_UNIT : 0);
    /* mtime: same as atime */
    size += XDR_UNIT + (sattr->set_mtime == NFS_TIME_SET_TO_CLIENT ? 2 * XDR_UNIT : 0);

    return size;
}

/*
 * Build sattr3 for mode-only operations (create, symlink, mkdir).
 * Size is fixed: 7 words (mode=set with value, rest=don't change)
 */
#define NFSV3_SATTR3_MODE_SIZE (7 * XDR_UNIT)

static uint8_t *
nfsv3_build_sattr3_mode(uint8_t *pt, uint32_t mode)
{
    /* mode: set_it=1, value */
    pt = xdr_build_u32(pt, 1);
    pt = xdr_build_u32(pt, mode);
    /* uid: set_it=0 */
    pt = xdr_build_u32(pt, 0);
    /* gid: set_it=0 */
    pt = xdr_build_u32(pt, 0);
    /* size: set_it=0 */
    pt = xdr_build_u32(pt, 0);
    /* atime: DONT_CHANGE */
    pt = xdr_build_u32(pt, 0);
    /* mtime: DONT_CHANGE */
    pt = xdr_build_u32(pt, 0);
    return pt;
}

/*
 * Parse NFSv3 file attributes from wire format to common format.
 *
 * RFC 1813 Section 2.5 - fattr3 structure
 *
 * NFSv3 improvements over NFSv2:
 * - 64-bit sizes and offsets (files > 4GB)
 * - Nanosecond timestamp resolution
 * - Separate major/minor device numbers
 * - 64-bit file IDs (no inode overflow)
 * - 'used' field for actual space consumed (sparse files)
 */
static void
nfsv3_parse_fattr(const struct nfsv3_fattr *wire, struct nfs_attr *out)
{
    out->type = ntohl(wire->type);
    out->mode = ntohl(wire->mode);
    out->nlink = ntohl(wire->nlink);
    out->uid = ntohl(wire->uid);
    out->gid = ntohl(wire->gid);
    out->size = be64toh(wire->size);
    out->used = be64toh(wire->used);
    out->rdev = ((uint64_t)ntohl(wire->rdev_major) << 32) | ntohl(wire->rdev_minor);
    out->fsid = be64toh(wire->fsid);
    out->fileid = be64toh(wire->fileid);
    out->atime.sec = ntohl(wire->atime_sec);
    out->atime.nsec = ntohl(wire->atime_nsec);
    out->mtime.sec = ntohl(wire->mtime_sec);
    out->mtime.nsec = ntohl(wire->mtime_nsec);
    out->ctime.sec = ntohl(wire->ctime_sec);
    out->ctime.nsec = ntohl(wire->ctime_nsec);
}

/*
 * Build file handle into buffer (variable length for v3)
 * Returns pointer past the written data
 */
static uint8_t *
nfsv3_build_fh(uint8_t *pt, const struct nfs_fh *fh)
{
    return xdr_build_opaque(pt, fh->data, fh->len);
}

/*
 * Build string into buffer (XDR string format)
 * Returns pointer past the written data
 */
static uint8_t *
nfsv3_build_string(uint8_t *pt, const char *str)
{
    return xdr_build_string(pt, str);
}

/*
 * Parse file handle from buffer
 * Returns pointer past the parsed data, or NULL on error
 */
static uint8_t *
nfsv3_parse_fh(uint8_t *pt, uint8_t *end, struct nfs_fh *fh)
{
    uint32_t len;
    uint32_t len_padded;

    if (pt + XDR_UNIT > end)
        return NULL;

    len = xdr_get_u32(pt);
    pt += XDR_UNIT;

    /* Validate length BEFORE XDR_ALIGN to prevent overflow */
    if (len == 0 || len > NFSV3_FHSIZE)
        return NULL;
    len_padded = XDR_ALIGN(len);

    /* Check bounds with aligned length */
    if (pt + len_padded > end)
        return NULL;

    nfs_fh_from_buf(fh, pt, len);
    pt += len_padded;
    return pt;
}

/*
 * Parse post_op_attr (optional file attributes).
 *
 * RFC 1813 Section 2.5 - post_op_attr
 *   union switch (bool attributes_follow) {
 *       TRUE:  fattr3 attributes;
 *       FALSE: void;
 *   };
 *
 * If attr is NULL, attributes are skipped but pointer still advances.
 * If has_attr is not NULL, set to 1 if attributes were present.
 * Returns pointer past the parsed data, or NULL on bounds error.
 */
static uint8_t *
nfsv3_parse_post_op_attr(uint8_t *pt, uint8_t *end,
    struct nfs_attr *attr, int *has_attr)
{
    uint32_t value_follows;

    if (pt + XDR_UNIT > end)
        return NULL;

    value_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;

    if (value_follows) {
        if (pt + sizeof(struct nfsv3_fattr) > end)
            return NULL;
        if (attr != NULL)
            nfsv3_parse_fattr((struct nfsv3_fattr *)pt, attr);
        if (has_attr != NULL)
            *has_attr = 1;
        pt += sizeof(struct nfsv3_fattr);
    } else {
        if (has_attr != NULL)
            *has_attr = 0;
    }

    return pt;
}

/*
 * Skip pre_op_attr (wcc_attr) in wcc_data.
 *
 * RFC 1813 Section 2.5 - pre_op_attr (wcc_attr)
 *   union switch (bool attributes_follow) {
 *       TRUE:  wcc_attr { size3 size; nfstime3 mtime; nfstime3 ctime; };
 *       FALSE: void;
 *   };
 *
 * The pre_op_attr is 24 bytes if present: size(8) + mtime(8) + ctime(8).
 * Returns pointer past the data, or NULL on bounds error.
 */
static uint8_t *
nfsv3_skip_pre_op_attr(uint8_t *pt, uint8_t *end)
{
    uint32_t value_follows;

    if (pt + XDR_UNIT > end)
        return NULL;

    value_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;

    if (value_follows) {
        /* wcc_attr: size(8) + mtime(8) + ctime(8) = 24 bytes */
        if (pt + 24 > end)
            return NULL;
        pt += 24;
    }

    return pt;
}

/*
 * Skip wcc_data (pre_op_attr + post_op_attr) and optionally parse post_op_attr.
 *
 * RFC 1813 Section 2.5 - wcc_data
 *   struct wcc_data {
 *       pre_op_attr before;
 *       post_op_attr after;
 *   };
 *
 * If attr is not NULL, parses post_op_attr into it.
 * If has_attr is not NULL, sets to 1 if post_op_attr was present.
 * Returns pointer past the data, or NULL on bounds error.
 */
static uint8_t *
nfsv3_parse_wcc_data(uint8_t *pt, uint8_t *end,
    struct nfs_attr *attr, int *has_attr)
{
    /* Skip pre_op_attr */
    pt = nfsv3_skip_pre_op_attr(pt, end);
    if (pt == NULL)
        return NULL;

    /* Parse post_op_attr */
    return nfsv3_parse_post_op_attr(pt, end, attr, has_attr);
}

/*
 * NFSv3 GETATTR (Procedure 1)
 *
 * RFC 1813 Section 3.3.1 - NFSPROC3_GETATTR
 *
 * Returns all file attributes. Does NOT follow symbolic links.
 * Unlike NFSv2, GETATTR is the only procedure that never returns
 * post_op_attr (since it returns the full attributes directly).
 *
 * Status codes: NFS3_OK, NFS3ERR_STALE, NFS3ERR_BADHANDLE,
 *               NFS3ERR_SERVERFAULT
 */
static int
nfsv3_getattr_impl(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_attr *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint8_t buf[RPC_BUFSIZE_LARGE];
    size_t totlen;
    uint8_t *pt;
    ssize_t n;
    uint32_t xid = rand();

    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(fh->len);

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_GETATTR);
    pt = buf + sizeof(struct rpc_call_hdr);

    pt = nfsv3_build_fh(pt, fh);
    (void)pt; /* silence dead store warning */

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    pt = buf + sizeof(struct rpc_nfsreply_hdr);

    if ((pt + sizeof(struct nfsv3_fattr)) > &buf[n]) {
        errno = EBADMSG;
        return -1;
    }

    nfsv3_parse_fattr((struct nfsv3_fattr *)pt, out);
    return 0;
}

/*
 * NFSv3 SETATTR (Procedure 2)
 *
 * RFC 1813 Section 3.3.2 - NFSPROC3_SETATTR
 *
 * Sets file attributes. NOT atomic - partial changes may occur on failure.
 * Uses sattr3 with explicit flags per field (unlike v2's -1 sentinel).
 *
 * sattrguard3: Optional ctime check to prevent lost updates. If guard.check
 * is TRUE and ctime doesn't match, returns NFS3ERR_NOT_SYNC. This
 * implementation does not use the guard.
 *
 * Status codes: NFS3_OK, NFS3ERR_PERM, NFS3ERR_IO, NFS3ERR_ACCES,
 *               NFS3ERR_INVAL, NFS3ERR_ROFS, NFS3ERR_NOT_SYNC
 */
static int
nfsv3_setattr_impl(struct nfsctx *ctx, const struct nfs_fh *fh,
    const struct nfs_sattr *sattr, struct nfs_attr *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint8_t buf[RPC_BUFSIZE_LARGE];
    size_t totlen;
    uint8_t *pt, *end;
    ssize_t n;
    uint32_t xid = rand();
    uint32_t value_follows;

    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(fh->len);
    totlen += nfsv3_sattr3_size(sattr);
    totlen += XDR_UNIT; /* guard */

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_SETATTR);
    pt = buf + sizeof(struct rpc_call_hdr);

    pt = nfsv3_build_fh(pt, fh);

    /* Build sattr3 (variable length) */
    pt = nfsv3_build_sattr3(pt, sattr);

    /* Guard (no guard) */
    pt = xdr_build_u32(pt, 0);
    (void)pt;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    /* Parse wcc_data to extract post_op_attr if caller wants it */
    if (out != NULL) {
        const size_t wcc_attr_size = 24;
        pt = buf + sizeof(struct rpc_nfsreply_hdr);
        end = buf + n;

        /* Skip pre_op_attr (wcc_attr: bool + optional 24 bytes) */
        if (pt + XDR_UNIT > end)
            return 0; /* Success, but no attrs to return */
        value_follows = xdr_get_u32(pt);
        pt += XDR_UNIT;
        if (value_follows) {
            /* wcc_attr: size(8) + mtime(8) + ctime(8) = 24 bytes */
            if (pt + wcc_attr_size > end)
                return 0;
            pt += wcc_attr_size;
        }

        /* Bounds check after wcc_data before parsing post_op_attr */
        if (pt + XDR_UNIT > end)
            return 0;
        value_follows = xdr_get_u32(pt);
        pt += XDR_UNIT;
        if (value_follows) {
            if (pt + sizeof(struct nfsv3_fattr) > end)
                return 0;
            nfsv3_parse_fattr((struct nfsv3_fattr *)pt, out);
        }
    }

    return 0;
}

/*
 * NFSv3 LOOKUP (Procedure 3)
 *
 * RFC 1813 Section 3.3.3 - NFSPROC3_LOOKUP
 *
 * Searches directory for name, returns file handle and attributes.
 * Does NOT follow symlinks. Returns post_op_attr for both the
 * looked-up object and the directory (unlike NFSv2).
 *
 * Status codes: NFS3_OK, NFS3ERR_NOENT, NFS3ERR_ACCES, NFS3ERR_NOTDIR,
 *               NFS3ERR_NAMETOOLONG, NFS3ERR_STALE, NFS3ERR_BADHANDLE
 */
static int
nfsv3_lookup_impl(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, struct nfs_lookup_res *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint8_t buf[RPC_BUFSIZE_LARGE];
    size_t totlen;
    uint8_t *pt;
    uint8_t *end;
    ssize_t n;
    uint32_t xid = rand();
    size_t namelen = strlen(name);

    if (namelen > NFS_MAXNAMLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(dirfh->len);
    totlen += XDR_VARLEN(namelen);

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_LOOKUP);
    pt = buf + sizeof(struct rpc_call_hdr);

    pt = nfsv3_build_fh(pt, dirfh);
    pt = nfsv3_build_string(pt, name);
    (void)pt;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    memset(out, 0, sizeof(*out));
    pt = buf + sizeof(struct rpc_nfsreply_hdr);
    end = buf + n;

    /* File handle */
    pt = nfsv3_parse_fh(pt, end, &out->fh);
    if (pt == NULL) {
        errno = EBADMSG;
        return -1;
    }

    /* Object attributes (optional) */
    pt = nfsv3_parse_post_op_attr(pt, end, &out->obj_attr, &out->has_obj_attr);
    if (pt == NULL) {
        errno = EBADMSG;
        return -1;
    }

    /* Directory attributes (optional) */
    pt = nfsv3_parse_post_op_attr(pt, end, &out->dir_attr, &out->has_dir_attr);
    if (pt == NULL) {
        errno = EBADMSG;
        return -1;
    }

    (void)pt; /* Silence unused warning - end of parsing */
    return 0;
}

/*
 * NFSv3 READLINK (Procedure 5)
 *
 * RFC 1813 Section 3.3.5 - NFSPROC3_READLINK
 *
 * Returns symbolic link target path (not validated, may be dangling).
 * Max path: NFS3_MAXPATHLEN (1024 bytes).
 * Returns post_op_attr for the symlink.
 *
 * Status codes: NFS3_OK, NFS3ERR_INVAL (not a symlink),
 *               NFS3ERR_STALE, NFS3ERR_BADHANDLE, NFS3ERR_IO
 */
static int
nfsv3_readlink_impl(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_readlink_res *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint32_t data_follows;
    uint32_t len;
    uint8_t *buf;
    size_t bufsize = IOBUFSIZE * 2;
    size_t totlen;
    uint8_t *pt;
    uint8_t *end;
    ssize_t n;
    uint32_t xid = rand();

    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(fh->len);

    if (totlen > bufsize) {
        errno = ENOBUFS;
        return -1;
    }

    buf = malloc(bufsize);
    if (buf == NULL)
        return -1;

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_READLINK);
    pt = buf + sizeof(struct rpc_call_hdr);

    pt = nfsv3_build_fh(pt, fh);
    (void)pt;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0) {
        free(buf);
        return -1;
    }

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, bufsize, xid)) < 0) {
        free(buf);
        return -1;
    }

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY_FREE(ctx, reply, n, buf);

    NFS_CHECK_STATUS_EX(ctx, reply, free(buf));

    pt = buf + sizeof(struct rpc_nfsreply_hdr);
    end = buf + n;

    /* Post operation attributes (optional) */
    if (pt + XDR_UNIT > end) {
        free(buf);
        errno = EBADMSG;
        return -1;
    }
    data_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;
    if (data_follows) {
        if (pt + sizeof(struct nfsv3_fattr) > end) {
            free(buf);
            errno = EBADMSG;
            return -1;
        }
        nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &out->attr);
        out->has_attr = 1;
        pt += sizeof(struct nfsv3_fattr);
    }

    /* Link data */
    if (pt + XDR_UNIT > end) {
        free(buf);
        errno = EBADMSG;
        return -1;
    }
    len = xdr_get_u32(pt);
    pt += XDR_UNIT;

    /* Validate length BEFORE XDR_ALIGN to prevent overflow */
    if (len > NFS_MAXPATHLEN) {
        free(buf);
        errno = ENAMETOOLONG;
        return -1;
    }

    /* Validate length against output buffer size */
    if (len >= sizeof(out->target)) {
        free(buf);
        errno = ENAMETOOLONG;
        return -1;
    }

    /* Check bounds with unpadded length (path_data is last field in response) */
    if (len > (size_t)(end - pt)) {
        free(buf);
        errno = EBADMSG;
        return -1;
    }

    memset(out->target, 0, sizeof(out->target));
    memcpy(out->target, pt, len);
    xdr_sanitize_string(out->target);
    free(buf);
    return 0;
}

/*
 * NFSv3 READ (Procedure 6)
 *
 * RFC 1813 Section 3.3.6 - NFSPROC3_READ
 *
 * Reads data from file. Uses 64-bit offsets (unlike NFSv2's 32-bit).
 * Returns explicit EOF flag (unlike NFSv2 which requires inference).
 *
 * The server may return fewer bytes than requested. EOF=TRUE with
 * count=0 indicates reading past end of file.
 *
 * Status codes: NFS3_OK, NFS3ERR_ACCES, NFS3ERR_INVAL, NFS3ERR_ISDIR,
 *               NFS3ERR_STALE, NFS3ERR_BADHANDLE, NFS3ERR_IO
 */
static int
nfsv3_read_impl(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint64_t offset, uint32_t count, struct nfs_read_res *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint32_t value_follows;
    uint8_t buf[RPC_BUFSIZE_SMALL];
    uint8_t *recvbuf;
    uint8_t *end;
    uint32_t buflen;
    size_t totlen;
    uint8_t *pt;
    ssize_t n;
    uint32_t xid = rand();

/* READ call footer: offset(8) + count(4) = 12 bytes */
#define READ_CALL_FOOTER_SIZE (8 + XDR_UNIT)

    size_t overhead;

    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(fh->len);
    totlen += READ_CALL_FOOTER_SIZE;

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_READ);
    pt = buf + sizeof(struct rpc_call_hdr);

    pt = nfsv3_build_fh(pt, fh);

    /* Build footer with alignment-safe writes */
    xdr_put_u64(pt, offset);
    pt += 8;
    xdr_put_u32(pt, count);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    /*
     * Allocate receive buffer with overflow protection.
     * NFSv3 READ reply: rpc_nfsreply_hdr + attr_follows(4) + [fattr] +
     *                   count(4) + eof(4) + data_len(4) + data
     */
    overhead = sizeof(struct rpc_nfsreply_hdr) + XDR_UNIT /* attributes_follow */
        + sizeof(struct nfsv3_fattr)                      /* optional, but allocate */
        + XDR_UNIT                                        /* count */
        + XDR_UNIT                                        /* eof */
        + XDR_UNIT;                                       /* data length */
    /* Check for XDR_ALIGN overflow (count + 3 must not wrap in 32-bit) */
    if (count > UINT32_MAX - (XDR_UNIT - 1)) {
        errno = EINVAL;
        rpc_unlock(ctx);
        return -1;
    }
    if (count > SIZE_MAX - overhead - (XDR_UNIT - 1)) { /* for ALIGN padding */
        errno = EINVAL;
        rpc_unlock(ctx);
        return -1;
    }
    buflen = overhead + XDR_ALIGN(count);

    if ((recvbuf = malloc(buflen)) == NULL) {
        errno = ENOMEM;
        rpc_unlock(ctx);
        return -1;
    }

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, recvbuf, buflen, xid)) < 0) {
        free(recvbuf);
        return -1;
    }

    reply = (struct rpc_nfsreply_hdr *)recvbuf;
    RPC_CHECK_REPLY_FREE(ctx, reply, n, recvbuf);

    NFS_CHECK_STATUS_EX(ctx, reply, free(recvbuf));

    pt = recvbuf + sizeof(struct rpc_nfsreply_hdr);
    end = recvbuf + n;

    /* Attributes (optional) */
    if (pt + XDR_UNIT > end)
        goto short_reply;
    value_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;
    if (value_follows == 1) {
        if (pt + sizeof(struct nfsv3_fattr) > end)
            goto short_reply;
        nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &out->attr);
        out->has_attr = 1;
        pt += sizeof(struct nfsv3_fattr);
    }

    /* Count */
    if (pt + XDR_UNIT > end)
        goto short_reply;
    out->count = xdr_get_u32(pt);
    pt += XDR_UNIT;

    /* EOF */
    if (pt + XDR_UNIT > end)
        goto short_reply;
    out->eof = xdr_get_u32(pt);
    pt += XDR_UNIT;

    /* Data length and pointer */
    if (pt + XDR_UNIT > end)
        goto short_reply;
    pt += XDR_UNIT; /* skip length field, use count */

    /* Validate that data fits in buffer (use subtraction to avoid pointer overflow) */
    if (out->count > (size_t)(end - pt))
        goto short_reply;
    out->data = pt;
    out->buf = recvbuf; /* caller must free */

    return 0;

short_reply:
    free(recvbuf);
    errno = EIO;
    return -1;
}

/*
 * NFSv3 WRITE (Procedure 7)
 *
 * RFC 1813 Section 3.3.7 - NFSPROC3_WRITE
 *
 * Writes data to file with configurable stability:
 *   UNSTABLE (0)  - Server may cache; must COMMIT before assuming durable
 *   DATA_SYNC (1) - Data on stable storage, metadata may be cached
 *   FILE_SYNC (2) - All data and metadata on stable storage (slowest)
 *
 * Returns 'committed' indicating actual stability level achieved.
 * Returns 'verf' (write verifier) for detecting server reboots between
 * UNSTABLE writes and COMMIT. This implementation uses FILE_SYNC.
 *
 * Status codes: NFS3_OK, NFS3ERR_ACCES, NFS3ERR_INVAL, NFS3ERR_FBIG,
 *               NFS3ERR_NOSPC, NFS3ERR_DQUOT, NFS3ERR_ROFS, NFS3ERR_STALE
 */
static int
nfsv3_write_impl(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint64_t offset, const uint8_t *data, uint32_t count,
    struct nfs_write_res *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint8_t buf[RPC_BUFSIZE_SMALL];
    uint8_t *end;
    size_t totlen;
    uint8_t *pt;
    ssize_t n;
    uint32_t xid = rand();

/* WRITE call footer: offset(8) + count(4) + stable(4) + datalen(4) = 20 bytes */
#define WRITE_CALL_FOOTER_SIZE (8 + 3 * XDR_UNIT)

    if (out != NULL)
        memset(out, 0, sizeof(*out));

    /* Check for XDR_ALIGN overflow before calculating total length */
    if (count > UINT32_MAX - (XDR_UNIT - 1)) {
        errno = EINVAL;
        return -1;
    }

    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(fh->len);
    totlen += WRITE_CALL_FOOTER_SIZE;
    totlen += XDR_ALIGN(count);

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_WRITE);
    pt = buf + sizeof(struct rpc_call_hdr);

    pt = nfsv3_build_fh(pt, fh);

    /* Build footer with alignment-safe writes */
    xdr_put_u64(pt, offset);
    pt += 8;
    xdr_put_u32(pt, count);
    pt += XDR_UNIT;
    xdr_put_u32(pt, NFS_FILE_SYNC);
    pt += XDR_UNIT;
    xdr_put_u32(pt, count); /* datalen */
    pt += XDR_UNIT;

    memcpy(pt, data, count);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    /* Parse response if caller wants it */
    if (out != NULL) {
        pt = buf + sizeof(struct rpc_nfsreply_hdr);
        end = buf + n;

        /* WCC data: pre_op_attr (skip) + post_op_attr */
        pt = nfsv3_parse_wcc_data(pt, end, &out->attr, &out->has_attr);
        if (pt == NULL)
            goto done;

        /* count + committed + verf */
        if (pt + XDR_UNIT + XDR_UNIT + sizeof(uint64_t) > end)
            goto done;
        out->count = xdr_get_u32(pt);
        pt += XDR_UNIT;
        out->committed = xdr_get_u32(pt);
        pt += XDR_UNIT;
        /*
         * Write verifier: OPAQUE 8-byte value (RFC 1813).
         * WARNING: Do NOT byte-swap - opaque values must be compared as raw bytes.
         */
        memcpy(&out->verifier, pt, sizeof(out->verifier));
    }

done:
    return 0;
}

/*
 * NFSv3 CREATE (Procedure 8)
 *
 * RFC 1813 Section 3.3.8 - NFSPROC3_CREATE
 *
 * Creates a regular file with three modes:
 *   UNCHECKED (0) - Create or truncate if exists (O_CREAT|O_TRUNC)
 *   GUARDED (1)   - Fail if exists (O_CREAT|O_EXCL)
 *   EXCLUSIVE (2) - Atomic create using createverf; for lock files
 *
 * Wire format (RFC 1813):
 *   union createhow3 switch (createmode3 mode) {
 *   case UNCHECKED:
 *   case GUARDED:
 *       sattr3 obj_attributes;
 *   case EXCLUSIVE:
 *       createverf3 verf;   (8 bytes)
 *   };
 *
 * EXCLUSIVE mode: createverf is stored in file and returned on success.
 * If file exists with matching verf, returns success (idempotent retry).
 *
 * Status codes: NFS3_OK, NFS3ERR_ACCES, NFS3ERR_EXIST (GUARDED),
 *               NFS3ERR_NOSPC, NFS3ERR_DQUOT, NFS3ERR_ROFS, NFS3ERR_STALE
 */
static int
nfsv3_create_impl(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, uint32_t mode, int create_mode,
    struct nfs_create_res *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint32_t value_follows;
    uint8_t buf[RPC_BUFSIZE_LARGE];
    size_t totlen;
    uint8_t *pt;
    uint8_t *end;
    ssize_t n;
    uint32_t xid = rand();
    size_t namelen = strlen(name);

    if (namelen > NFS_MAXNAMLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(dirfh->len);
    totlen += XDR_VARLEN(namelen);
    totlen += XDR_UNIT; /* create mode */

    /* EXCLUSIVE uses 8-byte verifier, others use sattr3 */
    if (create_mode == NFS_CREATE_EXCLUSIVE)
        totlen += 8; /* createverf3 */
    else
        totlen += NFSV3_SATTR3_MODE_SIZE;

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_CREATE);
    pt = buf + sizeof(struct rpc_call_hdr);

    pt = nfsv3_build_fh(pt, dirfh);
    pt = nfsv3_build_string(pt, name);

    /* Create mode */
    pt = xdr_build_u32(pt, create_mode);

    if (create_mode == NFS_CREATE_EXCLUSIVE) {
        /*
         * Create verifier: OPAQUE 8-byte value (RFC 1813).
         * We generate it from time+random; server stores it and returns
         * it on successful exclusive create for idempotent retry detection.
         */
        struct timeval tv;
        gettimeofday(&tv, NULL);
        pt = xdr_build_u32(pt, (uint32_t)tv.tv_sec);
        pt = xdr_build_u32(pt, (uint32_t)rand());
    } else {
        /* UNCHECKED or GUARDED: send sattr3 */
        pt = nfsv3_build_sattr3_mode(pt, mode);
    }
    (void)pt;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    memset(out, 0, sizeof(*out));
    pt = buf + sizeof(struct rpc_nfsreply_hdr);
    end = buf + n;

    /* File handle (optional) */
    if (pt + XDR_UNIT > end) {
        errno = EBADMSG;
        return -1;
    }
    value_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;
    if (value_follows == 1) {
        pt = nfsv3_parse_fh(pt, end, &out->fh);
        if (pt == NULL) {
            errno = EBADMSG;
            return -1;
        }
        out->has_fh = 1;
    }

    /* Object attributes (optional) */
    pt = nfsv3_parse_post_op_attr(pt, end, &out->attr, &out->has_attr);
    if (pt == NULL) {
        errno = EBADMSG;
        return -1;
    }

    (void)pt; /* Silence unused warning - end of parsing */
    return 0;
}

/*
 * Common implementation for REMOVE (procedure 12) and RMDIR (procedure 13).
 *
 * RFC 1813 Section 3.3.12 (REMOVE) and 3.3.13 (RMDIR)
 *
 * Both return wcc_data (weak cache consistency) for the directory:
 *   pre_op_attr: size, mtime, ctime before operation
 *   post_op_attr: full attributes after operation
 *
 * REMOVE: NFS3ERR_ISDIR if target is directory
 * RMDIR: NFS3ERR_NOTDIR if target is not directory, NFS3ERR_NOTEMPTY if not empty
 */
static int
nfsv3_unlink_common(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, uint32_t proc, struct nfs_wcc_data *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint8_t buf[RPC_BUFSIZE_LARGE];
    uint8_t *end;
    size_t totlen;
    uint8_t *pt;
    ssize_t n;
    uint32_t xid = rand();
    uint32_t value_follows;
    size_t namelen = strlen(name);

    if (out != NULL)
        memset(out, 0, sizeof(*out));

    if (namelen > NFS_MAXNAMLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(dirfh->len);
    totlen += XDR_VARLEN(namelen);

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, proc);
    pt = buf + sizeof(struct rpc_call_hdr);

    pt = nfsv3_build_fh(pt, dirfh);
    pt = nfsv3_build_string(pt, name);
    (void)pt;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    /* Parse wcc_data for directory */
    if (out != NULL) {
        pt = buf + sizeof(struct rpc_nfsreply_hdr);
        end = buf + n;

        /* pre_op_attr (skip) */
        if (pt + XDR_UNIT <= end) {
            value_follows = xdr_get_u32(pt);
            pt += XDR_UNIT;
            if (value_follows && pt + 24 <= end)
                pt += 24; /* size(8) + mtime(8) + ctime(8) */
        }

        /* post_op_attr */
        if (pt + XDR_UNIT <= end) {
            value_follows = xdr_get_u32(pt);
            pt += XDR_UNIT;
            if (value_follows && pt + sizeof(struct nfsv3_fattr) <= end) {
                nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &out->dir_attr);
                out->has_dir_attr = 1;
            }
        }
    }

    return 0;
}

/*
 * NFSv3 REMOVE (Procedure 12)
 */
static int
nfsv3_remove_impl(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, struct nfs_wcc_data *out)
{
    return nfsv3_unlink_common(ctx, dirfh, name, NFSV3_PROC_REMOVE, out);
}

/*
 * NFSv3 RENAME (Procedure 14)
 */
static int
nfsv3_rename_impl(struct nfsctx *ctx, const struct nfs_fh *srcfh,
    const char *srcname, const struct nfs_fh *dstfh, const char *dstname,
    struct nfs_rename_res *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint8_t buf[RPC_BUFSIZE_LARGE];
    uint8_t *end;
    size_t totlen;
    uint8_t *pt;
    ssize_t n;
    uint32_t xid = rand();
    uint32_t value_follows;
    size_t srcnamelen = strlen(srcname);
    size_t dstnamelen = strlen(dstname);

    if (out != NULL)
        memset(out, 0, sizeof(*out));

    if (srcnamelen > NFS_MAXNAMLEN || dstnamelen > NFS_MAXNAMLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(srcfh->len);
    totlen += XDR_VARLEN(srcnamelen);
    totlen += XDR_VARLEN(dstfh->len);
    totlen += XDR_VARLEN(dstnamelen);

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_RENAME);
    pt = buf + sizeof(struct rpc_call_hdr);

    pt = nfsv3_build_fh(pt, srcfh);
    pt = nfsv3_build_string(pt, srcname);
    pt = nfsv3_build_fh(pt, dstfh);
    pt = nfsv3_build_string(pt, dstname);
    (void)pt;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    /* Parse wcc_data for both directories */
    if (out != NULL) {
        pt = buf + sizeof(struct rpc_nfsreply_hdr);
        end = buf + n;

        /* Source directory wcc_data */
        /* pre_op_attr (skip) */
        if (pt + XDR_UNIT <= end) {
            value_follows = xdr_get_u32(pt);
            pt += XDR_UNIT;
            if (value_follows && pt + 24 <= end)
                pt += 24;
        }
        /* post_op_attr */
        if (pt + XDR_UNIT <= end) {
            value_follows = xdr_get_u32(pt);
            pt += XDR_UNIT;
            if (value_follows && pt + sizeof(struct nfsv3_fattr) <= end) {
                nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &out->src_dir_attr);
                out->has_src_dir_attr = 1;
                pt += sizeof(struct nfsv3_fattr);
            }
        }

        /* Destination directory wcc_data */
        /* pre_op_attr (skip) */
        if (pt + XDR_UNIT <= end) {
            value_follows = xdr_get_u32(pt);
            pt += XDR_UNIT;
            if (value_follows && pt + 24 <= end)
                pt += 24;
        }
        /* post_op_attr */
        if (pt + XDR_UNIT <= end) {
            value_follows = xdr_get_u32(pt);
            pt += XDR_UNIT;
            if (value_follows && pt + sizeof(struct nfsv3_fattr) <= end) {
                nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &out->dst_dir_attr);
                out->has_dst_dir_attr = 1;
            }
        }
    }

    return 0;
}

/*
 * NFSv3 LINK (Procedure 15)
 */
static int
nfsv3_link_impl(struct nfsctx *ctx, const struct nfs_fh *fh,
    const struct nfs_fh *dirfh, const char *name, struct nfs_link_res *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint8_t buf[IOBUFSIZE * 2];
    uint8_t *end;
    size_t totlen;
    uint8_t *pt;
    ssize_t n;
    uint32_t xid = rand();
    uint32_t value_follows;
    size_t namelen = strlen(name);

    if (out != NULL)
        memset(out, 0, sizeof(*out));

    if (namelen > NFS_MAXNAMLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(fh->len);
    totlen += XDR_VARLEN(dirfh->len);
    totlen += XDR_VARLEN(namelen);

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_LINK);
    pt = buf + sizeof(struct rpc_call_hdr);

    pt = nfsv3_build_fh(pt, fh);
    pt = nfsv3_build_fh(pt, dirfh);
    pt = nfsv3_build_string(pt, name);
    (void)pt;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    /* Parse file post_op_attr and directory wcc_data */
    if (out != NULL) {
        pt = buf + sizeof(struct rpc_nfsreply_hdr);
        end = buf + n;

        /* File post_op_attr (nlink changed) */
        if (pt + XDR_UNIT <= end) {
            value_follows = xdr_get_u32(pt);
            pt += XDR_UNIT;
            if (value_follows && pt + sizeof(struct nfsv3_fattr) <= end) {
                nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &out->file_attr);
                out->has_file_attr = 1;
                pt += sizeof(struct nfsv3_fattr);
            }
        }

        /* Directory wcc_data */
        /* pre_op_attr (skip) */
        if (pt + XDR_UNIT <= end) {
            value_follows = xdr_get_u32(pt);
            pt += XDR_UNIT;
            if (value_follows && pt + 24 <= end)
                pt += 24;
        }
        /* post_op_attr */
        if (pt + XDR_UNIT <= end) {
            value_follows = xdr_get_u32(pt);
            pt += XDR_UNIT;
            if (value_follows && pt + sizeof(struct nfsv3_fattr) <= end) {
                nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &out->dir_attr);
                out->has_dir_attr = 1;
            }
        }
    }

    return 0;
}

/*
 * NFSv3 SYMLINK (Procedure 10)
 */
static int
nfsv3_symlink_impl(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, const char *target, uint32_t mode,
    struct nfs_symlink_res *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint8_t buf[IOBUFSIZE * 2];
    uint8_t *end;
    size_t totlen;
    uint8_t *pt;
    ssize_t n;
    uint32_t xid = rand();
    uint32_t value_follows;
    size_t namelen = strlen(name);
    size_t targetlen = strlen(target);

    if (out != NULL)
        memset(out, 0, sizeof(*out));

    if (namelen > NFS_MAXNAMLEN || targetlen > NFS_MAXPATHLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(dirfh->len);
    totlen += XDR_VARLEN(namelen);
    totlen += NFSV3_SATTR3_MODE_SIZE;
    totlen += XDR_VARLEN(targetlen);

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_SYMLINK);
    pt = buf + sizeof(struct rpc_call_hdr);

    pt = nfsv3_build_fh(pt, dirfh);
    pt = nfsv3_build_string(pt, name);

    /* Attributes */
    pt = nfsv3_build_sattr3_mode(pt, mode);

    pt = nfsv3_build_string(pt, target);
    (void)pt;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    /* Parse symlink result */
    if (out != NULL) {
        pt = buf + sizeof(struct rpc_nfsreply_hdr);
        end = buf + n;

        /* post_op_fh3 for symlink */
        if (pt + XDR_UNIT <= end) {
            value_follows = xdr_get_u32(pt);
            pt += XDR_UNIT;
            if (value_follows && pt + XDR_UNIT <= end) {
                uint32_t fhlen = xdr_get_u32(pt);
                pt += XDR_UNIT;
                if (fhlen <= NFS_FHSIZE_MAX && pt + XDR_ALIGN(fhlen) <= end) {
                    out->fh.len = fhlen;
                    memcpy(out->fh.data, pt, fhlen);
                    out->has_fh = 1;
                    pt += XDR_ALIGN(fhlen);
                }
            }
        }

        /* post_op_attr for symlink */
        if (pt + XDR_UNIT <= end) {
            value_follows = xdr_get_u32(pt);
            pt += XDR_UNIT;
            if (value_follows && pt + sizeof(struct nfsv3_fattr) <= end) {
                nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &out->attr);
                out->has_attr = 1;
                pt += sizeof(struct nfsv3_fattr);
            }
        }

        /* Directory wcc_data */
        /* pre_op_attr (skip) */
        if (pt + XDR_UNIT <= end) {
            value_follows = xdr_get_u32(pt);
            pt += XDR_UNIT;
            if (value_follows && pt + 24 <= end)
                pt += 24;
        }
        /* post_op_attr */
        if (pt + XDR_UNIT <= end) {
            value_follows = xdr_get_u32(pt);
            pt += XDR_UNIT;
            if (value_follows && pt + sizeof(struct nfsv3_fattr) <= end) {
                nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &out->dir_attr);
                out->has_dir_attr = 1;
            }
        }
    }

    return 0;
}

/*
 * NFSv3 MKDIR (Procedure 9)
 */
static int
nfsv3_mkdir_impl(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, uint32_t mode, struct nfs_create_res *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint32_t value_follows;
    uint8_t buf[RPC_BUFSIZE_LARGE];
    size_t totlen;
    uint8_t *pt;
    uint8_t *end;
    ssize_t n;
    uint32_t xid = rand();
    size_t namelen = strlen(name);

    if (namelen > NFS_MAXNAMLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(dirfh->len);
    totlen += XDR_VARLEN(namelen);
    totlen += NFSV3_SATTR3_MODE_SIZE;

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_MKDIR);
    pt = buf + sizeof(struct rpc_call_hdr);

    pt = nfsv3_build_fh(pt, dirfh);
    pt = nfsv3_build_string(pt, name);

    /* Attributes */
    pt = nfsv3_build_sattr3_mode(pt, mode);
    (void)pt;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    memset(out, 0, sizeof(*out));
    pt = buf + sizeof(struct rpc_nfsreply_hdr);
    end = buf + n;

    /* File handle (optional) */
    if (pt + XDR_UNIT > end) {
        errno = EBADMSG;
        return -1;
    }
    value_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;
    if (value_follows == 1) {
        pt = nfsv3_parse_fh(pt, end, &out->fh);
        if (pt == NULL) {
            errno = EBADMSG;
            return -1;
        }
        out->has_fh = 1;
    }

    /* Object attributes (optional) */
    pt = nfsv3_parse_post_op_attr(pt, end, &out->attr, &out->has_attr);
    if (pt == NULL) {
        errno = EBADMSG;
        return -1;
    }

    (void)pt; /* Silence unused warning - end of parsing */
    return 0;
}

/*
 * NFSv3 RMDIR (Procedure 13)
 */
static int
nfsv3_rmdir_impl(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, struct nfs_wcc_data *out)
{
    return nfsv3_unlink_common(ctx, dirfh, name, NFSV3_PROC_RMDIR, out);
}

/*
 * NFSv3 READDIR (Procedure 16)
 */
static int
nfsv3_readdir_impl(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_dir *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;

/* READDIR call footer: cookie(8) + cookieverf(8) + count(4) = 20 bytes */
#define READDIR_CALL_FOOTER_SIZE (8 + 8 + XDR_UNIT)

    uint8_t *buf;
    size_t bufsize = IOBUFSIZE * 2;
    size_t totlen;
    uint8_t *pt, *end;
    uint32_t value_follows;
    uint64_t verifier;
    uint64_t cookie;
    uint64_t prev_cookie;
    size_t prev_count;
    ssize_t n;
    uint32_t xid;

    nfs_dir_init(out);
    verifier = 0;
    cookie = 0;
    prev_cookie = 0;

    buf = malloc(bufsize);
    if (buf == NULL)
        return -1;

call_again:
    prev_count = out->count;
    xid = rand();
    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(fh->len);
    totlen += READDIR_CALL_FOOTER_SIZE;

    if (totlen > bufsize) {
        free(buf);
        errno = ENOBUFS;
        nfs_dir_free(out);
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_READDIR);
    pt = buf + sizeof(struct rpc_call_hdr);

    pt = nfsv3_build_fh(pt, fh);

    /*
     * Cookie and verifier: OPAQUE 8-byte values (RFC 1813).
     * WARNING: Do NOT byte-swap - these are echoed back exactly as received.
     */
    memcpy(pt, &cookie, sizeof(cookie));
    pt += 8;
    memcpy(pt, &verifier, sizeof(verifier));
    pt += 8;
    xdr_put_u32(pt, IOBUFSIZE);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0) {
        free(buf);
        nfs_dir_free(out);
        return -1;
    }

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, bufsize, xid)) < 0) {
        free(buf);
        nfs_dir_free(out);
        return -1;
    }

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY_FREE(ctx, reply, n, buf);

    NFS_CHECK_STATUS_EX(ctx, reply, { free(buf); nfs_dir_free(out); });

    pt = buf + sizeof(struct rpc_nfsreply_hdr);
    end = buf + n;

    /* Dir attributes (optional) - need 4 bytes for value_follows */
    if (pt + XDR_UNIT > end) {
        free(buf);
        errno = EBADMSG;
        nfs_dir_free(out);
        return -1;
    }
    value_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;
    if (value_follows) {
        if (pt + sizeof(struct nfsv3_fattr) > end) {
            free(buf);
            errno = EBADMSG;
            nfs_dir_free(out);
            return -1;
        }
        nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &out->dir_attr);
        out->has_dir_attr = 1;
        pt += sizeof(struct nfsv3_fattr);
    }

    /*
     * Cookie verifier: OPAQUE 8-byte value (RFC 1813).
     * WARNING: Do NOT byte-swap - store as-is to echo back in next request.
     */
    if (pt + 12 > end) {  /* verifier(8) + value_follows(4) */
        free(buf);
        errno = EBADMSG;
        nfs_dir_free(out);
        return -1;
    }
    memcpy(&verifier, pt, sizeof(verifier));
    pt += 8;

    /* Entries */
    value_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;

    while (value_follows) {
        struct nfs_dirent ent;
        uint32_t len, len_padded;

        /* Prevent unbounded allocation from malicious server */
        if (out->count >= NFS_READDIR_MAX_ENTRIES) {
            fprintf(stderr, "** Error: Too many directory entries (max %d)\n",
                NFS_READDIR_MAX_ENTRIES);
            free(buf);
            nfs_dir_free(out);
            errno = EOVERFLOW;
            return -1;
        }

        memset(&ent, 0, sizeof(ent));

        /* Need at least: fileid(8) + namelen(4) */
        if (pt + 12 > end) {
            free(buf);
            errno = EBADMSG;
            nfs_dir_free(out);
            return -1;
        }

        /* File ID (use memcpy for safe unaligned access) */
        memcpy(&ent.fileid, pt, sizeof(ent.fileid));
        ent.fileid = be64toh(ent.fileid);
        pt += 8;

        /* Name length */
        len = xdr_get_u32(pt);
        pt += XDR_UNIT;

        /* Validate name length BEFORE XDR_ALIGN to prevent overflow */
        if (len > NFS_MAXNAMLEN) {
            free(buf);
            errno = EBADMSG;
            nfs_dir_free(out);
            return -1;
        }
        len_padded = XDR_ALIGN(len);

        /* Need room for: name_data + cookie(8) + value_follows(4) */
        if (pt + len_padded + sizeof(uint64_t) + XDR_UNIT > end) {
            free(buf);
            errno = EBADMSG;
            nfs_dir_free(out);
            return -1;
        }

        memcpy(ent.name, pt, len);
        ent.name[len] = '\0';
        xdr_sanitize_string(ent.name);
        pt += len_padded;

        /*
         * Cookie: OPAQUE 8-byte value (RFC 1813).
         * WARNING: Do NOT byte-swap - used for pagination, echoed back as-is.
         */
        memcpy(&ent.cookie, pt, sizeof(ent.cookie));
        cookie = ent.cookie;
        pt += sizeof(uint64_t);

        if (nfs_dir_add(out, &ent) < 0) {
            free(buf);
            nfs_dir_free(out);
            return -1;
        }

        value_follows = xdr_get_u32(pt);
        pt += XDR_UNIT;
    }

    /* EOF - need 4 bytes */
    if (pt + XDR_UNIT > end) {
        free(buf);
        errno = EBADMSG;
        nfs_dir_free(out);
        return -1;
    }
    out->eof = xdr_get_u32(pt);

    if (!out->eof) {
        /*
         * Detect cookie stall from malicious server.
         * If we got entries but cookie didn't change, server is looping us.
         * If we got no entries and cookie didn't change, also stuck.
         */
        if (out->count > prev_count && cookie == prev_cookie) {
            /* Got entries but cookie unchanged - server is broken/malicious */
            free(buf);
            errno = ELOOP;
            nfs_dir_free(out);
            return -1;
        }
        if (out->count == prev_count) {
            /* Got no new entries - treat as stall */
            free(buf);
            errno = ELOOP;
            nfs_dir_free(out);
            return -1;
        }
        prev_cookie = cookie;
        goto call_again;
    }

    free(buf);
    return 0;
}

/*
 * NFSv3 READDIRPLUS (Procedure 17)
 *
 * RFC 1813 Section 3.3.17 - NFSPROC3_READDIRPLUS
 *
 * Returns entries with file handles and attributes (N+1 RPCs -> ~1 RPC).
 * Some servers may omit fh/attr for entries they can't provide efficiently.
 *
 * dircount: max bytes of directory data (names/cookies)
 * maxcount: max total reply size including attributes
 *
 * cookieverf: Server sets on first call, client echoes on subsequent.
 * If directory modified, server may return NFS3ERR_BAD_COOKIE.
 *
 * Note: READDIRPLUS may fail on very large directories due to UDP size.
 */
static int
nfsv3_readdirplus_impl(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_dir *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;

/* READDIRPLUS call footer: cookie(8) + verifier(8) + dircount(4) + maxcount(4) = 24 bytes */
#define READDIRPLUS_CALL_FOOTER_SIZE (8 + 8 + 2 * XDR_UNIT)
#define READDIRPLUS_BUFSIZE          (IOBUFSIZE * 10)

    uint8_t *buf;
    size_t totlen;
    uint8_t *pt, *end;
    uint32_t value_follows;
    uint64_t verifier;
    uint64_t cookie;
    uint64_t prev_cookie;
    size_t prev_count;
    ssize_t n;
    uint32_t xid;
    int ret = -1;

    nfs_dir_init(out);
    verifier = 0;
    cookie = 0;
    prev_cookie = 0;

    buf = malloc(READDIRPLUS_BUFSIZE);
    if (buf == NULL)
        return -1;

call_again:
    prev_count = out->count;
    xid = rand();
    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(fh->len);
    totlen += READDIRPLUS_CALL_FOOTER_SIZE;

    if (totlen > READDIRPLUS_BUFSIZE) {
        errno = ENOBUFS;
        goto cleanup;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_READDIRPLUS);
    pt = buf + sizeof(struct rpc_call_hdr);

    pt = nfsv3_build_fh(pt, fh);

    /*
     * Cookie and verifier: OPAQUE 8-byte values (RFC 1813).
     * WARNING: Do NOT byte-swap - these are echoed back exactly as received.
     */
    memcpy(pt, &cookie, sizeof(cookie));
    pt += 8;
    memcpy(pt, &verifier, sizeof(verifier));
    pt += 8;
    xdr_put_u32(pt, IOBUFSIZE / 2); /* dircount */
    pt += XDR_UNIT;
    xdr_put_u32(pt, IOBUFSIZE);     /* maxcount */

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        goto cleanup;

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf,
             READDIRPLUS_BUFSIZE, xid)) < 0)
        goto cleanup;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY_EX(ctx, reply, n, 1, { free(buf); nfs_dir_free(out); });

    NFS_CHECK_STATUS_EX(ctx, reply, { free(buf); nfs_dir_free(out); });

    pt = buf + sizeof(struct rpc_nfsreply_hdr);
    end = buf + n;

    /* Dir attributes (optional) - need 4 bytes for value_follows */
    if (pt + XDR_UNIT > end) {
        errno = EBADMSG;
        goto cleanup;
    }
    value_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;
    if (value_follows) {
        if (pt + sizeof(struct nfsv3_fattr) > end) {
            errno = EBADMSG;
            goto cleanup;
        }
        nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &out->dir_attr);
        out->has_dir_attr = 1;
        pt += sizeof(struct nfsv3_fattr);
    }

    /*
     * Cookie verifier: OPAQUE 8-byte value (RFC 1813).
     * WARNING: Do NOT byte-swap - store as-is to echo back in next request.
     */
    if (pt + 12 > end) {  /* verifier(8) + value_follows(4) */
        errno = EBADMSG;
        goto cleanup;
    }
    memcpy(&verifier, pt, sizeof(verifier));
    pt += 8;

    /* Entries */
    value_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;

    while (value_follows) {
        struct nfs_dirent ent;
        uint32_t len, len_padded;

        /* Prevent unbounded allocation from malicious server */
        if (out->count >= NFS_READDIR_MAX_ENTRIES) {
            fprintf(stderr, "** Error: Too many directory entries (max %d)\n",
                NFS_READDIR_MAX_ENTRIES);
            errno = EOVERFLOW;
            goto cleanup;
        }

        memset(&ent, 0, sizeof(ent));

        /* Need at least: fileid(8) + namelen(4) */
        if (pt + 12 > end) {
            errno = EBADMSG;
            goto cleanup;
        }

        /* File ID (use memcpy for safe unaligned access) */
        memcpy(&ent.fileid, pt, sizeof(ent.fileid));
        ent.fileid = be64toh(ent.fileid);
        pt += 8;

        /* Name length */
        len = xdr_get_u32(pt);
        pt += XDR_UNIT;

        /* Validate name length BEFORE XDR_ALIGN to prevent overflow */
        if (len > NFS_MAXNAMLEN) {
            errno = EBADMSG;
            goto cleanup;
        }
        len_padded = XDR_ALIGN(len);

        /* Bounds check after alignment: name_data + cookie(8) + value_follows(4) */
        if (pt + len_padded + sizeof(uint64_t) + XDR_UNIT > end) {
            errno = EBADMSG;
            goto cleanup;
        }

        memcpy(ent.name, pt, len);
        ent.name[len] = '\0';
        xdr_sanitize_string(ent.name);
        pt += len_padded;

        /*
         * Cookie: OPAQUE 8-byte value (RFC 1813).
         * WARNING: Do NOT byte-swap - used for pagination, echoed back as-is.
         */
        memcpy(&ent.cookie, pt, sizeof(ent.cookie));
        cookie = ent.cookie;
        pt += 8;

        /* Name attributes (optional) */
        if (pt + XDR_UNIT > end) {
            errno = EBADMSG;
            goto cleanup;
        }
        value_follows = xdr_get_u32(pt);
        pt += XDR_UNIT;
        if (value_follows == 1) {
            if (pt + sizeof(struct nfsv3_fattr) > end) {
                errno = EBADMSG;
                goto cleanup;
            }
            nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &ent.attr);
            ent.has_attr = 1;
            pt += sizeof(struct nfsv3_fattr);
        }

        /* File handle (optional) - need at least 4 bytes for value_follows */
        if (pt + XDR_UNIT > end) {
            errno = EBADMSG;
            goto cleanup;
        }
        value_follows = xdr_get_u32(pt);
        pt += XDR_UNIT;
        if (value_follows == 1) {
            /* Need 4 bytes for fh length */
            if (pt + XDR_UNIT > end) {
                errno = EBADMSG;
                goto cleanup;
            }
            len = xdr_get_u32(pt);
            pt += XDR_UNIT;

            /* Validate FH length BEFORE XDR_ALIGN to prevent overflow
             * Note: reject zero-length FH as invalid */
            if (len == 0 || len > NFS_FHSIZE_MAX) {
                errno = EBADMSG;
                goto cleanup;
            }
            len_padded = XDR_ALIGN(len);

            /* Check bounds after alignment */
            if (pt + len_padded > end) {
                errno = EBADMSG;
                goto cleanup;
            }

            nfs_fh_from_buf(&ent.fh, pt, len);
            ent.has_fh = 1;
            pt += len_padded;
        }

        if (nfs_dir_add(out, &ent) < 0)
            goto cleanup;

        /* Need 4 bytes for next value_follows */
        if (pt + XDR_UNIT > end) {
            errno = EBADMSG;
            goto cleanup;
        }
        value_follows = xdr_get_u32(pt);
        pt += XDR_UNIT;
    }

    /* EOF - need 4 bytes */
    if (pt + XDR_UNIT > end) {
        errno = EBADMSG;
        goto cleanup;
    }
    out->eof = xdr_get_u32(pt);

    if (!out->eof) {
        /* Detect malicious server returning same cookie forever */
        if (out->count > prev_count && cookie == prev_cookie) {
            errno = ELOOP;
            goto cleanup;
        }
        /* No new entries means we're stuck */
        if (out->count == prev_count) {
            errno = ELOOP;
            goto cleanup;
        }
        prev_cookie = cookie;
        goto call_again;
    }

    ret = 0;

cleanup:
    free(buf);
    if (ret < 0)
        nfs_dir_free(out);
    return ret;
}

/*
 * NFSv3 MKNOD (Procedure 11)
 *
 * RFC 1813 Section 3.3.11 - NFSPROC3_MKNOD
 *
 * Creates special files (no NFSv2 equivalent):
 *   NF3CHR (2)  - Character device (uses specdata3: major/minor)
 *   NF3BLK (3)  - Block device (uses specdata3: major/minor)
 *   NF3SOCK (5) - Unix domain socket (specdata ignored)
 *   NF3FIFO (6) - Named pipe/FIFO (specdata ignored)
 *
 * Creating device nodes typically requires root privileges on server.
 *
 * Status codes: NFS3_OK, NFS3ERR_ACCES, NFS3ERR_EXIST, NFS3ERR_NOSPC,
 *               NFS3ERR_DQUOT, NFS3ERR_ROFS, NFS3ERR_NOTSUPP
 */
static int
nfsv3_mknod_impl(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, int type, uint32_t mode,
    uint32_t major, uint32_t minor, struct nfs_create_res *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint32_t value_follows;
    uint8_t *buf;
    size_t bufsize = IOBUFSIZE * 2;
    size_t totlen;
    uint8_t *pt;
    uint8_t *end;
    ssize_t n;
    uint32_t xid = rand();
    size_t namelen = strlen(name);

    if (namelen > NFS_MAXNAMLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(dirfh->len);
    totlen += XDR_VARLEN(namelen);
    totlen += XDR_UNIT; /* type */
    totlen += NFSV3_SATTR3_MODE_SIZE;
    /* RFC 1813: major/minor (specdata3) only for CHR and BLK devices */
    if (type == NFS_FTYPE_CHR || type == NFS_FTYPE_BLK)
        totlen += XDR_UNIT + XDR_UNIT; /* major/minor */

    if (totlen > bufsize) {
        errno = ENOBUFS;
        return -1;
    }

    buf = malloc(bufsize);
    if (buf == NULL)
        return -1;

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_MKNOD);
    pt = buf + sizeof(struct rpc_call_hdr);

    pt = nfsv3_build_fh(pt, dirfh);
    pt = nfsv3_build_string(pt, name);

    /* Type */
    pt = xdr_build_u32(pt, type);

    /* Attributes */
    pt = nfsv3_build_sattr3_mode(pt, mode);

    /* RFC 1813: major/minor (specdata3) only for CHR and BLK devices */
    if (type == NFS_FTYPE_CHR || type == NFS_FTYPE_BLK) {
        pt = xdr_build_u32(pt, major);
        pt = xdr_build_u32(pt, minor);
    }
    (void)pt;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0) {
        free(buf);
        return -1;
    }

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, bufsize, xid)) < 0) {
        free(buf);
        return -1;
    }

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY_FREE(ctx, reply, n, buf);

    NFS_CHECK_STATUS_EX(ctx, reply, free(buf));

    memset(out, 0, sizeof(*out));
    pt = buf + sizeof(struct rpc_nfsreply_hdr);
    end = buf + n;

    /* File handle (optional) */
    if (pt + XDR_UNIT > end) {
        free(buf);
        errno = EBADMSG;
        return -1;
    }
    value_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;
    if (value_follows == 1) {
        pt = nfsv3_parse_fh(pt, end, &out->fh);
        if (pt == NULL) {
            free(buf);
            errno = EBADMSG;
            return -1;
        }
        out->has_fh = 1;
    }

    /* Object attributes (optional) */
    if (pt + XDR_UNIT > end) {
        free(buf);
        errno = EBADMSG;
        return -1;
    }
    value_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;
    if (value_follows == 1) {
        if (pt + sizeof(struct nfsv3_fattr) > end) {
            free(buf);
            errno = EBADMSG;
            return -1;
        }
        nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &out->attr);
        out->has_attr = 1;
    }

    free(buf);
    return 0;
}

/*
 * NFSv3 FSSTAT (Procedure 18)
 *
 * RFC 1813 Section 3.3.18 - NFSPROC3_FSSTAT
 *
 * Returns dynamic filesystem information (space usage, file counts).
 * Used for df-like operations.
 *
 * Status codes: NFS3_OK, NFS3ERR_IO, NFS3ERR_STALE, NFS3ERR_BADHANDLE,
 *               NFS3ERR_SERVERFAULT
 */
static int
nfsv3_fsstat_impl(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_fsstat_res *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint8_t buf[RPC_BUFSIZE_LARGE];
    size_t totlen;
    uint8_t *pt, *end;
    ssize_t n;
    uint32_t xid = rand();
    uint32_t value_follows;

    totlen = sizeof(struct rpc_call_hdr) + XDR_VARLEN(fh->len);

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_FSSTAT);
    pt = buf + sizeof(struct rpc_call_hdr);
    pt = nfsv3_build_fh(pt, fh);
    (void)pt;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    memset(out, 0, sizeof(*out));
    pt = buf + sizeof(struct rpc_nfsreply_hdr);
    end = buf + n;

    /* Post-op attributes (optional) */
    if (pt + XDR_UNIT > end)
        return 0;
    value_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;
    if (value_follows && pt + sizeof(struct nfsv3_fattr) <= end) {
        nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &out->attr);
        out->has_attr = 1;
        pt += sizeof(struct nfsv3_fattr);
    }

    /* FSSTAT3resok: tbytes, fbytes, abytes, tfiles, ffiles, afiles (6 uint64), invarsec (uint32) */
    if (pt + 6 * sizeof(uint64_t) + XDR_UNIT > end) {
        errno = EBADMSG;
        return -1;
    }

    out->tbytes = xdr_get_u64(pt);
    pt += 8;
    out->fbytes = xdr_get_u64(pt);
    pt += 8;
    out->abytes = xdr_get_u64(pt);
    pt += 8;
    out->tfiles = xdr_get_u64(pt);
    pt += 8;
    out->ffiles = xdr_get_u64(pt);
    pt += 8;
    out->afiles = xdr_get_u64(pt);
    pt += 8;
    out->invarsec = xdr_get_u32(pt);

    /* v3 doesn't use block-based values */
    out->bsize = 0;
    out->tsize = 0;
    out->blocks = 0;
    out->bfree = 0;
    out->bavail = 0;

    return 0;
}

/*
 * NFSv3 FSINFO (Procedure 19)
 *
 * RFC 1813 Section 3.3.19 - NFSPROC3_FSINFO
 *
 * Returns static filesystem information (max sizes, capabilities).
 * Used for client configuration (optimal read/write sizes).
 *
 * Status codes: NFS3_OK, NFS3ERR_STALE, NFS3ERR_BADHANDLE, NFS3ERR_SERVERFAULT
 */
static int
nfsv3_fsinfo_impl(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_fsinfo_res *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint8_t buf[RPC_BUFSIZE_LARGE];
    size_t totlen;
    uint8_t *pt, *end;
    ssize_t n;
    uint32_t xid = rand();
    uint32_t value_follows;

    totlen = sizeof(struct rpc_call_hdr) + XDR_VARLEN(fh->len);

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_FSINFO);
    pt = buf + sizeof(struct rpc_call_hdr);
    pt = nfsv3_build_fh(pt, fh);
    (void)pt;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    memset(out, 0, sizeof(*out));
    pt = buf + sizeof(struct rpc_nfsreply_hdr);
    end = buf + n;

    /* Post-op attributes (optional) */
    if (pt + XDR_UNIT > end)
        return 0;
    value_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;
    if (value_follows && pt + sizeof(struct nfsv3_fattr) <= end) {
        nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &out->attr);
        out->has_attr = 1;
        pt += sizeof(struct nfsv3_fattr);
    }

    /* FSINFO3resok: 7 * uint32 + size3 + time + uint32 = 7*4 + 8 + 8 + 4 = 48 bytes */
    if (pt + 48 > end) {
        errno = EBADMSG;
        return -1;
    }

    out->rtmax = xdr_get_u32(pt);
    pt += XDR_UNIT;
    out->rtpref = xdr_get_u32(pt);
    pt += XDR_UNIT;
    out->rtmult = xdr_get_u32(pt);
    pt += XDR_UNIT;
    out->wtmax = xdr_get_u32(pt);
    pt += XDR_UNIT;
    out->wtpref = xdr_get_u32(pt);
    pt += XDR_UNIT;
    out->wtmult = xdr_get_u32(pt);
    pt += XDR_UNIT;
    out->dtpref = xdr_get_u32(pt);
    pt += XDR_UNIT;

    /* maxfilesize (size3 = uint64) */
    out->maxfilesize = xdr_get_u64(pt);
    pt += 8;

    /* time_delta (nfstime3) */
    out->time_delta.sec = xdr_get_u32(pt);
    pt += XDR_UNIT;
    out->time_delta.nsec = xdr_get_u32(pt);
    pt += XDR_UNIT;

    /* properties */
    out->properties = xdr_get_u32(pt);

    return 0;
}

/*
 * NFSv3 ACCESS (Procedure 4)
 *
 * RFC 1813 Section 3.3.4 - NFSPROC3_ACCESS
 *
 * Checks access permissions for a file. More efficient than GETATTR
 * because server can check actual permissions (ACLs, security labels).
 *
 * Status codes: NFS3_OK, NFS3ERR_IO, NFS3ERR_STALE, NFS3ERR_BADHANDLE,
 *               NFS3ERR_SERVERFAULT
 */
static int
nfsv3_access_impl(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint32_t access_mask, struct nfs_access_res *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint8_t buf[RPC_BUFSIZE_LARGE];
    size_t totlen;
    uint8_t *pt, *end;
    ssize_t n;
    uint32_t xid = rand();
    uint32_t value_follows;

    totlen = sizeof(struct rpc_call_hdr) + XDR_VARLEN(fh->len) + XDR_UNIT;

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_ACCESS);
    pt = buf + sizeof(struct rpc_call_hdr);
    pt = nfsv3_build_fh(pt, fh);

    /* Access mask */
    pt = xdr_build_u32(pt, access_mask);
    (void)pt;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    memset(out, 0, sizeof(*out));
    pt = buf + sizeof(struct rpc_nfsreply_hdr);
    end = buf + n;

    /* Post-op attributes (optional) */
    if (pt + XDR_UNIT > end)
        return 0;
    value_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;
    if (value_follows && pt + sizeof(struct nfsv3_fattr) <= end) {
        nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &out->attr);
        out->has_attr = 1;
        pt += sizeof(struct nfsv3_fattr);
    }

    /* Access result */
    if (pt + XDR_UNIT > end) {
        errno = EBADMSG;
        return -1;
    }
    out->access = xdr_get_u32(pt);

    return 0;
}

/*
 * NFSv3 PATHCONF (Procedure 20)
 *
 * RFC 1813 Section 3.3.20 - NFSPROC3_PATHCONF
 *
 * Returns POSIX pathconf(2) information for a file.
 *
 * Status codes: NFS3_OK, NFS3ERR_STALE, NFS3ERR_BADHANDLE, NFS3ERR_SERVERFAULT
 */
static int
nfsv3_pathconf_impl(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_pathconf_res *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint8_t buf[RPC_BUFSIZE_LARGE];
    size_t totlen;
    uint8_t *pt, *end;
    ssize_t n;
    uint32_t xid = rand();
    uint32_t value_follows;

    totlen = sizeof(struct rpc_call_hdr) + XDR_VARLEN(fh->len);

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_PATHCONF);
    pt = buf + sizeof(struct rpc_call_hdr);
    pt = nfsv3_build_fh(pt, fh);
    (void)pt;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    memset(out, 0, sizeof(*out));
    pt = buf + sizeof(struct rpc_nfsreply_hdr);
    end = buf + n;

    /* Post-op attributes (optional) */
    if (pt + XDR_UNIT > end)
        return 0;
    value_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;
    if (value_follows && pt + sizeof(struct nfsv3_fattr) <= end) {
        nfsv3_parse_fattr((struct nfsv3_fattr *)pt, &out->attr);
        out->has_attr = 1;
        pt += sizeof(struct nfsv3_fattr);
    }

    /* PATHCONF3resok: linkmax, name_max, 4 bools */
    if (pt + 6 * XDR_UNIT > end) {
        errno = EBADMSG;
        return -1;
    }

    out->linkmax = xdr_get_u32(pt);
    pt += XDR_UNIT;
    out->name_max = xdr_get_u32(pt);
    pt += XDR_UNIT;
    out->no_trunc = xdr_get_u32(pt) != 0;
    pt += XDR_UNIT;
    out->chown_restricted = xdr_get_u32(pt) != 0;
    pt += XDR_UNIT;
    out->case_insensitive = xdr_get_u32(pt) != 0;
    pt += XDR_UNIT;
    out->case_preserving = xdr_get_u32(pt) != 0;

    return 0;
}

/*
 * NULL - NFSv3 connectivity test.
 *
 * RFC 1813 Section 3.3.1 - NFSPROC3_NULL (procedure 0)
 *
 * Does nothing. Used to test server availability and measure round-trip time.
 * Returns 0 on success, -1 on error.
 */
int
nfsv3_null(struct nfsctx *ctx)
{
    return rpc_simple_call(ctx, RPC_PROGRAM_NFS, NFS_VERSION_3,
        RPC_NFS_PROCEDURE_NULL, ctx->ports.nfsd,
        NULL, 0, NULL, 0, NULL);
}

/*
 * WRITE with stability mode - Same as nfsv3_write_impl but allows
 * caller to specify stability level.
 *
 * Returns 0 on success, -1 on error.
 */
int
nfsv3_write_stable(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint64_t offset, const uint8_t *data, uint32_t count,
    int stability, struct nfs_write_res *out)
{
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint8_t buf[RPC_BUFSIZE_SMALL];
    uint8_t *end;
    size_t totlen;
    uint8_t *pt;
    ssize_t n;
    uint32_t xid = rand();

    struct write_call_footer {
        uint64_t offset;
        uint32_t count;
        uint32_t stable;
        uint32_t datalen;
    } __attribute__((packed)) * footer;

    if (out != NULL)
        memset(out, 0, sizeof(*out));

    /* Check for XDR_ALIGN overflow before calculating total length */
    if (count > UINT32_MAX - (XDR_UNIT - 1)) {
        errno = EINVAL;
        return -1;
    }

    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(fh->len);
    totlen += sizeof(struct write_call_footer);
    totlen += XDR_ALIGN(count);

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0x00, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_WRITE);
    pt = buf + sizeof(struct rpc_call_hdr);

    pt = nfsv3_build_fh(pt, fh);

    footer = (struct write_call_footer *)pt;
    pt += sizeof(struct write_call_footer);
    footer->offset = htobe64(offset);
    footer->count = htonl(count);
    footer->stable = htonl(stability);
    footer->datalen = htonl(count);

    memcpy(pt, data, count);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    /* Parse response if caller wants it */
    if (out != NULL) {
        pt = buf + sizeof(struct rpc_nfsreply_hdr);
        end = buf + n;

        /* WCC data: pre_op_attr (skip) + post_op_attr */
        pt = nfsv3_parse_wcc_data(pt, end, &out->attr, &out->has_attr);
        if (pt == NULL)
            goto done;

        /* count + committed + verf */
        if (pt + XDR_UNIT + XDR_UNIT + sizeof(uint64_t) > end)
            goto done;
        out->count = xdr_get_u32(pt);
        pt += XDR_UNIT;
        out->committed = xdr_get_u32(pt);
        pt += XDR_UNIT;
        /*
         * Write verifier: OPAQUE 8-byte value (RFC 1813).
         * WARNING: Do NOT byte-swap - opaque values must be compared as raw bytes.
         */
        memcpy(&out->verifier, pt, sizeof(out->verifier));
    }

done:
    return 0;
}

/*
 * COMMIT - Commit cached data to stable storage.
 *
 * RFC 1813 Section 3.3.21 - NFSPROC3_COMMIT (procedure 21)
 *
 * Forces or flushes data previously written with UNSTABLE to stable
 * storage. The offset and count specify the range to commit; offset=0
 * and count=0 means commit the entire file.
 *
 * Returns a write verifier that changes if the server reboots. If the
 * verifier differs from what was returned by WRITE, the data may have
 * been lost and needs to be rewritten.
 *
 * Returns 0 on success, -1 on error.
 */
int
nfsv3_commit(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint64_t offset, uint32_t count, struct nfs_commit_res *out)
{
    uint8_t buf[RPC_BUFSIZE_LARGE];
    struct rpc_call_hdr *call;
    struct rpc_nfsreply_hdr *reply;
    uint8_t *pt, *end;
    size_t totlen;
    ssize_t n;
    uint32_t xid;

    if (out != NULL)
        memset(out, 0, sizeof(*out));

    xid = rand();
    print(V_TRACE, ctx, "NFS3 COMMIT XID 0x%08x offset=%lu count=%u\n",
        xid, (unsigned long)offset, count);

    /* Build request: RPC header + fh + offset(8) + count(4) */
    totlen = sizeof(struct rpc_call_hdr);
    totlen += XDR_VARLEN(fh->len);
    totlen += 8 + XDR_UNIT; /* offset + count */

    if (totlen > sizeof(buf)) {
        errno = ENOBUFS;
        return -1;
    }

    memset(buf, 0, totlen);
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, NFSV3_PROC_COMMIT);
    pt = buf + sizeof(struct rpc_call_hdr);

    /* File handle */
    pt = nfsv3_build_fh(pt, fh);

    /* offset (64-bit) */
    pt = xdr_build_u64(pt, offset);

    /* count (32-bit) */
    pt = xdr_build_u32(pt, count);
    (void)pt;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    memset(buf, 0, sizeof(buf));
    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd,
             buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    /* Parse response if caller wants it */
    if (out != NULL) {
        pt = buf + sizeof(struct rpc_nfsreply_hdr);
        end = buf + n;

        /* WCC data: pre_op_attr (skip) + post_op_attr */
        pt = nfsv3_parse_wcc_data(pt, end, &out->attr, &out->has_attr);
        if (pt == NULL)
            goto done;

        /*
         * Write verifier: OPAQUE 8-byte value (RFC 1813).
         * WARNING: Do NOT byte-swap - opaque values must be compared as raw bytes.
         */
        if (pt + 8 > end)
            goto done;
        memcpy(&out->verifier, pt, sizeof(out->verifier));
    }

done:
    return 0;
}

/* NFSv3 operations table */
struct nfs_ops nfsv3_unified_ops = {
    .getattr = nfsv3_getattr_impl,
    .setattr = nfsv3_setattr_impl,
    .lookup = nfsv3_lookup_impl,
    .readlink = nfsv3_readlink_impl,
    .read = nfsv3_read_impl,
    .write = nfsv3_write_impl,
    .create = nfsv3_create_impl,
    .remove = nfsv3_remove_impl,
    .rename = nfsv3_rename_impl,
    .link = nfsv3_link_impl,
    .symlink = nfsv3_symlink_impl,
    .mkdir = nfsv3_mkdir_impl,
    .rmdir = nfsv3_rmdir_impl,
    .readdir = nfsv3_readdir_impl,
    .readdirplus = nfsv3_readdirplus_impl,
    .mknod = nfsv3_mknod_impl,
    .statfs = nfsv3_fsstat_impl,
    .fsinfo = nfsv3_fsinfo_impl,
    .access = nfsv3_access_impl,
    .pathconf = nfsv3_pathconf_impl,
};
