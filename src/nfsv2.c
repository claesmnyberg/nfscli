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
 * nfsv2.c - NFSv2 protocol implementation (RFC 1094)
 *
 * Key characteristics:
 * - Fixed 32-byte file handles
 * - 32-bit offsets and sizes
 * - Microsecond timestamps
 */

#include <stdlib.h>
#include <unistd.h>

#include "nfs_ops.h"
#include "nfscli.h"
#include "nfsv2.h"
#include "print.h"
#include "rpc.h"

/*
 * Parse NFSv2 fattr into common nfs_attr structure.
 *
 * RFC 1094 Section 2.3.4 - fattr structure
 *
 * NFSv2 limitations vs NFSv3:
 * - size is 32-bit (max 4GB files)
 * - timestamps use microseconds (not nanoseconds)
 * - rdev is a single 32-bit value (not separate major/minor)
 * - fileid is 32-bit (can overflow on modern filesystems)
 *
 * The 'used' field is calculated from blocks * blocksize since
 * NFSv2 doesn't have an explicit 'used' field like NFSv3.
 */
static void
nfsv2_parse_fattr(const struct nfsv2_fattr *wire, struct nfs_attr *out)
{
    uint32_t blocks, blocksize;

    out->type = ntohl(wire->type);
    out->mode = ntohl(wire->mode);
    out->nlink = ntohl(wire->nlink);
    out->uid = ntohl(wire->uid);
    out->gid = ntohl(wire->gid);
    out->size = ntohl(wire->size);
    /* Avoid multiplication overflow and division by zero */
    blocks = ntohl(wire->blocks);
    blocksize = ntohl(wire->blocksize);
    if (blocksize == 0) {
        out->used = 0;
    } else {
        out->used = (uint64_t)blocks * (uint64_t)blocksize;
    }
    out->rdev = ntohl(wire->rdev);
    out->fsid = ntohl(wire->fsid);
    out->fileid = ntohl(wire->fileid);
    out->atime.sec = ntohl(wire->atime.seconds);
    out->atime.nsec = (ntohl(wire->atime.useconds) % 1000000) * 1000; /* usec -> nsec */
    out->mtime.sec = ntohl(wire->mtime.seconds);
    out->mtime.nsec = (ntohl(wire->mtime.useconds) % 1000000) * 1000;
    out->ctime.sec = ntohl(wire->ctime.seconds);
    out->ctime.nsec = (ntohl(wire->ctime.useconds) % 1000000) * 1000;
}

/*
 * Build NFSv2 sattr from common nfs_sattr structure.
 *
 * RFC 1094 Section 2.3.5 - sattr structure
 *
 * Setting a field to -1 (0xFFFFFFFF) means "don't change".
 * This differs from NFSv3 which uses an explicit flag for each field.
 * NFSv2 sattr cannot set atime/mtime to specific values; it can only
 * set them to "now" (by setting to non-negative values other than -1).
 */
static void
nfsv2_build_sattr(struct nfsv2_sattr *wire, const struct nfs_sattr *sattr)
{
    /* Start with all fields set to "don't change" */
    memset(wire, 0xff, sizeof(*wire));

    if (sattr->set_mode)
        wire->mode = htonl(sattr->mode);

    if (sattr->set_uid)
        wire->uid = htonl(sattr->uid);

    if (sattr->set_gid)
        wire->gid = htonl(sattr->gid);

    if (sattr->set_size)
        wire->size = htonl((uint32_t)sattr->size); /* v2: 32-bit only */

    /* NFSv2 time: any non-0xFFFFFFFF value means "set to now" */
    if (sattr->set_atime) {
        wire->atime.seconds = htonl(sattr->atime.sec);
        wire->atime.useconds = htonl(sattr->atime.nsec / 1000);
    }

    if (sattr->set_mtime) {
        wire->mtime.seconds = htonl(sattr->mtime.sec);
        wire->mtime.useconds = htonl(sattr->mtime.nsec / 1000);
    }
}

/*
 * Build NFSv2 sattr for mode-only operations (create, symlink, mkdir).
 * These don't need the full nfs_sattr structure.
 */
static void
nfsv2_build_sattr_mode(struct nfsv2_sattr *wire, uint32_t mode)
{
    memset(wire, 0xff, sizeof(*wire)); /* -1 means "don't change" */
    wire->mode = htonl(mode);
}

/*
 * GETATTR - Get file attributes.
 *
 * RFC 1094 Section 2.3.5 - NFSPROC_GETATTR (procedure 1)
 *
 * Returns all file attributes. Unlike stat(2), this does NOT follow
 * symbolic links - attributes of the symlink itself are returned.
 *
 * Status codes: NFS_OK, NFSERR_STALE, NFSERR_IO
 */
static int
nfsv2_getattr_impl(struct nfsctx *ctx, const uint8_t fh[NFSV2_FHSIZE],
    struct nfs_attr *out)
{
    struct {
        struct rpc_call_hdr hdr;
        uint8_t fh[NFSV2_FHSIZE];
    } __attribute__((packed)) req;

    struct {
        struct rpc_nfsreply_hdr hdr;
        struct nfsv2_fattr attr;
    } __attribute__((packed)) reply;

    uint32_t xid;
    ssize_t n;

    xid = rand();
    print(V_TRACE, ctx, "NFS2 GETATTR XID 0x%08x\n", xid);

    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req.hdr, RPC_PROGRAM_NFS, 2, NFSV2_PROC_GETATTR);
    memcpy(req.fh, fh, NFSV2_FHSIZE);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, (uint8_t *)&req, sizeof(req)) < 0)
        return -1;

    memset(&reply, 0, sizeof(reply));
    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, (uint8_t *)&reply, sizeof(reply), xid)) < 0)
        return -1;

    RPC_CHECK_REPLY(ctx, &reply.hdr, n);

    NFS_CHECK_STATUS(ctx, &reply.hdr);

    nfsv2_parse_fattr(&reply.attr, out);
    return 0;
}

/*
 * SETATTR - Set file attributes.
 *
 * RFC 1094 Section 2.3.6 - NFSPROC_SETATTR (procedure 2)
 *
 * Sets file attributes. Not atomic - may partially succeed on error.
 * Setting size to 0 truncates the file. Only permission bits in mode
 * are used (file type bits are ignored).
 *
 * Status codes: NFS_OK, NFSERR_PERM, NFSERR_IO, NFSERR_ACCES,
 *               NFSERR_ISDIR (size!=0 on dir), NFSERR_ROFS
 */
static int
nfsv2_setattr_impl(struct nfsctx *ctx, const uint8_t fh[NFSV2_FHSIZE],
    const struct nfs_sattr *sattr, struct nfs_attr *out)
{
    struct {
        struct rpc_call_hdr hdr;
        uint8_t fh[NFSV2_FHSIZE];
        struct nfsv2_sattr attr;
    } __attribute__((packed)) req;

    struct {
        struct rpc_nfsreply_hdr hdr;
        struct nfsv2_fattr attr;
    } __attribute__((packed)) reply;

    uint32_t xid;
    ssize_t n;

    /* NFSv2 only supports 32-bit file sizes */
    if (sattr->set_size && sattr->size > UINT32_MAX) {
        fprintf(stderr, "** Error: NFSv2 does not support files > 4GB\n");
        errno = EFBIG;
        return -1;
    }

    xid = rand();
    print(V_TRACE, ctx, "NFS2 SETATTR XID 0x%08x\n", xid);

    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req.hdr, RPC_PROGRAM_NFS, 2, NFSV2_PROC_SETATTR);
    memcpy(req.fh, fh, NFSV2_FHSIZE);
    nfsv2_build_sattr(&req.attr, sattr);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, (uint8_t *)&req, sizeof(req)) < 0)
        return -1;

    memset(&reply, 0, sizeof(reply));
    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, (uint8_t *)&reply, sizeof(reply), xid)) < 0)
        return -1;

    RPC_CHECK_REPLY(ctx, &reply.hdr, n);

    NFS_CHECK_STATUS(ctx, &reply.hdr);

    /* Return the new attributes if requested */
    if (out != NULL)
        nfsv2_parse_fattr(&reply.attr, out);

    return 0;
}

/*
 * LOOKUP - Look up file name.
 *
 * RFC 1094 Section 2.3.7 - NFSPROC_LOOKUP (procedure 4)
 *
 * Searches a directory for a name and returns the file handle.
 * Does NOT follow symlinks - returns the symlink's own handle.
 * Name must not contain '/' characters.
 *
 * Looking up "." returns dirfh itself. Looking up ".." returns
 * the parent directory (or dirfh at filesystem root).
 *
 * Status codes: NFS_OK, NFSERR_NOENT, NFSERR_ACCES, NFSERR_NOTDIR,
 *               NFSERR_NAMETOOLONG, NFSERR_STALE
 */
static int
nfsv2_lookup_impl(struct nfsctx *ctx, const uint8_t dirfh[NFSV2_FHSIZE],
    const char *name, struct nfs_lookup_res *out)
{
    struct {
        struct rpc_call_hdr hdr;
        uint8_t fh[NFSV2_FHSIZE];
        uint32_t namelen;
    } __attribute__((packed)) req;

    uint8_t buf[1024];
    struct rpc_nfsreply_hdr *reply;
    uint8_t *reply_fh;
    struct nfsv2_fattr *reply_attr;
    size_t namelen, totlen;
    uint32_t xid;
    ssize_t n;

    namelen = strlen(name);
    if (namelen > NFS_MAXNAMLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /* Build request: fixed header + variable name */
    totlen = sizeof(req) + XDR_ALIGN(namelen);
    if (totlen > sizeof(buf)) {
        errno = ENOMEM;
        return -1;
    }

    xid = rand();
    print(V_TRACE, ctx, "NFS2 LOOKUP XID 0x%08x\n", xid);

    memset(buf, 0, sizeof(buf));
    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req.hdr, RPC_PROGRAM_NFS, 2, NFSV2_PROC_LOOKUP);
    memcpy(req.fh, dirfh, NFSV2_FHSIZE);
    req.namelen = htonl(namelen);

    memcpy(buf, &req, sizeof(req));
    /* Additional buffer bounds check (namelen already validated against NFS_MAXNAMLEN) */
    if (sizeof(req) + namelen > sizeof(buf)) {
        errno = ENOMEM;
        return -1;
    }
    memcpy(buf + sizeof(req), name, namelen);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    memset(buf, 0, sizeof(buf));
    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    /* Parse result - avoid packed struct for alignment safety */
    reply_fh = buf + sizeof(struct rpc_nfsreply_hdr);
    reply_attr = (struct nfsv2_fattr *)(reply_fh + NFSV2_FHSIZE);

    memset(out, 0, sizeof(*out));
    nfs_fh_from_buf(&out->fh, reply_fh, NFSV2_FHSIZE);
    nfsv2_parse_fattr(reply_attr, &out->obj_attr);
    out->has_obj_attr = 1;
    out->has_dir_attr = 0; /* v2 doesn't return dir attrs */

    return 0;
}

/*
 * READLINK - Read symbolic link.
 *
 * RFC 1094 Section 2.3.9 - NFSPROC_READLINK (procedure 5)
 *
 * Returns the target path stored in the symbolic link. The path
 * is NOT validated - may point to non-existent file or be relative.
 * Max path length is NFS_MAXPATHLEN (1024 bytes).
 *
 * Status codes: NFS_OK, NFSERR_STALE, NFSERR_IO
 *               (Note: NFSERR_INVAL if fh is not a symlink)
 */
static int
nfsv2_readlink_impl(struct nfsctx *ctx, const uint8_t fh[NFSV2_FHSIZE],
    struct nfs_readlink_res *out)
{
    struct {
        struct rpc_call_hdr hdr;
        uint8_t fh[NFSV2_FHSIZE];
    } __attribute__((packed)) req;

    uint8_t replybuf[2048];
    struct rpc_nfsreply_hdr *reply;
    uint8_t *pt, *end;
    uint32_t xid, len;
    ssize_t n;

    xid = rand();
    print(V_TRACE, ctx, "NFS2 READLINK XID 0x%08x\n", xid);

    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req.hdr, RPC_PROGRAM_NFS, 2, NFSV2_PROC_READLINK);
    memcpy(req.fh, fh, NFSV2_FHSIZE);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, (uint8_t *)&req, sizeof(req)) < 0)
        return -1;

    memset(replybuf, 0, sizeof(replybuf));
    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, replybuf, sizeof(replybuf), xid)) < 0)
        return -1;

    reply = (struct rpc_nfsreply_hdr *)replybuf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    pt = replybuf + sizeof(struct rpc_nfsreply_hdr);
    end = replybuf + n;

    /* Need at least 4 bytes for length field */
    if (pt + XDR_UNIT > end) {
        errno = EBADMSG;
        return -1;
    }

    len = xdr_get_u32(pt);
    pt += XDR_UNIT;

    /* Validate path length (buffer is NFS_MAXPATHLEN + 1) */
    if (len > NFS_MAXPATHLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /* Verify we have enough data for the path */
    if (pt + len > end) {
        errno = EBADMSG;
        return -1;
    }

    memset(out->target, 0, sizeof(out->target));
    memcpy(out->target, pt, len);
    xdr_sanitize_string(out->target);

    return 0;
}

/*
 * READ - Read from file.
 *
 * RFC 1094 Section 2.3.10 - NFSPROC_READ (procedure 6)
 *
 * Reads data starting at offset. NFSv2 uses 32-bit offsets (max 4GB).
 * The 'totalcount' field is unused and should be 0 (RFC 1094).
 * Actual bytes returned may be less than count (server limit or EOF).
 *
 * NFSv2 has no explicit EOF field - must infer EOF when returned
 * count < requested count or count == 0.
 *
 * Status codes: NFS_OK, NFSERR_IO, NFSERR_ACCES, NFSERR_STALE
 *               (NFSERR_ISDIR if attempting to read a directory)
 */
static int
nfsv2_read_impl(struct nfsctx *ctx, const uint8_t fh[NFSV2_FHSIZE],
    uint32_t offset, uint32_t count, struct nfs_read_res *out)
{
    struct {
        struct rpc_call_hdr hdr;
        uint8_t fh[NFSV2_FHSIZE];
        uint32_t offset;
        uint32_t count;
        uint32_t totalcount; /* unused per RFC 1094 */
    } __attribute__((packed)) req;

    uint8_t *replybuf;
    struct rpc_nfsreply_hdr *reply;
    uint8_t *pt;
    uint8_t *end;
    uint32_t xid, datalen;
    ssize_t n;
    size_t bufsize;
    size_t overhead;

    /*
     * Calculate buffer size with overflow protection.
     * NFSv2 READ reply: rpc_nfsreply_hdr + fattr + data_len(4) + data
     */
    overhead = sizeof(struct rpc_nfsreply_hdr) + sizeof(struct nfsv2_fattr) + XDR_UNIT; /* data length field */
    if (count > SIZE_MAX - overhead) {
        errno = EINVAL;
        return -1;
    }
    bufsize = overhead + count;
    replybuf = malloc(bufsize);
    if (replybuf == NULL)
        return -1;

    xid = rand();
    print(V_TRACE, ctx, "NFS2 READ XID 0x%08x\n", xid);

    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req.hdr, RPC_PROGRAM_NFS, 2, NFSV2_PROC_READ);
    memcpy(req.fh, fh, NFSV2_FHSIZE);
    req.offset = htonl(offset);
    req.count = htonl(count);
    req.totalcount = 0;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, (uint8_t *)&req, sizeof(req)) < 0) {
        free(replybuf);
        return -1;
    }

    memset(replybuf, 0, bufsize);
    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, replybuf, bufsize, xid)) < 0) {
        free(replybuf);
        return -1;
    }

    reply = (struct rpc_nfsreply_hdr *)replybuf;
    RPC_CHECK_REPLY(ctx, reply, n);

    NFS_CHECK_STATUS_EX(ctx, reply, free(replybuf));

    /* Parse header and fattr */
    pt = replybuf + sizeof(struct rpc_nfsreply_hdr);
    end = replybuf + n;

    /* Parse file attributes */
    if (pt + sizeof(struct nfsv2_fattr) > end) {
        free(replybuf);
        errno = EIO;
        return -1;
    }
    nfsv2_parse_fattr((struct nfsv2_fattr *)pt, &out->attr);
    out->has_attr = 1;
    pt += sizeof(struct nfsv2_fattr);

    /* Read data length */
    if (pt + XDR_UNIT > end) {
        free(replybuf);
        errno = EIO;
        return -1;
    }
    datalen = xdr_get_u32(pt);
    pt += XDR_UNIT;

    /* Validate datalen does not exceed requested count (RFC 1094 semantics) */
    if (datalen > count) {
        free(replybuf);
        errno = EIO;
        return -1;
    }

    /* Validate data fits (use subtraction to avoid pointer overflow) */
    if (datalen > (size_t)(end - pt)) {
        free(replybuf);
        errno = EIO;
        return -1;
    }

    out->data = pt;
    out->count = datalen;
    /*
     * NFSv2 READ reply has no explicit EOF field (unlike v3).
     * Infer EOF if we got less data than requested - caller should
     * also check for zero-length reads as a more reliable indicator.
     */
    out->eof = (datalen < count) ? 1 : 0;
    out->buf = replybuf; /* caller must free */

    return 0;
}

/*
 * WRITE - Write to file.
 *
 * RFC 1094 Section 2.3.11 - NFSPROC_WRITE (procedure 8)
 *
 * Writes data starting at offset. NFSv2 uses 32-bit offsets (max 4GB).
 * The 'beginoffset' and 'totalcount' fields are unused (RFC 1094).
 *
 * NFSv2 has no stability modes - all writes are synchronous (FILE_SYNC
 * equivalent). Server MUST commit data to stable storage before reply.
 * This makes NFSv2 writes slower than NFSv3 UNSTABLE writes but safer.
 *
 * NFSv2 does not return a write count - success means all data written.
 *
 * Status codes: NFS_OK, NFSERR_IO, NFSERR_ACCES, NFSERR_NOSPC,
 *               NFSERR_ROFS, NFSERR_STALE
 */
static int
nfsv2_write_impl(struct nfsctx *ctx, const uint8_t fh[NFSV2_FHSIZE],
    uint32_t offset, const uint8_t *data, uint32_t count,
    struct nfs_write_res *out)
{
    struct {
        struct rpc_call_hdr hdr;
        uint8_t fh[NFSV2_FHSIZE];
        uint32_t beginoffset; /* unused per RFC 1094 */
        uint32_t offset;
        uint32_t totalcount;  /* unused per RFC 1094 */
        uint32_t count;
    } __attribute__((packed)) req;

    struct {
        struct rpc_nfsreply_hdr hdr;
        struct nfsv2_fattr attr;
    } __attribute__((packed)) reply;

    uint8_t *buf;
    size_t totlen;
    uint32_t xid;
    ssize_t n;

    if (out != NULL)
        memset(out, 0, sizeof(*out));

    /* Check for XDR_ALIGN overflow before calculating total length */
    if (count > UINT32_MAX - (XDR_UNIT - 1)) {
        errno = EINVAL;
        return -1;
    }

    /* Build request: fixed header + variable data */
    totlen = sizeof(req) + XDR_ALIGN(count);
    buf = malloc(totlen);
    if (buf == NULL)
        return -1;

    xid = rand();
    print(V_TRACE, ctx, "NFS2 WRITE XID 0x%08x\n", xid);

    memset(buf, 0, totlen);
    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req.hdr, RPC_PROGRAM_NFS, 2, NFSV2_PROC_WRITE);
    memcpy(req.fh, fh, NFSV2_FHSIZE);
    req.beginoffset = 0;
    req.offset = htonl(offset);
    req.totalcount = 0;
    req.count = htonl(count);

    memcpy(buf, &req, sizeof(req));
    memcpy(buf + sizeof(req), data, count);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0) {
        free(buf);
        return -1;
    }
    free(buf);

    memset(&reply, 0, sizeof(reply));
    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, (uint8_t *)&reply, sizeof(reply), xid)) < 0)
        return -1;

    RPC_CHECK_REPLY(ctx, &reply.hdr, n);

    NFS_CHECK_STATUS(ctx, &reply.hdr);

    /* Parse response if caller wants it */
    if (out != NULL) {
        nfsv2_parse_fattr(&reply.attr, &out->attr);
        out->has_attr = 1;
        out->count = count;             /* v2 doesn't return count, assume all written */
        out->committed = NFS_FILE_SYNC; /* v2 is always FILE_SYNC equivalent */
    }

    return 0;
}

/*
 * CREATE - Create a file.
 *
 * RFC 1094 Section 2.3.12 - NFSPROC_CREATE (procedure 9)
 *
 * Creates a regular file. If file exists, behavior is server-dependent:
 * most servers truncate the file (like O_CREAT|O_TRUNC). This differs
 * from NFSv3 which has explicit UNCHECKED/GUARDED/EXCLUSIVE modes.
 *
 * Returns file handle and attributes of the new file.
 *
 * Status codes: NFS_OK, NFSERR_IO, NFSERR_ACCES, NFSERR_EXIST,
 *               NFSERR_NOSPC, NFSERR_ROFS, NFSERR_NAMETOOLONG
 */
static int
nfsv2_create_impl(struct nfsctx *ctx, const uint8_t dirfh[NFSV2_FHSIZE],
    const char *name, uint32_t mode, struct nfs_create_res *out)
{
    struct {
        struct rpc_call_hdr hdr;
        uint8_t fh[NFSV2_FHSIZE];
        uint32_t namelen;
    } __attribute__((packed)) req;

    struct {
        struct rpc_reply r;
        struct rpc_verifier v;
        uint32_t accept_state;
        uint32_t status;
        uint8_t fh[NFSV2_FHSIZE];
        struct nfsv2_fattr attr;
    } __attribute__((packed)) * reply;

    struct nfsv2_sattr sattr;
    uint8_t buf[1024];
    size_t namelen, totlen, name_padded;
    uint32_t xid;
    ssize_t n;

    namelen = strlen(name);
    if (namelen > NFS_MAXNAMLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /* Build request: fixed header + variable name + fixed sattr */
    name_padded = XDR_ALIGN(namelen);
    totlen = sizeof(req) + name_padded + sizeof(sattr);
    if (totlen > sizeof(buf)) {
        errno = ENOMEM;
        return -1;
    }

    xid = rand();
    print(V_TRACE, ctx, "NFS2 CREATE XID 0x%08x\n", xid);

    memset(buf, 0, sizeof(buf));
    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req.hdr, RPC_PROGRAM_NFS, 2, NFSV2_PROC_CREATE);
    memcpy(req.fh, dirfh, NFSV2_FHSIZE);
    req.namelen = htonl(namelen);

    nfsv2_build_sattr_mode(&sattr, mode);

    memcpy(buf, &req, sizeof(req));
    memcpy(buf + sizeof(req), name, namelen);
    memcpy(buf + sizeof(req) + name_padded, &sattr, sizeof(sattr));

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    memset(buf, 0, sizeof(buf));
    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (void *)buf;
    RPC_CHECK_REPLY(ctx, (struct rpc_reply_hdr *)reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    /* Parse result */
    memset(out, 0, sizeof(*out));
    nfs_fh_from_buf(&out->fh, reply->fh, NFSV2_FHSIZE);
    nfsv2_parse_fattr(&reply->attr, &out->attr);
    out->has_fh = 1;
    out->has_attr = 1;

    return 0;
}

/*
 * Common implementation for REMOVE and RMDIR.
 *
 * RFC 1094 Section 2.3.13 (REMOVE) and 2.3.18 (RMDIR)
 *
 * Both procedures have identical wire format - only procedure number differs.
 * REMOVE is for files; RMDIR is for directories.
 *
 * REMOVE status: NFS_OK, NFSERR_NOENT, NFSERR_ACCES, NFSERR_IO,
 *                NFSERR_ROFS, NFSERR_ISDIR
 * RMDIR status: NFS_OK, NFSERR_NOENT, NFSERR_ACCES, NFSERR_IO,
 *               NFSERR_ROFS, NFSERR_EXIST (dir not empty), NFSERR_NOTDIR
 */
static int
nfsv2_unlink_common(struct nfsctx *ctx, const uint8_t dirfh[NFSV2_FHSIZE],
    const char *name, uint32_t proc)
{
    struct {
        struct rpc_call_hdr hdr;
        uint8_t fh[NFSV2_FHSIZE];
        uint32_t namelen;
    } __attribute__((packed)) req;

    uint8_t buf[512];
    struct rpc_reply_hdr *reply;
    size_t namelen, totlen;
    uint32_t xid;
    ssize_t n;

    namelen = strlen(name);
    if (namelen > NFS_MAXNAMLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /* Build request: fixed header + variable name */
    totlen = sizeof(req) + XDR_ALIGN(namelen);
    if (totlen > sizeof(buf)) {
        errno = ENOMEM;
        return -1;
    }

    xid = rand();
    print(V_TRACE, ctx, "NFS2 UNLINK XID 0x%08x\n", xid);

    memset(buf, 0, sizeof(buf));
    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req.hdr, RPC_PROGRAM_NFS, 2, proc);
    memcpy(req.fh, dirfh, NFSV2_FHSIZE);
    req.namelen = htonl(namelen);

    memcpy(buf, &req, sizeof(req));
    memcpy(buf + sizeof(req), name, namelen);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    memset(buf, 0, sizeof(buf));
    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_reply_hdr *)buf;
    RPC_CHECK_EMPTY_REPLY(ctx, reply, n);

    return 0;
}

/*
 * REMOVE - Remove a file
 */
static int
nfsv2_remove_impl(struct nfsctx *ctx, const uint8_t dirfh[NFSV2_FHSIZE],
    const char *name)
{
    return nfsv2_unlink_common(ctx, dirfh, name, NFSV2_PROC_REMOVE);
}

/*
 * RENAME - Rename a file.
 *
 * RFC 1094 Section 2.3.14 - NFSPROC_RENAME (procedure 11)
 *
 * Atomically renames a file. If target exists, it is removed first.
 * Renaming "." or ".." is undefined behavior.
 *
 * Unlike NFSv3, NFSv2 does not define NFSERR_XDEV for cross-filesystem
 * renames, but servers typically return NFSERR_ACCES or NFSERR_IO.
 *
 * Status codes: NFS_OK, NFSERR_NOENT, NFSERR_ACCES, NFSERR_IO,
 *               NFSERR_ROFS, NFSERR_EXIST (if target is non-empty dir)
 */
static int
nfsv2_rename_impl(struct nfsctx *ctx,
    const uint8_t srcfh[NFSV2_FHSIZE], const char *srcname,
    const uint8_t dstfh[NFSV2_FHSIZE], const char *dstname)
{
    uint8_t buf[1024];
    struct rpc_call_hdr *call;
    struct rpc_reply_hdr *reply;
    uint8_t *pt;
    size_t srclen, dstlen, totlen;
    uint32_t xid;
    ssize_t n;

    srclen = strlen(srcname);
    dstlen = strlen(dstname);

    if (srclen > NFS_MAXNAMLEN || dstlen > NFS_MAXNAMLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    xid = rand();
    print(V_TRACE, ctx, "NFS2 RENAME XID 0x%08x\n", xid);

    totlen = sizeof(struct rpc_call_hdr) +
        NFSV2_FHSIZE + XDR_VARLEN(srclen) +
        NFSV2_FHSIZE + XDR_VARLEN(dstlen);

    if (totlen > sizeof(buf)) {
        errno = ENOMEM;
        return -1;
    }

    memset(buf, 0, sizeof(buf));
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 2, NFSV2_PROC_RENAME);

    pt = buf + sizeof(struct rpc_call_hdr);

    /* Source */
    memcpy(pt, srcfh, NFSV2_FHSIZE);
    pt += NFSV2_FHSIZE;
    pt = xdr_build_u32(pt, srclen);
    memcpy(pt, srcname, srclen);
    pt += XDR_ALIGN(srclen);

    /* Destination */
    memcpy(pt, dstfh, NFSV2_FHSIZE);
    pt += NFSV2_FHSIZE;
    pt = xdr_build_u32(pt, dstlen);
    memcpy(pt, dstname, dstlen);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    memset(buf, 0, sizeof(buf));
    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_reply_hdr *)buf;
    RPC_CHECK_EMPTY_REPLY(ctx, reply, n);

    return 0;
}

/*
 * LINK - Create hard link.
 *
 * RFC 1094 Section 2.3.15 - NFSPROC_LINK (procedure 12)
 *
 * Creates a new name for an existing file (hard link). Both file handle
 * and target directory must be on the same filesystem. Hard links to
 * directories are prohibited.
 *
 * Status codes: NFS_OK, NFSERR_IO, NFSERR_ACCES, NFSERR_EXIST,
 *               NFSERR_ISDIR (linking to directory), NFSERR_ROFS,
 *               NFSERR_NAMETOOLONG
 *               (Note: NFSERR_XDEV not defined in v2; cross-fs returns IO)
 */
static int
nfsv2_link_impl(struct nfsctx *ctx,
    const uint8_t fh[NFSV2_FHSIZE],
    const uint8_t dirfh[NFSV2_FHSIZE],
    const char *name)
{
    struct {
        struct rpc_call_hdr hdr;
        uint8_t fh[NFSV2_FHSIZE];    /* file to link */
        uint8_t dirfh[NFSV2_FHSIZE]; /* directory for new link */
        uint32_t namelen;
    } __attribute__((packed)) req;

    uint8_t buf[512];
    struct rpc_reply_hdr *reply;
    size_t namelen, totlen;
    uint32_t xid;
    ssize_t n;

    namelen = strlen(name);
    if (namelen > NFS_MAXNAMLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /* Build request: fixed header + variable name */
    totlen = sizeof(req) + XDR_ALIGN(namelen);
    if (totlen > sizeof(buf)) {
        errno = ENOMEM;
        return -1;
    }

    xid = rand();
    print(V_TRACE, ctx, "NFS2 LINK XID 0x%08x\n", xid);

    memset(buf, 0, sizeof(buf));
    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req.hdr, RPC_PROGRAM_NFS, 2, NFSV2_PROC_LINK);
    memcpy(req.fh, fh, NFSV2_FHSIZE);
    memcpy(req.dirfh, dirfh, NFSV2_FHSIZE);
    req.namelen = htonl(namelen);

    memcpy(buf, &req, sizeof(req));
    memcpy(buf + sizeof(req), name, namelen);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    memset(buf, 0, sizeof(buf));
    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_reply_hdr *)buf;
    RPC_CHECK_EMPTY_REPLY(ctx, reply, n);

    return 0;
}

/*
 * SYMLINK - Create symbolic link.
 *
 * RFC 1094 Section 2.3.16 - NFSPROC_SYMLINK (procedure 13)
 *
 * Creates a symbolic link. Target path is stored as-is without validation.
 * Unlike NFSv3, SYMLINK does NOT return the new symlink's file handle -
 * client must do a LOOKUP to get it.
 *
 * Mode bits are sent but typically ignored for symlinks (always 0777).
 *
 * Status codes: NFS_OK, NFSERR_IO, NFSERR_ACCES, NFSERR_EXIST,
 *               NFSERR_NOSPC, NFSERR_ROFS, NFSERR_NAMETOOLONG
 */
static int
nfsv2_symlink_impl(struct nfsctx *ctx,
    const uint8_t dirfh[NFSV2_FHSIZE],
    const char *name, const char *target, uint32_t mode)
{
    uint8_t buf[2048];
    struct rpc_call_hdr *call;
    struct rpc_reply_hdr *reply;
    uint8_t *pt;
    size_t namelen, targetlen, totlen;
    uint32_t xid;
    ssize_t n;

    namelen = strlen(name);
    targetlen = strlen(target);

    if (namelen > NFS_MAXNAMLEN || targetlen > NFS_MAXPATHLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    xid = rand();
    print(V_TRACE, ctx, "NFS2 SYMLINK XID 0x%08x\n", xid);

    totlen = sizeof(struct rpc_call_hdr) + NFSV2_FHSIZE +
        XDR_VARLEN(namelen) + XDR_VARLEN(targetlen) +
        sizeof(struct nfsv2_sattr);

    if (totlen > sizeof(buf)) {
        errno = ENOMEM;
        return -1;
    }

    memset(buf, 0, sizeof(buf));
    call = (struct rpc_call_hdr *)buf;
    RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 2, NFSV2_PROC_SYMLINK);

    pt = buf + sizeof(struct rpc_call_hdr);

    /* Directory */
    memcpy(pt, dirfh, NFSV2_FHSIZE);
    pt += NFSV2_FHSIZE;

    /* Name */
    pt = xdr_build_u32(pt, namelen);
    memcpy(pt, name, namelen);
    pt += XDR_ALIGN(namelen);

    /* Target path */
    pt = xdr_build_u32(pt, targetlen);
    memcpy(pt, target, targetlen);
    pt += XDR_ALIGN(targetlen);

    /* Attributes */
    nfsv2_build_sattr_mode((struct nfsv2_sattr *)pt, mode);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    memset(buf, 0, sizeof(buf));
    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (struct rpc_reply_hdr *)buf;
    RPC_CHECK_EMPTY_REPLY(ctx, reply, n);

    return 0;
}

/*
 * MKDIR - Create directory.
 *
 * RFC 1094 Section 2.3.17 - NFSPROC_MKDIR (procedure 14)
 *
 * Creates a new directory with "." and ".." entries. Returns file handle
 * and attributes of the new directory.
 *
 * Effective mode is (mode & ~umask) where umask is server-side.
 *
 * Status codes: NFS_OK, NFSERR_IO, NFSERR_ACCES, NFSERR_EXIST,
 *               NFSERR_NOSPC, NFSERR_ROFS, NFSERR_NAMETOOLONG
 */
static int
nfsv2_mkdir_impl(struct nfsctx *ctx, const uint8_t dirfh[NFSV2_FHSIZE],
    const char *name, uint32_t mode, struct nfs_create_res *out)
{
    struct {
        struct rpc_call_hdr hdr;
        uint8_t fh[NFSV2_FHSIZE];
        uint32_t namelen;
    } __attribute__((packed)) req;

    struct {
        struct rpc_reply r;
        struct rpc_verifier v;
        uint32_t accept_state;
        uint32_t status;
        uint8_t fh[NFSV2_FHSIZE];
        struct nfsv2_fattr attr;
    } __attribute__((packed)) * reply;

    struct nfsv2_sattr sattr;
    uint8_t buf[1024];
    size_t namelen, totlen, name_padded;
    uint32_t xid;
    ssize_t n;

    namelen = strlen(name);
    if (namelen > NFS_MAXNAMLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /* Build request: fixed header + variable name + fixed sattr */
    name_padded = XDR_ALIGN(namelen);
    totlen = sizeof(req) + name_padded + sizeof(sattr);
    if (totlen > sizeof(buf)) {
        errno = ENOMEM;
        return -1;
    }

    xid = rand();
    print(V_TRACE, ctx, "NFS2 MKDIR XID 0x%08x\n", xid);

    memset(buf, 0, sizeof(buf));
    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req.hdr, RPC_PROGRAM_NFS, 2, NFSV2_PROC_MKDIR);
    memcpy(req.fh, dirfh, NFSV2_FHSIZE);
    req.namelen = htonl(namelen);

    nfsv2_build_sattr_mode(&sattr, mode);

    memcpy(buf, &req, sizeof(req));
    memcpy(buf + sizeof(req), name, namelen);
    memcpy(buf + sizeof(req) + name_padded, &sattr, sizeof(sattr));

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, buf, totlen) < 0)
        return -1;

    memset(buf, 0, sizeof(buf));
    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, buf, sizeof(buf), xid)) < 0)
        return -1;

    reply = (void *)buf;
    RPC_CHECK_REPLY(ctx, (struct rpc_reply_hdr *)reply, n);

    NFS_CHECK_STATUS(ctx, reply);

    /* Parse result */
    memset(out, 0, sizeof(*out));
    nfs_fh_from_buf(&out->fh, reply->fh, NFSV2_FHSIZE);
    nfsv2_parse_fattr(&reply->attr, &out->attr);
    out->has_fh = 1;
    out->has_attr = 1;

    return 0;
}

/*
 * RMDIR - Remove directory
 */
static int
nfsv2_rmdir_impl(struct nfsctx *ctx, const uint8_t dirfh[NFSV2_FHSIZE],
    const char *name)
{
    return nfsv2_unlink_common(ctx, dirfh, name, NFSV2_PROC_RMDIR);
}

/*
 * READDIR - Read directory.
 *
 * RFC 1094 Section 2.3.19 - NFSPROC_READDIR (procedure 16)
 *
 * Returns directory entries (fileid, name, cookie). Cookie is an opaque
 * position marker for resuming reads; cookie 0 starts from beginning.
 *
 * NFSv2 READDIR only returns names and file IDs - no attributes or
 * file handles (unlike NFSv3 READDIRPLUS). Client must LOOKUP each
 * entry to get file handles.
 *
 * Entry order is filesystem-dependent. Directory changes during
 * iteration may cause entries to be skipped or returned twice.
 *
 * Status codes: NFS_OK, NFSERR_IO, NFSERR_ACCES, NFSERR_NOTDIR, NFSERR_STALE
 */
static int
nfsv2_readdir_impl(struct nfsctx *ctx, const uint8_t fh[NFSV2_FHSIZE],
    struct nfs_dir *out)
{
    struct {
        struct rpc_call_hdr hdr;
        uint8_t fh[NFSV2_FHSIZE];
        uint32_t cookie;
        uint32_t count;
    } __attribute__((packed)) req;

    uint8_t *replybuf;
    size_t replybufsize = IOBUFSIZE * 2;
    struct rpc_nfsreply_hdr *reply;
    uint8_t *pt, *end;
    uint32_t xid, cookie, value_follows, eof;
    uint32_t prev_cookie;
    size_t prev_count;
    ssize_t n;

    nfs_dir_init(out);
    cookie = 0;
    prev_cookie = 0;

    replybuf = malloc(replybufsize);
    if (replybuf == NULL)
        return -1;

    do {
        prev_count = out->count;
        xid = rand();
        print(V_TRACE, ctx, "NFS2 READDIR XID 0x%08x\n", xid);

        memset(&req, 0, sizeof(req));
        RPC_INIT_REQ(&req.hdr, RPC_PROGRAM_NFS, 2, NFSV2_PROC_READDIR);
        memcpy(req.fh, fh, NFSV2_FHSIZE);
        /* Cookie: OPAQUE value - echo back exactly as received from server */
        req.cookie = cookie;
        req.count = htonl(IOBUFSIZE);

        if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, (uint8_t *)&req, sizeof(req)) < 0) {
            free(replybuf);
            nfs_dir_free(out);
            return -1;
        }

        memset(replybuf, 0, replybufsize);
        if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, replybuf, replybufsize, xid)) < 0) {
            free(replybuf);
            nfs_dir_free(out);
            return -1;
        }

        reply = (struct rpc_nfsreply_hdr *)replybuf;
        RPC_CHECK_REPLY_FREE(ctx, reply, n, replybuf);

        NFS_CHECK_STATUS_EX(ctx, reply, { free(replybuf); nfs_dir_free(out); });

        pt = replybuf + sizeof(struct rpc_nfsreply_hdr);
        end = replybuf + n;

        /* Check bounds for value_follows */
        if (pt + XDR_UNIT > end) {
            free(replybuf);
            errno = EBADMSG;
            nfs_dir_free(out);
            return -1;
        }
        value_follows = xdr_get_u32(pt);
        pt += XDR_UNIT;

        while (value_follows) {
            struct nfs_dirent ent;
            uint32_t fileid, namelen, namelen_padded;

            /* Prevent unbounded allocation from malicious server */
            if (out->count >= NFS_READDIR_MAX_ENTRIES) {
                fprintf(stderr, "** Error: Too many directory entries (max %d)\n",
                    NFS_READDIR_MAX_ENTRIES);
                free(replybuf);
                nfs_dir_free(out);
                errno = EOVERFLOW;
                return -1;
            }

            memset(&ent, 0, sizeof(ent));

            /* Check bounds for fileid + namelen (8 bytes minimum) */
            if (pt + 8 > end) {
                free(replybuf);
                errno = EBADMSG;
                nfs_dir_free(out);
                return -1;
            }

            fileid = xdr_get_u32(pt);
            pt += XDR_UNIT;

            namelen = xdr_get_u32(pt);
            pt += XDR_UNIT;

            /* Validate namelen BEFORE XDR_ALIGN to prevent overflow */
            if (namelen > NFS_MAXNAMLEN) {
                free(replybuf);
                errno = EBADMSG;
                nfs_dir_free(out);
                return -1;
            }

            /* Check for XDR_ALIGN overflow before computing padded length */
            if (namelen > UINT32_MAX - (XDR_UNIT - 1)) {
                free(replybuf);
                errno = EBADMSG;
                nfs_dir_free(out);
                return -1;
            }
            namelen_padded = XDR_ALIGN(namelen);

            /* Need room for: name_data + cookie(4) + value_follows(4) */
            if (pt + namelen_padded + XDR_UNIT + XDR_UNIT > end) {
                free(replybuf);
                errno = EBADMSG;
                nfs_dir_free(out);
                return -1;
            }

            ent.fileid = fileid;
            memcpy(ent.name, pt, namelen);
            ent.name[namelen] = '\0';
            xdr_sanitize_string(ent.name);
            pt += namelen_padded;

            /*
             * Cookie: OPAQUE 32-bit value (RFC 1094).
             * Note: Using xdr_get_u32 here for consistency with how we echo
             * it back; both use same byte order so round-trip works.
             */
            cookie = xdr_get_u32(pt);
            ent.cookie = cookie;
            pt += XDR_UNIT;

            ent.has_fh = 0;
            ent.has_attr = 0;

            if (nfs_dir_add(out, &ent) < 0) {
                free(replybuf);
                nfs_dir_free(out);
                return -1;
            }

            /* Bounds check for value_follows */
            if (pt + XDR_UNIT > end) {
                free(replybuf);
                errno = EBADMSG;
                nfs_dir_free(out);
                return -1;
            }
            value_follows = xdr_get_u32(pt);
            pt += XDR_UNIT;
        }

        /* Check bounds for eof */
        if (pt + XDR_UNIT > end) {
            free(replybuf);
            errno = EBADMSG;
            nfs_dir_free(out);
            return -1;
        }
        eof = xdr_get_u32(pt);

        /* Detect malicious server returning same cookie forever */
        if (!eof) {
            if (out->count > prev_count && cookie == prev_cookie) {
                free(replybuf);
                errno = ELOOP;
                nfs_dir_free(out);
                return -1;
            }
            /* No new entries means we're stuck */
            if (out->count == prev_count) {
                free(replybuf);
                errno = ELOOP;
                nfs_dir_free(out);
                return -1;
            }
            prev_cookie = cookie;
        }

    } while (!eof);

    free(replybuf);
    out->eof = 1;
    return 0;
}

/*
 * STATFS - Get filesystem statistics.
 *
 * RFC 1094 Section 2.3.18 - NFSPROC_STATFS (procedure 17)
 *
 * Returns filesystem information including block size and block counts.
 * Status codes: NFS_OK, NFSERR_STALE, NFSERR_IO
 */
static int
nfsv2_statfs_impl(struct nfsctx *ctx, const uint8_t fh[NFSV2_FHSIZE],
    struct nfs_fsstat_res *out)
{
    struct {
        struct rpc_call_hdr hdr;
        uint8_t fh[NFSV2_FHSIZE];
    } __attribute__((packed)) req;

    struct {
        struct rpc_nfsreply_hdr hdr;
        uint32_t tsize;  /* optimum transfer size */
        uint32_t bsize;  /* block size */
        uint32_t blocks; /* total blocks */
        uint32_t bfree;  /* free blocks */
        uint32_t bavail; /* available blocks */
    } __attribute__((packed)) reply;

    uint32_t xid;
    ssize_t n;

    xid = rand();
    print(V_TRACE, ctx, "NFS2 STATFS XID 0x%08x\n", xid);

    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req.hdr, RPC_PROGRAM_NFS, 2, NFSV2_PROC_STATFS);
    memcpy(req.fh, fh, NFSV2_FHSIZE);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.nfsd, (uint8_t *)&req, sizeof(req)) < 0)
        return -1;

    memset(&reply, 0, sizeof(reply));
    if ((n = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.nfsd, (uint8_t *)&reply, sizeof(reply), xid)) < 0)
        return -1;

    RPC_CHECK_REPLY(ctx, &reply.hdr, n);

    NFS_CHECK_STATUS(ctx, &reply.hdr);

    memset(out, 0, sizeof(*out));
    out->tsize = ntohl(reply.tsize);
    out->bsize = ntohl(reply.bsize);
    out->blocks = ntohl(reply.blocks);
    out->bfree = ntohl(reply.bfree);
    out->bavail = ntohl(reply.bavail);

    /* Convert to bytes for unified interface */
    out->tbytes = (uint64_t)out->blocks * out->bsize;
    out->fbytes = (uint64_t)out->bfree * out->bsize;
    out->abytes = (uint64_t)out->bavail * out->bsize;

    /* v2 doesn't have file counts */
    out->tfiles = 0;
    out->ffiles = 0;
    out->afiles = 0;
    out->invarsec = 0;
    out->has_attr = 0;

    return 0;
}

/*
 * Wrapper macros for unified ops table (v3-style signatures)
 * Validate file handle length, extract raw data, truncate offsets for v2.
 */
#define V2_CHECK_FH(fh)              \
    if ((fh)->len != NFSV2_FHSIZE) { \
        errno = EINVAL;              \
        return -1;                   \
    }

#define V2_WRAP(name, args, call)        \
    static int nfsv2_wrap_##name args    \
    {                                    \
        V2_CHECK_FH(fh);                 \
        return nfsv2_##name##_impl call; \
    }

V2_WRAP(getattr, (struct nfsctx * ctx, const struct nfs_fh *fh, struct nfs_attr *out),
    (ctx, fh->data, out))
V2_WRAP(setattr, (struct nfsctx * ctx, const struct nfs_fh *fh, const struct nfs_sattr *sattr, struct nfs_attr *out),
    (ctx, fh->data, sattr, out))
V2_WRAP(lookup, (struct nfsctx * ctx, const struct nfs_fh *fh, const char *n, struct nfs_lookup_res *out),
    (ctx, fh->data, n, out))
V2_WRAP(readlink, (struct nfsctx * ctx, const struct nfs_fh *fh, struct nfs_readlink_res *out),
    (ctx, fh->data, out))
V2_WRAP(read, (struct nfsctx * ctx, const struct nfs_fh *fh, uint64_t off, uint32_t cnt, struct nfs_read_res *out),
    (ctx, fh->data, (uint32_t)off, cnt, out))
V2_WRAP(write, (struct nfsctx * ctx, const struct nfs_fh *fh, uint64_t off, const uint8_t *d, uint32_t cnt, struct nfs_write_res *out),
    (ctx, fh->data, (uint32_t)off, d, cnt, out))
static int
nfsv2_wrap_remove(struct nfsctx *ctx, const struct nfs_fh *fh, const char *n,
    struct nfs_wcc_data *out)
{
    (void)out; /* v2 doesn't return wcc_data */
    V2_CHECK_FH(fh);
    return nfsv2_remove_impl(ctx, fh->data, n);
}
static int
nfsv2_wrap_symlink(struct nfsctx *ctx, const struct nfs_fh *fh, const char *n,
    const char *t, uint32_t m, struct nfs_symlink_res *out)
{
    (void)out; /* v2 doesn't return symlink FH */
    V2_CHECK_FH(fh);
    return nfsv2_symlink_impl(ctx, fh->data, n, t, m);
}
V2_WRAP(mkdir, (struct nfsctx * ctx, const struct nfs_fh *fh, const char *n, uint32_t m, struct nfs_create_res *out),
    (ctx, fh->data, n, m, out))
static int
nfsv2_wrap_rmdir(struct nfsctx *ctx, const struct nfs_fh *fh, const char *n,
    struct nfs_wcc_data *out)
{
    (void)out; /* v2 doesn't return wcc_data */
    V2_CHECK_FH(fh);
    return nfsv2_rmdir_impl(ctx, fh->data, n);
}
V2_WRAP(readdir, (struct nfsctx * ctx, const struct nfs_fh *fh, struct nfs_dir *out),
    (ctx, fh->data, out))
V2_WRAP(statfs, (struct nfsctx * ctx, const struct nfs_fh *fh, struct nfs_fsstat_res *out),
    (ctx, fh->data, out))

/* Create wrapper - accepts but ignores create_mode (NFSv2 has no mode concept) */
static int
nfsv2_wrap_create(struct nfsctx *ctx, const struct nfs_fh *fh,
    const char *n, uint32_t m, int create_mode, struct nfs_create_res *out)
{
    (void)create_mode; /* NFSv2 ignores create mode */
    V2_CHECK_FH(fh);
    return nfsv2_create_impl(ctx, fh->data, n, m, out);
}

/* Dual file handle operations */
static int
nfsv2_wrap_rename(struct nfsctx *ctx, const struct nfs_fh *sfh,
    const char *sn, const struct nfs_fh *dfh, const char *dn,
    struct nfs_rename_res *out)
{
    (void)out; /* v2 doesn't return wcc_data */
    V2_CHECK_FH(sfh);
    V2_CHECK_FH(dfh);
    return nfsv2_rename_impl(ctx, sfh->data, sn, dfh->data, dn);
}

static int
nfsv2_wrap_link(struct nfsctx *ctx, const struct nfs_fh *fh,
    const struct nfs_fh *dfh, const char *n, struct nfs_link_res *out)
{
    (void)out; /* v2 doesn't return wcc_data */
    V2_CHECK_FH(fh);
    V2_CHECK_FH(dfh);
    return nfsv2_link_impl(ctx, fh->data, dfh->data, n);
}

/*
 * NULL - NFSv2 connectivity test.
 *
 * RFC 1094 Section 2.2.1 - NFSPROC_NULL (procedure 0)
 *
 * Does nothing. Used to test server availability and measure round-trip time.
 * Returns 0 on success, -1 on error.
 */
int
nfsv2_null(struct nfsctx *ctx)
{
    return rpc_simple_call(ctx, RPC_PROGRAM_NFS, NFS_VERSION_2,
        RPC_NFS_PROCEDURE_NULL, ctx->ports.nfsd,
        NULL, 0, NULL, 0, NULL);
}

/*
 * NFSv2 unified operations table (v3-style signatures)
 * readdirplus, mknod, fsinfo, access, pathconf return ENOTSUP as v2 doesn't have these
 */
struct nfs_ops nfsv2_unified_ops = {
    .getattr = nfsv2_wrap_getattr,
    .setattr = nfsv2_wrap_setattr,
    .lookup = nfsv2_wrap_lookup,
    .readlink = nfsv2_wrap_readlink,
    .read = nfsv2_wrap_read,
    .write = nfsv2_wrap_write,
    .create = nfsv2_wrap_create,
    .remove = nfsv2_wrap_remove,
    .rename = nfsv2_wrap_rename,
    .link = nfsv2_wrap_link,
    .symlink = nfsv2_wrap_symlink,
    .mkdir = nfsv2_wrap_mkdir,
    .rmdir = nfsv2_wrap_rmdir,
    .readdir = nfsv2_wrap_readdir,
    .readdirplus = NULL, /* emulated in nfs.c */
    .mknod = NULL,       /* not supported in v2 */
    .statfs = nfsv2_wrap_statfs,
    .fsinfo = NULL,      /* v3 only */
    .access = NULL,      /* v3 only */
    .pathconf = NULL,    /* v3 only */
};
