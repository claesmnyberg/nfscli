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
 * mount.c - Mount protocol implementation
 *
 * RFC 1094 Appendix A - Mount Protocol (v1)
 * RFC 1813 Appendix I - Mount Protocol (v3)
 *
 * This file implements the mount protocol dispatcher and version-independent
 * operations. The main difference between v1 and v3 is the file handle format:
 *   - v1: Fixed 32-byte file handle
 *   - v3: Variable-length file handle (max 64 bytes) with length prefix
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "mount.h"
#include "mount_types.h"
#include "nfscli.h"
#include "nfsh.h"
#include "portmap.h"
#include "print.h"
#include "rpc.h"
#include "xdr.h"

/* Buffer size for mount protocol responses (16KB is plenty for export/dump lists) */
#define MOUNT_RECVBUF_SIZE 16384

/* Auth flavor parsing limits */
#define MAX_AUTH_FLAVORS   32
#define AUTH_FLAVOR_MAXLEN 24 /* ", UNKNOWN(4294967295)" + slack */

/* Maximum mount entries to prevent DoS from malicious server */
#define MOUNT_MAX_ENTRIES 10000

/*
 * Convert auth flavor number to name string.
 * RFC 1831 Section 9 defines AUTH_NONE, AUTH_SYS, AUTH_SHORT, AUTH_DH.
 * RFC 2203 defines RPCSEC_GSS.
 */
static const char *
auth_flavor_name(uint32_t flavor)
{
    switch (flavor) {
    case 0:
        return "AUTH_NONE";
    case 1:
        return "AUTH_SYS";
    case 2:
        return "AUTH_SHORT";
    case 3:
        return "AUTH_DH";
    case 6:
        return "RPCSEC_GSS";
    default:
        return "UNKNOWN";
    }
}

/*
 * Parse and log auth flavors from mount v3 response.
 * Purely informational - failures are silently ignored.
 */
static void
parse_auth_flavors(struct nfsctx *ctx, const uint8_t *pt, const uint8_t *end)
{
    uint32_t num_flavors, i;
    char buf[MAX_AUTH_FLAVORS * AUTH_FLAVOR_MAXLEN];
    char *p = buf;
    char *bufend = buf + sizeof(buf);
    int n;

    if (pt + XDR_UNIT > end)
        return;

    num_flavors = xdr_get_u32(pt);
    pt += XDR_UNIT;

    if (num_flavors == 0 || num_flavors > MAX_AUTH_FLAVORS)
        return;
    if (pt + num_flavors * XDR_UNIT > end)
        return;

    for (i = 0; i < num_flavors; i++) {
        uint32_t flavor = xdr_get_u32(pt);
        pt += XDR_UNIT;
        n = snprintf(p, bufend - p, "%s%s(%u)",
            i > 0 ? ", " : "", auth_flavor_name(flavor), flavor);
        if (n > 0 && p + n < bufend)
            p += n;
    }

    print(V_DETAIL, ctx, "Auth flavors (%u): %s\n", num_flavors, buf);
}

/*
 * Parse an XDR string into a fixed-size buffer with truncation.
 *
 * Reads length-prefixed XDR string, copies up to bufsize-1 bytes,
 * null-terminates, and advances pointer past XDR-aligned data.
 *
 * Returns pointer past the parsed data, or NULL on bounds error.
 */
static const uint8_t *
parse_xdr_string_to_buf(const uint8_t *pt, const uint8_t *end,
    char *buf, size_t bufsize)
{
    uint32_t len;
    uint32_t len_padded;
    uint32_t copy_len;

    if (pt + XDR_UNIT > end)
        return NULL;

    len = xdr_get_u32(pt);
    pt += XDR_UNIT;

    /* Validate length BEFORE XDR_ALIGN to prevent overflow */
    if (len > NFS_MAXPATHLEN)
        return NULL;
    len_padded = XDR_ALIGN(len);

    /* Check bounds with aligned length */
    if (pt + len_padded > end)
        return NULL;

    /* Copy with truncation */
    copy_len = len;
    if (copy_len >= bufsize)
        copy_len = bufsize - 1;
    memcpy(buf, pt, copy_len);
    buf[copy_len] = '\0';
    xdr_sanitize_string(buf);

    return pt + len_padded;
}

/*
 * Convert mount protocol error to errno.
 * Mount errors 1-22 happen to match POSIX errno on Linux,
 * but higher values need explicit mapping.
 */
static int
mount_err_to_errno(uint32_t status)
{
    switch (status) {
    case MNT_OK:
        return 0;
    case MNT_ERR_PERM:
        return EPERM;
    case MNT_ERR_NOENT:
        return ENOENT;
    case MNT_ERR_IO:
        return EIO;
    case MNT_ERR_ACCESS:
        return EACCES;
    case MNT_ERR_NOTDIR:
        return ENOTDIR;
    case MNT_ERR_INVAL:
        return EINVAL;
    case MNT_ERR_NAMETOOLONG:
        return ENAMETOOLONG;
    case MNT_ERR_NOTSUPP:
        return EOPNOTSUPP;
    case MNT_ERR_SERVERFAULT:
        return EIO; /* No direct equivalent */
    default:
        return EIO; /* Unknown error */
    }
}

/*
 * Wire format structures
 */

/* Mount v1 reply (RFC 1094) - fixed 32-byte file handle */
struct mountv1_mnt_reply {
    struct rpc_reply r;
    struct rpc_verifier v;
    uint32_t accept_state;
    uint32_t status;
    /* 32-byte file handle follows if status == 0 */
} __attribute__((packed));

/* Mount v3 reply (RFC 1813) - variable-length file handle */
struct mountv3_mnt_reply {
    struct rpc_reply r;
    struct rpc_verifier v;
    uint32_t accept_state;
    uint32_t status;
    uint32_t fhlen;
    /* File handle data follows, then auth flavors */
} __attribute__((packed));

/*
 * Convert mount error code to string
 */
const char *
mount_errstr(int err)
{
    switch (err) {
    case MNT_OK:
        return "OK";
    case MNT_ERR_PERM:
        return "Not owner";
    case MNT_ERR_NOENT:
        return "No such file or directory";
    case MNT_ERR_IO:
        return "I/O error";
    case MNT_ERR_ACCESS:
        return "Permission denied";
    case MNT_ERR_NOTDIR:
        return "Not a directory";
    case MNT_ERR_INVAL:
        return "Invalid argument";
    case MNT_ERR_NAMETOOLONG:
        return "File name too long";
    case MNT_ERR_NOTSUPP:
        return "Operation not supported";
    case MNT_ERR_SERVERFAULT:
        return "Server fault";
    default:
        return strerror(err);
    }
}

/*
 * Annotate subnet-looking IP addresses with inferred CIDR notation.
 * NFS servers often return "192.168.56.0" without a netmask.
 * We add "/24", "/16", or "/8" based on common conventions.
 * Works in-place on the group string (must have space for suffix).
 */
static void
annotate_subnet_groups(char *group, size_t group_size)
{
    char *p, *end;
    char result[MOUNT_EXPORT_GROUP_MAX];
    char *rp = result;
    char *rend = result + sizeof(result);
    int a, b, c, d;
    int n;

    if (group == NULL || group[0] == '\0')
        return;

    p = group;
    end = group + strlen(group);

    while (p < end && rp < rend - 1) {
        /* Try to parse an IP address at current position */
        n = 0;
        if (sscanf(p, "%d.%d.%d.%d%n", &a, &b, &c, &d, &n) == 4 && n > 0) {
            /* Valid IP address parsed */
            int cidr = 0;

            /* Check if it looks like a subnet */
            if (a >= 1 && a <= 255 && b >= 0 && b <= 255 &&
                c >= 0 && c <= 255 && d >= 0 && d <= 255) {
                /* Infer CIDR based on trailing zeros */
                if (d == 0 && c == 0 && b == 0)
                    cidr = 8;  /* x.0.0.0 -> /8 */
                else if (d == 0 && c == 0)
                    cidr = 16; /* x.y.0.0 -> /16 */
                else if (d == 0)
                    cidr = 24; /* x.y.z.0 -> /24 */
            }

            /* Copy IP address */
            if (rp + n < rend) {
                memcpy(rp, p, n);
                rp += n;
            }
            p += n;

            /* Add CIDR suffix if it looks like a subnet */
            if (cidr > 0) {
                /* Check if next char is already a / (has netmask) */
                if (*p != '/') {
                    int len = snprintf(rp, rend - rp, "/%d", cidr);
                    if (len > 0 && rp + len < rend)
                        rp += len;
                }
            }
        } else {
            /* Not an IP, copy single character */
            *rp++ = *p++;
        }
    }
    *rp = '\0';

    /* Copy back to original buffer */
    snprintf(group, group_size, "%s", result);
}

/*
 * Free an export list
 */
void
mount_export_free(struct mount_export *exports)
{
    struct mount_export *cur, *next;

    for (cur = exports; cur != NULL; cur = next) {
        next = cur->next;
        if (cur->fh != NULL)
            free(cur->fh);
        free(cur);
    }
}

/*
 * Free a mount entry list
 */
void
mount_entry_free(struct mount_entry *entries)
{
    struct mount_entry *cur, *next;

    for (cur = entries; cur != NULL; cur = next) {
        next = cur->next;
        free(cur);
    }
}

/*
 * MNT - Mount a filesystem export (common implementation).
 *
 * RFC 1094 Appendix A.5.1 (v1) / RFC 1813 Appendix I.3 (v3)
 *
 * Returns the root file handle for the exported filesystem.
 * The client uses this handle for subsequent NFS operations.
 *
 * v1/v2: Fixed 32-byte file handle (FHSIZE)
 * v3: Variable-length handle (1-64 bytes) with auth flavor list
 *
 * Status codes: MNT_OK, MNT_PERM, MNT_NOENT, MNT_IO, MNT_ACCES,
 *               MNT_NOTDIR, MNT_INVAL, MNT_NAMETOOLONG, MNT_NOTSUPP
 *
 * Note: Mount v2 is not RFC-defined but is wire-compatible with v1.
 */
static int
mount_mnt_common(struct nfsctx *ctx, const char *path, uint8_t **fh, int version)
{
    uint8_t buf[RPC_BUFSIZE_LARGE];
    int mlen;
    size_t pathlen;

    struct {
        struct rpc_call r;
        struct rpc_creds c;
        struct rpc_verifier v;
        uint32_t pathlen;
        uint8_t path[NAMEMAXLEN];
    } __attribute__((packed)) req;

    struct rpc_reply_hdr *reply;
    ssize_t len;
    uint32_t xid;
    int fhlen;
    uint32_t fhlen_raw = 0;
    uint32_t status;
    uint8_t *fhdata;

    pathlen = strlen(path);
    if (pathlen >= sizeof(req.path)) {
        fprintf(stderr, "** Error: Path too long\n");
        errno = ENAMETOOLONG;
        return -1;
    }

    xid = rand();
    print(V_TRACE, ctx, "MNT XID 0x%08x\n", xid);

    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req, RPC_PROGRAM_MOUNT, version, MOUNTPROC_MNT);

    snprintf((char *)req.path, sizeof(req.path), "%s", path);
    req.pathlen = htonl(pathlen);
    mlen = (sizeof(req) - sizeof(req.path)) + XDR_ALIGN(pathlen);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.mountd, (uint8_t *)&req, mlen) < 0)
        return -1;

    memset(buf, 0, sizeof(buf));
    reply = (struct rpc_reply_hdr *)buf;

    if ((len = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.mountd, buf, sizeof(buf), xid)) < 0) {
        /* Timeout already reported by rpc_recv_xid */
        return -1;
    }

    RPC_CHECK_REPLY(ctx, reply, len);

    /* Status is at same offset for both v1 and v3 */
    status = xdr_get_u32(buf + sizeof(struct rpc_reply_hdr));

    if (status != MNT_OK) {
        if (!ctx->quiet)
            fprintf(stderr, "** Error: Mount failed: %u: %s\n",
                status, mount_errstr(status));
        errno = mount_err_to_errno(status);
        return -1;
    }

    if (version == 1 || version == 2) {
        /* v1/v2: Fixed 32-byte file handle, no length prefix */
        fhlen = MOUNTV1_FHSIZE;
        fhdata = buf + sizeof(struct mountv1_mnt_reply);
        if ((size_t)len < sizeof(struct mountv1_mnt_reply)) {
            fprintf(stderr, "** Error: Short mount reply\n");
            errno = EPROTO;
            return -1;
        }
    } else {
        /* v3: Variable-length file handle with length prefix */
        if ((size_t)len < sizeof(struct mountv3_mnt_reply)) {
            fprintf(stderr, "** Error: Short mount reply\n");
            errno = EPROTO;
            return -1;
        }
        fhlen_raw = xdr_get_u32(buf + sizeof(struct rpc_reply_hdr) + XDR_UNIT);
        fhdata = buf + sizeof(struct mountv3_mnt_reply);
        /* Validate file handle length BEFORE XDR_ALIGN to prevent overflow (RFC 1813: 1-64 bytes) */
        if (fhlen_raw == 0 || fhlen_raw > MOUNTV3_FHSIZE_MAX) {
            fprintf(stderr, "** Error: Invalid file handle length %u\n", fhlen_raw);
            errno = EPROTO;
            return -1;
        }
        fhlen = (int)fhlen_raw;

        /* Check bounds with aligned length */
        if (XDR_ALIGN(fhlen_raw) > (size_t)(buf + len - fhdata)) {
            fprintf(stderr, "** Error: File handle exceeds reply bounds\n");
            errno = EPROTO;
            return -1;
        }

        /* Parse auth_flavors (RFC 1813 Appendix I.3) */
        parse_auth_flavors(ctx, fhdata + XDR_ALIGN(fhlen_raw), buf + len);
    }

    if (fh != NULL) {
        if ((*fh = malloc(fhlen)) == NULL) {
            fprintf(stderr, "** Error: Failed to allocate %d bytes\n", fhlen);
            return -1;
        }
        memcpy(*fh, fhdata, fhlen);
    }

    return fhlen;
}

/*
 * Mount dispatcher - mounts a filesystem export
 * Dispatches to v1/v2/v3 based on ctx->proto.mount_version.
 * Returns file handle length on success, -1 on error.
 *
 * Note: RFC 1094 defines mount v1 (for NFS v2), RFC 1813 defines mount v3
 * (for NFS v3). There is no RFC-defined mount v2, but some servers advertise
 * it via portmap. Mount v2 is wire-compatible with v1 (both use fixed 32-byte
 * file handles), so we handle them identically.
 */
int
mount_mnt(struct nfsctx *ctx, const char *path, uint8_t **fh)
{
    if (ctx->proto.mount_version < 1 || ctx->proto.mount_version > 3) {
        fprintf(stderr, "** Error: Unsupported mount version %d\n",
            ctx->proto.mount_version);
        errno = ENOTSUP;
        return -1;
    }
    return mount_mnt_common(ctx, path, fh, ctx->proto.mount_version);
}

/*
 * Mount with caching - checks cache first, mounts if needed.
 * Unlike mount_mnt, writes directly to caller's buffer (no allocation).
 * Returns file handle length on success, -1 on error.
 */
int
mount_mnt_cached(struct nfsctx *ctx, const char *path,
    uint8_t *fh_out, size_t fh_out_size, int flags)
{
    uint8_t *fh;
    int fhlen;

    /* Always check cache - mount FH cache is always enabled */
    if (mount_fh_cache_lookup(ctx, path, fh_out, &fhlen) == 0) {
        ctx->cache.mount_fh.hits++;
        return fhlen;
    }

    /* Cache miss - do the mount */
    ctx->cache.mount_fh.misses++;
    fhlen = mount_mnt(ctx, path, &fh);
    if (fhlen < 0)
        return -1;

    /* Copy to output buffer */
    if ((size_t)fhlen > fh_out_size) {
        free(fh);
        errno = ENOSPC;
        return -1;
    }
    memcpy(fh_out, fh, fhlen);

    /* Always add to cache - mount FH cache is always enabled */
    mount_fh_cache_add(ctx, path, fh, fhlen);
    free(fh);

    /*
     * Immediately unmount to remove from server's client list.
     * The FH remains valid - NFS doesn't require an active mount entry.
     * Silently ignore errors (server may not support UMNT, or path may differ).
     */
    if (flags & MNT_CACHE_UMNT) {
        int saved_quiet = ctx->quiet;
        ctx->quiet = 1;
        mount_umnt(ctx, path);
        ctx->quiet = saved_quiet;
    }

    return fhlen;
}

/*
 * XDR list header - value_follows + string length.
 * Used for both export and group list entries.
 */
struct xdr_list_hdr {
    uint32_t value_follows;
    uint32_t len;
} __attribute__((packed));

/*
 * Check if group string matches "everyone" patterns.
 */
static int
is_everyone_group(const char *group)
{
    if (strcmp(group, "* ") == 0)
        return 1;
    if (strstr(group, "*.") != NULL)
        return 1;
    if (strcasecmp(group, "Everyone") == 0)
        return 1;
    return 0;
}

/*
 * Copy XDR string to buffer with truncation.
 * Returns bytes consumed from input, or 0 on error.
 */
static size_t
copy_xdr_string(const uint8_t *pt, const uint8_t *end, char *dst, size_t dstlen)
{
    uint32_t len;
    size_t copy_len;

    if (pt + XDR_UNIT > end)
        return 0;

    len = xdr_get_u32(pt);
    if (len > NFS_MAXPATHLEN)
        return 0;
    if (pt + XDR_UNIT + XDR_ALIGN(len) > end)
        return 0;

    copy_len = len;
    if (copy_len >= dstlen)
        copy_len = dstlen - 1;

    memcpy(dst, pt + XDR_UNIT, copy_len);
    dst[copy_len] = '\0';
    xdr_sanitize_string(dst);

    return XDR_UNIT + XDR_ALIGN(len);
}

/*
 * Parse groups for a single export entry.
 * Returns pointer past the groups, or NULL on error.
 */
static const uint8_t *
parse_export_groups(struct mount_export *cur, const uint8_t *pt, const uint8_t *end)
{
    struct xdr_list_hdr *hdr;
    size_t pos = 0;
    size_t group_count = 0;

    hdr = (struct xdr_list_hdr *)pt;
    if ((uint8_t *)hdr + sizeof(*hdr) > end)
        return NULL;

    /* No groups = everyone allowed */
    if (ntohl(hdr->value_follows) == 0) {
        snprintf(cur->group, sizeof(cur->group), "<everyone>");
        cur->everyone = 1;
    }

    while (ntohl(hdr->value_follows) == 1) {
        uint32_t grouplen;
        size_t remaining;

        if (group_count >= MOUNT_MAX_GROUPS_PER_EXPORT) {
            fprintf(stderr, "** Error: Too many groups for export (max %d)\n",
                MOUNT_MAX_GROUPS_PER_EXPORT);
            return NULL;
        }
        group_count++;

        grouplen = ntohl(hdr->len);
        if (grouplen > MOUNT_EXPORT_GROUP_MAX || grouplen > UINT32_MAX - (XDR_UNIT - 1)) {
            fprintf(stderr, "** Error: Group name too long (%u)\n", grouplen);
            return NULL;
        }

        pt = (uint8_t *)hdr + sizeof(*hdr);
        if (pt + XDR_ALIGN(grouplen) > end) {
            fprintf(stderr, "** Error: Response truncated in group list\n");
            return NULL;
        }

        /* Append group to buffer if space remains */
        remaining = sizeof(cur->group) - pos;
        if (remaining > 1 && grouplen < remaining - 1) {
            memcpy(&cur->group[pos], pt, grouplen);
            pos += grouplen;
            cur->group[pos++] = ' ';
        }

        pt += XDR_ALIGN(grouplen);
        hdr = (struct xdr_list_hdr *)pt;
        if ((uint8_t *)hdr + sizeof(*hdr) > end)
            return NULL;
    }

    /* Sanitize group names for terminal safety */
    xdr_sanitize_string(cur->group);

    /* Skip past the value_follows==0 terminator */
    return (uint8_t *)hdr + sizeof(uint32_t);
}

/*
 * EXPORT - Get list of exported filesystems.
 *
 * RFC 1094 Appendix A.5.2 / RFC 1813 Appendix I.4 - MOUNTPROC_EXPORT
 *
 * Returns all filesystem exports and their access groups.
 * Groups specify which hosts/networks may mount the export.
 * Empty group list means the export is world-accessible.
 *
 * Wire format: Linked list of (dirpath, groups) entries.
 * This procedure is identical across mount protocol versions.
 */
int
mount_get_exports(struct nfsctx *ctx, struct mount_export **exports)
{
    uint8_t *buf = NULL;
    struct mount_export *head = NULL, *cur = NULL;
    struct rpc_call_hdr req;
    struct rpc_reply_hdr *reply;
    const uint8_t *pt, *end;
    ssize_t len;
    uint32_t xid;
    size_t export_count = 0;
    int ret = -1;

    *exports = NULL;

    buf = malloc(MOUNT_RECVBUF_SIZE);
    if (buf == NULL) {
        fprintf(stderr, "** Error: Failed to allocate receive buffer\n");
        return -1;
    }

    /* Send EXPORT request */
    xid = rand();
    print(V_TRACE, ctx, "EXPORT XID 0x%08x\n", xid);

    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req, RPC_PROGRAM_MOUNT, ctx->proto.mount_version, MOUNTPROC_EXPORT);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.mountd, (uint8_t *)&req, sizeof(req)) < 0)
        goto cleanup;

    /* Receive response */
    reply = (struct rpc_reply_hdr *)buf;
    len = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.mountd, buf, MOUNT_RECVBUF_SIZE, xid);
    if (len < (ssize_t)sizeof(struct rpc_reply_hdr)) {
        if (!g_interrupted && len >= 0)
            fprintf(stderr, "** Error: Bad length (%zd) of received data\n", len);
        goto cleanup;
    }

    RPC_CHECK_REPLY(ctx, reply, len);

    /* Parse export list */
    end = buf + len;
    pt = buf + sizeof(struct rpc_reply_hdr);

    while (pt + sizeof(uint32_t) <= end && xdr_get_u32(pt) == 1) {
        size_t consumed;

        if (export_count >= MOUNT_MAX_EXPORTS) {
            fprintf(stderr, "** Error: Too many exports (max %d)\n", MOUNT_MAX_EXPORTS);
            goto cleanup;
        }
        export_count++;

        /* Bounds check: need value_follows + len fields */
        if (pt + sizeof(struct xdr_list_hdr) > end) {
            fprintf(stderr, "** Error: Response truncated in export header\n");
            goto cleanup;
        }

        /* Allocate new export entry */
        if (head == NULL) {
            head = cur = calloc(1, sizeof(struct mount_export));
        } else {
            cur->next = calloc(1, sizeof(struct mount_export));
            cur = cur->next;
        }
        if (cur == NULL) {
            fprintf(stderr, "** Error: Failed to allocate memory\n");
            goto cleanup;
        }

        /* Parse export path (skip value_follows to get XDR string) */
        consumed = copy_xdr_string(pt + sizeof(uint32_t), end, cur->name, sizeof(cur->name));
        if (consumed == 0) {
            fprintf(stderr, "** Error: Failed to parse export name\n");
            goto cleanup;
        }
        pt += sizeof(uint32_t) + consumed;

        /* Parse groups */
        pt = parse_export_groups(cur, pt, end);
        if (pt == NULL)
            goto cleanup;

        if (pt + sizeof(uint32_t) > end) {
            fprintf(stderr, "** Error: Response truncated\n");
            goto cleanup;
        }

        /* Annotate subnet-looking IPs with CIDR notation */
        annotate_subnet_groups(cur->group, sizeof(cur->group));

        if (is_everyone_group(cur->group))
            cur->everyone = 1;
    }

    /* Success */
    *exports = head;
    head = NULL;
    ret = 0;

    /* Always cache exports - needed for export jumping and completion */
    mount_exports_cache(ctx, *exports);

cleanup:
    mount_export_free(head);
    free(buf);
    return ret;
}

/*
 * DUMP - Get list of mounted clients.
 *
 * RFC 1094 Appendix A.5.3 / RFC 1813 Appendix I.5 - MOUNTPROC_DUMP
 *
 * Returns all clients that have mounted filesystems from this server.
 * Each entry contains (hostname, directory) pairs.
 *
 * Note: This information is maintained by mountd and may not reflect
 * actual NFS connections (clients may unmount without notifying server).
 */
int
mount_dump_list(struct nfsctx *ctx, struct mount_entry **entries)
{
    uint8_t *buf = NULL;
    struct mount_entry *head = NULL, *cur = NULL, *prev = NULL;
    struct rpc_call_hdr req;
    struct rpc_reply_hdr *reply;
    const uint8_t *pt, *end;
    ssize_t len;
    uint32_t xid;
    size_t entry_count = 0;
    int ret = -1;

    *entries = NULL;

    buf = malloc(MOUNT_RECVBUF_SIZE);
    if (buf == NULL) {
        fprintf(stderr, "** Error: Failed to allocate receive buffer\n");
        return -1;
    }

    /* Send DUMP request */
    xid = rand();
    print(V_TRACE, ctx, "DUMP XID 0x%08x\n", xid);

    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req, RPC_PROGRAM_MOUNT, ctx->proto.mount_version, MOUNTPROC_DUMP);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.mountd, (uint8_t *)&req, sizeof(req)) < 0)
        goto cleanup;

    /* Receive response */
    reply = (struct rpc_reply_hdr *)buf;
    len = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.mountd, buf, MOUNT_RECVBUF_SIZE, xid);
    if (len < 0) {
        fprintf(stderr, "** Error: Failed to receive response: %s\n", strerror(errno));
        goto cleanup;
    }

    RPC_CHECK_REPLY(ctx, reply, len);

    /* Parse mount entry list */
    end = buf + len;
    pt = buf + sizeof(struct rpc_reply_hdr);

    while (pt + XDR_UNIT <= end && xdr_get_u32(pt) == 1) {
        pt += XDR_UNIT;

        if (entry_count >= MOUNT_MAX_ENTRIES) {
            fprintf(stderr, "** Error: Too many mount entries (max %d)\n", MOUNT_MAX_ENTRIES);
            goto cleanup;
        }
        entry_count++;

        cur = calloc(1, sizeof(struct mount_entry));
        if (cur == NULL) {
            fprintf(stderr, "** Error: Failed to allocate memory\n");
            goto cleanup;
        }

        if (head == NULL)
            head = cur;
        if (prev != NULL)
            prev->next = cur;
        prev = cur;

        /* Hostname */
        pt = parse_xdr_string_to_buf(pt, end, cur->hostname, sizeof(cur->hostname));
        if (pt == NULL) {
            fprintf(stderr, "** Error: Short mount dump reply\n");
            goto cleanup;
        }

        /* Directory */
        pt = parse_xdr_string_to_buf(pt, end, cur->directory, sizeof(cur->directory));
        if (pt == NULL) {
            fprintf(stderr, "** Error: Short mount dump reply\n");
            goto cleanup;
        }
    }

    /* Success */
    *entries = head;
    head = NULL;
    ret = 0;

cleanup:
    mount_entry_free(head);
    free(buf);
    return ret;
}

/*
 * NULL - Mount daemon connectivity test.
 *
 * RFC 1094 Appendix A.5.1 / RFC 1813 Appendix I.4 - MOUNTPROC_NULL
 *
 * Does nothing. Used to test server availability and measure round-trip time.
 * Returns 0 on success, -1 on error.
 */
int
mount_null(struct nfsctx *ctx)
{
    return rpc_simple_call(ctx, RPC_PROGRAM_MOUNT, ctx->proto.mount_version,
        RPC_MOUNT_PROCEDURE_NULL, ctx->ports.mountd,
        NULL, 0, NULL, 0, NULL);
}

/*
 * UMNT - Unmount a specific filesystem.
 *
 * RFC 1094 Appendix A.5.3 / RFC 1813 Appendix I.6 - MOUNTPROC_UMNT
 *
 * Informs the server that this client has unmounted the specified path.
 * The server removes this client's entry for that path from its mount list.
 *
 * Note: This is advisory only; NFS itself is stateless and the server
 * cannot enforce unmounts. Client file handles remain valid until
 * the server reboots or the export is unexported.
 */
int
mount_umnt(struct nfsctx *ctx, const char *path)
{
    uint8_t args[NFS_MAXPATHLEN + XDR_UNIT];
    size_t pathlen, args_len;
    uint8_t *pt;

    if (path == NULL || *path == '\0') {
        errno = EINVAL;
        return -1;
    }

    pathlen = strlen(path);
    if (pathlen > NFS_MAXPATHLEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /* Build XDR string: length + data (padded) */
    memset(args, 0, sizeof(args));
    pt = args;
    pt = xdr_build_u32(pt, pathlen);
    memcpy(pt, path, pathlen);
    args_len = XDR_UNIT + XDR_ALIGN(pathlen);

    return rpc_simple_call(ctx, RPC_PROGRAM_MOUNT, ctx->proto.mount_version,
        RPC_MOUNT_PROCEDURE_UMNT, ctx->ports.mountd,
        args, args_len, NULL, 0, NULL);
}

/*
 * UMNTALL - Unmount all filesystems for this client.
 *
 * RFC 1094 Appendix A.5.4 / RFC 1813 Appendix I.7 - MOUNTPROC_UMNTALL
 *
 * Informs the server that this client has unmounted all filesystems.
 * The server removes all entries for this client from its mount list.
 *
 * Note: This is advisory only; NFS itself is stateless and the server
 * cannot enforce unmounts. Client file handles remain valid until
 * the server reboots or the export is unexported.
 */
int
mount_umntall(struct nfsctx *ctx)
{
    return rpc_simple_call(ctx, RPC_PROGRAM_MOUNT, ctx->proto.mount_version,
        RPC_MOUNT_PROCEDURE_UMNTALL, ctx->ports.mountd,
        NULL, 0, NULL, 0, NULL);
}

/*
 * Set mount protocol version.
 * Also queries portmap for the port if changing to a different version.
 * Returns version on success, 0 if version unavailable (mask says no),
 * -1 on invalid input.
 */
int
set_mount_version(struct nfsctx *ctx, uint8_t version)
{
    uint16_t port;

    if (ctx == NULL || version < 1 || version > 3) {
        errno = EINVAL;
        return -1;
    }

    /* If mask is populated, validate against it */
    if (ctx->proto.mount_version_mask != 0) {
        if (!(ctx->proto.mount_version_mask & VERSION_AVAIL(version)))
            return 0; /* Version not available */
    }

    /* Set version (mask==0 means no discovery yet, trust user) */
    ctx->proto.mount_version = version;

    /* Query portmap for the port of this specific version */
    port = portmap_getport(ctx, PMAP_PROG_MOUNTD, version);
    if (port != 0)
        ctx->ports.mountd = port;

    return version;
}

/*
 * Set highest supported mount protocol version
 */
int
set_highest_mount_version(struct nfsctx *ctx)
{
    uint8_t version;
    uint8_t mask;

    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Mask out flags to get version bits only (bits 1-3) */
    mask = ctx->proto.mount_version_mask & VERSION_AVAIL_ALL;
    if (mask == 0)
        return 0; /* No versions available */

    for (version = 3; version > 0; version--) {
        if (mask & VERSION_AVAIL(version)) {
            ctx->proto.mount_version = version;
            return version;
        }
    }

    return 0;
}

/*
 * Initialize mount protocol version by querying portmapper.
 * Probes versions 1, 2, 3 via GETPORT and sets version mask.
 */
void
init_mount_version(struct nfsctx *ctx)
{
    uint16_t port;

    if (ctx == NULL || ctx->proto.mount_version_mask)
        return;

    /* Probe mount versions 1, 2, 3 */
    ctx->proto.mount_version_mask = portmap_probe(ctx, PMAP_PROG_MOUNTD, 1, 3, &port);

    /* Only mark as fully probed if we found at least one version.
     * This allows retry on subsequent calls if portmap was unreachable. */
    if (ctx->proto.mount_version_mask & VERSION_AVAIL_ALL) {
        ctx->proto.mount_version_mask |= VERSION_MASK_FULL;
        if (ctx->ports.mountd == 0)
            ctx->ports.mountd = port;
    }
    set_highest_mount_version(ctx);
}

/*
 * Clear the exports cache
 */
void
mount_exports_cache_clear(struct nfsctx *ctx)
{
    if (ctx->cache.exports != NULL) {
        size_t i;
        for (i = 0; i < ctx->cache.exports_count; i++)
            free(ctx->cache.exports[i]);
        free(ctx->cache.exports);
        ctx->cache.exports = NULL;
        ctx->cache.exports_count = 0;
    }
}

/*
 * Ensure exports cache is populated (auto-fetch if empty).
 * Called automatically by cache query functions.
 */
static void
mount_exports_ensure_cached(struct nfsctx *ctx)
{
    struct mount_export *exports = NULL;
    int saved_quiet;

    if (ctx->cache.exports != NULL && ctx->cache.exports_count > 0)
        return;

    /* Can't fetch exports if mount port is not yet resolved */
    if (ctx->ports.mountd == 0)
        return;

    /* Suppress errors during auto-fetch */
    saved_quiet = ctx->quiet;
    ctx->quiet = 1;
    if (mount_get_exports(ctx, &exports) == 0 && exports != NULL) {
        /* Cache was populated by mount_get_exports if enabled */
        mount_export_free(exports);
    }
    ctx->quiet = saved_quiet;
}

/*
 * Get number of cached exports
 */
size_t
mount_exports_cache_count(struct nfsctx *ctx)
{
    mount_exports_ensure_cached(ctx);
    return ctx->cache.exports_count;
}

/*
 * Get cached export by index
 * Returns export path string, or NULL if index out of range
 */
const char *
mount_exports_cache_get(struct nfsctx *ctx, size_t index)
{
    mount_exports_ensure_cached(ctx);
    if (index >= ctx->cache.exports_count)
        return NULL;
    return ctx->cache.exports[index];
}

/*
 * Find the best matching export for a path.
 * Returns the longest export that is a prefix of path, or NULL if none match.
 */
const char *
mount_exports_find_best(struct nfsctx *ctx, const char *path)
{
    const char *best = NULL;
    size_t best_len = 0;
    size_t i;

    mount_exports_ensure_cached(ctx);
    if (ctx->cache.exports == NULL || ctx->cache.exports_count == 0)
        return NULL;

    for (i = 0; i < ctx->cache.exports_count; i++) {
        const char *exp = ctx->cache.exports[i];
        size_t exp_len = strlen(exp);

        /* Check if path starts with this export */
        if (strncmp(path, exp, exp_len) == 0) {
            /* Must match at path boundary */
            if (path[exp_len] == '\0' || path[exp_len] == '/') {
                if (exp_len > best_len) {
                    best = exp;
                    best_len = exp_len;
                }
            }
        }
    }

    return best;
}

/*
 * Initialize export selection iterator for reaching a target path.
 */
void
mount_export_iter_init(struct mount_export_iter *iter, const char *target_path)
{
    iter->target_path = target_path;
    iter->path_len = strlen(target_path);
    iter->pass = 0;
    iter->index = 0;
}

/*
 * Get next export to try for reaching target path.
 * Returns export path, or NULL when all exports exhausted.
 *
 * Iterates in priority order:
 *   Pass 0: Cached FHs with nearer paths (no MOUNT RPC needed)
 *   Pass 1: Cached FHs with farther paths (no MOUNT RPC needed)
 *   Pass 2: Uncached exports with nearer paths (requires MOUNT RPC)
 *   Pass 3: Uncached exports with farther paths (requires MOUNT RPC)
 */
const char *
mount_export_iter_next(struct nfsctx *ctx, struct mount_export_iter *iter)
{
    const char *export_path;

    while (iter->pass <= 3) {
        while ((export_path = mount_exports_cache_get(ctx, iter->index)) != NULL) {
            size_t exp_len = strlen(export_path);
            int is_cached;
            int path_is_prefix;

            iter->index++;

            is_cached = (mount_fh_cache_lookup(ctx, export_path, NULL, NULL) == 0);

            /*
             * path_is_prefix: target path is a prefix of the export path.
             * e.g., if target=/data and export=/data/backup, we can descend
             * into the export and climb back up to reach /data.
             * Special case: path_len == 1 means root ("/") is prefix of all.
             */
            path_is_prefix = (exp_len > iter->path_len &&
                strncmp(export_path, iter->target_path, iter->path_len) == 0 &&
                (iter->path_len == 1 || export_path[iter->path_len] == '/'));

            /* Check if this export matches current pass criteria */
            if (iter->pass == 0) {
                /* Pass 0: Cached FHs with nearer paths */
                if (!is_cached || !path_is_prefix)
                    continue;
            } else if (iter->pass == 1) {
                /* Pass 1: Cached FHs with farther paths */
                if (!is_cached || path_is_prefix)
                    continue;
            } else if (iter->pass == 2) {
                /* Pass 2: Uncached exports with nearer paths */
                if (is_cached || !path_is_prefix)
                    continue;
            } else {
                /* Pass 3: Uncached exports with farther paths */
                if (is_cached || path_is_prefix)
                    continue;
            }

            return export_path;
        }

        /* Move to next pass, reset index */
        iter->pass++;
        iter->index = 0;
    }

    return NULL;
}

/*
 * Count path components in a path (e.g., "/" = 0, "/foo" = 1, "/foo/bar" = 2)
 */
static int
path_component_count(const char *path)
{
    int count = 0;
    const char *p = path;

    while (*p) {
        /* Skip leading slashes */
        while (*p == '/')
            p++;
        if (*p == '\0')
            break;
        count++;
        /* Skip to next slash or end */
        while (*p && *p != '/')
            p++;
    }
    return count;
}

/*
 * Compare exports by path depth (fewer components first).
 * This ensures exports closer to root are tried first when browsing.
 */
static int
export_cmp_by_depth(const void *a, const void *b)
{
    const char *pa = *(const char **)a;
    const char *pb = *(const char **)b;
    int depth_a = path_component_count(pa);
    int depth_b = path_component_count(pb);

    if (depth_a != depth_b)
        return depth_a - depth_b;
    /* Same depth - sort alphabetically for consistency */
    return strcmp(pa, pb);
}

/*
 * Cache exports from an export list.
 * Returns number of exports cached, or -1 on error.
 * Exports are sorted by path depth (fewest components first).
 */
int
mount_exports_cache(struct nfsctx *ctx, struct mount_export *exports)
{
    struct mount_export *xpl;
    size_t count = 0;
    char *export_copy;

    /* Count exports */
    for (xpl = exports; xpl != NULL; xpl = xpl->next)
        count++;

    if (count == 0)
        return 0;

    /* Clear old cache */
    mount_exports_cache_clear(ctx);

    /* Check for overflow before malloc */
    if (count > SIZE_MAX / sizeof(char *)) {
        fprintf(stderr, "** Error: Too many exports to cache\n");
        errno = ENOMEM;
        return -1;
    }

    /* Allocate new cache */
    ctx->cache.exports = malloc(count * sizeof(char *));
    if (ctx->cache.exports == NULL)
        return -1;

    /* Copy export names */
    ctx->cache.exports_count = 0;
    for (xpl = exports; xpl != NULL; xpl = xpl->next) {
        export_copy = strdup(xpl->name);
        if (export_copy == NULL) {
            /* strdup failed - clean up and return error */
            mount_exports_cache_clear(ctx);
            return -1;
        }
        ctx->cache.exports[ctx->cache.exports_count] = export_copy;
        ctx->cache.exports_count++;
    }

    /* Sort by path depth (fewest components first) */
    if (ctx->cache.exports_count > 1)
        qsort(ctx->cache.exports, ctx->cache.exports_count, sizeof(char *),
            export_cmp_by_depth);

    return (int)ctx->cache.exports_count;
}

/*
 * Mount file handle cache functions
 */

/*
 * Hash function for path strings (djb2 algorithm)
 */
static unsigned int
mount_fh_path_hash(const char *path)
{
    unsigned int hash = 5381;
    int c;

    while ((c = (unsigned char)*path++) != 0)
        hash = ((hash << 5) + hash) + c;

    return hash % MOUNT_FH_CACHE_BUCKETS;
}

/*
 * Clear mount file handle cache
 */
void
mount_fh_cache_clear(struct nfsctx *ctx)
{
    size_t i;

    if (ctx->cache.mount_fh.entries != NULL) {
        for (i = 0; i < ctx->cache.mount_fh.count; i++)
            free(ctx->cache.mount_fh.entries[i].path);
        free(ctx->cache.mount_fh.entries);
        ctx->cache.mount_fh.entries = NULL;
        ctx->cache.mount_fh.count = 0;
        ctx->cache.mount_fh.capacity = 0;
    }
    /* Clear hash buckets */
    for (i = 0; i < MOUNT_FH_CACHE_BUCKETS; i++) {
        free(ctx->cache.mount_fh.hash_buckets[i]);
        ctx->cache.mount_fh.hash_buckets[i] = NULL;
        ctx->cache.mount_fh.hash_bucket_counts[i] = 0;
        ctx->cache.mount_fh.hash_bucket_caps[i] = 0;
    }
    ctx->cache.mount_fh.hits = 0;
    ctx->cache.mount_fh.misses = 0;
}

/*
 * Add index to hash bucket
 */
static int
mount_fh_hash_add(struct nfsctx *ctx, unsigned int bucket, size_t idx)
{
    size_t *new_bucket;
    size_t new_cap;

    if (ctx->cache.mount_fh.hash_bucket_counts[bucket] >=
        ctx->cache.mount_fh.hash_bucket_caps[bucket]) {
        /* Grow bucket */
        if (ctx->cache.mount_fh.hash_bucket_caps[bucket] == 0)
            new_cap = 4;
        else if (ctx->cache.mount_fh.hash_bucket_caps[bucket] > SIZE_MAX / 2)
            return -1;
        else
            new_cap = ctx->cache.mount_fh.hash_bucket_caps[bucket] * 2;
        new_bucket = realloc(ctx->cache.mount_fh.hash_buckets[bucket],
            new_cap * sizeof(size_t));
        if (new_bucket == NULL)
            return -1;
        ctx->cache.mount_fh.hash_buckets[bucket] = new_bucket;
        ctx->cache.mount_fh.hash_bucket_caps[bucket] = new_cap;
    }
    ctx->cache.mount_fh.hash_buckets[bucket]
                                    [ctx->cache.mount_fh.hash_bucket_counts[bucket]++] = idx;
    return 0;
}

/*
 * Add a file handle to the mount cache
 */
void
mount_fh_cache_add(struct nfsctx *ctx, const char *path,
    const uint8_t *fh, int fhlen)
{
    size_t i;
    char *pathcopy;
    unsigned int bucket;

    if (path == NULL || fh == NULL || fhlen <= 0)
        return;

    bucket = mount_fh_path_hash(path);

    /* Check if already cached using hash table (O(1) average) */
    for (i = 0; i < ctx->cache.mount_fh.hash_bucket_counts[bucket]; i++) {
        size_t idx = ctx->cache.mount_fh.hash_buckets[bucket][i];
        if (idx < ctx->cache.mount_fh.count &&
            strcmp(ctx->cache.mount_fh.entries[idx].path, path) == 0) {
            /* Update existing entry */
            memcpy(ctx->cache.mount_fh.entries[idx].fh, fh, fhlen);
            ctx->cache.mount_fh.entries[idx].fhlen = fhlen;
            return;
        }
    }

    /* Need to add new entry */
    if (ctx->cache.mount_fh.count >= ctx->cache.mount_fh.capacity) {
        size_t new_cap;
        struct nfs_mount_fh_entry *new_cache;
        if (ctx->cache.mount_fh.capacity == 0)
            new_cap = 8;
        else if (ctx->cache.mount_fh.capacity > SIZE_MAX / 2)
            return; /* Overflow protection */
        else
            new_cap = ctx->cache.mount_fh.capacity * 2;
        new_cache = realloc(ctx->cache.mount_fh.entries,
            new_cap * sizeof(*new_cache));
        if (new_cache == NULL)
            return;
        ctx->cache.mount_fh.entries = new_cache;
        ctx->cache.mount_fh.capacity = new_cap;
    }

    /* Validate fhlen to prevent buffer overflow */
    if (fhlen <= 0 || fhlen > NFS_FHSIZE_MAX)
        return;

    pathcopy = strdup(path);
    if (pathcopy == NULL)
        return;

    /* Add entry to array */
    i = ctx->cache.mount_fh.count;
    ctx->cache.mount_fh.entries[i].path = pathcopy;
    memcpy(ctx->cache.mount_fh.entries[i].fh, fh, fhlen);
    ctx->cache.mount_fh.entries[i].fhlen = fhlen;
    ctx->cache.mount_fh.count++;

    /* Add index to hash bucket */
    mount_fh_hash_add(ctx, bucket, i);
}

/*
 * Lookup a file handle in the mount cache
 * Returns 0 on hit, -1 on miss
 * Uses hash table for O(1) average lookup.
 */
int
mount_fh_cache_lookup(struct nfsctx *ctx, const char *path,
    uint8_t *fh_out, int *fhlen_out)
{
    size_t i;
    unsigned int bucket;

    if (ctx->cache.mount_fh.entries == NULL || path == NULL)
        return -1;

    bucket = mount_fh_path_hash(path);

    /* Search hash bucket (O(1) average) */
    for (i = 0; i < ctx->cache.mount_fh.hash_bucket_counts[bucket]; i++) {
        size_t idx = ctx->cache.mount_fh.hash_buckets[bucket][i];
        if (idx < ctx->cache.mount_fh.count &&
            strcmp(ctx->cache.mount_fh.entries[idx].path, path) == 0) {
            if (fh_out != NULL)
                memcpy(fh_out, ctx->cache.mount_fh.entries[idx].fh,
                    ctx->cache.mount_fh.entries[idx].fhlen);
            if (fhlen_out != NULL)
                *fhlen_out = ctx->cache.mount_fh.entries[idx].fhlen;
            return 0;
        }
    }

    return -1;
}

/*
 * Remove index from hash bucket
 */
static void
mount_fh_hash_remove(struct nfsctx *ctx, unsigned int bucket, size_t idx)
{
    size_t i;

    for (i = 0; i < ctx->cache.mount_fh.hash_bucket_counts[bucket]; i++) {
        if (ctx->cache.mount_fh.hash_buckets[bucket][i] == idx) {
            /* Move last to this slot */
            ctx->cache.mount_fh.hash_bucket_counts[bucket]--;
            if (i < ctx->cache.mount_fh.hash_bucket_counts[bucket])
                ctx->cache.mount_fh.hash_buckets[bucket][i] =
                    ctx->cache.mount_fh.hash_buckets[bucket]
                                                    [ctx->cache.mount_fh.hash_bucket_counts[bucket]];
            return;
        }
    }
}

/*
 * Update hash bucket index (when entry is moved)
 */
static void
mount_fh_hash_update_idx(struct nfsctx *ctx, unsigned int bucket,
    size_t old_idx, size_t new_idx)
{
    size_t i;

    for (i = 0; i < ctx->cache.mount_fh.hash_bucket_counts[bucket]; i++) {
        if (ctx->cache.mount_fh.hash_buckets[bucket][i] == old_idx) {
            ctx->cache.mount_fh.hash_buckets[bucket][i] = new_idx;
            return;
        }
    }
}

/*
 * Invalidate a cached file handle (e.g., on ESTALE error)
 */
void
mount_fh_cache_invalidate(struct nfsctx *ctx, const char *path)
{
    size_t i;
    unsigned int bucket;

    if (ctx->cache.mount_fh.entries == NULL || path == NULL)
        return;

    bucket = mount_fh_path_hash(path);

    /* Find entry using hash table */
    for (i = 0; i < ctx->cache.mount_fh.hash_bucket_counts[bucket]; i++) {
        size_t idx = ctx->cache.mount_fh.hash_buckets[bucket][i];
        if (idx < ctx->cache.mount_fh.count &&
            strcmp(ctx->cache.mount_fh.entries[idx].path, path) == 0) {
            /* Remove from hash table first */
            mount_fh_hash_remove(ctx, bucket, idx);

            /* Free the entry */
            free(ctx->cache.mount_fh.entries[idx].path);

            /* Move last entry to this slot */
            if (idx < ctx->cache.mount_fh.count - 1) {
                size_t last = ctx->cache.mount_fh.count - 1;
                unsigned int last_bucket =
                    mount_fh_path_hash(ctx->cache.mount_fh.entries[last].path);
                ctx->cache.mount_fh.entries[idx] =
                    ctx->cache.mount_fh.entries[last];
                /* Update hash table for moved entry */
                mount_fh_hash_update_idx(ctx, last_bucket, last, idx);
            }
            ctx->cache.mount_fh.count--;
            return;
        }
    }
}

/*
 * Return number of cached mount file handles.
 */
size_t
mount_fh_cache_count(struct nfsctx *ctx)
{
    return ctx->cache.mount_fh.count;
}

/*
 * Query all file handles from the mount cache for completion.
 * Returns NULL-terminated array of hex-encoded file handles.
 * Caller must free the result with nfs_dir_query_free() or similar.
 */
char **
mount_fh_cache_query_handles(struct nfsctx *ctx, const char *prefix)
{
    char **results = NULL;
    size_t count = 0;
    size_t capacity = 16;
    size_t prefix_len;
    size_t i;
    struct nfs_mount_fh_entry *entry;
    char hexbuf[NFS_FHSIZE_MAX * 2 + 1];
    int j;
    size_t new_cap;
    char **new_results;
    char *hex_copy;

    if (ctx == NULL || ctx->cache.mount_fh.entries == NULL)
        return NULL;

    prefix_len = prefix ? strlen(prefix) : 0;

    /* Check for overflow before malloc */
    if (capacity >= SIZE_MAX / sizeof(char *) - 1) {
        return NULL;
    }

    results = malloc((capacity + 1) * sizeof(char *));
    if (results == NULL)
        return NULL;

    for (i = 0; i < ctx->cache.mount_fh.count; i++) {
        entry = &ctx->cache.mount_fh.entries[i];

        if (entry->fhlen <= 0 || entry->fhlen > NFS_FHSIZE_MAX)
            continue;

        /* Convert FH to hex string */
        for (j = 0; j < entry->fhlen; j++)
            snprintf(hexbuf + j * 2, 3, "%02x", entry->fh[j]);
        hexbuf[entry->fhlen * 2] = '\0';

        /* Check prefix match */
        if (prefix_len > 0 && strncmp(hexbuf, prefix, prefix_len) != 0)
            continue;

        /* Grow array if needed */
        if (count >= capacity) {
            if (capacity > SIZE_MAX / 2) {
                for (j = 0; j < (int)count; j++)
                    free(results[j]);
                free(results);
                return NULL;
            }
            new_cap = capacity * 2;
            new_results = realloc(results, (new_cap + 1) * sizeof(char *));
            if (new_results == NULL) {
                for (j = 0; j < (int)count; j++)
                    free(results[j]);
                free(results);
                return NULL;
            }
            results = new_results;
            capacity = new_cap;
        }

        hex_copy = strdup(hexbuf);
        if (hex_copy == NULL) {
            for (j = 0; j < (int)count; j++)
                free(results[j]);
            free(results);
            return NULL;
        }
        results[count] = hex_copy;
        count++;
    }

    results[count] = NULL;
    return results;
}
