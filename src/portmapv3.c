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
 * portmapv3.c - RPCBIND v3 protocol (RFC 1833)
 *
 * Implements rpcbind v3 procedures:
 *   RPCBPROC_NULL       (0) - Connectivity test
 *   RPCBPROC_SET        (1) - Register service (not implemented)
 *   RPCBPROC_UNSET      (2) - Unregister service (not implemented)
 *   RPCBPROC_GETADDR    (3) - Get universal address for program/version
 *   RPCBPROC_DUMP       (4) - List all registered services
 *   RPCBPROC_CALLIT     (5) - Indirect call (not implemented)
 *   RPCBPROC_GETTIME    (6) - Get server time
 *   RPCBPROC_UADDR2TADDR(7) - Convert uaddr to taddr (not implemented)
 *   RPCBPROC_TADDR2UADDR(8) - Convert taddr to uaddr (not implemented)
 *
 * Key difference from portmapper v2: Uses universal addresses (uaddr)
 * instead of port numbers. Format: "h1.h2.h3.h4.p1.p2" where port = p1*256+p2
 */

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "nfscli.h"
#include "nfsh.h"
#include "portmap.h"
#include "portmap_ops.h"
#include "print.h"
#include "rpc.h"
#include "xdr.h"

/* RPCBIND v3 procedure numbers (RFC 1833 Section 2.1) */
#define RPCBPROC_NULL        0
#define RPCBPROC_SET         1
#define RPCBPROC_UNSET       2
#define RPCBPROC_GETADDR     3
#define RPCBPROC_DUMP        4
#define RPCBPROC_CALLIT      5
#define RPCBPROC_GETTIME     6
#define RPCBPROC_UADDR2TADDR 7
#define RPCBPROC_TADDR2UADDR 8

/*
 * Parse universal address to extract port.
 *
 * Universal address format for IPv4 (RFC 5665 Section 5.2.3.3):
 *   "h1.h2.h3.h4.p1.p2" where port = (p1 * 256) + p2
 *   Example: "192.168.1.1.8.1" = 192.168.1.1:2049
 *
 * Returns port in network byte order, 0 on parse error.
 */
static int
uaddr_to_port(const char *uaddr, size_t len)
{
    char tmp[64];
    char *last_dot = NULL, *second_last_dot = NULL;
    char *s, *endp;
    long p1, p2;
    size_t copylen;

    if (uaddr == NULL || len == 0)
        return 0;

    copylen = len < sizeof(tmp) - 1 ? len : sizeof(tmp) - 1;
    memcpy(tmp, uaddr, copylen);
    tmp[copylen] = '\0';

    /* Find last two dots */
    for (s = tmp; *s; s++) {
        if (*s == '.') {
            second_last_dot = last_dot;
            last_dot = s;
        }
    }

    if (last_dot == NULL || second_last_dot == NULL)
        return 0;

    /* Parse p1 (high byte) */
    errno = 0;
    p1 = strtol(second_last_dot + 1, &endp, 10);
    if (endp == second_last_dot + 1 || *endp != '.' || p1 < 0 || p1 > 255 || errno != 0)
        return 0;

    /* Parse p2 (low byte) */
    errno = 0;
    p2 = strtol(last_dot + 1, &endp, 10);
    if (endp == last_dot + 1 || *endp != '\0' || p2 < 0 || p2 > 255 || errno != 0)
        return 0;

    return htons((int)(p1 * 256 + p2));
}

/*
 * rpcbv3_null - Test rpcbind v3 connectivity.
 *
 * RFC 1833 Section 2.1 - RPCBPROC_NULL (procedure 0)
 * Does nothing. Used to test rpcbind availability.
 *
 * Returns 0 on success, -1 on error.
 */
int
rpcbv3_null(struct nfsctx *ctx)
{
    return rpc_simple_call(ctx, RPC_PROGRAM_PORTMAP, PMAP_VERSION_3,
        RPC_PORTMAP_PROCEDURE_NULL, ctx->ports.rpc,
        NULL, 0, NULL, 0, NULL);
}

/*
 * rpcbv3_getaddr - Query universal address for an RPC program/version.
 *
 * RFC 1833 Section 2.1 - RPCBPROC_GETADDR (procedure 3)
 *
 *   "RPCBPROC_GETADDR returns the universal address for the given
 *    program, version, and netid. The owner field is ignored."
 *
 * Wire format (request):
 *   struct rpcb {
 *       unsigned int r_prog;   -- program number
 *       unsigned int r_vers;   -- version number
 *       string r_netid<>;      -- network id ("udp", "tcp", etc.)
 *       string r_addr<>;       -- universal address (can be empty)
 *       string r_owner<>;      -- owner (ignored, can be empty)
 *   };
 *
 * Wire format (response):
 *   string uaddr<>;            -- universal address (empty = not registered)
 *
 * Returns port in network byte order, 0 if not registered, -1 on RPC error.
 */
int
rpcbv3_getaddr(struct nfsctx *ctx, uint32_t program, uint32_t version)
{
    uint8_t reqbuf[256];
    uint8_t replybuf[512];
    uint8_t *p;
    struct rpc_call *r;
    struct rpc_creds *c;
    struct rpc_verifier *v;
    struct rpc_reply *rr;
    uint32_t xid;
    ssize_t len;
    uint32_t uaddr_len;
    char *uaddr;

    xid = rand();
    print(V_TRACE, ctx, "RPCB3 GETADDR XID 0x%08x prog=%u vers=%u\n",
        xid, program, version);

    memset(reqbuf, 0, sizeof(reqbuf));
    p = reqbuf;

    /* RPC call header */
    r = (struct rpc_call *)p;
    r->xid = htonl(xid);
    r->msgtype = htonl(RPC_MSG_TYPE_CALL);
    r->version = htonl(2);
    r->program = htonl(RPC_PROGRAM_PORTMAP);
    r->program_version = htonl(PMAP_VERSION_3);
    r->procedure = htonl(RPCBPROC_GETADDR);
    p += sizeof(struct rpc_call);

    /* AUTH_NULL credentials */
    c = (struct rpc_creds *)p;
    c->flavor = htonl(FLAVOR_AUTH_NULL);
    c->length = htonl(0);
    p += 8; /* Only flavor + length for AUTH_NULL */

    /* AUTH_NULL verifier */
    v = (struct rpc_verifier *)p;
    v->flavor = htonl(FLAVOR_AUTH_NULL);
    v->length = htonl(0);
    p += sizeof(struct rpc_verifier);

    /* rpcb struct: prog, vers, netid, addr, owner */
    xdr_put_u32(p, program);
    p += XDR_UNIT;
    xdr_put_u32(p, version);
    p += XDR_UNIT;

    /* netid: "udp" (XDR string) */
    p = xdr_build_string(p, "udp");

    /* addr: empty string */
    xdr_put_u32(p, 0);
    p += XDR_UNIT;

    /* owner: empty string */
    xdr_put_u32(p, 0);
    p += XDR_UNIT;

    if (udp_write(ctx, ctx->server.ip, ctx->ports.rpc,
            reqbuf, (size_t)(p - reqbuf)) < 0)
        return -1;

    memset(replybuf, 0, sizeof(replybuf));
    len = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.rpc,
        replybuf, sizeof(replybuf), xid);

    if (len < (ssize_t)(sizeof(struct rpc_reply) + sizeof(struct rpc_verifier) + 8)) {
        errno = EPROTO;
        return -1;
    }

    rr = (struct rpc_reply *)replybuf;
    if (ntohl(rr->reply_state) != RPC_ACCEPTED) {
        errno = EPROTO;
        return -1;
    }

    /* Skip to procedure data: rpc_reply + verifier + accept_state */
    p = replybuf + sizeof(struct rpc_reply) + sizeof(struct rpc_verifier) + XDR_UNIT;

    /* Parse uaddr string length */
    uaddr_len = xdr_get_u32(p);
    p += XDR_UNIT;

    if (uaddr_len == 0)
        return 0; /* Empty string = not registered */

    /* Validate length and check bounds (no XDR_ALIGN for final string) */
    if (uaddr_len > 256 || p + uaddr_len > replybuf + len) {
        errno = EPROTO;
        return -1;
    }

    uaddr = (char *)p;
    return uaddr_to_port(uaddr, uaddr_len);
}

/*
 * rpcbv3_dump - List all registered RPC services.
 *
 * RFC 1833 Section 2.1 - RPCBPROC_DUMP (procedure 4)
 *
 * Returns list of rpcb entries (program, version, netid, addr, owner).
 * This function converts to portmap_dump_entry format for compatibility,
 * parsing the universal address to extract the port number.
 *
 * Returns entry count on success, -1 on error.
 * Caller must free the returned list with portmap_dump_free().
 */
int
rpcbv3_dump(struct nfsctx *ctx, struct portmap_dump_entry **de)
{
    uint8_t reqbuf[128];
    uint8_t replybuf[65535];
    uint8_t *p, *end;
    struct rpc_call *r;
    struct rpc_creds *c;
    struct rpc_verifier *v;
    struct rpc_reply *rr;
    uint32_t xid;
    ssize_t len;
    uint32_t value_follows;
    struct portmap_dump_entry *head = NULL, *cur = NULL, *entry;
    size_t entry_count = 0;
    uint32_t prog, vers, slen;
    char netid[32];
    int port;

    *de = NULL;

    xid = rand();
    print(V_TRACE, ctx, "RPCB3 DUMP XID 0x%08x\n", xid);

    memset(reqbuf, 0, sizeof(reqbuf));
    p = reqbuf;

    /* RPC call header */
    r = (struct rpc_call *)p;
    r->xid = htonl(xid);
    r->msgtype = htonl(RPC_MSG_TYPE_CALL);
    r->version = htonl(2);
    r->program = htonl(RPC_PROGRAM_PORTMAP);
    r->program_version = htonl(PMAP_VERSION_3);
    r->procedure = htonl(RPCBPROC_DUMP);
    p += sizeof(struct rpc_call);

    /* AUTH_NULL credentials */
    c = (struct rpc_creds *)p;
    c->flavor = htonl(FLAVOR_AUTH_NULL);
    c->length = htonl(0);
    p += 8;

    /* AUTH_NULL verifier */
    v = (struct rpc_verifier *)p;
    v->flavor = htonl(FLAVOR_AUTH_NULL);
    v->length = htonl(0);
    p += sizeof(struct rpc_verifier);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.rpc,
            reqbuf, (size_t)(p - reqbuf)) < 0)
        return -1;

    memset(replybuf, 0, sizeof(replybuf));
    len = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.rpc,
        replybuf, sizeof(replybuf), xid);

    if (len < (ssize_t)(sizeof(struct rpc_reply) + sizeof(struct rpc_verifier) + 8)) {
        if (len < 0)
            ctx->portmap.unreachable = 1;
        errno = EPROTO;
        return -1;
    }

    rr = (struct rpc_reply *)replybuf;
    if (ntohl(rr->reply_state) != RPC_ACCEPTED) {
        errno = EPROTO;
        return -1;
    }

    /* Skip to procedure data */
    p = replybuf + sizeof(struct rpc_reply) + sizeof(struct rpc_verifier) + XDR_UNIT;
    end = replybuf + len;

    /* Check for value_follows */
    if (p + XDR_UNIT > end) {
        errno = EPROTO;
        return -1;
    }

    value_follows = xdr_get_u32(p);
    p += XDR_UNIT;

    while (value_follows && p < end) {
        if (entry_count >= PMAP_DUMP_MAX_ENTRIES) {
            fprintf(stderr, "** Error: Too many rpcbind entries (max %d)\n",
                PMAP_DUMP_MAX_ENTRIES);
            portmap_dump_free(head);
            errno = EPROTO;
            return -1;
        }

        /* Parse rpcb entry: prog, vers, netid, addr, owner */
        if (p + 2 * XDR_UNIT > end)
            break;

        prog = xdr_get_u32(p);
        p += XDR_UNIT;
        vers = xdr_get_u32(p);
        p += XDR_UNIT;

        /* netid string */
        if (p + XDR_UNIT > end)
            break;
        slen = xdr_get_u32(p);
        p += XDR_UNIT;

        /* Validate slen BEFORE XDR_ALIGN to prevent overflow */
        if (slen > 256)
            break;
        /* Check XDR_ALIGN won't overflow before using it */
        if (slen > UINT32_MAX - (XDR_UNIT - 1))
            break;
        if (XDR_ALIGN(slen) > (size_t)(end - p))
            break;

        if (slen < sizeof(netid)) {
            memcpy(netid, p, slen);
            netid[slen] = '\0';
        } else {
            netid[0] = '\0';
        }
        p += XDR_ALIGN(slen);

        /* addr string (universal address) */
        if (p + XDR_UNIT > end)
            break;
        slen = xdr_get_u32(p);
        p += XDR_UNIT;

        /* Validate slen BEFORE XDR_ALIGN to prevent overflow */
        if (slen > 256)
            break;
        /* Check XDR_ALIGN won't overflow before using it */
        if (slen > UINT32_MAX - (XDR_UNIT - 1))
            break;
        if (XDR_ALIGN(slen) > (size_t)(end - p))
            break;

        port = uaddr_to_port((char *)p, slen);
        p += XDR_ALIGN(slen);

        /* owner string */
        char owner[32] = "";
        if (p + XDR_UNIT > end)
            break;
        slen = xdr_get_u32(p);
        p += XDR_UNIT;

        /* Validate slen BEFORE XDR_ALIGN to prevent overflow */
        if (slen > 256)
            break;
        /* Check XDR_ALIGN won't overflow before using it */
        if (slen > UINT32_MAX - (XDR_UNIT - 1))
            break;
        if (XDR_ALIGN(slen) > (size_t)(end - p))
            break;
        if (slen > 0 && slen < sizeof(owner)) {
            memcpy(owner, p, slen);
            owner[slen] = '\0';
        }
        p += XDR_ALIGN(slen);

        /* Create entry */
        entry = calloc(1, sizeof(struct portmap_dump_entry));
        if (entry == NULL) {
            portmap_dump_free(head);
            return -1;
        }

        entry->pm_prog = prog;
        entry->pm_vers = vers;
        entry->pm_port = (port > 0) ? ntohs((uint16_t)port) : 0;

        /* Copy netid and owner for v3 display, sanitized for terminal safety */
        snprintf(entry->pm_netid, sizeof(entry->pm_netid), "%s", netid);
        xdr_sanitize_string(entry->pm_netid);
        snprintf(entry->pm_owner, sizeof(entry->pm_owner), "%s", owner);
        xdr_sanitize_string(entry->pm_owner);

        /* Map netid to protocol */
        if (strcmp(netid, "udp") == 0 || strcmp(netid, "udp6") == 0)
            entry->pm_prot = IPPROTO_UDP;
        else if (strcmp(netid, "tcp") == 0 || strcmp(netid, "tcp6") == 0)
            entry->pm_prot = IPPROTO_TCP;
        else
            entry->pm_prot = 0;

        if (head == NULL)
            head = entry;
        else
            cur->next = entry;
        cur = entry;
        entry_count++;

        /* Next entry? */
        if (p + XDR_UNIT > end)
            break;
        value_follows = xdr_get_u32(p);
        p += XDR_UNIT;
    }

    *de = head;
    return entry_count;
}

/*
 * rpcbv3_gettime - Get server time.
 *
 * RFC 1833 Section 2.1 - RPCBPROC_GETTIME (procedure 6)
 *
 * Returns server's time as seconds since Unix epoch.
 *
 * Returns time on success, 0 on error.
 */
uint32_t
rpcbv3_gettime(struct nfsctx *ctx)
{
    uint8_t reqbuf[128];
    uint8_t replybuf[128];
    uint8_t *p;
    struct rpc_call *r;
    struct rpc_creds *c;
    struct rpc_verifier *v;
    struct rpc_reply *rr;
    uint32_t xid;
    ssize_t len;

    xid = rand();
    print(V_TRACE, ctx, "RPCB3 GETTIME XID 0x%08x\n", xid);

    memset(reqbuf, 0, sizeof(reqbuf));
    p = reqbuf;

    /* RPC call header */
    r = (struct rpc_call *)p;
    r->xid = htonl(xid);
    r->msgtype = htonl(RPC_MSG_TYPE_CALL);
    r->version = htonl(2);
    r->program = htonl(RPC_PROGRAM_PORTMAP);
    r->program_version = htonl(PMAP_VERSION_3);
    r->procedure = htonl(RPCBPROC_GETTIME);
    p += sizeof(struct rpc_call);

    /* AUTH_NULL credentials */
    c = (struct rpc_creds *)p;
    c->flavor = htonl(FLAVOR_AUTH_NULL);
    c->length = htonl(0);
    p += 8;

    /* AUTH_NULL verifier */
    v = (struct rpc_verifier *)p;
    v->flavor = htonl(FLAVOR_AUTH_NULL);
    v->length = htonl(0);
    p += sizeof(struct rpc_verifier);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.rpc,
            reqbuf, (size_t)(p - reqbuf)) < 0)
        return 0;

    memset(replybuf, 0, sizeof(replybuf));
    len = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.rpc,
        replybuf, sizeof(replybuf), xid);

    if (len < (ssize_t)(sizeof(struct rpc_reply) + sizeof(struct rpc_verifier) + 8))
        return 0;

    rr = (struct rpc_reply *)replybuf;
    if (ntohl(rr->reply_state) != RPC_ACCEPTED)
        return 0;

    /* Skip to procedure data */
    p = replybuf + sizeof(struct rpc_reply) + sizeof(struct rpc_verifier) + XDR_UNIT;

    return xdr_get_u32(p);
}

/*
 * RPCBIND v3 operations vtable
 */
struct portmap_ops rpcbv3_ops = {
    .null = rpcbv3_null,
    .getport = rpcbv3_getaddr,
    .dump = rpcbv3_dump,
};
