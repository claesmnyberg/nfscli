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
 * portmapv2.c - Portmapper v2 protocol (RFC 1833)
 *
 * Implements portmapper v2 procedures:
 *   PMAPPROC_NULL    (0) - Connectivity test
 *   PMAPPROC_SET     (1) - Register service (not implemented - requires root)
 *   PMAPPROC_UNSET   (2) - Unregister service (not implemented - requires root)
 *   PMAPPROC_GETPORT (3) - Get port for program/version
 *   PMAPPROC_DUMP    (4) - List all registered services
 */

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

/* Portmapper v2 procedure numbers (RFC 1833 Section 3) */
#define PMAPPROC_NULL    0
#define PMAPPROC_SET     1
#define PMAPPROC_UNSET   2
#define PMAPPROC_GETPORT 3
#define PMAPPROC_DUMP    4
#define PMAPPROC_CALLIT  5

/*
 * Parse a portmap v2 mapping entry (4 x u32: prog, vers, prot, port).
 * Returns pointer past entry on success, NULL if bounds exceeded.
 */
static const uint8_t *
parse_pmap_entry(const uint8_t *p, const uint8_t *end,
    struct portmap_dump_entry *e)
{
    if (p + 4 * XDR_UNIT > end)
        return NULL;
    e->pm_prog = xdr_get_u32(p);
    e->pm_vers = xdr_get_u32(p + XDR_UNIT);
    e->pm_prot = xdr_get_u32(p + 2 * XDR_UNIT);
    e->pm_port = xdr_get_u32(p + 3 * XDR_UNIT);
    return p + 4 * XDR_UNIT;
}

/*
 * pmapv2_null - Test portmapper v2 connectivity.
 *
 * RFC 1833 Section 3.2 - PMAPPROC_NULL (procedure 0)
 * Does nothing. Used to test portmapper availability.
 *
 * Returns 0 on success, -1 on error.
 */
int
pmapv2_null(struct nfsctx *ctx)
{
    return rpc_simple_call(ctx, RPC_PROGRAM_PORTMAP, PMAP_VERSION_2,
        RPC_PORTMAP_PROCEDURE_NULL, ctx->ports.rpc,
        NULL, 0, NULL, 0, NULL);
}

/*
 * pmapv2_getport - Query port for an RPC program/version.
 *
 * RFC 1833 Section 3.2 - PMAPPROC_GETPORT (procedure 3)
 *
 *   "Given a program number, version number, and transport protocol number,
 *    this procedure returns the port number on which the program is awaiting
 *    call requests. A port value of zeros means the program has not been
 *    registered."
 *
 * Wire format (request):
 *   struct mapping {
 *       unsigned int prog;   -- program number
 *       unsigned int vers;   -- version number
 *       unsigned int prot;   -- IPPROTO_TCP (6) or IPPROTO_UDP (17)
 *       unsigned int port;   -- ignored in request
 *   };
 *
 * Wire format (response):
 *   unsigned int port;       -- port number (0 = not registered)
 *
 * Returns port in network byte order, 0 if not registered, -1 on RPC error.
 */
int
pmapv2_getport(struct nfsctx *ctx, uint32_t program, uint32_t version)
{
    struct {
        struct rpc_call r;
        struct rpc_creds c;
        struct rpc_verifier v;
        uint32_t program;
        uint32_t version;
        uint32_t proto;
        uint32_t port;
    } __attribute__((packed)) req;

    struct {
        struct rpc_reply r;
        struct rpc_verifier v;
        uint32_t accept_state;
        uint32_t port;
    } __attribute__((packed)) reply;

    uint32_t xid;
    ssize_t len;

    xid = rand();
    print(V_TRACE, ctx, "PMAP2 GETPORT XID 0x%08x prog=%u vers=%u\n",
        xid, program, version);

    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req, RPC_PROGRAM_PORTMAP, PMAP_VERSION_2, PMAPPROC_GETPORT);

    req.program = htonl(program);
    req.version = htonl(version);
    req.proto = htonl(IPPROTO_UDP);
    req.port = htonl(0);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.rpc,
            (uint8_t *)&req, sizeof(req)) < 0)
        return -1;

    memset(&reply, 0, sizeof(reply));
    len = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.rpc,
        (uint8_t *)&reply, sizeof(reply), xid);

    if (len < (ssize_t)sizeof(reply)) {
        if (len < 0)
            ctx->portmap.unreachable = 1;
        errno = EPROTO;
        return -1;
    }

    if (ntohl(reply.r.reply_state) != RPC_ACCEPTED) {
        errno = EPROTO;
        return -1;
    }

    /* port=0 means service not registered */
    return htons(ntohl(reply.port));
}

/*
 * pmapv2_dump - List all registered RPC services.
 *
 * RFC 1833 Section 3.2 - PMAPPROC_DUMP (procedure 4)
 *
 *   "PMAPPROC_DUMP returns the complete contents of the port mapper
 *    database. The procedure takes no parameters and returns a list
 *    of program, version, protocol, and port values."
 *
 * Wire format (request):
 *   void;                     -- no parameters
 *
 * Wire format (response):
 *   struct pmaplist {
 *       mapping map;          -- program, version, protocol, port
 *       pmaplist *next;       -- value_follows (XDR bool) + next entry
 *   };
 *
 * Returns entry count on success, -1 on error.
 * Caller must free the returned list with portmap_dump_free().
 */
int
pmapv2_dump(struct nfsctx *ctx, struct portmap_dump_entry **de)
{
    struct {
        struct rpc_call r;
        struct rpc_creds c;
        struct rpc_verifier v;
    } __attribute__((packed)) req;

    struct rpc_reply_hdr {
        struct rpc_reply r;
        struct rpc_verifier v;
        uint32_t accept_state;
    } __attribute__((packed)) * rh;

    uint8_t buf[65535];
    uint8_t *pt, *end;
    uint32_t xid;
    uint32_t value_follows;
    ssize_t len;
    struct portmap_dump_entry *cur;
    size_t entry_count;

    *de = NULL;

    xid = rand();
    print(V_TRACE, ctx, "PMAP2 DUMP XID 0x%08x\n", xid);

    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req, RPC_PROGRAM_PORTMAP, PMAP_VERSION_2, PMAPPROC_DUMP);

    if (udp_write(ctx, ctx->server.ip, ctx->ports.rpc,
            (uint8_t *)&req, sizeof(req)) < 0)
        return -1;

    memset(buf, 0, sizeof(buf));
    len = rpc_recv_xid(ctx, ctx->server.ip, ctx->ports.rpc,
        buf, sizeof(buf), xid);

    if (len < (ssize_t)sizeof(struct rpc_reply_hdr)) {
        if (!g_interrupted && len >= 0)
            fprintf(stderr, "** Error: Bad length (%zd) of received data\n", len);
        if (len < 0)
            ctx->portmap.unreachable = 1;
        errno = EPROTO;
        return -1;
    }

    rh = (struct rpc_reply_hdr *)buf;
    RPC_CHECK_REPLY(ctx, rh, len);

    pt = buf + sizeof(struct rpc_reply_hdr);
    end = buf + len;

    /* Check bounds for first value_follows */
    if (pt + XDR_UNIT > end) {
        fprintf(stderr, "** Error: Response too short for value_follows\n");
        errno = EPROTO;
        return -1;
    }
    value_follows = xdr_get_u32(pt);
    pt += XDR_UNIT;

    if (value_follows) {
        cur = calloc(1, sizeof(struct portmap_dump_entry));
        if (cur == NULL)
            return -1;
        *de = cur;
    }

    /* Parse entry list */
    entry_count = 0;

    while (value_follows == 1) {
        /* Prevent overflow before parsing entry */
        if (entry_count >= PMAP_DUMP_MAX_ENTRIES) {
            fprintf(stderr, "** Error: Too many portmap entries (max %d)\n",
                PMAP_DUMP_MAX_ENTRIES);
            portmap_dump_free(*de);
            *de = NULL;
            errno = EPROTO;
            return -1;
        }

        /* Parse entry (bounds-checked by helper) */
        pt = (uint8_t *)parse_pmap_entry(pt, end, cur);
        if (pt == NULL) {
            fprintf(stderr, "** Error: Response truncated in entry list\n");
            portmap_dump_free(*de);
            *de = NULL;
            errno = EPROTO;
            return -1;
        }
        entry_count++;

        /* Check bounds for next value_follows */
        if (pt + XDR_UNIT > end) {
            fprintf(stderr, "** Error: Response truncated after entry\n");
            portmap_dump_free(*de);
            *de = NULL;
            errno = EPROTO;
            return -1;
        }
        value_follows = xdr_get_u32(pt);
        pt += XDR_UNIT;

        if (value_follows) {
            /* Check will be performed at top of loop before parsing next entry */
            cur->next = calloc(1, sizeof(struct portmap_dump_entry));
            if (cur->next == NULL) {
                portmap_dump_free(*de);
                *de = NULL;
                return -1;
            }
            cur = cur->next;
        }
    }

    return entry_count;
}

/*
 * Portmapper v2 operations vtable
 */
struct portmap_ops pmapv2_ops = {
    .null = pmapv2_null,
    .getport = pmapv2_getport,
    .dump = pmapv2_dump,
};
