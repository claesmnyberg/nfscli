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
 * portmap_ops.h - Portmapper/RPCBIND operations vtable
 *
 * Dispatch tables for portmapper v2 and rpcbind v3:
 * - Portmapper v2: Port-based lookups (RFC 1833 Section 3)
 * - RPCBIND v3: Universal address lookups (RFC 1833 Section 2)
 */

#ifndef PORTMAP_OPS_H
#define PORTMAP_OPS_H

#include <stdint.h>

struct nfsctx;
struct portmap_dump_entry;

/*
 * Portmapper/RPCBIND protocol versions
 */
#define PMAP_VERSION_2 2 /* Portmapper v2 (port-based) */
#define PMAP_VERSION_3 3 /* RPCBIND v3 (uaddr-based) */

/*
 * Portmapper v2 functions (portmapv2.c)
 *
 * These use simple port number responses.
 */
int pmapv2_null(struct nfsctx *ctx);
int pmapv2_getport(struct nfsctx *ctx, uint32_t program, uint32_t version);
int pmapv2_dump(struct nfsctx *ctx, struct portmap_dump_entry **de);

/*
 * RPCBIND v3 functions (portmapv3.c)
 *
 * These use universal addresses in responses.
 * getaddr returns port extracted from uaddr for compatibility.
 */
int rpcbv3_null(struct nfsctx *ctx);
int rpcbv3_getaddr(struct nfsctx *ctx, uint32_t program, uint32_t version);
int rpcbv3_dump(struct nfsctx *ctx, struct portmap_dump_entry **de);
uint32_t rpcbv3_gettime(struct nfsctx *ctx);

/*
 * Portmapper operations vtable
 *
 * Provides unified interface across portmapper versions.
 * null() - Test connectivity
 * getport() - Get port for program/version (returns network byte order, 0 if not found, -1 on error)
 * dump() - List all registered services
 */
struct portmap_ops {
    int (*null)(struct nfsctx *ctx);
    int (*getport)(struct nfsctx *ctx, uint32_t program, uint32_t version);
    int (*dump)(struct nfsctx *ctx, struct portmap_dump_entry **de);
};

/* Vtables for each version */
extern struct portmap_ops pmapv2_ops;
extern struct portmap_ops rpcbv3_ops;

/*
 * Get ops table for specific version
 */
static inline struct portmap_ops *
portmap_get_ops(int version)
{
    switch (version) {
    case PMAP_VERSION_2:
        return &pmapv2_ops;
    case PMAP_VERSION_3:
        return &rpcbv3_ops;
    default:
        return NULL;
    }
}

#endif /* PORTMAP_OPS_H */
