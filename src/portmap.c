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
 * portmap.c - Portmapper/RPCBIND client (RFC 1833)
 *
 * Version-agnostic wrapper layer that dispatches to:
 *   - portmapv2.c for portmapper v2 operations
 *   - portmapv3.c for rpcbind v3 operations
 *
 * Provides version probing, caching, and fallback logic.
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

/*
 * GETPORT - Query port for an RPC program/version.
 *
 * Tries portmapper v2 first, falls back to rpcbind v3 on failure.
 * Returns port in network byte order, or 0 if service unavailable.
 */
uint16_t
portmap_getport(struct nfsctx *ctx, uint32_t program, uint32_t version)
{
    int port;

    /* Short-circuit if portmapper already known unreachable */
    if (ctx->portmap.unreachable)
        return 0;

    /* If portmap version is forced, use only that version */
    if (ctx->portmap.version == 3) {
        port = rpcbv3_getaddr(ctx, program, version);
        return (port > 0) ? (uint16_t)port : 0;
    }
    if (ctx->portmap.version == 2) {
        port = pmapv2_getport(ctx, program, version);
        return (port > 0) ? (uint16_t)port : 0;
    }

    /* Auto: try portmapper v2 first */
    port = pmapv2_getport(ctx, program, version);
    if (port > 0)
        return (uint16_t)port;

    /* If v2 failed (not just "not registered"), try v3 */
    if (port < 0) {
        print(V_DETAIL, ctx, "Portmapper v2 failed, trying rpcbind v3\n");
        port = rpcbv3_getaddr(ctx, program, version);
        if (port > 0)
            return (uint16_t)port;
    }

    return 0;
}

/*
 * RPC NULL procedure probe - verify a specific program/version is available.
 *
 * Calls RPC procedure 0 (NULL) which every RPC service must implement.
 * If the server returns PROG_MISMATCH, the version is not supported.
 * This is used to verify versions when GETPORT may be unreliable.
 *
 * Returns 1 if version is supported, 0 if not supported or error.
 */
int
rpc_null_probe(struct nfsctx *ctx, uint32_t program, uint32_t version,
    uint16_t port)
{
    struct {
        struct rpc_call r;
        struct rpc_creds c;
        struct rpc_verifier v;
    } __attribute__((packed)) req;

    struct {
        struct rpc_reply r;
        struct rpc_verifier v;
        uint32_t accept_state;
    } __attribute__((packed)) reply;

    uint32_t xid;
    ssize_t len;

    xid = rand();
    memset(&req, 0, sizeof(req));
    RPC_INIT_REQ(&req, program, version, 0); /* procedure 0 = NULL */

    if (udp_write(ctx, ctx->server.ip, port, (uint8_t *)&req, sizeof(req)) < 0)
        return 0;

    memset(&reply, 0, sizeof(reply));
    len = rpc_recv_xid(ctx, ctx->server.ip, port,
        (uint8_t *)&reply, sizeof(reply), xid);
    if (len < (ssize_t)sizeof(reply))
        return 0;

    /* Check RPC accepted */
    if (ntohl(reply.r.reply_state) != RPC_ACCEPTED)
        return 0;

    /* Check accept_state - PROG_MISMATCH means version not supported */
    if (ntohl(reply.accept_state) == RPC_ERR_PROG_MISMATCH)
        return 0;

    /* SUCCESS or other accept_state means version is available */
    return (ntohl(reply.accept_state) == RPC_EXEC_SUCCESS) ? 1 : 0;
}

/*
 * Extract version info for a program from a dump list.
 *
 * Scans dump entries for matching program/version/protocol (UDP only).
 * Returns bitmask of available versions. If port_out is non-NULL,
 * stores port of highest available version.
 */
static uint8_t
dump_extract_versions(struct portmap_dump_entry *de, uint32_t program,
    uint8_t min_ver, uint8_t max_ver, uint16_t *port_out)
{
    struct portmap_dump_entry *cur;
    uint8_t mask = 0;
    uint16_t best_port = 0;
    uint8_t best_ver = 0;

    for (cur = de; cur != NULL; cur = cur->next) {
        if (cur->pm_prog != program)
            continue;
        if (cur->pm_prot != IPPROTO_UDP)
            continue;
        if (cur->pm_vers < min_ver || cur->pm_vers > max_ver)
            continue;
        if (cur->pm_vers >= 8)
            continue; /* Version too high for bitmask */

        mask |= (uint8_t)(1U << cur->pm_vers);

        if (cur->pm_vers > best_ver) {
            best_ver = (uint8_t)cur->pm_vers;
            best_port = htons((uint16_t)cur->pm_port);
        }
    }

    if (port_out != NULL)
        *port_out = best_port;

    return mask;
}

/*
 * Check if a program uses different ports for different versions.
 * Returns 1 if multiple versions exist with different ports, 0 otherwise.
 */
static int
dump_has_perversion_ports(struct portmap_dump_entry *de, uint32_t program)
{
    struct portmap_dump_entry *cur;
    uint32_t first_port = 0;
    int found_any = 0;

    for (cur = de; cur != NULL; cur = cur->next) {
        if (cur->pm_prog != program)
            continue;
        if (cur->pm_prot != IPPROTO_UDP)
            continue;
        if (cur->pm_port == 0)
            continue;

        if (!found_any) {
            first_port = cur->pm_port;
            found_any = 1;
        } else if (cur->pm_port != first_port) {
            return 1; /* Different port found */
        }
    }

    return 0;
}

/*
 * Probe version range using GETPORT + NULL verification (fallback method).
 *
 * This is less efficient than DUMP but works when DUMP is unavailable.
 * Iterates from max_ver down, using NULL probe to verify each version.
 * Also detects buggy portmappers that return ports for unregistered versions.
 */
static uint8_t
portmap_probe_fallback(struct nfsctx *ctx, uint32_t program,
    uint8_t min_ver, uint8_t max_ver, uint16_t *port_out)
{
    uint8_t mask = 0;
    uint16_t port, best_port = 0;
    int ver;

    print(V_DETAIL, ctx, "DUMP unavailable, falling back to GETPORT+NULL probe\n");

    for (ver = max_ver; ver >= min_ver; ver--) {
        port = portmap_getport(ctx, program, (uint32_t)ver);
        if (port == 0)
            continue;

        /* Verify with NULL probe */
        if (!rpc_null_probe(ctx, program, (uint32_t)ver, port)) {
            /* GETPORT returned port but version doesn't work - buggy portmapper */
            if (ctx->portmap.getport_status == PMAP_GETPORT_UNKNOWN) {
                ctx->portmap.getport_status = PMAP_GETPORT_BUGGY;
                print(V_DETAIL, ctx, "Note: portmapper returns ports for "
                                     "unregistered versions\n");
            }
            continue;
        }

        /* NULL probe succeeded - GETPORT is reliable */
        if (ctx->portmap.getport_status == PMAP_GETPORT_UNKNOWN)
            ctx->portmap.getport_status = PMAP_GETPORT_OK;

        mask |= (uint8_t)(1U << ver);
        if (best_port == 0)
            best_port = port;
    }

    if (port_out != NULL)
        *port_out = best_port;

    /* Record GETPORT as discovery method if we found anything */
    if (mask != 0)
        ctx->portmap.discovery_method = 2;

    return mask;
}

/*
 * Probe version range for an RPC program.
 *
 * Preferred method: Uses PMAPPROC_DUMP to reliably enumerate registered
 * versions. This avoids the GETPORT bug where some portmappers return a port
 * for ANY version of a program (see portmap.h header for details).
 *
 * Caching: DUMP results are cached in ctx->portmap.cache for subsequent probes.
 * Use portmap_cache_invalidate() to clear the cache if needed.
 *
 * Fallback: If DUMP fails (restricted systems, old implementations), falls
 * back to iterating GETPORT calls with NULL procedure verification.
 *
 * Returns bitmask of available versions (bit N set = version N available).
 * If port_out is non-NULL, stores port of highest available version.
 */
uint8_t
portmap_probe(struct nfsctx *ctx, uint32_t program,
    uint8_t min_ver, uint8_t max_ver, uint16_t *port_out)
{
    struct portmap_dump_entry *de;

    /* Check if DUMP is known to have failed */
    if (ctx->portmap.dump_status == PMAP_DUMP_UNAVAIL) {
        /* Don't retry if portmapper is unreachable */
        if (ctx->portmap.unreachable)
            return 0;
        return portmap_probe_fallback(ctx, program, min_ver, max_ver, port_out);
    }

    /* Use cached DUMP results if available */
    if (ctx->portmap.cache_valid && ctx->portmap.cache != NULL) {
        de = ctx->portmap.cache;
    } else {
        /* Try DUMP - most reliable method */
        if (portmap_dump(ctx, &de) < 0) {
            /* DUMP failed, remember this and use fallback */
            ctx->portmap.dump_status = PMAP_DUMP_UNAVAIL;
            /* Don't retry if portmapper is unreachable */
            if (ctx->portmap.unreachable)
                return 0;
            return portmap_probe_fallback(ctx, program, min_ver, max_ver, port_out);
        }
        /* Cache successful DUMP results */
        ctx->portmap.dump_status = PMAP_DUMP_OK;
        ctx->portmap.discovery_method = 1;
        ctx->portmap.cache = de;
        ctx->portmap.cache_valid = 1;

        /* Detect if mount daemon uses per-version ports (common on Linux) */
        ctx->portmap.mount_perversion_ports =
            dump_has_perversion_ports(de, PMAP_PROG_MOUNTD);
    }

    /* Note: don't free de - it's now cached in ctx->portmap.cache */
    return dump_extract_versions(de, program, min_ver, max_ver, port_out);
}

/*
 * Verify a specific version is available using GETPORT + NULL probe.
 *
 * Use this when the user explicitly requests a specific version (e.g.,
 * "getport mount 3"). First calls GETPORT to obtain the port, then verifies
 * the version with a NULL procedure call to handle buggy portmappers.
 *
 * If cache is available, extracts port from cache to avoid GETPORT RPC.
 *
 * Returns port in network byte order, or 0 if version unavailable.
 */
uint16_t
portmap_verify(struct nfsctx *ctx, uint32_t program, uint32_t version)
{
    uint16_t port = 0;

    /* Check cache first */
    if (ctx->portmap.cache_valid && ctx->portmap.cache != NULL) {
        struct portmap_dump_entry *cur;
        for (cur = ctx->portmap.cache; cur != NULL; cur = cur->next) {
            if (cur->pm_prog == program && cur->pm_vers == version &&
                cur->pm_prot == IPPROTO_UDP && cur->pm_port > 0) {
                port = htons((uint16_t)cur->pm_port);
                break;
            }
        }
    }

    /* Fall back to GETPORT if not in cache */
    if (port == 0)
        port = portmap_getport(ctx, program, version);
    if (port == 0)
        return 0;

    /* Verify with NULL probe to handle buggy portmappers */
    if (!rpc_null_probe(ctx, program, version, port)) {
        /* GETPORT returned port but version doesn't actually work */
        if (ctx->portmap.getport_status == PMAP_GETPORT_UNKNOWN) {
            ctx->portmap.getport_status = PMAP_GETPORT_BUGGY;
            print(V_DETAIL, ctx, "Note: portmapper returns ports for "
                                 "unregistered versions\n");
        }
        return 0;
    }

    /* NULL probe succeeded - GETPORT is reliable */
    if (ctx->portmap.getport_status == PMAP_GETPORT_UNKNOWN)
        ctx->portmap.getport_status = PMAP_GETPORT_OK;

    /* Record that we used GETPORT (if not already set) */
    if (ctx->portmap.discovery_method == 0)
        ctx->portmap.discovery_method = 2;

    return port;
}

/*
 * Free a linked list of portmap dump entries.
 */
void
portmap_dump_free(struct portmap_dump_entry *de)
{
    while (de != NULL) {
        struct portmap_dump_entry *next = de->next;
        free(de);
        de = next;
    }
}

/*
 * Invalidate the portmap cache.
 *
 * Called when cached data may be stale (e.g., RPC failure to a cached port).
 * Clears the cache but preserves status flags (dump_status, getport_status,
 * discovery_method) since those reflect server behavior, not transient state.
 */
void
portmap_cache_invalidate(struct nfsctx *ctx)
{
    if (ctx->portmap.cache != NULL) {
        portmap_dump_free(ctx->portmap.cache);
        ctx->portmap.cache = NULL;
    }
    ctx->portmap.cache_valid = 0;
    ctx->portmap.unreachable = 0; /* Allow retry after invalidation */
}

/*
 * DUMP - List all registered RPC services.
 *
 * Respects forced portmap version, otherwise defaults to v2.
 * Note: This is primarily used internally by portmap_probe().
 * The 'rpcinfo' command handles version selection itself.
 */
int
portmap_dump(struct nfsctx *ctx, struct portmap_dump_entry **de)
{
    if (ctx->portmap.version == 3)
        return rpcbv3_dump(ctx, de);
    return pmapv2_dump(ctx, de);
}

/*
 * NULL - Portmapper connectivity test for specific version.
 *
 * Returns 0 on success, -1 on error.
 */
int
portmap_null_version(struct nfsctx *ctx, uint32_t version)
{
    struct portmap_ops *ops = portmap_get_ops((int)version);

    if (ops == NULL || ops->null == NULL) {
        errno = ENOTSUP;
        return -1;
    }

    return ops->null(ctx);
}

/*
 * NULL - Portmapper connectivity test (v2).
 *
 * Returns 0 on success, -1 on error.
 */
int
portmap_null(struct nfsctx *ctx)
{
    return pmapv2_null(ctx);
}

/*
 * Probe available portmap/rpcbind versions.
 *
 * Tests v2 (portmapper) and v3 (rpcbind) by calling NULL procedure.
 * Returns bitmask: bit 2 = v2 available, bit 3 = v3 available.
 */
uint8_t
portmap_probe_versions(struct nfsctx *ctx)
{
    uint8_t mask = 0;

    /* Test portmapper v2 */
    if (portmap_null_version(ctx, PMAP_VERSION_2) == 0) {
        mask |= (1U << PMAP_VERSION_2);
        print(V_DEBUG, ctx, "Portmap v2 available\n");
    }

    /* Test rpcbind v3 */
    if (portmap_null_version(ctx, PMAP_VERSION_3) == 0) {
        mask |= (1U << PMAP_VERSION_3);
        print(V_DEBUG, ctx, "Rpcbind v3 available\n");
    }

    return mask;
}

/*
 * Initialize portmap version detection.
 *
 * Probes server for available portmap/rpcbind versions and caches result.
 * Called during connection setup to enable version-aware operations.
 */
void
init_portmap_version(struct nfsctx *ctx)
{
    if (ctx->portmap.version_mask != 0)
        return; /* Already initialized */

    ctx->portmap.version_mask = portmap_probe_versions(ctx);

    if (ctx->portmap.version_mask == 0) {
        print(V_INFO, ctx, "Warning: portmapper not responding\n");
        ctx->portmap.unreachable = 1;
    }
}
