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
 * portmap.h - Portmapper/RPCBIND client (RFC 1833)
 *
 * Implements portmapper operations: GETPORT, DUMP, and version probing.
 * Used to discover NFS and mount daemon ports.
 */

#ifndef PORTMAP_H
#define PORTMAP_H

#include <stddef.h>
#include <stdint.h>

/*
 * RPC program numbers (RFC 5531 Appendix B)
 *
 * The portmapper (RFC 1833) runs on port 111 and maps RPC program/version
 * pairs to network ports. Program numbers 0x00000000-0x1FFFFFFF are defined
 * by the RPC standard, 0x20000000-0x3FFFFFFF are user-defined.
 */

/* Core RPC services */
#define PMAP_PROG_PORTMAPPER 100000 /* RFC 1833: Port Mapper / RPCBIND */
#define PMAP_PROG_RSTATD     100001
#define PMAP_PROG_RUSERSD    100002
#define PMAP_PROG_NFS        100003 /* RFC 1094/1813: NFS */
#define PMAP_PROG_YP_SERV    100004
#define PMAP_PROG_MOUNTD     100005 /* RFC 1094/1813: Mount daemon */
#define PMAP_PROG_YP_BIND    100006
#define PMAP_PROG_YP_XFR     100007
#define PMAP_PROG_YP_SERV2   100008
#define PMAP_PROG_WALLD      100009
#define PMAP_PROG_RQUOTA     100010
#define PMAP_PROG_SPRAY      100011
#define PMAP_PROG_WALLCD     100012
#define PMAP_PROG_BOOTPARAM  100013

/* NFS */
#define PMAP_PROG_LLOCKMGR    100020
#define PMAP_PROG_NLOCKMGR    100021
#define PMAP_PROG_STATUS_MON  100024
#define PMAP_PROG_YP_UPDATED  100028
#define PMAP_PROG_YP_XFRD     100029
#define PMAP_PROG_AMM         100030
#define PMAP_PROG_KERBD       100032
#define PMAP_PROG_NFSD        100033
#define PMAP_PROG_NFS_ACL_SOL 100039

/* NIS / YP */
#define PMAP_PROG_KEYSERV  100100
#define PMAP_PROG_KEYENVOY 100101
#define PMAP_PROG_SECUREFS 100102

/* Additional RPC programs */
#define PMAP_PROG_RSTAT  100200
#define PMAP_PROG_RUSERS 100201
#define PMAP_PROG_SPRAY2 100202
#define PMAP_PROG_WALL2  100203

/* Kerberos */
#define PMAP_PROG_KRB_V4 100221
#define PMAP_PROG_KRB_V5 100222

/* Linux-specific extensions */
#define PMAP_PROG_NFS_ACL_LINUX 100227
#define PMAP_PROG_NFS_RDMA      100403

/* Solaris-specific */
#define PMAP_PROG_METAD    100229 /* metad (Solaris Volume Manager metadata daemon) */
#define PMAP_PROG_METAMHD  100230 /* metamhd (multi-host metadata daemon) */
#define PMAP_PROG_SADMIND  100232 /* sadmind (Solaris remote admin) */
#define PMAP_PROG_UFSD     100233 /* ufsd (UFS server daemon) */
#define PMAP_PROG_GRPSERVD 100234 /* grpservd */
#define PMAP_PROG_CACHEFSD 100235 /* cachefsd */
#define PMAP_PROG_METAMEDD 100242 /* metamedd (mediator daemon for HA) */

/* HP-UX specific */
#define PMAP_PROG_CMSD       100068 /* Cluster Metadata Service (HP-UX) */
#define PMAP_PROG_TTDBSERVER 100083 /* HP transactional DB service */

/*
 * Portmapper protocol versions (RFC 1833)
 * v2 = original portmapper (PMAPPROC_*)
 * v3 = rpcbind (RPCBPROC_*)
 */
#define PMAP_VERSION_2 2
#define PMAP_VERSION_3 3

/*
 * Transport protocol values for portmap (RFC 1833)
 * These are IANA IP protocol numbers.
 */
#define PMAP_PROT_NONE 0
#define PMAP_PROT_TCP  6  /* IPPROTO_TCP */
#define PMAP_PROT_UDP  17 /* IPPROTO_UDP */

/* DoS prevention limit for DUMP parsing */
#define PMAP_DUMP_MAX_ENTRIES 10000

struct portmap_dump_entry {
    uint32_t pm_prog;
    uint32_t pm_vers;
    uint32_t pm_prot;
    uint32_t pm_port;
    /* rpcbind v3 extended fields (empty for v2) */
    char pm_netid[16]; /* "udp", "tcp", "udp6", "tcp6", "ticots", "ticotso", etc */
    char pm_owner[32]; /* owner string (usually "superuser" or empty) */
    struct portmap_dump_entry *next;
};

struct nfsctx;

/*
 * portmap.c - Portmapper/rpcbind client functions
 *
 * RELIABILITY NOTE:
 * Some portmapper implementations (notably HP-UX, some older systems) have a
 * bug where GETPORT/GETADDR return a port for ANY registered version of a
 * program, rather than returning 0 for unregistered versions as specified in
 * RFC 1833. This affects both portmapper v2 (PMAPPROC_GETPORT) and rpcbind v3
 * (RPCBPROC_GETADDR) since the bug is in the server implementation, not the
 * protocol.
 *
 * To work around this, version discovery uses DUMP (which returns actual
 * registered program/version pairs) rather than iterating GETPORT calls.
 * For explicit version verification, we call the RPC NULL procedure on the
 * target service - if it returns PROG_MISMATCH, the version is not supported.
 *
 * portmap_getport() - Query port for specific program/version.
 *   Tries portmapper v2 (PMAPPROC_GETPORT) first, falls back to rpcbind v3
 *   (RPCBPROC_GETADDR) on failure. Returns port in network byte order, or 0.
 *   WARNING: May return a port even if version is not registered (see above).
 *
 * portmap_probe() - Discover available versions for a program.
 *   Uses DUMP to reliably enumerate registered versions (avoids GETPORT bug).
 *   Returns bitmask of available versions (bit N = version N available).
 *   If port_out is non-NULL, stores port of highest available version.
 *
 * portmap_verify() - Verify a specific version is available.
 *   Calls GETPORT to get port, then NULL procedure to verify version works.
 *   Use this when user explicitly requests a specific version.
 *   Returns port in network byte order, or 0 if version unavailable.
 *
 * portmap_dump() - List all registered RPC services.
 *   Returns linked list of all mappings. Caller must free with portmap_dump_free().
 */
uint16_t portmap_getport(struct nfsctx *ctx, uint32_t program, uint32_t version);
uint8_t portmap_probe(struct nfsctx *ctx, uint32_t program,
    uint8_t min_ver, uint8_t max_ver, uint16_t *port_out);
uint16_t portmap_verify(struct nfsctx *ctx, uint32_t program, uint32_t version);
int portmap_dump(struct nfsctx *ctx, struct portmap_dump_entry **de);
void portmap_dump_free(struct portmap_dump_entry *de);
void portmap_cache_invalidate(struct nfsctx *ctx);
int portmap_null(struct nfsctx *ctx);
int portmap_null_version(struct nfsctx *ctx, uint32_t version);

/* Low-level version-specific functions (for diagnostics) */
int rpc_null_probe(struct nfsctx *ctx, uint32_t program, uint32_t version,
    uint16_t port);

/* Version detection */
uint8_t portmap_probe_versions(struct nfsctx *ctx);
void init_portmap_version(struct nfsctx *ctx);

#endif /* PORTMAP_H */
