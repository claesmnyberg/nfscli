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
 * rpc.h - RPC utilities (RFC 1057)
 *
 * Shared RPC-level utilities for NFS, mount, and portmap clients.
 * Handles XDR encoding, AUTH_UNIX credentials, and RPC message framing.
 */

#ifndef RPC_H
#define RPC_H

#include <arpa/inet.h> /* ntohl */
#include <stddef.h>    /* NULL */
#include <stdint.h>
#include <sys/types.h>

#include "xdr.h"       /* alignment-safe XDR primitives */

struct nfsctx;

/* Machine name for AUTH_UNIX credentials */
#define MACHINE_NAME     "desktop"
#define MACHINE_NAME_LEN 7

/* RPC buffer sizes for request/reply packets */
#define RPC_BUFSIZE_SMALL 4096 /* Small operations (write, read request) */
#define RPC_BUFSIZE_LARGE 8192 /* Large operations (most NFS calls) */

/*
 * RPC message types (RFC 5531 Section 9)
 */
#define RPC_MSG_TYPE_CALL  0
#define RPC_MSG_TYPE_REPLY 1

/*
 * RPC program numbers (RFC 5531 Appendix B, RFC 1833)
 * These are registered with IANA.
 */
#define RPC_PROGRAM_PORTMAP 100000 /* RFC 1833: Port Mapper / RPCBIND */
#define RPC_PROGRAM_NFS     100003 /* RFC 1094/1813: NFS */
#define RPC_PROGRAM_MOUNT   100005 /* RFC 1094/1813: Mount daemon */

/*
 * Portmap procedures (RFC 1833 Section 3)
 */
#define RPC_PORTMAP_PROCEDURE_NULL    0 /* PMAPPROC_NULL */
#define RPC_PORTMAP_PROCEDURE_GETPORT 3 /* PMAPPROC_GETPORT */
#define RPC_PORTMAP_PROCEDURE_DUMP    4 /* PMAPPROC_DUMP */

/*
 * Mount procedures (RFC 1094 Appendix A, RFC 1813 Section 5)
 */
#define RPC_MOUNT_PROCEDURE_NULL    0 /* MOUNTPROC_NULL */
#define RPC_MOUNT_PROCEDURE_MNT     1 /* MOUNTPROC_MNT */
#define RPC_MOUNT_PROCEDURE_DUMP    2 /* MOUNTPROC_DUMP */
#define RPC_MOUNT_PROCEDURE_UMNT    3 /* MOUNTPROC_UMNT */
#define RPC_MOUNT_PROCEDURE_UMNTALL 4 /* MOUNTPROC_UMNTALL */
#define RPC_MOUNT_PROCEDURE_EXPORT  5 /* MOUNTPROC_EXPORT */

/*
 * NFS procedures (RFC 1094 Section 2.2, RFC 1813 Section 3.3)
 */
#define RPC_NFS_PROCEDURE_NULL 0 /* NFSPROC_NULL / NFSPROC3_NULL */

/*
 * RPC accept_stat values (RFC 5531 Section 9, RFC 1057 Section 9)
 */
#define RPC_EXEC_SUCCESS      0 /* SUCCESS: RPC executed successfully */
#define RPC_ERR_PROG_UNAVAIL  1 /* PROG_UNAVAIL: program not available */
#define RPC_ERR_PROG_MISMATCH 2 /* PROG_MISMATCH: version not supported */
#define RPC_ERR_PROC_UNAVAIL  3 /* PROC_UNAVAIL: procedure not available */
#define RPC_ERR_GARBAGE_ARGS  4 /* GARBAGE_ARGS: parameters undecodable */
#define RPC_ERR_SYSTEM        5 /* SYSTEM_ERR: system error (RFC 5531 only) */

/*
 * Authentication flavors (RFC 5531 Section 8.2, RFC 1057 Section 9.1)
 */
#define FLAVOR_AUTH_NULL 0 /* AUTH_NONE: no authentication */
#define FLAVOR_AUTH_UNIX 1 /* AUTH_SYS/AUTH_UNIX: Unix-style uid/gid */
#define FLAVOR_AUTH_DES  3 /* AUTH_DES: DES-based authentication */
#define FLAVOR_AUTH_GSS  6 /* RPCSEC_GSS: GSS-API based (Kerberos) */

/*
 * RPC rejection reasons (reply_stat = RPC_DENIED)
 */
#define RPC_REJECT_MISMATCH 0 /* RPC version mismatch */
#define RPC_REJECT_AUTH     1 /* Authentication error */

/*
 * Authentication status codes (when reject = RPC_REJECT_AUTH)
 */
#define AUTH_STAT_OK           0 /* success */
#define AUTH_STAT_BADCRED      1 /* bad credential (seal broken) */
#define AUTH_STAT_REJECTEDCRED 2 /* client must begin new session */
#define AUTH_STAT_BADVERF      3 /* bad verifier (seal broken) */
#define AUTH_STAT_REJECTEDVERF 4 /* verifier expired or replayed */
#define AUTH_STAT_TOOWEAK      5 /* rejected for security reasons */

/*
 * RPC reply header size (xid + msgtype + reply_state = 12 bytes)
 * Used by helper functions before struct rpc_reply is defined.
 */
#define RPC_REPLY_HDR_SIZE 12

struct rpc_call {
    uint32_t xid;
    uint32_t msgtype;
    uint32_t version;
    uint32_t program;
    uint32_t program_version;
    uint32_t procedure;
} __attribute__((packed));

struct rpc_creds {
    uint32_t flavor;
    uint32_t length;
    uint32_t stamp;
    uint32_t machine_name_len;
    uint8_t machine_name[8];
    uint32_t uid;
    uint32_t gid;
    uint32_t auxgids;
} __attribute__((packed));

struct rpc_verifier {
    uint32_t flavor;
    uint32_t length;
} __attribute__((packed));

/*
 * Skip past variable-length verifier in RPC reply.
 *
 * RPC reply format after rpc_reply header:
 *   verf_flavor (4) + verf_len (4) + verf_data (verf_len, padded to 4)
 *   accept_state (4)
 *   procedure-specific data...
 *
 * This function returns pointer to accept_state given pointer to reply buffer.
 * Returns NULL if buffer too small.
 */
static inline uint8_t *
rpc_skip_verifier(uint8_t *buf, size_t buflen)
{
    uint8_t *p;
    uint32_t verf_len;

    /* Need at least: rpc_reply(12) + verf_flavor(4) + verf_len(4) + accept_state(4) */
    if (buflen < RPC_REPLY_HDR_SIZE + 12)
        return NULL;

    p = buf + RPC_REPLY_HDR_SIZE;
    p += XDR_UNIT; /* skip verf_flavor */
    verf_len = xdr_get_u32(p);
    p += XDR_UNIT; /* skip verf_len field */

    /* Validate verf_len before XDR_ALIGN to prevent overflow */
    if (verf_len > 0x1FFFFFFF)
        return NULL;

    /* Check we have room for verf_data + accept_state */
    if (p + XDR_ALIGN(verf_len) + XDR_UNIT > buf + buflen)
        return NULL;

    p += XDR_ALIGN(verf_len); /* skip verf_data with padding */
    return p;                 /* points to accept_state */
}

/*
 * Get pointer to data after accept_state in RPC reply.
 * Returns NULL if buffer too small or accept_state != SUCCESS.
 */
static inline uint8_t *
rpc_reply_data(uint8_t *buf, size_t buflen, uint32_t *accept_state_out)
{
    uint8_t *p = rpc_skip_verifier(buf, buflen);
    uint32_t accept_state;

    if (p == NULL)
        return NULL;

    accept_state = xdr_get_u32(p);
    if (accept_state_out)
        *accept_state_out = accept_state;

    if (accept_state != RPC_EXEC_SUCCESS)
        return NULL;

    return p + XDR_UNIT; /* pointer to procedure-specific data */
}

/*
 * Get pointer to NFS procedure data after NFS status in RPC reply.
 * Handles variable-length verifier properly.
 *
 * Returns NULL if:
 * - Buffer too small
 * - accept_state != SUCCESS
 *
 * Sets *nfs_status_out to the NFS status code.
 * Returns pointer to data AFTER the NFS status word.
 */
static inline uint8_t *
rpc_nfs_data(uint8_t *buf, size_t buflen, uint32_t *nfs_status_out)
{
    uint8_t *p = rpc_reply_data(buf, buflen, NULL);

    if (p == NULL)
        return NULL;

    /* Need at least 4 bytes for NFS status */
    if (p + XDR_UNIT > buf + buflen)
        return NULL;

    if (nfs_status_out)
        *nfs_status_out = xdr_get_u32(p);

    return p + XDR_UNIT; /* pointer to NFS procedure-specific data */
}

/*
 * Get accept_state from RPC reply, handling variable-length verifier.
 * Returns RPC_EXEC_SUCCESS or error code, -1 if buffer too small.
 */
static inline int
rpc_get_accept_state(uint8_t *buf, size_t buflen)
{
    uint8_t *p = rpc_skip_verifier(buf, buflen);
    if (p == NULL)
        return -1;
    return xdr_get_u32(p);
}

/*
 * Check if reply has a non-empty verifier.
 * Returns verifier length (0 if empty, >0 if has data).
 * Returns -1 if buffer too small.
 *
 * Note: Most NFS servers return empty AUTH_NULL verifiers.
 * Non-empty verifiers would cause issues with current struct-based parsing.
 */
static inline int
rpc_verifier_len(uint8_t *buf, size_t buflen)
{
    uint8_t *p;

    if (buflen < RPC_REPLY_HDR_SIZE + 8)
        return -1;

    p = buf + RPC_REPLY_HDR_SIZE;
    p += XDR_UNIT; /* skip verf_flavor */
    return xdr_get_u32(p);
}

struct rpc_call_hdr {
    struct rpc_call r;
    struct rpc_creds c;
    struct rpc_verifier v;
} __attribute__((packed));

/* RPC reply states */
#define RPC_ACCEPTED 0
#define RPC_DENIED   1

struct rpc_reply {
    uint32_t xid;
    uint32_t msgtype;
    uint32_t reply_state;
} __attribute__((packed));

struct rpc_reply_hdr {
    struct rpc_reply r;
    struct rpc_verifier v;
    uint32_t accept_state;
} __attribute__((packed));

/* RPC reply with NFS status code */
struct rpc_nfsreply_hdr {
    struct rpc_reply r;
    struct rpc_verifier v;
    uint32_t accept_state;
    uint32_t status;
} __attribute__((packed));

/*
 * Initialize RPC call header with AUTH_UNIX credentials (RFC 5531 Section 9).
 * Assumes 'xid' and 'ctx' are in scope.
 */
#define RPC_INIT_REQ(__call, __prog, __ver, __proc)                           \
    do {                                                                      \
        (__call)->r.xid = htonl(xid);                                         \
        (__call)->r.msgtype = htonl(RPC_MSG_TYPE_CALL);                       \
        (__call)->r.version = htonl(2); /* RPC version 2 (RFC 5531) */        \
        (__call)->r.program = htonl(__prog);                                  \
        (__call)->r.program_version = htonl(__ver);                           \
        (__call)->r.procedure = htonl(__proc);                                \
        /* AUTH_UNIX credentials */                                           \
        (__call)->c.flavor = htonl(FLAVOR_AUTH_UNIX);                         \
        (__call)->c.length = htonl(sizeof(struct rpc_creds) - 8);             \
        (__call)->c.stamp = htonl(rand());                                    \
        (__call)->c.machine_name_len = htonl(MACHINE_NAME_LEN);               \
        memcpy((__call)->c.machine_name, MACHINE_NAME,                        \
            sizeof((__call)->c.machine_name));                                \
        (__call)->c.uid = htonl(ctx->uid);                                    \
        (__call)->c.gid = htonl(ctx->gid);                                    \
        (__call)->c.auxgids = htonl(0);                                       \
        /* AUTH_NULL verifier */                                              \
        (__call)->v.flavor = htonl(FLAVOR_AUTH_NULL);                         \
        (__call)->v.length = htonl(0);                                        \
    } while (0)

extern const char *rpc_exec_errstr(int);
extern const char *rpc_auth_errstr(uint32_t auth_stat);
extern void rpc_print_reject(const uint8_t *buf, ssize_t len);

/*
 * Validate RPC reply header.
 * _ctx: nfsctx pointer (used to check quiet flag)
 * _r: pointer to reply struct (must have r.xid, r.msgtype, r.reply_state, accept_state)
 * _len: received length
 * _chk_accept: if non-zero, also check accept_state
 * _cleanup: statement to execute before returning on error (use (void)0 for none)
 *
 * Note: XID validation is now handled by udp_read_xid() which discards stale responses.
 */
#define RPC_CHECK_REPLY_EX(_ctx, _r, _len, _chk_accept, _cleanup)                           \
    do {                                                                                    \
        if ((_len) >= 8 && ntohl((_r)->r.msgtype) != RPC_MSG_TYPE_REPLY) {                  \
            if (!(_ctx)->quiet)                                                             \
                fprintf(stderr, "** Warning: Did not receive Reply response, ignoring\n");  \
            errno = EPROTO;                                                                 \
            _cleanup;                                                                       \
            return -1;                                                                      \
        }                                                                                   \
        if ((_len) >= 12 && ntohl((_r)->r.reply_state) != RPC_ACCEPTED) {                   \
            if (!(_ctx)->quiet)                                                             \
                rpc_print_reject((const uint8_t *)(_r), (_len));                            \
            errno = EPROTO;                                                                 \
            _cleanup;                                                                       \
            return -1;                                                                      \
        }                                                                                   \
        if ((_chk_accept) && (_len) >= 16 &&                                                \
            ntohl((_r)->accept_state) != RPC_EXEC_SUCCESS) {                                \
            if (!(_ctx)->quiet)                                                             \
                fprintf(stderr, "** Error: RPC exec failed (%d): %s\n",                     \
                    ntohl((_r)->accept_state), rpc_exec_errstr(ntohl((_r)->accept_state))); \
            errno = EPROTO;                                                                 \
            _cleanup;                                                                       \
            return -1;                                                                      \
        }                                                                                   \
        if ((_len) < (ssize_t)sizeof(*(_r))) {                                              \
            if (!(_ctx)->quiet)                                                             \
                fprintf(stderr, "** Error: Short reply, got %zd, expected at least %zu\n",  \
                    (ssize_t)(_len), sizeof(*(_r)));                                        \
            errno = EPROTO;                                                                 \
            _cleanup;                                                                       \
            return -1;                                                                      \
        }                                                                                   \
    } while (0)

/* Standard reply check */
#define RPC_CHECK_REPLY(_ctx, _r, _len) \
    RPC_CHECK_REPLY_EX(_ctx, _r, _len, 1, (void)0)

/* Reply check without accept_state validation */
#define RPC_CHECK_EMPTY_REPLY(_ctx, _r, _len) \
    RPC_CHECK_REPLY_EX(_ctx, _r, _len, 0, (void)0)

/* Reply check that frees memory on error */
#define RPC_CHECK_REPLY_FREE(_ctx, _r, _len, _ptr) \
    RPC_CHECK_REPLY_EX(_ctx, _r, _len, 1, free(_ptr))

/* rpc.c - RPC utilities */

/*
 * RPC name lookup tables
 */
struct rpc_lookup_entry {
    uint32_t value;
    const char *name;
};

extern const struct rpc_lookup_entry rpc_programs[];
extern const struct rpc_lookup_entry rpc_protocols[];

size_t rpc_lookup_name(uint32_t value, const struct rpc_lookup_entry *table,
    char *buf, size_t buflen);

#define rpc_program_name(prog, buf, buflen)  rpc_lookup_name(prog, rpc_programs, buf, buflen)
#define rpc_protocol_name(prog, buf, buflen) rpc_lookup_name(prog, rpc_protocols, buf, buflen)

/*
 * Read RPC response, discarding stale responses with wrong XID.
 * Returns length of received data on success, -1 on error.
 */
extern ssize_t rpc_recv_xid(struct nfsctx *, uint32_t ip, uint16_t port,
    uint8_t *buf, size_t buflen, uint32_t expected_xid);

/* Execute a simple RPC call with optional args and reply */
int rpc_simple_call(struct nfsctx *ctx, uint32_t program, uint32_t version,
    uint32_t procedure, uint16_t port,
    const uint8_t *args, size_t args_len,
    uint8_t *reply, size_t reply_max, size_t *reply_len);

/*
 * RPC socket locking for fork synchronization.
 * Acquire lock before udp_write, release after rpc_recv_xid.
 */
extern void rpc_lock(struct nfsctx *ctx);
extern void rpc_unlock(struct nfsctx *ctx);

#endif /* RPC_H */
