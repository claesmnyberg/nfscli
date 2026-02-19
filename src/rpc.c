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
 * rpc.c - RPC utilities (RFC 1057)
 *
 * This file contains RPC-level utilities that are shared across
 * the various RPC clients (NFS, mount, portmap).
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "rpc.h"
#include "nfscli.h"
#include "portmap.h"
#include "print.h"

/*
 * RPC socket locking for fork synchronization.
 *
 * When concurrent_fork is set (pipeline or NFS I/O redirection), multiple
 * processes (parent and child) share the same UDP socket. We use a
 * pipe-based token to ensure only one process does RPC send+receive at a time.
 *
 * Implementation:
 *   - A single-byte token sits in the pipe (rpc_lock_pipe)
 *   - To acquire: read() the byte (blocks if another process has it)
 *   - To release: write() the byte back
 *   - Simpler than file locking, works across fork() without shared memory
 *
 * Acquire/Release Pattern:
 *   - Token acquired in udp_write() before sending request
 *   - Token released in rpc_recv_xid() after receiving response
 *   - This asymmetric pattern intentionally spans function boundaries
 *   - Ensures entire RPC request-response cycle is atomic
 *
 * Error handling:
 *   - If pipe read/write fails, abort() - unrecoverable state
 *   - On send error, udp_write() releases the lock before returning
 */
void
rpc_lock(struct nfsctx *ctx)
{
    char tok;
    ssize_t n;

    if (!ctx->concurrent_fork)
        return;

    /* Block until we get the token, retrying on EINTR */
    while ((n = read(ctx->rpc_lock_pipe[0], &tok, 1)) < 0) {
        if (errno == EINTR)
            continue;
        fprintf(stderr, "** Fatal: RPC lock read failed: %s\n",
            strerror(errno));
        abort();
    }
    if (n == 0) {
        fprintf(stderr, "** Fatal: RPC lock pipe closed unexpectedly\n");
        abort();
    }
}

void
rpc_unlock(struct nfsctx *ctx)
{
    ssize_t n;

    if (!ctx->concurrent_fork)
        return;

    /* Put the token back, retrying on EINTR */
    while ((n = write(ctx->rpc_lock_pipe[1], "X", 1)) < 0) {
        if (errno == EINTR)
            continue;
        fprintf(stderr, "** Fatal: RPC unlock write failed: %s\n",
            strerror(errno));
        abort();
    }
    if (n == 0) {
        fprintf(stderr, "** Fatal: RPC unlock wrote 0 bytes\n");
        abort();
    }
}

/*
 * Convert RPC accept_state error code to string.
 *
 * RFC 1057 Section 8 - RPC Message Protocol
 *
 * Accept states for MSG_ACCEPTED replies:
 *   SUCCESS (0)       - RPC executed successfully
 *   PROG_UNAVAIL (1)  - Remote hasn't exported program
 *   PROG_MISMATCH (2) - Remote can't support version
 *   PROC_UNAVAIL (3)  - Program can't support procedure
 *   GARBAGE_ARGS (4)  - Procedure can't decode params
 *   SYSTEM_ERR (5)    - System error on server (added in later revisions)
 */
const char *
rpc_exec_errstr(int err)
{
    switch (err) {
    case RPC_EXEC_SUCCESS:
        return "Success";
    case RPC_ERR_PROG_UNAVAIL:
        return "Program unavailable";
    case RPC_ERR_PROG_MISMATCH:
        return "Program version mismatch";
    case RPC_ERR_PROC_UNAVAIL:
        return "Procedure unavailable";
    case RPC_ERR_GARBAGE_ARGS:
        return "Garbage arguments";
    case RPC_ERR_SYSTEM:
        return "System error";
    default:
        return "Unknown error";
    }
}

/*
 * Convert auth_stat code to human-readable string.
 * RFC 5531 Section 9 - Authentication Status
 */
const char *
rpc_auth_errstr(uint32_t auth_stat)
{
    static const char *names[] = {
        "AUTH_OK",           /* 0 - success */
        "AUTH_BADCRED",      /* 1 - bad credential (seal broken) */
        "AUTH_REJECTEDCRED", /* 2 - client must begin new session */
        "AUTH_BADVERF",      /* 3 - bad verifier (seal broken) */
        "AUTH_REJECTEDVERF", /* 4 - verifier expired or replayed */
        "AUTH_TOOWEAK",      /* 5 - rejected for security reasons */
        "AUTH_INVALIDRESP",  /* 6 - bogus response verifier */
        "AUTH_FAILED"        /* 7 - unknown reason */
    };
    if (auth_stat < sizeof(names) / sizeof(names[0]))
        return names[auth_stat];
    return "UNKNOWN";
}

/*
 * Print detailed RPC reject error.
 * Called when reply_state != RPC_ACCEPTED.
 *
 * RFC 1831/5531: rejected_reply contains:
 *   - reject_stat (RPC_MISMATCH=0 or AUTH_ERROR=1)
 *   - If RPC_MISMATCH: low and high version numbers
 *   - If AUTH_ERROR: auth_stat code
 */
void
rpc_print_reject(const uint8_t *buf, ssize_t len)
{
    const size_t rpc_reply_min_size = sizeof(struct rpc_reply) + sizeof(struct rpc_verifier) + XDR_UNIT;
    uint32_t reject_stat;

    /* Need at least: rpc_reply + verifier + reject_stat */
    if ((size_t)len < rpc_reply_min_size) {
        fprintf(stderr, "** Error: RPC rejected (short reply, len=%zd)\n", len);
        return;
    }

    reject_stat = xdr_get_u32(buf + sizeof(struct rpc_reply) + sizeof(struct rpc_verifier));

    if (reject_stat == 0) {
        /* RPC_MISMATCH - extract version range (need 2 x uint32) */
        const size_t mismatch_size = rpc_reply_min_size + (2 * XDR_UNIT);
        if ((size_t)len >= mismatch_size) {
            size_t offset = sizeof(struct rpc_reply) + sizeof(struct rpc_verifier) + XDR_UNIT;
            uint32_t low = xdr_get_u32(buf + offset);
            uint32_t high = xdr_get_u32(buf + offset + XDR_UNIT);
            fprintf(stderr, "** Error: RPC version mismatch, server supports v%u-%u\n",
                low, high);
        } else {
            fprintf(stderr, "** Error: RPC version mismatch\n");
        }
    } else if (reject_stat == 1) {
        /* AUTH_ERROR - extract auth_stat */
        const size_t auth_error_size = rpc_reply_min_size + XDR_UNIT;
        if ((size_t)len >= auth_error_size) {
            size_t offset = sizeof(struct rpc_reply) + sizeof(struct rpc_verifier) + XDR_UNIT;
            uint32_t auth = xdr_get_u32(buf + offset);
            fprintf(stderr, "** Error: Authentication failed: %s (%u)\n",
                rpc_auth_errstr(auth), auth);
        } else {
            fprintf(stderr, "** Error: Authentication failed\n");
        }
    } else {
        fprintf(stderr, "** Error: RPC rejected (reject_stat=%u)\n", reject_stat);
    }
}

/*
 * RPC program number to name mapping
 */
const struct rpc_lookup_entry rpc_programs[] = {
    {PMAP_PROG_PORTMAPPER, "portmapper"},
    {PMAP_PROG_RSTATD, "rstatd"},
    {PMAP_PROG_RUSERSD, "rusersd"},
    {PMAP_PROG_NFS, "nfs"},
    {PMAP_PROG_YP_SERV, "ypserv"},
    {PMAP_PROG_MOUNTD, "mountd"},
    {PMAP_PROG_YP_BIND, "ypbind"},
    {PMAP_PROG_YP_XFR, "ypxfr"},
    {PMAP_PROG_YP_SERV2, "ypserv2"},
    {PMAP_PROG_WALLD, "walld"},
    {PMAP_PROG_RQUOTA, "rquota"},
    {PMAP_PROG_SPRAY, "sprayd"},
    {PMAP_PROG_WALLCD, "wallcd"},
    {PMAP_PROG_BOOTPARAM, "bootparam"},
    {PMAP_PROG_NLOCKMGR, "nlockmgr"},
    {PMAP_PROG_LLOCKMGR, "llockmgr"},
    {PMAP_PROG_STATUS_MON, "status"},
    {PMAP_PROG_YP_UPDATED, "ypupdated"},
    {PMAP_PROG_YP_XFRD, "ypxfrd"},
    {PMAP_PROG_AMM, "amm"},
    {PMAP_PROG_KERBD, "kerbd"},
    {PMAP_PROG_NFSD, "nfsd"},
    {PMAP_PROG_NFS_ACL_SOL, "nfs_acl"},
    {PMAP_PROG_KEYSERV, "keyserv"},
    {PMAP_PROG_KEYENVOY, "keyenvoy"},
    {PMAP_PROG_SECUREFS, "securefs"},
    {PMAP_PROG_RSTAT, "rstat"},
    {PMAP_PROG_RUSERS, "rusers"},
    {PMAP_PROG_SPRAY2, "spray"},
    {PMAP_PROG_WALL2, "wall"},
    {PMAP_PROG_KRB_V4, "kerberos_v4"},
    {PMAP_PROG_KRB_V5, "kerberos_v5"},
    {PMAP_PROG_NFS_ACL_LINUX, "nfs_acl"},
    {PMAP_PROG_NFS_RDMA, "nfs_rdma"},
    {PMAP_PROG_METAD, "metad"},
    {PMAP_PROG_METAMHD, "metamhd"},
    {PMAP_PROG_SADMIND, "sadmind"},
    {PMAP_PROG_UFSD, "ufsd"},
    {PMAP_PROG_GRPSERVD, "grpservd"},
    {PMAP_PROG_CACHEFSD, "cachefsd"},
    {PMAP_PROG_METAMEDD, "metamedd"},
    {PMAP_PROG_CMSD, "cmsd"},
    {PMAP_PROG_TTDBSERVER, "ttdbserver"},
    {0, NULL}};

/*
 * RPC protocol number to name mapping
 */
const struct rpc_lookup_entry rpc_protocols[] = {
    {PMAP_PROT_TCP, "tcp"},
    {PMAP_PROT_UDP, "udp"},
    {PMAP_PROT_NONE, "none"},
    {0, NULL}};

/*
 * Look up name for an RPC value in a lookup table
 */
size_t
rpc_lookup_name(uint32_t value, const struct rpc_lookup_entry *table,
    char *buf, size_t buflen)
{
    const struct rpc_lookup_entry *p;
    size_t len;

    if (buflen > 0)
        buf[0] = '\0'; /* default: empty string */

    for (p = table; p->name; p++) {
        if (p->value == value) {
            len = strlen(p->name);

            if (buflen > 0) {
                strncpy(buf, p->name, buflen - 1);
                buf[buflen - 1] = '\0';
            }

            return len; /* return real length, not truncated */
        }
    }

    return 0;           /* unknown -> empty string */
}

/*
 * Read RPC response, discarding stale responses with wrong XID.
 *
 * RFC 1057 Section 8 - Transaction ID (XID)
 *
 * The XID is used to match requests with replies. Stale responses
 * (from retransmitted requests) may arrive after the correct response.
 * This function discards responses with mismatched XIDs.
 *
 * Note: XIDs should be unique per client. Using rand() is acceptable
 * for this CLI tool but production code should use a proper counter.
 *
 * Returns length of received data on success, -1 on error.
 */
#define RPC_RECV_XID_MAX_RETRIES 10

ssize_t
rpc_recv_xid(struct nfsctx *ctx, uint32_t ip, uint16_t port,
    uint8_t *buf, size_t buflen, uint32_t expected_xid)
{
    ssize_t n;
    int retries = 0;

    while (retries < RPC_RECV_XID_MAX_RETRIES) {
        n = udp_read(ctx, ip, port, buf, buflen);
        if (n < 0) {
            rpc_unlock(ctx);
            return -1;
        }

        if (n >= 4) {
            uint32_t got_xid = xdr_get_u32(buf);
            if (got_xid == expected_xid) {
                rpc_unlock(ctx);
                return n; /* Success - XID matches */
            }

            /* Stale response - discard and retry */
            fprintf(stderr, "** Discarding stale response (XID %08x, expected %08x)\n",
                got_xid, expected_xid);
        }
        retries++;
    }

    fprintf(stderr, "** Error: Too many stale RPC responses (expected XID %08x, got %d mismatches)\n",
        expected_xid, retries);
    errno = ETIMEDOUT;
    rpc_unlock(ctx);
    return -1;
}

/*
 * rpc_simple_call - Execute a simple RPC call.
 *
 * RFC 1057 Section 8 - RPC Message Protocol
 *
 * Handles the common pattern of: build request, append args, send,
 * receive, validate. Caller is responsible for building XDR args
 * and parsing any result data in the reply.
 *
 * Parameters:
 *   ctx       - NFS context
 *   program   - RPC program number
 *   version   - Program version
 *   procedure - Procedure number
 *   port      - UDP port
 *   args      - Optional XDR-encoded arguments (NULL if none)
 *   args_len  - Length of arguments (0 if none)
 *   reply     - Buffer for reply data after RPC header (NULL if not needed)
 *   reply_max - Max reply buffer size
 *   reply_len - Output: actual reply data length (NULL if not needed)
 *
 * Returns 0 on success, -1 on error.
 */
int
rpc_simple_call(struct nfsctx *ctx, uint32_t program, uint32_t version,
    uint32_t procedure, uint16_t port,
    const uint8_t *args, size_t args_len,
    uint8_t *reply, size_t reply_max, size_t *reply_len)
{
    uint8_t reqbuf[RPC_BUFSIZE_SMALL];
    uint8_t replybuf[RPC_BUFSIZE_SMALL];
    struct rpc_call_hdr *req = (struct rpc_call_hdr *)reqbuf;
    struct rpc_reply_hdr *rep = (struct rpc_reply_hdr *)replybuf;
    size_t req_len;
    size_t data_offset;
    size_t data_len;
    ssize_t len;
    uint32_t xid;

    /* Build request header */
    req_len = sizeof(struct rpc_call_hdr);
    memset(req, 0, sizeof(*req));
    xid = rand();
    RPC_INIT_REQ(req, program, version, procedure);

    print(V_TRACE, ctx, "RPC call prog=%u vers=%u proc=%u XID 0x%08x\n",
        program, version, procedure, xid);

    /* Append arguments if provided */
    if (args != NULL && args_len > 0) {
        if (req_len + args_len > sizeof(reqbuf)) {
            errno = EMSGSIZE;
            return -1; /* Args too large */
        }
        memcpy(reqbuf + req_len, args, args_len);
        req_len += args_len;
    }

    /* Send request */
    if (udp_write(ctx, ctx->server.ip, port, reqbuf, req_len) < 0)
        return -1;

    /* Receive reply */
    memset(replybuf, 0, sizeof(replybuf));
    len = rpc_recv_xid(ctx, ctx->server.ip, port,
        replybuf, sizeof(replybuf), xid);
    if (len < (ssize_t)sizeof(struct rpc_reply_hdr)) {
        errno = EPROTO;
        return -1;
    }

    /* Validate RPC-level success */
    if (ntohl(rep->r.reply_state) != RPC_ACCEPTED) {
        errno = EPROTO;
        return -1;
    }
    if (ntohl(rep->accept_state) != RPC_EXEC_SUCCESS) {
        errno = EPROTO;
        return -1;
    }

    /* Copy reply data (after header) to caller's buffer */
    data_offset = sizeof(struct rpc_reply_hdr);
    data_len = (size_t)len - data_offset;

    if (reply != NULL && reply_max > 0) {
        size_t copy_len = (data_len < reply_max) ? data_len : reply_max;
        memcpy(reply, replybuf + data_offset, copy_len);
    }
    if (reply_len != NULL)
        *reply_len = data_len;

    return 0;
}
