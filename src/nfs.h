
/*
 * Copyright (C)  2023-2024 Claes M Nyberg <cmn@signedness.org>
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
 *      This product includes software developed by Claes M Nyberg.
 * 4. The name Claes M Nyberg may not be used to endorse or promote
 *    products derived from this software without specific prior written
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
#ifndef NFS_H
#define NFS_H

#include <stdint.h>

#include "nfsh.h"

struct rpc_call {
    uint32_t xid;
    uint32_t msgtype;
    #define RPC_MSG_TYPE_CALL   0
    #define RPC_MSG_TYPE_REPLY  1

    uint32_t version;
    uint32_t program;
    #define RPC_PROGRAM_PORTMAP 100000
    #define RPC_PROGRAM_NFS     100003
    #define RPC_PROGRAM_MOUNT   100005

    uint32_t program_version;
    uint32_t procedure;
    #define RPC_NFS_PROCEDURE_LOOKUP        3
    #define RPC_NFS_PROCEDURE_READ          6
    #define RPC_NFS_PROCEDURE_MKDIR         9
    #define RPC_NFS_PROCEDURE_LINK          15
    #define RPC_NFS_PROCEDURE_READDIRPLUS   17
    #define RPC_PORTMAP_PROCEDURE_GETPORT   3
    #define RPC_MOUNT_PROCEDURE_MNT         1
    #define RPC_MOUNT_PROCEDURE_EXPORT      5

} __attribute__((packed));

struct rpc_reply {
    uint32_t xid;
    uint32_t msgtype;
    uint32_t reply_state;
        #define RPC_ACCEPTED 0
} __attribute__((packed));


#define NFS3_OK 0
#define RPC_EXEC_SUCCESS 0

struct rpc_creds {
    uint32_t flavor;
    #define FLAVOR_AUTH_UNIX    1
    uint32_t length;
};

struct rpc_verifier {
    uint32_t flavor;
    uint32_t length;
};

#define RPC_CHECK_REPLY(_r)                                                                 \
{                                                                                       \
    if (ntohl((_r)->r.xid) != xid) {                                                    \
        fprintf(stderr, "** Warning: Recevied bad XID, got %08x, expected %08x\n",      \
            (_r)->r.xid, htonl(xid));                                                   \
        return -1;                                                                      \
    }                                                                                   \
                                                                                        \
    if (ntohl((_r)->r.msgtype) != RPC_MSG_TYPE_REPLY) {                                 \
        fprintf(stderr, "** Warning: Did not receive Reply response, ignoring\n");      \
        return -1;                                                                      \
    }                                                                                   \
                                                                                        \
    if (ntohl((_r)->r.reply_state) != RPC_ACCEPTED) {                                   \
        fprintf(stderr, "** Error: RPC reply state not accepted\n");                    \
        return -1;                                                                      \
    }                                                                                   \
                                                                                        \
    if (ntohl((_r)->accept_state) != RPC_EXEC_SUCCESS) {                                \
        fprintf(stderr, "** Error: RPC exec failed\n");                                 \
        return -1;                                                                      \
    }                                                                                   \
                                                                                        \
    if (ntohl((_r)->status) != NFS3_OK) {                                               \
        fprintf(stderr, "** Error: Receive status not NFS3_OK\n");                      \
        return -1;                                                                      \
    }                                                                                   \
}


/* rpc.c */

/* portmap.c */
extern int portmap_getport(struct nfsctx *, uint32_t);
#define portmap_getport_nfsd(__ctx)	portmap_getport((__ctx), RPC_PROGRAM_NFS)
#define portmap_getport_mountd(__ctx)	portmap_getport((__ctx), RPC_PROGRAM_MOUNT)


#endif /* NFS_H */
