
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>

#include "nfscli.h"


/*
 * Send the GETPORT Call to portmap for specific program.
 * Returns the port number in network byte order on success, 0 on error.
 */
int
portmap_getport(struct nfsctx *ctx, uint32_t rpc_program)
{
    struct {
        struct rpc_call r;
        struct rpc_creds c;
        struct rpc_verifier v;
    	uint32_t program;
    	uint32_t version;
    	uint32_t proto;
    	uint32_t port;
    } __attribute__((packed)) getport;

    struct {
        struct rpc_reply r;
        struct rpc_verifier v;
        uint32_t accept_state;
        uint32_t port;
    } __attribute__((packed)) getport_reply;

    uint32_t xid;
    ssize_t len;
    memset(&getport, 0x00, sizeof(getport));

    xid = rand();
    print(1, ctx, "Generated XID 0x%08x\n", xid);
    memset(&getport, 0x00, sizeof(getport));
	RPC_INIT_REQ(&getport, RPC_PROGRAM_PORTMAP, 2, RPC_PORTMAP_PROCEDURE_GETPORT);
	

    getport.program = htonl(rpc_program);
    getport.version = htonl(3);
    getport.proto = htonl(IPPROTO_UDP);
    getport.port = htonl(0);

    if (udp_write(ctx, ctx->ip, ctx->port_rpc,
            (uint8_t *)&getport, sizeof(getport)) < 0) {
        return 0;
    }

    memset(&getport_reply, 0x00, sizeof(getport_reply));
    if ( (len = udp_read(ctx, ctx->ip, ctx->port_rpc,
            (uint8_t *)&getport_reply, sizeof(getport_reply))) < sizeof(getport_reply)) {
        fprintf(stderr, "** Error: Bad length (%ld) of received data\n", len);
        return 0;
    }

	RPC_CHECK_REPLY(&getport_reply, len);

    return htons(ntohl(getport_reply.port));
}

