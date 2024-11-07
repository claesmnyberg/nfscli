
/*
 * Copyright (C)  2023-2024 Claes M Nyberg <cmn@signedness.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *	must display the following acknowledgement:
 *	  This product includes software developed by Claes M Nyberg.
 * 4. The name Claes M Nyberg may not be used to endorse or promote
 *	products derived from this software without specific prior written
 *	permission.
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

#ifndef NFSCLI_H
#define NFSCLI_H

#define NFSCLI_VERSION  "1.5"

#include "str.h"
#include "net.h"
#include "nfsh.h"
#include "nfsv3.h"
#include "print.h"

#define PORT_LOCAL_DEFAULT	516
#define PORT_NFSD_DEFAULT	2049
#define PORT_RPC_DEFAULT	111

struct nfsctx {
	/* Verbose level */
	uint32_t verbose;

	/* Commands to run */
	char *exec;

	/* UDP/raw socket */
	int sock;

	/* Recv timeout in seconds */
	struct timeval tv;

	/* Spoof IP */
	uint32_t spoof;
	char *sip;
	char *ifc;
	uint8_t ifmac[6]; /* HW address of selected interface */

	/* Receive buffer for reading packets */
	pthread_mutex_t lock;
	uint8_t recvbuf[MTU_MAX*2];
	uint32_t recvlen;
	int readsock;
#define SPOOF_RECV_TIMEOUT_SEC	3

	/* UID in RPC Call */
	uint32_t uid;

	/* GID in RPC Call */
	uint32_t gid;

	/* Server name and IP */
	char *server;
	uint32_t ip;

	/* Local port */
	uint16_t port_local;

	/* RPC port */
	uint16_t port_rpc;

	/* NFS port */
	uint16_t port_nfsd;

	/* Mountd port */
	uint16_t port_mountd;

	/* machine name */
	char *machine_name;
};


#endif /* NFSCLI_H */

