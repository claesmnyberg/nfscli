
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

#include "nfscli.h"


/*
 * Create list of exported shares
 */
int
mount_export(struct nfsctx *ctx, struct export_reply **xl)
{
    uint8_t buf[65535];
    uint8_t *pt;
	struct export_reply *cur;

    struct {
        struct rpc_call r;
        struct rpc_creds c;
        struct rpc_verifier v;
    } __attribute__((packed)) mount_export;

    struct mount_reply {
        struct rpc_reply r;
        struct rpc_verifier v;
        uint32_t accept_state;
    } __attribute__((packed)) *mr;

    struct export_info {
        uint32_t value_follows;
        uint32_t len;
    } __attribute__((packed)) *share;

    ssize_t len;
    uint32_t xid;
	size_t i;
	*xl = NULL;

    xid = rand();
    print(1, ctx, "Generated XID 0x%08x\n", xid);

    memset(&mount_export, 0x00, sizeof(mount_export));
	RPC_INIT_REQ(&mount_export, RPC_PROGRAM_MOUNT, 3, RPC_MOUNT_PROCEDURE_EXPORT);

    if (udp_write(ctx, ctx->ip, ctx->port_mountd,
            (uint8_t *)&mount_export, sizeof(mount_export)) < 0) {
        return -1;
    }

	memset(buf, 0x00, sizeof(buf));
    if ( (len = udp_read(ctx, ctx->ip, ctx->port_mountd,
            (uint8_t *)buf, sizeof(buf))) < sizeof(struct mount_reply)) {
        fprintf(stderr, "** Error: Bad length (%ld) of received data\n", len);
        return -1;
    }

    mr = (struct mount_reply *)buf;
	RPC_CHECK_REPLY(mr, len);

	cur = calloc(1, sizeof(struct export_reply));
	*xl = cur;

    share = (struct export_info *)&buf[sizeof(struct mount_reply)];
    pt = (uint8_t *)share + sizeof(struct export_info);
    while (ntohl(share->value_follows) == 1) {

        /* Directory */
		share->len = ntohl(share->len);
		memcpy(cur->name, pt, share->len > sizeof(cur->name) 
			? share->len : sizeof(cur->name));
        pt += ALIGN(share->len, 4);

        /* Groups */
        share = (struct export_info *)pt;
        pt = (uint8_t *)share + sizeof(struct export_info);

		/* No group, everyone allowed */
		if (ntohl(share->value_follows) == 0) {
			snprintf(cur->group, sizeof(cur->group), "<everyone>");
			cur->everyone = 1;
		}

		i = 0;
        while (ntohl(share->value_follows) == 1) {
			share->len = ntohl(share->len);

			if ((share->len + i) < (sizeof(cur->group) - 1)) {
				memcpy(&cur->group[i], pt, share->len);
				i += share->len;
				cur->group[i++] = ' ';
			}
			else {
				char tmp[1024];
				memset(tmp, 0x00, sizeof(tmp));
				memcpy(tmp, pt, share->len > sizeof(tmp) ? sizeof(tmp) : share->len);
				fprintf(stderr, "** Warning: Group %s not saved due to short buffer\n", tmp);
			}

            pt += ALIGN(share->len, 4);
            share = (struct export_info *)pt;
            pt = (uint8_t *)share + sizeof(struct export_info);
        }

        pt = (uint8_t *)share + sizeof(uint32_t);
        share = (struct export_info *)pt;
        pt = (uint8_t *)share + sizeof(struct export_info);

		/* Check for known "everyone" patterns and tag share */
		if (strcmp(cur->group, "* ") == 0) 
			cur->everyone = 1;
		else if (strstr(cur->group, "*.") != NULL) 
			cur->everyone = 1;
		else if (strcasecmp(cur->group, "Everyone") == 0)
			cur->everyone = 1;
		else if (strcasecmp(cur->group, "everyone") == 0)
			cur->everyone = 1;

		if (ntohl(share->value_follows) == 1) {
			cur->next = calloc(1, sizeof(struct export_reply));
			cur = cur->next;
		}
    }

    return 0;
}

/*
 * Send mount command to NFS server.
 * Returns the length of the file handle on succes, -1 on error.
 * Memory is allocated for the fh pointer and has to be free'd
 * using free(3) when the caller has finished using it.
 */
int
mount_mount(struct nfsctx *ctx, char *path, uint8_t **fh)
{
    uint8_t buf[8192];
	int mlen;

    struct {
        struct rpc_call r;
        struct rpc_creds c;
        struct rpc_verifier v;

        uint32_t pathlen;
        uint8_t path[256];

    } __attribute__((packed)) mount;
    struct mount_reply {
        struct rpc_reply r;
        struct rpc_verifier v;
        uint32_t accept_state;

        uint32_t status;

        uint32_t flen;
        /* File handle goes here */

        //uint32_t flavors;
        //uint32_t flavor;
    } __attribute__((packed)) *reply;

    ssize_t len;
    uint32_t xid;

    xid = rand();
    print(1, ctx, "Generated XID 0x%08x\n", xid);

    memset(&mount, 0x00, sizeof(mount));
	RPC_INIT_REQ(&mount, RPC_PROGRAM_MOUNT, 3, RPC_MOUNT_PROCEDURE_MNT);

    if (strlen(path) >= (sizeof(mount.path)-1)) {
        fprintf(stderr, "** Error: Path to long\n");
        return -1;
    }

    snprintf((char *)mount.path, sizeof(mount.path), "%s", path);
    mount.pathlen = htonl(strlen((char *)mount.path));
	mlen = (sizeof(mount) - sizeof(mount.path)) + ALIGN(strlen(path), 4);

    if (udp_write(ctx, ctx->ip, ctx->port_mountd,
            (uint8_t *)&mount, mlen) < 0) {
        return -1;
    }

    memset(buf, 0x00, sizeof(buf));
    reply = (struct mount_reply *)buf;

    if ( (len = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
        fprintf(stderr, "** Error: Bad length (%ld) of received data\n", len);
        return -1;
    }

	if (reply->status != 0) {
		fprintf(stderr, "** Error: Mount failed: %u: %s\n", 
			ntohl(reply->status), strerror(ntohl(reply->status)));
		errno = ntohl(reply->status);
		return -1;
	}

	RPC_CHECK_REPLY(reply, len);

    if (ntohl(reply->status) != 0) {
        fprintf(stderr, "** Error: RPC exec failed, status=%d\n", ntohl(reply->status));
        return -1;
    }

    if (fh != NULL) {
        int flen = ntohl(reply->flen);

        if ( (*fh = malloc(flen)) == NULL) {
            fprintf(stderr, "** Error: Failed to allocate %d bytes\n", flen);
            return -1;
        }
        memcpy(*fh, buf + sizeof(struct mount_reply), flen);
    }

    return ntohl(reply->flen);
}


/*
 * Send UMNTALL command to mount process.
 */
int
mount_umntall(struct nfsctx *ctx)
{
    uint8_t buf[8192];
	struct rpc_call_hdr umntall;
	struct rpc_reply_hdr *reply;
    ssize_t len;
    uint32_t xid;

    xid = rand();
    print(1, ctx, "Generated XID 0x%08x\n", xid);

    memset(&umntall, 0x00, sizeof(umntall));
	RPC_INIT_REQ(&umntall, RPC_PROGRAM_MOUNT, 3, RPC_MOUNT_PROCEDURE_UMNTALL);

    if (udp_write(ctx, ctx->ip, ctx->port_mountd,
            (uint8_t *)&umntall, sizeof(umntall)) < 0) {
        return -1;
    }

    memset(buf, 0x00, sizeof(buf));
    reply = (struct rpc_reply_hdr *)buf;

    if ( (len = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
        fprintf(stderr, "** Error: Bad length (%ld) of received data\n", len);
        return -1;
    }

	RPC_CHECK_REPLY(reply, len);
    return 0;
}



/*
 * Send DUMP command to mount process.
 */
int
mount_dump(struct nfsctx *ctx)
{
    uint8_t buf[65535];
	uint32_t value_follows;
	uint8_t *pt;
	struct rpc_call_hdr dump;
	struct rpc_reply_hdr *reply;

    ssize_t len;
    uint32_t xid;

    xid = rand();
    print(1, ctx, "Generated XID 0x%08x\n", xid);

    memset(&dump, 0x00, sizeof(dump));
	RPC_INIT_REQ(&dump, RPC_PROGRAM_MOUNT, 3, RPC_MOUNT_PROCEDURE_DUMP);

    if (udp_write(ctx, ctx->ip, ctx->port_mountd,
            (uint8_t *)&dump, sizeof(dump)) < 0) {
        return -1;
    }

    memset(buf, 0x00, sizeof(buf));
    reply = (struct rpc_reply_hdr *)buf;

    if ( (len = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
        fprintf(stderr, "** Error: Failed to receive response: %s\n", strerror(errno));
        return -1;
    }

	RPC_CHECK_REPLY(reply, len);

	pt = (uint8_t *)(buf + sizeof(struct rpc_reply_hdr));
	value_follows = ntohl(*(uint32_t *)pt);
	pt += 4;

	/* Traverse list and print clients */
	while (value_follows == 1) {
		uint32_t n;

		n = ntohl(*(uint32_t *)pt);
		pt += 4;

		/* Hostname */
		fwrite(pt, n, 1, stdout);
		printf(":");
		pt += ALIGN(n, 4);

		n = ntohl(*(uint32_t *)pt);
		pt += 4;		

		/* Directory */
		fwrite(pt, n, 1, stdout);
		printf("\n");
		pt += ALIGN(n, 4);

		value_follows = ntohl(*(uint32_t *)pt);
		pt += 4;

		if (pt > &buf[len]) {
			fprintf(stderr, "** Error: Supplied length exceeds response buffer\n");
			return -1;
		}
	}

    return 0;
}

