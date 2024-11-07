
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
#include <stdarg.h>
#include <stdint.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "nfscli.h"


static void
usage(char *pname)
{
	printf("\n");
	printf("Usage: %s <server-ip> [Option(s)]\n", pname);
	printf("Options:\n");
	printf(" -e --exec <cmds>           - Execute semicolon separated commands\n");
	printf(" -m --port-mountd <port>    - Server mount port\n");
	printf(" -p --port-nfsd <port>      - Server nfs port, defaults to %u\n", PORT_NFSD_DEFAULT);
	printf(" -s --port-local <port>     - Local UDP port, defaults to %u\n", PORT_LOCAL_DEFAULT);
	printf(" -S --spoof-ip <iface>:<ip> - Spoof source IP using a raw socket\n");
	printf(" -t --timeout <sec>         - Receive timeout on UDP socket\n");
	printf(" -v --verbose               - Verbose level, repeat to increase\n");
	printf("\n");
	exit(EXIT_FAILURE);
}


/* Commandline options */
const struct option longopts[] =
{
    {"exec", 1, NULL, 'e'},
    {"port-nfsd", 1, NULL, 'p'},
    {"port-local", 1, NULL, 's'},
    {"spoof-ip", 1, NULL, 'S'},
    {"port-mountd", 1, NULL, 'm'},
    {"timeout", 1, NULL, 't'},
    {"verbose", 0, NULL, 'v'},
    {NULL, 0, NULL, 0}
};


int
main(int argc, char **argv)
{
	struct nfsctx ctx;
	int longindex;
	int i;

	printf("\nNFS v3 CLI v%s, By Claes M Nyberg <cmn@signedness.org>\n", 
		NFSCLI_VERSION);

	/* Default values */
	memset(&ctx, 0x00, sizeof(struct nfsctx));
	ctx.port_nfsd = htons(PORT_NFSD_DEFAULT);
	ctx.port_local = htons(PORT_LOCAL_DEFAULT);
	ctx.port_rpc = htons(PORT_RPC_DEFAULT);

	if (argc < 2)
		usage(argv[0]);
	
	ctx.server = argv[1];
	if ( (ctx.ip = net_inetaddr(ctx.server)) == -1) {
		fprintf(stderr, "Failed to resolve server IP %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	while ( (i = getopt_long(argc-1, &argv[1], "e:p:s:S:t:vm:", longopts, &longindex)) != -1) {

		switch (i) {
			case 'e':
				ctx.exec = strdup(optarg);
				break;

			case 'S':
				char *iface;
				char *ip;
				char *ep;

				if ( (ep = strchr(optarg, ':')) == NULL) {
					fprintf(stderr, "Failed to parse interface name in spoofed IP\n");
					exit(EXIT_FAILURE);
				}

				iface = optarg;
				ip = ep+1;
				*ep = '\0';

				if ( (ctx.spoof = net_inetaddr(ip)) == -1) {
					fprintf(stderr, "Failed to resolve spoofed IP %s\n", 
						strerror(errno));
					exit(EXIT_FAILURE);
				}
				ctx.sip = strdup(ip);
				ctx.ifc = strdup(iface);

				break;

			case 's':
				if (atoi(optarg) < 0 || atoi(optarg) > 65535) {
					fprintf(stderr, "** Error: Invalid source port\n");
					exit(EXIT_FAILURE);
				}

				ctx.port_local = htons(atoi(optarg));
				if (ctx.port_local == 0) {
					fprintf(stderr, "** Error: Invalid source port\n");
					exit(EXIT_FAILURE);
				}
				break;

			case 'p':
				if (atoi(optarg) < 0 || atoi(optarg) > 65535) {
					fprintf(stderr, "** Error: Invalid server nfs port\n");
					exit(EXIT_FAILURE);
				}

				ctx.port_nfsd = htons(atoi(optarg));
				if (ctx.port_nfsd == 0) {
					fprintf(stderr, "** Error: Invalid server nfs port\n");
					exit(EXIT_FAILURE);
				}
				break;

            case 'm':
                if (atoi(optarg) < 0 || atoi(optarg) > 65535) {
                    fprintf(stderr, "** Error: Invalid server mount port\n");
                    exit(EXIT_FAILURE);
                }

                ctx.port_mountd = htons(atoi(optarg));
                if (ctx.port_mountd == 0) {
                    fprintf(stderr, "** Error: Invalid server mount port\n");
                    exit(EXIT_FAILURE);
                }
                break;

			case 't':
				ctx.tv.tv_sec = atoi(optarg);
				ctx.tv.tv_usec = 0;
				break;

			case 'v':
				ctx.verbose++;
				break;

			default:
				usage(argv[0]);
		}
	}

	/* Open raw socket */
	if (ctx.spoof != 0) {
		struct timeval tv;

		if ( (ctx.sock = rawpkt_open(ctx.ifc)) < 0) {
			fprintf(stderr, "** Error: Failed to create raw socket: %s\n", strerror(errno));
				exit(EXIT_FAILURE);
		}

		if ( (ctx.readsock = rawcap_open(ctx.ifc, 1)) < 0) {
			fprintf(stderr, "** Error: Failed to create raw socket: %s\n", strerror(errno));
				exit(EXIT_FAILURE);
		}

		/* Set read timeout */
		tv.tv_sec = SPOOF_RECV_TIMEOUT_SEC;
		if (ctx.tv.tv_sec != 0)
			tv.tv_sec = ctx.tv.tv_sec;
		tv.tv_usec = 0;

		if (setsockopt(ctx.readsock, SOL_SOCKET, 
				SO_RCVTIMEO, (const char*)&tv, sizeof tv)) {
			fprintf(stderr, "** Error: Failed to set recv timeout on raw socket: %s\n", 
				strerror(errno));
			exit(EXIT_FAILURE);
		}

		/* Init mutex */
		pthread_mutex_init(&ctx.lock, NULL);

		printf("\n***** WARNING ** WARNING ** WARNING ** WARNING *****\n");
		printf("*                                                  *\n");
		printf("* You are using a raw socket with a spoofed IP.    *\n");
		printf("*         BEWARE OF LIMITED PERFORMANCE            *\n");
		printf("* Use with caution and check your egress filtering *\n");
		printf("*                                                  *\n");
		printf("***** WARNING ** WARNING ** WARNING ** WARNING *****\n\n");

		/* Run ARP reply thread */
		printf("Starting ARP reply thread\n");
		if (thread_run_arpreply(&ctx) != 0)
			exit(EXIT_FAILURE);
	}

	/* Open regular socket */
    else {
		if (ctx.spoof != 0) 
			printf("** Ignoring -a (start ARP spoof thread), makes no sense without -S\n");

		if ( (ctx.sock = udp_socket(0, ctx.port_local)) < 0) {
        	fprintf(stderr, "Failed to create UDP socket (with source port %d): %s\n", 
				ctx.port_local, strerror(errno));
        	fprintf(stderr, "Change port or get root?\n");
        	exit(EXIT_FAILURE);
    	}

		if (ctx.tv.tv_sec != 0) {
			if (setsockopt(ctx.sock, SOL_SOCKET, SO_RCVTIMEO, 
					(const char*)&ctx.tv, sizeof(struct timeval))) {
				fprintf(stderr, "** Error: Failed to set recv timeout on raw socket: %s\n", 
					strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
	}

	srand(time(NULL) ^ getpid());
	nfsh(&ctx);
}
