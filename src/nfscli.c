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
 * nfscli.c - Main entry point
 *
 * Parses command-line arguments, initializes context, and starts
 * the interactive shell or batch execution mode.
 */

#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "display.h"
#include "mount.h"
#include "nfs_cache.h"
#include "nfs_escape.h"
#include "nfscli.h"
#include "nfsh.h"
#include "portmap.h"

/*
 * Clean up all cached data before exit.
 * Ensures valgrind reports no leaks from caches.
 */
static void
nfsctx_cleanup(struct nfsctx *ctx)
{
    if (!ctx)
        return;

    /* Clear all NFS caches */
    nfs_cache_invalidate_all(ctx); /* Directory cache */
    nfs_symlink_cache_clear(ctx);
    nfs_attr_cache_clear(ctx);
    nfs_fh_type_cache_clear(ctx);
    nfs_parent_cache_clear();

    /* Clear mount caches */
    mount_exports_cache_clear(ctx);
    mount_fh_cache_clear(ctx);

    /* Clear portmap cache */
    portmap_cache_invalidate(ctx);

    /* Close socket (only regular mode; spoof mode handled by stop_spoof_threads) */
    if (ctx->net.spoof_ip == 0 && ctx->net.sock >= 0) {
        close(ctx->net.sock);
        ctx->net.sock = -1;
    }

    /* Free strdup'd strings */
    free(ctx->exec);
    ctx->exec = NULL;

    free(ctx->net.spoof_str);
    ctx->net.spoof_str = NULL;

    free(ctx->net.iface);
    ctx->net.iface = NULL;
}

static void
usage(char *pname)
{
    printf("\n");
    printf("Usage: %s <server-ip> [Option(s)]\n", pname);
    printf("Options:\n");
    printf("    --enhanced-completion    -  Enable enhanced tab completion (NFS v2)\n");
    printf("    --no-cache               -  Disable directory caching\n");
    printf(" -e --exec <cmds>            -  Execute semicolon-separated commands\n");
    printf(" -m --port-mountd <port>     -  Server mount port\n");
    printf(" -p --port-nfsd <port>       -  Server nfs port, defaults to %u\n", (unsigned)PORT_NFSD_DEFAULT);
    printf(" -s --port-local <port>      -  Local UDP port, defaults to %u\n", (unsigned)PORT_LOCAL_DEFAULT);
    printf(" -S --spoof-ip <iface>:<ip>  -  Spoof source IP using a raw socket\n");
    printf(" -t --timeout <sec>          -  Send/receive timeout on UDP socket\n");
    printf(" -v --verbose                -  Verbose level, repeat to increase\n");
    printf("\n");
    exit(EXIT_FAILURE);
}

/* Long-only option values (must be > 255 to avoid conflict with short opts) */
enum {
    OPT_NO_CACHE = 256,
    OPT_ENHANCED_COMPLETION
};

/* Commandline options */
const struct option longopts[] =
    {
        {"exec", 1, NULL, 'e'},
        {"no-cache", 0, NULL, OPT_NO_CACHE},
        {"port-nfsd", 1, NULL, 'p'},
        {"port-local", 1, NULL, 's'},
        {"enhanced-completion", 0, NULL, OPT_ENHANCED_COMPLETION},
        {"spoof-ip", 1, NULL, 'S'},
        {"port-mountd", 1, NULL, 'm'},
        {"timeout", 1, NULL, 't'},
        {"verbose", 0, NULL, 'v'},
        {NULL, 0, NULL, 0}};

int
main(int argc, char **argv)
{
    struct nfsctx ctx;
    struct timeval tv;
    int longindex;
    int i;

    /* Default values */
    memset(&ctx, 0x00, sizeof(struct nfsctx));
    ctx.ports.nfsd = htons(PORT_NFSD_DEFAULT);
    ctx.ports.local = htons(PORT_LOCAL_DEFAULT);
    ctx.ports.rpc = htons(PORT_RPC_DEFAULT);

    ctx.proto.mount_version = 0;
    ctx.proto.mount_version_mask = 0;
    ctx.proto.nfs_version = 0;
    ctx.proto.nfs_version_mask = 0;
    ctx.cache.mount_fh.hits = 0;
    ctx.cache.mount_fh.misses = 0;
    ctx.cache.enabled = 1;

    /* Initialize terminal state */
    ctx.term.stdin_tty = isatty(STDIN_FILENO);
    ctx.term.stdout_tty = isatty(STDOUT_FILENO);
    ctx.term.interactive = ctx.term.stdin_tty && ctx.term.stdout_tty;
    ctx.term.use_colors = term_use_colors();

    /* Initialize RPC lock pipe for fork synchronization */
    if (pipe(ctx.rpc_lock_pipe) < 0) {
        fprintf(stderr, "Failed to create RPC lock pipe: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    /* Put initial token in pipe */
    if (write(ctx.rpc_lock_pipe[1], "X", 1) != 1) {
        fprintf(stderr, "Failed to initialize RPC lock token\n");
        exit(EXIT_FAILURE);
    }
    ctx.concurrent_fork = 0;

    if (argc < 2)
        usage(argv[0]);

    ctx.server.name = argv[1];
    if ((ctx.server.ip = net_inetaddr(ctx.server.name)) == (uint32_t)-1) {
        fprintf(stderr, "Failed to resolve server '%s': %s\n", ctx.server.name, strerror(errno));
        exit(EXIT_FAILURE);
    }

    while ((i = getopt_long(argc - 1, &argv[1], "e:p:s:S:t:vm:", longopts, &longindex)) != -1) {

        switch (i) {
        case OPT_NO_CACHE:
            ctx.cache.enabled = 0;
            break;

        case OPT_ENHANCED_COMPLETION:
            ctx.completion = COMPLETION_ENHANCED;
            break;

        case 'e':
            ctx.exec = strdup(optarg);
            if (ctx.exec == NULL) {
                fprintf(stderr, "** Error: Memory allocation failed\n");
                goto opt_fail;
            }
            break;

        case 'S': {
            char *iface;
            char *ip;
            char *ep;

            if ((ep = strchr(optarg, ':')) == NULL) {
                fprintf(stderr, "Failed to parse interface name in spoofed IP\n");
                goto opt_fail;
            }

            iface = optarg;
            ip = ep + 1;
            *ep = '\0';

            if ((ctx.net.spoof_ip = net_inetaddr(ip)) == (uint32_t)-1) {
                fprintf(stderr, "Failed to resolve spoofed IP '%s': %s\n",
                    ip, strerror(errno));
                goto opt_fail;
            }
            ctx.net.spoof_str = strdup(ip);
            ctx.net.iface = strdup(iface);
            if (ctx.net.spoof_str == NULL || ctx.net.iface == NULL) {
                fprintf(stderr, "** Error: Memory allocation failed\n");
                goto opt_fail;
            }
        } break;

        case 's': {
            char *endptr;
            long port;
            errno = 0;
            port = strtol(optarg, &endptr, 10);
            if (errno != 0 || *endptr != '\0' || port <= 0 || port > 65535) {
                fprintf(stderr, "** Error: Invalid source port\n");
                goto opt_fail;
            }
            ctx.ports.local = htons((uint16_t)port);
        } break;

        case 'p': {
            char *endptr;
            long port;
            errno = 0;
            port = strtol(optarg, &endptr, 10);
            if (errno != 0 || *endptr != '\0' || port <= 0 || port > 65535) {
                fprintf(stderr, "** Error: Invalid server nfs port\n");
                goto opt_fail;
            }
            ctx.ports.nfsd = htons((uint16_t)port);
        } break;

        case 'm': {
            char *endptr;
            long port;
            errno = 0;
            port = strtol(optarg, &endptr, 10);
            if (errno != 0 || *endptr != '\0' || port <= 0 || port > 65535) {
                fprintf(stderr, "** Error: Invalid server mount port\n");
                goto opt_fail;
            }
            ctx.ports.mountd = htons((uint16_t)port);
        } break;

        case 't': {
            char *endptr;
            long timeout;
            errno = 0;
            timeout = strtol(optarg, &endptr, 10);
            if (errno != 0 || *endptr != '\0' || timeout < 0) {
                fprintf(stderr, "** Error: Invalid timeout value\n");
                goto opt_fail;
            }
            ctx.net.timeout.tv_sec = timeout;
            ctx.net.timeout.tv_usec = 0;
        } break;

        case 'v':
            ctx.verbose++;
            break;

        default:
            free(ctx.exec);
            free(ctx.net.spoof_str);
            free(ctx.net.iface);
            usage(argv[0]);
            /* NOTREACHED - usage() exits */
        }
    }

    if (0) {
opt_fail:
        /* Clean up allocations on option parsing failure */
        free(ctx.exec);
        free(ctx.net.spoof_str);
        free(ctx.net.iface);
        exit(EXIT_FAILURE);
    }

    /* Open raw socket */
    if (ctx.net.spoof_ip != 0) {
        if ((ctx.net.sock = rawpkt_open(ctx.net.iface)) < 0) {
            fprintf(stderr, "** Error: Failed to create raw socket: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        if ((ctx.net.readsock = rawcap_open(ctx.net.iface, 1)) < 0) {
            fprintf(stderr, "** Error: Failed to create raw socket: %s\n", strerror(errno));
            close(ctx.net.sock);
            exit(EXIT_FAILURE);
        }

        /* Attach BPF filter to reduce userspace packet processing */
        if (rawcap_set_filter(ctx.net.readsock, ctx.server.ip, ctx.net.spoof_ip) < 0) {
            fprintf(stderr, "Note: BPF filter not available, using userspace filtering\n");
        }

        /* Set read timeout */
        tv.tv_sec = SPOOF_RECV_TIMEOUT_SEC;
        if (ctx.net.timeout.tv_sec != 0)
            tv.tv_sec = ctx.net.timeout.tv_sec;
        tv.tv_usec = 0;

        if (setsockopt(ctx.net.readsock, SOL_SOCKET,
                SO_RCVTIMEO, (const char *)&tv, sizeof tv)) {
            fprintf(stderr, "** Error: Failed to set recv timeout on raw socket: %s\n",
                strerror(errno));
            close(ctx.net.readsock);
            close(ctx.net.sock);
            exit(EXIT_FAILURE);
        }

        /* Set write timeout */
        if (setsockopt(ctx.net.sock, SOL_SOCKET,
                SO_SNDTIMEO, (const char *)&tv, sizeof tv)) {
            fprintf(stderr, "** Error: Failed to set send timeout on raw socket: %s\n",
                strerror(errno));
            close(ctx.net.readsock);
            close(ctx.net.sock);
            exit(EXIT_FAILURE);
        }

        printf("\n***** WARNING ** WARNING ** WARNING ** WARNING *****\n");
        printf("*                                                  *\n");
        printf("* You are using a raw socket with a spoofed IP.    *\n");
        printf("* Use with caution and check your egress filtering *\n");
        printf("*                                                  *\n");
        printf("***** WARNING ** WARNING ** WARNING ** WARNING *****\n\n");

        /* Start persistent receiver thread */
        printf("Starting receiver thread\n");
        if (start_recv_thread(&ctx) != 0) {
            close(ctx.net.readsock);
            close(ctx.net.sock);
            exit(EXIT_FAILURE);
        }

        /* Run ARP reply thread */
        printf("Starting ARP reply thread\n");
        if (thread_run_arpreply(&ctx) != 0) {
            stop_spoof_threads(&ctx);
            close(ctx.net.sock);
            exit(EXIT_FAILURE);
        }

        /* Send gratuitous ARP to pre-populate target's cache */
        printf("Sending gratuitous ARP for %s\n", ctx.net.spoof_str);
        send_gratuitous_arp(&ctx);
    }

    /* Open regular socket */
    else {
        if ((ctx.net.sock = udp_socket(0, ctx.ports.local)) < 0) {
            fprintf(stderr, "Failed to create UDP socket (with source port %u): %s\n",
                ntohs(ctx.ports.local), strerror(errno));
            fprintf(stderr, "Change port or get root?\n");
            exit(EXIT_FAILURE);
        }

        /* Set socket timeouts - use -t value or default */
        tv.tv_sec = ctx.net.timeout.tv_sec ? ctx.net.timeout.tv_sec : UDP_RECV_TIMEOUT_SEC;
        tv.tv_usec = 0;

        if (setsockopt(ctx.net.sock, SOL_SOCKET, SO_RCVTIMEO,
                (const char *)&tv, sizeof(tv))) {
            fprintf(stderr, "** Error: Failed to set recv timeout on socket: %s\n",
                strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (setsockopt(ctx.net.sock, SOL_SOCKET, SO_SNDTIMEO,
                (const char *)&tv, sizeof(tv))) {
            fprintf(stderr, "** Error: Failed to set send timeout on socket: %s\n",
                strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    srand(time(NULL) ^ getpid());
    nfsh(&ctx);

    /* Clean up threads before exit */
    stop_spoof_threads(&ctx);

    /* Clean up caches */
    nfsctx_cleanup(&ctx);

    return 0;
}
