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
 * net.c - Network layer with IP spoofing support
 *
 * Handles low-level networking: UDP sockets, raw sockets for IP spoofing,
 * interface selection, and packet send/receive with timeouts.
 *
 * IP Spoofing Architecture (enabled with -S flag):
 *
 *   Normal mode: Standard UDP sockets, kernel handles everything.
 *
 *   Spoof mode: Bypass kernel networking to forge source IP:
 *
 *     Sending:
 *       1. Build raw Ethernet frame with forged IP/UDP headers
 *       2. Use PF_PACKET socket to inject at Layer 2
 *       3. Source IP is spoofed address, not our real IP
 *       4. rawpkt_add_ipv4() / rawpkt_add_udp() build the packet
 *
 *     Receiving:
 *       1. Responses come to spoofed IP (not normally routed to us)
 *       2. Sniff with PF_PACKET + BPF filter on the interface
 *       3. Persistent receiver thread (thread_recv_persistent) handles this
 *       4. Main thread signals expected port, waits on semaphore
 *
 *     ARP Handling:
 *       1. Send gratuitous ARP to claim spoofed IP on local network
 *       2. Background thread (arp_responder) answers ARP requests
 *       3. Required so server can resolve spoofed IP to our MAC
 *
 *   Synchronization (spoof mode):
 *     - recv_mutex protects expected_sport and recv_waiting
 *     - recv_sem signals when expected packet arrives or timeout
 *     - RPC lock (rpc_lock/unlock in rpc.c) serializes forked processes
 *
 *   BPF Filter (attach_bpf_filter):
 *     - Kernel-level packet filtering before userspace copy
 *     - Accept only: UDP from server_ip to spoof_ip
 *     - Reduces CPU overhead from processing irrelevant packets
 */

#include <alloca.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/filter.h>

#include "net.h"
#include "nfscli.h"
#include "nfsh.h"
#include "print.h"
#include "rpc.h"
#include "str.h"

/*
 * Initialize ARP packet common fields.
 * Sets up Ethernet and ARP headers for standard Ethernet/IPv4 ARP.
 */
static void
arp_pkt_init(ARP_pkt *pkt, const uint8_t *src_mac, uint16_t op)
{
    memset(pkt, 0, sizeof(*pkt));

    /* Ethernet header */
    memcpy(pkt->ehdr.src, src_mac, 6);
    pkt->ehdr.proto = htons(ETH_PROTO_ARP);

    /* ARP header */
    pkt->ahdr.arp_hrd = htons(HW_ADDR_ETHERNET);
    pkt->ahdr.arp_pro = htons(PROTOTYPE_IPV4);
    pkt->ahdr.arp_hln = 6;
    pkt->ahdr.arp_pln = 4;
    pkt->ahdr.arp_op = htons(op);

    /* Sender MAC */
    memcpy(pkt->smac, src_mac, 6);
}

/*
 * Read MAC address for IP from /proc/net/arp on Linux.
 * Destination buffer must be at least 6 bytes long.
 * Returns 0 on success, -1 on error and if the MAC address was not found;
 */
#define ARP_CACHE_FILE "/proc/net/arp"
int
arpcache(const char *ip, uint8_t *dst)
{
    FILE *fp;
    char buf[1024]; /* One line in ARP_CACHE_FILE should not exceed 1024 bytes */

    if ((fp = fopen(ARP_CACHE_FILE, "r")) == NULL) {
        fprintf(stderr, "** Error: Failed to open %s: %s\n",
            ARP_CACHE_FILE, strerror(errno));
        return -1;
    }

    memset(buf, 0x00, sizeof(buf));
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        char aip[64];
        char hwtype[16];
        char flags[16];
        char mac[32];
        char mask[16];
        char device[32];

        if (sscanf(buf, "%63s %15s %15s %31s %15s %31s",
                aip, hwtype, flags, mac, mask, device) != 6)
            continue;
        if (strcmp(aip, ip) == 0) {
            unsigned long hw_type;
            char *endptr;

            errno = 0;
            hw_type = strtoul(hwtype, &endptr, 0);
            if (endptr == hwtype || *endptr != '\0' || errno != 0 || hw_type != 1) {
                fprintf(stderr, "** Error: Found server IP in ARP cache, but HW Type is %s (not 1)\n",
                    hwtype);
                fclose(fp);
                errno = ENOENT;
                return -1;
            }

            printf("IP %s has HW address %s in ARP cache\n", ip, mac);
            if (sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                    &dst[0], &dst[1], &dst[2], &dst[3], &dst[4], &dst[5]) != 6) {
                fprintf(stderr, "** Error: Invalid MAC address format: %s\n", mac);
                fclose(fp);
                errno = EINVAL;
                return -1;
            }
            fclose(fp);
            return 0;
        }

        memset(buf, 0x00, sizeof(buf));
    }

    fclose(fp);
    errno = ENOENT;
    return -1;
}

/*
 * ARP reply thread
 * Send ARP reply packets in reply to requests for the
 * spoofed IPv4 address
 */
static void *
thread_arpreply(void *a)
{
    struct nfsctx *ctx;
    int sock;
    struct ifreq ifr;
    struct sockaddr_ll sa;
    ARP_pkt arp_reply;

    ctx = (struct nfsctx *)a;

    /* Set up reply packet template */
    arp_pkt_init(&arp_reply, ctx->net.ifmac, ARP_REPLY);
    arp_reply.sip = ctx->net.spoof_ip;

    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        fprintf(stderr, "** Error: opening raw socket: %s\n", strerror(errno));
        return NULL;
    }

    /* Get interface index */
    memset(&ifr, 0x00, sizeof(ifr));
    strncpy(ifr.ifr_name, ctx->net.iface, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
        fprintf(stderr, "** Error: Failed to get interface index: %s\n", strerror(errno));
        close(sock);
        return NULL;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sll_ifindex = ifr.ifr_ifindex;
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);

    /* Read ARP request packets and send responses */
    while (!ctx->net.shutdown) {
        ARP_pkt *arp_req;
        /* Align buffer for safe struct access on ARM */
        uint32_t buf32[8192 / sizeof(uint32_t)];
        uint8_t *buf = (uint8_t *)buf32;
        ssize_t n;

        if ((n = read(sock, buf, sizeof(buf32))) <= 0) {
            if (ctx->net.shutdown)
                break;
            if (n < 0 && errno == EINTR)
                continue; /* Signal interrupted, retry */
            fprintf(stderr, "** Error: ARP reply thread read failed: %s\n",
                n < 0 ? strerror(errno) : "empty read");
            close(sock);
            return NULL;
        }

        arp_req = (ARP_pkt *)buf;
        if (n < (ssize_t)sizeof(ARP_pkt))
            continue;

        /* Check Ethernet protocol field for ARP */
        if (ntohs(arp_req->ehdr.proto) != ETH_PROTO_ARP)
            continue;

        if (ntohs(arp_req->ahdr.arp_hrd) != HW_ADDR_ETHERNET)
            continue;

        if (ntohs(arp_req->ahdr.arp_pro) != ADDR_TYPE_IPV4)
            continue;

        if (arp_req->ahdr.arp_hln != 6)
            continue;

        if (arp_req->ahdr.arp_pln != 4)
            continue;

        if (ntohs(arp_req->ahdr.arp_op) != ARP_REQUEST)
            continue;

        /* This is not a request for HW address of the spoofed IP */
        if (arp_req->tip != ctx->net.spoof_ip)
            continue;

        /* Copy values to reply packet */
        memcpy(arp_reply.ehdr.dest, arp_req->ehdr.src, 6);
        memcpy(arp_reply.tmac, arp_req->smac, 6);
        arp_reply.tip = arp_req->sip;

        /* Send reply */
        if (sendto(sock, &arp_reply, sizeof(arp_reply), 0,
                (struct sockaddr *)&sa, sizeof(sa)) != sizeof(arp_reply)) {
            fprintf(stderr, "** Error: Failed to send ARP reply: %s\n", strerror(errno));
        }
    }

    close(sock);
    return NULL;
}

/*
 * Start ARP reply thread
 */
int
thread_run_arpreply(struct nfsctx *ctx)
{
    struct ifreq ifr;
    pthread_attr_t attr;
    int e;

    /* Get MAC address of spoof interface */
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ctx->net.iface);
    if (ioctl(ctx->net.sock, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "** Error: Failed to get spoof interface MAC address: %s\n",
            strerror(errno));
        return -1;
    }
    memcpy(ctx->net.ifmac, ifr.ifr_hwaddr.sa_data, 6);

    pthread_attr_init(&attr);
    /* Create joinable thread for clean shutdown */
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    if ((e = pthread_create(&ctx->net.arp_thread, &attr, thread_arpreply, (void *)ctx)) != 0) {
        fprintf(stderr, "** Error: Failed to start ARP reply thread: %s\n",
            strerror(e));
        pthread_attr_destroy(&attr);
        errno = e;
        return -1;
    }
    ctx->net.arp_thread_started = 1;
    pthread_attr_destroy(&attr);

    return 0;
}

/*
 * Send gratuitous ARP to pre-populate target's ARP cache.
 *
 * This announces our MAC address for the spoofed IP before we start
 * communicating, reducing latency on the first RPC exchange.
 */
int
send_gratuitous_arp(struct nfsctx *ctx)
{
    int sock;
    struct ifreq ifr;
    struct sockaddr_ll sa;
    ARP_pkt garp;

    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
        fprintf(stderr, "** Warning: Failed to open socket for gratuitous ARP: %s\n",
            strerror(errno));
        return -1;
    }

    /* Get interface index */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ctx->net.iface, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "** Warning: Failed to get interface index for gratuitous ARP: %s\n",
            strerror(errno));
        close(sock);
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sll_ifindex = ifr.ifr_ifindex;
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_halen = 6;
    memset(sa.sll_addr, 0xff, 6); /* Broadcast */

    /* Build gratuitous ARP reply (broadcast) */
    arp_pkt_init(&garp, ctx->net.ifmac, ARP_REPLY);

    /* Gratuitous ARP: broadcast destination, sender and target IP are the same */
    memset(garp.ehdr.dest, 0xff, 6);
    garp.sip = ctx->net.spoof_ip;
    memset(garp.tmac, 0xff, 6); /* Broadcast target */
    garp.tip = ctx->net.spoof_ip;

    if (sendto(sock, &garp, sizeof(garp), 0,
            (struct sockaddr *)&sa, sizeof(sa)) != sizeof(garp)) {
        fprintf(stderr, "** Warning: Failed to send gratuitous ARP: %s\n",
            strerror(errno));
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

/*
 * Persistent UDP receiver thread.
 * Runs forever, receiving packets and signaling when expected packet arrives.
 */
static void *
thread_recv_persistent(void *a)
{
    struct nfsctx *ctx = (struct nfsctx *)a;
    IPv4_hdr *iph;
    UDP_hdr *udph;
    uint32_t buf32[(MTU_MAX * 2) / sizeof(uint32_t)]; /* Aligned for struct access */
    uint8_t *buf = (uint8_t *)buf32;
    ssize_t len;
    uint16_t ip_tlen, hdr_size;
    uint32_t payload_len;
    size_t min_pkt_size;

    while (!ctx->net.shutdown) {
        /* Receive next packet (blocks until packet or timeout) */
        len = recv(ctx->net.readsock, buf, sizeof(buf32), 0);

        if (len < 0) {
            if (errno == EINTR)
                continue;
            if (ctx->net.shutdown)
                break;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Timeout - if we were waiting, signal failure */
                pthread_mutex_lock(&ctx->net.recv_mutex);
                if (ctx->net.recv_waiting) {
                    ctx->net.recvlen = 0;
                    ctx->net.recv_waiting = 0;
                    pthread_mutex_unlock(&ctx->net.recv_mutex);
                    sem_post(&ctx->net.recv_sem);
                } else {
                    pthread_mutex_unlock(&ctx->net.recv_mutex);
                }
                continue;
            }
            /* Real error - keep going */
            continue;
        }

        /* Validate packet structure (local buffer, no lock needed) */
        if (len <= (ssize_t)(sizeof(Eth_hdr) + sizeof(IPv4_hdr) + sizeof(UDP_hdr)))
            continue;

        iph = (IPv4_hdr *)(buf + sizeof(Eth_hdr));

        if (iph->ip_ver != 4)
            continue;

        if (len < (ssize_t)(sizeof(Eth_hdr) + ntohs(iph->ip_tlen)))
            continue;

        /* BPF should have filtered these, but double-check */
        if (iph->ip_sadd != ctx->server.ip || iph->ip_dadd != ctx->net.spoof_ip)
            continue;

        if (iph->ip_prot != IP_PROTO_UDP)
            continue;

        if (iph->ip_hlen < 5 || iph->ip_hlen > 15)
            continue;

        udph = (UDP_hdr *)((uint8_t *)iph + (iph->ip_hlen * 4));

        /* Check destination port (constant, no lock needed) */
        if (udph->udp_dprt != ctx->ports.local)
            continue;

        /*
         * Lock to check recv_waiting and expected_sport atomically,
         * then copy payload if this is the expected response.
         */
        pthread_mutex_lock(&ctx->net.recv_mutex);

        if (!ctx->net.recv_waiting ||
            udph->udp_sprt != ctx->net.expected_sport) {
            pthread_mutex_unlock(&ctx->net.recv_mutex);
            continue;
        }

        /* Valid packet - extract payload */
        ip_tlen = ntohs(iph->ip_tlen);
        hdr_size = (iph->ip_hlen * 4) + sizeof(UDP_hdr);

        if (ip_tlen < hdr_size) {
            pthread_mutex_unlock(&ctx->net.recv_mutex);
            continue;
        }

        payload_len = ip_tlen - hdr_size;

        min_pkt_size = sizeof(Eth_hdr) + (iph->ip_hlen * 4) + sizeof(UDP_hdr);
        if ((size_t)len < min_pkt_size ||
            payload_len > (size_t)(len - min_pkt_size)) {
            pthread_mutex_unlock(&ctx->net.recv_mutex);
            continue;
        }

        if (payload_len > sizeof(ctx->net.recvbuf)) {
            pthread_mutex_unlock(&ctx->net.recv_mutex);
            continue;
        }

        memcpy(ctx->net.recvbuf, (uint8_t *)udph + sizeof(UDP_hdr), payload_len);
        ctx->net.recvlen = payload_len;

        /* Signal packet received */
        ctx->net.recv_waiting = 0;
        pthread_mutex_unlock(&ctx->net.recv_mutex);
        sem_post(&ctx->net.recv_sem);
    }

    return NULL;
}

/*
 * Start the persistent receiver thread.
 * Called once at startup when using IP spoofing.
 */
int
start_recv_thread(struct nfsctx *ctx)
{
    pthread_attr_t attr;
    int e;

    if (sem_init(&ctx->net.recv_sem, 0, 0) != 0) {
        fprintf(stderr, "** Error: sem_init failed: %s\n", strerror(errno));
        return -1;
    }

    if ((e = pthread_mutex_init(&ctx->net.recv_mutex, NULL)) != 0) {
        fprintf(stderr, "** Error: pthread_mutex_init failed: %s\n", strerror(e));
        sem_destroy(&ctx->net.recv_sem);
        errno = e;
        return -1;
    }

    ctx->net.sync_initialized = 1;
    ctx->net.recv_waiting = 0;
    ctx->net.recvlen = 0;

    if ((e = pthread_attr_init(&attr)) != 0) {
        fprintf(stderr, "** Error: pthread_attr_init failed: %s\n", strerror(e));
        pthread_mutex_destroy(&ctx->net.recv_mutex);
        sem_destroy(&ctx->net.recv_sem);
        ctx->net.sync_initialized = 0;
        errno = e;
        return -1;
    }
    /* Create joinable thread for clean shutdown */
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    if ((e = pthread_create(&ctx->net.recv_thread, &attr, thread_recv_persistent, ctx)) != 0) {
        fprintf(stderr, "** Error: Failed to start receiver thread: %s\n", strerror(e));
        pthread_attr_destroy(&attr);
        pthread_mutex_destroy(&ctx->net.recv_mutex);
        sem_destroy(&ctx->net.recv_sem);
        ctx->net.sync_initialized = 0;
        errno = e;
        return -1;
    }
    ctx->net.recv_thread_started = 1;

    pthread_attr_destroy(&attr);
    return 0;
}

/*
 * Stop spoofing threads and clean up resources.
 * Called on program exit when using IP spoofing.
 */
void
stop_spoof_threads(struct nfsctx *ctx)
{
    if (ctx->net.spoof_ip == 0)
        return; /* Not using spoofing */

    /* Signal threads to stop */
    ctx->net.shutdown = 1;

    /* Close sockets to unblock threads */
    if (ctx->net.readsock >= 0) {
        close(ctx->net.readsock);
        ctx->net.readsock = -1;
    }

    /* Wait for threads to finish (only if they were started) */
    if (ctx->net.recv_thread_started)
        pthread_join(ctx->net.recv_thread, NULL);
    if (ctx->net.arp_thread_started)
        pthread_join(ctx->net.arp_thread, NULL);

    /* Clean up synchronization primitives (only if initialized) */
    if (ctx->net.sync_initialized) {
        sem_destroy(&ctx->net.recv_sem);
        pthread_mutex_destroy(&ctx->net.recv_mutex);
        ctx->net.sync_initialized = 0;
    }
}

/*
 * Write UDP datagram to network based on settings
 */
ssize_t
udp_write(struct nfsctx *ctx, uint32_t ip, uint16_t port, const uint8_t *data, size_t datalen)
{
    ssize_t ret;

    if (port == 0) {
        fprintf(stderr, "** Error: Destination port is zero\n");
        errno = EINVAL;
        return -1;
    }

    /*
     * Acquire RPC lock if in concurrent fork scenario.
     *
     * LOCK CONTRACT: This function acquires the RPC lock. On error, we
     * release it here. On success, the caller (rpc_recv_xid) is responsible
     * for releasing the lock after receiving the response. This asymmetric
     * pattern ensures the lock is held for the entire request-response cycle.
     */
    rpc_lock(ctx);

    /*
     * Send a raw packet with spoofed source IP
     */
    if (ctx->net.spoof_ip != 0) {
        /* Align buffer for safe struct access on ARM */
        uint32_t buf32[(MTU_MAX + 1024) / sizeof(uint32_t)];
        uint8_t *buf = (uint8_t *)buf32;

        memset(buf, 0x00, sizeof(buf32));

        if (rawpkt_add_ipv4(buf, 0x00, rand(), 128, ctx->net.spoof_ip, ip) < 0) {
            rpc_unlock(ctx);
            return -1;
        }

        if (rawpkt_add_udp(buf, ctx->ports.local, port, data, datalen) < 0) {
            rpc_unlock(ctx);
            return -1;
        }

        if ((sizeof(IPv4_hdr) + sizeof(UDP_hdr) + datalen) > sizeof(buf32)) {
            fprintf(stderr, "** Error: payload data exceeds buffer size\n");
            errno = EMSGSIZE;
            rpc_unlock(ctx);
            return -1;
        }

        /* Tell receiver what to expect (under lock) */
        pthread_mutex_lock(&ctx->net.recv_mutex);
        ctx->net.recvlen = 0;
        ctx->net.expected_sport = port;
        ctx->net.recv_waiting = 1;
        pthread_mutex_unlock(&ctx->net.recv_mutex);

        /* Send the packet */
        ret = udp_sendto(ctx->net.sock, ip, port, buf,
            sizeof(IPv4_hdr) + sizeof(UDP_hdr) + datalen);
        if (ret < 0)
            rpc_unlock(ctx);
        return ret;
    }

    /*
     * Send regular UDP datagram
     */
    ret = udp_sendto(ctx->net.sock, ip, port, data, datalen);
    if (ret < 0)
        rpc_unlock(ctx);
    return ret;
}

/*
 * Read UDP datagram based on settings
 */
ssize_t
udp_read(struct nfsctx *ctx, uint32_t ip, uint16_t port, uint8_t *buf, size_t buflen)
{
    (void)ip;
    (void)port;

    /*
     * Using raw sockets - wait for receiver thread to signal
     */
    if (ctx->net.spoof_ip != 0) {
        ssize_t ret;

        /* Wait for packet (receiver thread signals via semaphore) */
        while (sem_wait(&ctx->net.recv_sem) != 0) {
            if (errno == EINTR)
                continue; /* Interrupted by signal, retry */
            fprintf(stderr, "** Error: sem_wait failed: %s\n", strerror(errno));
            return -1;
        }

        /* Read received data under lock */
        pthread_mutex_lock(&ctx->net.recv_mutex);

        /* Check if we got data or timeout */
        if (ctx->net.recvlen == 0) {
            pthread_mutex_unlock(&ctx->net.recv_mutex);
            print(V_DEBUG, ctx, "** Warning: Receive timeout or empty\n");
            errno = ETIMEDOUT;
            return -1;
        }

        ret = ctx->net.recvlen;
        if (ctx->net.recvlen > buflen) {
            fprintf(stderr, "** Error: Buffer too small, truncating\n");
            ret = buflen;
        }

        memcpy(buf, ctx->net.recvbuf, ret);
        pthread_mutex_unlock(&ctx->net.recv_mutex);
        return ret;
    }

    /*
     * Regular UDP socket
     */
    return udp_recv(ctx->net.sock, ip, port, buf, buflen, ctx->quiet);
}

/*
 * Returns the length of received data on success, -1 on error.
 * If quiet is nonzero, timeout errors are suppressed.
 */
ssize_t
udp_recv(int sock, uint32_t ip, uint16_t port, uint8_t *buf, size_t buflen,
    int quiet)
{
    ssize_t len;
    struct sockaddr_in sa;
    socklen_t addrlen;

    memset(&sa, 0x00, sizeof(struct sockaddr_in));
    sa.sin_family = PF_INET;
    sa.sin_addr.s_addr = ip;
    sa.sin_port = port;
    addrlen = sizeof(struct sockaddr_in);

    while ((len = recvfrom(sock, buf, buflen, 0, (struct sockaddr *)&sa, &addrlen)) == -1) {
        if (errno == EINTR) {
            if (g_interrupted) {
                fprintf(stderr, "\nInterrupted\n");
                return -1;
            }
            continue; /* Retry if interrupted by signal but not Ctrl-C */
        }
        if (!quiet) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                fprintf(stderr, "** Error: Receive timeout\n");
            else
                fprintf(stderr, "** Error: Failed to receive: %s\n",
                    strerror(errno));
        }
        return -1;
    }

    return len;
}

/*
 * Send UDP datagram.
 * On success, the number of bytes sent is returned.
 * IP and port in network byte order.
 */
ssize_t
udp_sendto(int sock, uint32_t ip, uint16_t port, const uint8_t *buf, size_t buflen)
{
    struct sockaddr_in da;
    socklen_t addrlen;
    ssize_t ret;

    memset(&da, 0x00, sizeof(struct sockaddr_in));
    da.sin_family = PF_INET;
    da.sin_addr.s_addr = ip;
    da.sin_port = port;
    addrlen = sizeof(struct sockaddr_in);

    ret = sendto(sock, buf, buflen, 0, (struct sockaddr *)&da, addrlen);
    if (ret < 0) {
        fprintf(stderr, "** Error: Failed to send: %s\n", strerror(errno));
        return -1;
    }

    return ret;
}

/*
 * Create UDP socket and bind to address.
 * IP and port in network byte order.
 * Returns a socket descriptor on success, -1 on error;
 */
int
udp_socket(uint32_t ip, uint16_t port)
{
    int sock;
    struct sockaddr_in usin;

    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        return (-1);

    memset(&usin, 0x00, sizeof(usin));
    usin.sin_family = PF_INET;
    usin.sin_addr.s_addr = ip;
    usin.sin_port = port;

    if (bind(sock, (struct sockaddr *)&usin, sizeof(usin)) < 0) {
        close(sock);
        return (-1);
    }

    return (sock);
}

/*
 * Translate hostname or dotted decimal host address
 * into a network byte ordered IP address.
 * Returns (uint32_t)-1 on error.
 */
uint32_t
net_inetaddr(const char *host)
{
    in_addr_t addr;
    struct hostent *hent;

    addr = inet_addr(host);
    if (addr == INADDR_NONE) {
        if ((hent = gethostbyname(host)) == NULL)
            return (uint32_t)-1;
        memcpy(&addr, hent->h_addr, sizeof(addr));
    }

    return addr;
}

static int
rawsock_bind(int sock, const char *ifc, int promisc)
{
    struct sockaddr_ll sll;
    struct ifreq ifr;

    /* Find interface index */
    memset(&ifr, 0x00, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifc);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "** Error: ioctl failed to find interface: %s\n", strerror(errno));
        return -1;
    }

    /* Bind raw socket to the interface */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_IP);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "** Error: failed to bind interface to raw socket: %s\n",
            strerror(errno));
        return -1;
    }

    /* Enable promiscuous mode */
    if (promisc) {
        struct packet_mreq mr;

        memset(&mr, 0, sizeof(mr));
        mr.mr_ifindex = ifr.ifr_ifindex;
        mr.mr_type = PACKET_MR_PROMISC;

        if (setsockopt(sock, SOL_PACKET,
                PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
            fprintf(stderr, "** Error: failed to set promiscuous mode: %s\n",
                strerror(errno));
            return -1;
        }
    }

    return 0;
}

/*
 * Open raw socket for reading packets
 * Returns socket descriptor on success, -1 on error
 */
int
rawcap_open(const char *ifc, int promisc)
{
    int sock;

    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        fprintf(stderr, "** Error: Failed to open raw socket: %s\n", strerror(errno));
        return -1;
    }

    if (rawsock_bind(sock, ifc, promisc) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

/*
 * Attach BPF filter to raw capture socket to improve spoofed receive performance.
 *
 * Filters for: UDP packets from server_ip to spoof_ip.
 * Port filtering is left to userspace since it varies per RPC call.
 *
 * Returns 0 on success, -1 on failure (caller should fall back to userspace filtering).
 */
int
rawcap_set_filter(int sock, uint32_t server_ip, uint32_t spoof_ip)
{
    /*
     * BPF filter for PF_PACKET socket (receives Ethernet frames).
     * Offsets: Eth header=14, IP proto=14+9=23, IP src=14+12=26, IP dst=14+16=30
     *
     * Filter logic:
     *   if (eth_type != IP) drop
     *   if (ip_proto != UDP) drop
     *   if (ip_src != server_ip) drop
     *   if (ip_dst != spoof_ip) drop
     *   accept
     */
    struct sock_filter filter[] = {
        /* Load Ethernet type (offset 12, 2 bytes) */
        {BPF_LD | BPF_H | BPF_ABS, 0, 0, 12},
        /* If not IP (0x0800), jump to drop */
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 7, ETH_P_IP},

        /* Load IP protocol (offset 23, 1 byte) */
        {BPF_LD | BPF_B | BPF_ABS, 0, 0, 23},
        /* If not UDP (17), jump to drop */
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 5, IPPROTO_UDP},

        /* Load IP source address (offset 26, 4 bytes) */
        {BPF_LD | BPF_W | BPF_ABS, 0, 0, 26},
        /* If not server_ip, jump to drop */
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 3, ntohl(server_ip)},

        /* Load IP destination address (offset 30, 4 bytes) */
        {BPF_LD | BPF_W | BPF_ABS, 0, 0, 30},
        /* If not spoof_ip, jump to drop */
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 1, ntohl(spoof_ip)},

        /* Accept: return max packet length */
        {BPF_RET | BPF_K, 0, 0, 0xFFFFFFFF},

        /* Drop: return 0 */
        {BPF_RET | BPF_K, 0, 0, 0},
    };

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
        /* Filter attachment failed - caller should use userspace filtering */
        return -1;
    }

    return 0;
}

/*
 * Open raw socket for sending packets
 * Returns a socket descriptor on success, -1 on error.
 */
int
rawpkt_open(const char *ifc)
{
    int fd;
    const int one = 1;

    if ((fd = socket(AF_INET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        fprintf(stderr, "** Error: Failed to open raw socket: %s\n",
            strerror(errno));
        return (-1);
    }

    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL,
            (void *)&one, (socklen_t)sizeof(one)) < 0) {
        fprintf(stderr, "** Error: Cannot set header included: %s\n",
            strerror(errno));
        close(fd);
        return (-1);
    }

    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifc, strlen(ifc)) < 0) {
        fprintf(stderr, "** Error: Could not bind to interface: %s\n",
            strerror(errno));
        close(fd);
        return (-1);
    }

    return (fd);
}

/*
 * Generates ones-complement checksum over data in network byte order.
 * Returns result in network byte order.
 */
static uint16_t
chksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;

    /* Sum 16-bit words (big-endian) */
    while (len > 1) {
        sum += ((uint32_t)data[0] << 8) | data[1];
        data += 2;
        len -= 2;
    }

    /* Add odd byte if present */
    if (len == 1)
        sum += (uint32_t)data[0] << 8;

    /* Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum >> 16) + (sum & 0xFFFF);

    return htons((uint16_t)~sum);
}

/*
 * Add IPv4 header to buffer buf.
 * The total length field as well as the IP checksum
 * is set when a protocol is added.
 * Note that all values is assumed to be in network byte order.
 * Returns -1 on error and zero on success.
 */
int
rawpkt_add_ipv4(uint8_t *buf, uint8_t tos, uint16_t id,
    uint8_t ttl, uint32_t sadd, uint32_t dadd)
{
    IPv4_hdr *iph;

    if (buf == NULL) {
        fprintf(stderr, "** Error: rawpkt_add_ipv4(): "
                        "Received NULL pointer as buf\n");
        errno = EINVAL;
        return (-1);
    }

    iph = (IPv4_hdr *)buf;
    iph->ip_ver = 4;
    iph->ip_hlen = 5;
    iph->ip_tos = tos;
    iph->ip_id = id;
    iph->ip_flgs = 0x0; /* (Don't) fragment */
    iph->ip_off = 0x00; /* Fragment offset */
    iph->ip_ttl = ttl;
    iph->ip_sadd = sadd;
    iph->ip_dadd = dadd;

    return (0);
}

/*
 * A UDP header is added to the buffer which is assumed to already
 * contain an IPv4 header. The total length and proto field in the IPv4
 * header is set here as well as the checksum.
 * We also calculate the UDP checksum each time. This could perhaps be
 * randomized since it is optional under IPv4.
 * All arguments (except paylen) assumed to be in network byte order.
 */
int
rawpkt_add_udp(uint8_t *packet, uint16_t sport, uint16_t dport,
    const uint8_t *payload, uint16_t paylen)
{
    IPv4_hdr *iph;
    UDP_hdr *udph;
    Pseudo_hdr *phdr;
    uint8_t *pbuf;
    size_t plen;

    if (packet == NULL) {
        fprintf(stderr, "** Error: rawpkt_add_udp(): "
                        "Received NULL pointer as packet\n");
        errno = EINVAL;
        return (-1);
    }

    /* Check paylen first to prevent overflow in addition */
    if (paylen > (int)(MTU_MAX - sizeof(IPv4_hdr) - sizeof(UDP_hdr))) {
        fprintf(stderr, "** Error: Packet payload (%d bytes) is greater than "
                        "maximum size allowed (%d bytes)\n",
            paylen, (int)(MTU_MAX - sizeof(IPv4_hdr) - sizeof(UDP_hdr)));
        errno = EMSGSIZE;
        return (-1);
    }

    plen = sizeof(Pseudo_hdr) + sizeof(UDP_hdr) + paylen;
    pbuf = alloca(plen); /* Safe: plen bounded by MTU_MAX check above */
    memset(pbuf, 0x00, plen);

    iph = (IPv4_hdr *)packet;

    /* Build Pseudo header  */
    phdr = (Pseudo_hdr *)pbuf;
    phdr->phd_saddr = iph->ip_sadd;
    phdr->phd_daddr = iph->ip_dadd;
    phdr->phd_zero = 0;
    phdr->phd_proto = IP_PROTO_UDP;
    phdr->phd_hlen = htons(sizeof(UDP_hdr) + paylen);

    /* Build UDP header */
    udph = (UDP_hdr *)(pbuf + sizeof(Pseudo_hdr));
    udph->udp_sprt = sport;
    udph->udp_dprt = dport;
    udph->udp_len = htons(sizeof(UDP_hdr) + paylen);
    memcpy(pbuf + sizeof(Pseudo_hdr) + sizeof(UDP_hdr), payload, paylen);

    /* UDP checksum */
    udph->udp_sum = chksum(pbuf, sizeof(Pseudo_hdr) + sizeof(UDP_hdr) + paylen);

    /* Copy UDP header to real packet */
    memcpy(packet + sizeof(IPv4_hdr), pbuf + sizeof(Pseudo_hdr),
        sizeof(UDP_hdr) + paylen);

    /* Set remaining IP header values and calculate IP checksum */
    iph = (IPv4_hdr *)packet;
    iph->ip_tlen = SETIPLENFIX(sizeof(IPv4_hdr) + sizeof(UDP_hdr) + paylen);
    iph->ip_prot = IP_PROTO_UDP;
    iph->ip_sum = 0; /* Must be zero before computing checksum */
    iph->ip_sum = chksum(packet, sizeof(IPv4_hdr));

    return (0);
}
