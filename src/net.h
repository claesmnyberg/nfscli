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
 * net.h - Network layer
 *
 * Handles low-level networking: UDP sockets, raw sockets for IP spoofing,
 * interface selection, and packet send/receive with timeouts.
 */

#ifndef NET_H
#define NET_H

#include <arpa/inet.h>
#include <stdint.h>

#include <sys/types.h>

#ifndef FIXIPLEN
#define SETIPLENFIX(x) x
#define GETIPLENFIX(x) x
#else
#define SETIPLENFIX(x) htons(x)
#define GETIPLENFIX(x) ntohs(x)
#endif /* FIXIPLEN */

#define IP_PROTO_TCP  0x06
#define IP_PROTO_UDP  0x11
#define IP_PROTO_ICMP 0x1

#define MTU_MAX 1500

#define PROTOTYPE_IPV4 0x0800
#define ETH_PROTO_ARP  0x0806

/*
 * Ethernet Header
 */
typedef struct {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t proto;
} __attribute__((packed)) Eth_hdr;

/*
 * Internet Protocol version 4 header
 */
typedef struct {
#ifdef WORDS_BIGENDIAN
    uint8_t ip_ver : 4,   /* IP version */
        ip_hlen : 4;      /* Header length in (4 byte) words */
#else
    uint8_t ip_hlen : 4,  /* Header length in (4 byte) words */
        ip_ver : 4;       /* IP version */
#endif
    uint8_t ip_tos;       /* Type of service */
    uint16_t ip_tlen;     /* Datagram total length */
    uint16_t ip_id;       /* Identification number */
#ifdef WORDS_BIGENDIAN
    uint16_t ip_flgs : 3, /* Fragmentation flags */
        ip_off : 13;      /* Fragment offset */
#else
    uint16_t ip_off : 13, /* Fragment offset */
        ip_flgs : 3;      /* Fragmentation flags */
#endif
    uint8_t ip_ttl;       /* Time to live */
    uint8_t ip_prot;      /* Transport layer protocol (ICMP=1, TCP=6, UDP=17) */
    uint16_t ip_sum;      /* Checksum */
    uint32_t ip_sadd;     /* Source address */
    uint32_t ip_dadd;     /* Destination address */
} __attribute__((packed)) IPv4_hdr;

/*
 * Checksum header
 * Used for UDP and TCP checksum calculations.
 * W. Richard Stevens TCP/IP illustrated Vol 1 page 145.
 */
typedef struct {
    uint32_t phd_saddr; /* Source address */
    uint32_t phd_daddr; /* Destination address */
    uint8_t phd_zero;   /* Zero byte */
    uint8_t phd_proto;  /* Protocol code */
    uint16_t phd_hlen;  /* Length of TCP/UDP header */
} __attribute__((packed)) Pseudo_hdr;

/*
 * User Datagram Protocol Header
 */
typedef struct {
    uint16_t udp_sprt; /* Source port */
    uint16_t udp_dprt; /* Destination port */
    uint16_t udp_len;  /* Length of UDP header including data */
    uint16_t udp_sum;  /* Checksum */
} __attribute__((packed)) UDP_hdr;

#define ARP_REQUEST      0x0001
#define ARP_REPLY        0x0002
#define HW_ADDR_ETHERNET 0x0001
#define ADDR_TYPE_IPV4   0x0800

/*
 * ARP Header
 */
typedef struct {
    uint16_t arp_hrd; /* format of hardware address */
    uint16_t arp_pro; /* format of protocol address */
    uint8_t arp_hln;  /* length of hardware address (ETH_ADDR_LEN) */
    uint8_t arp_pln;  /* length of protocol address (IP_ADDR_LEN) */
    uint16_t arp_op;  /* operation */
} __attribute__((packed)) ARP_hdr;

/*
 * Complete ARP packet (Ethernet + ARP header + addresses)
 */
typedef struct {
    Eth_hdr ehdr;    /* Ethernet Header */
    ARP_hdr ahdr;    /* ARP header */
    uint8_t smac[6]; /* Sender MAC */
    uint32_t sip;    /* Sender IP */
    uint8_t tmac[6]; /* Target MAC */
    uint32_t tip;    /* Target IP */
} __attribute__((packed)) ARP_pkt;

/* net.c */
extern int arpcache(const char *, uint8_t *);
extern int rawpkt_open(const char *);
extern int rawcap_open(const char *, int);
extern int rawcap_set_filter(int sock, uint32_t server_ip, uint32_t spoof_ip);
extern int rawpkt_add_ipv4(uint8_t *, uint8_t, uint16_t, uint8_t, uint32_t, uint32_t);
extern int rawpkt_add_udp(uint8_t *, uint16_t, uint16_t, const uint8_t *, uint16_t);
extern ssize_t udp_recv(int, uint32_t, uint16_t, uint8_t *, size_t, int quiet);
extern ssize_t udp_sendto(int, uint32_t, uint16_t, const uint8_t *, size_t);
extern int udp_socket(uint32_t, uint16_t);
extern uint32_t net_inetaddr(const char *);

struct nfsctx;
extern int thread_run_arpreply(struct nfsctx *);
extern int send_gratuitous_arp(struct nfsctx *);
extern int start_recv_thread(struct nfsctx *);
extern void stop_spoof_threads(struct nfsctx *);
extern ssize_t udp_write(struct nfsctx *, uint32_t, uint16_t, const uint8_t *, size_t);
extern ssize_t udp_read(struct nfsctx *, uint32_t, uint16_t, uint8_t *, size_t);

#endif /* NET_H */
