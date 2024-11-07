
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

#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <alloca.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pthread.h>

#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>

#include "net.h"
#include "nfscli.h"


/*
 * Read MAC address for IP from /proc/net/arp on Linux.
 * Destination buffer must be at leat 6 bytes long.
 * Returns 0 on success, -1 on error and if the MAC address was not found;
 */
#define ARP_CACHE_FILE "/proc/net/arp"
int
arpcache(char *ip, uint8_t *dst)
{
	FILE *fp;
	char buf[1024]; /* One line in ARP_CACHE_FILE should not exceed 1024 bytes */


	if ( (fp = fopen(ARP_CACHE_FILE, "r")) == NULL) {
		fprintf(stderr, "** Error: Failed to open %s: %s\n", 
			ARP_CACHE_FILE, strerror(errno));
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char aip[1024];
		char hwtype[1024];
		char flags[1024];
		char mac[1024];
		char mask[1024];
		char device[1024];

		sscanf(buf, "%s %s %s %s %s %s", aip, hwtype, flags, mac, mask, device);
		if (strcmp(aip, ip) == 0) {

			if (strtoul(hwtype, NULL, 0) != 1) {
				fprintf(stderr, "** Error: Found server IP in ARP cache, but HW Type is %s (not 1))\n",
					hwtype);
				return 0;
			}

			printf("IP %s has HW address %s in ARP cache\n", ip, mac);
			sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
				&dst[0], &dst[1], &dst[2], &dst[3], &dst[4], &dst[5]);
			fclose(fp);
			return 0;
		}

		memset(buf, 0x00, sizeof(buf));
	}

	fclose(fp);
	return -1;
}


/*
 * ARP reply thread
 * Send ARP reply packets in reply to requests for the
 * spoofed IPv4 address
 */
void *
thread_arpreply(void *a)
{
	struct nfsctx *ctx;
	int sock;
	struct ifreq ifr;
	struct sockaddr_ll sa;

	ctx = (struct nfsctx *)a;

	struct arppkt {
		Eth_hdr ehdr;		/* Ethernet Header */
		ARP_hdr ahdr;		/* ARP header */
		uint8_t smac[6]; 	/* Sender MAC */
		uint32_t sip;		/* Sender IP */
		uint8_t tmac[6];	/* Target MAC */
		uint32_t tip;		/* Target IP */
	} __attribute__((packed)) arp_reply;


	/* Set up reply packet */
	//memcpy(arp_reply.ehdr.dest, ctx->tmac, 6);
	memcpy(arp_reply.ehdr.src, ctx->ifmac, 6);
	arp_reply.ehdr.proto = htons(ETH_PROTO_ARP);

	arp_reply.ahdr.arp_hrd = htons(0x01);
	arp_reply.ahdr.arp_pro = htons(PROTOTYPE_IPV4);
	arp_reply.ahdr.arp_hln = 6;
	arp_reply.ahdr.arp_pln = 4;
	arp_reply.ahdr.arp_op = htons(ARP_REPLY);

	memcpy(arp_reply.smac, ctx->ifmac, 6);
	arp_reply.sip = ctx->spoof;

	//memcpy(arp_reply.tmac, ctx->tmac, 6);
	//arp_reply.tip = ctx->ip;

	if ( (sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		fprintf(stderr, "** Error: opening raw socket: %s\n", strerror(errno));
		return NULL;
	}

	/* Get interface index */
	memset(&ifr, 0x00, sizeof(ifr));
	strncpy(ifr.ifr_name, ctx->ifc, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';

	if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
		fprintf(stderr, "** Error: Failed to get interface index: %s\n", strerror(errno));
		return NULL;
	}

	sa.sll_ifindex   = ifr.ifr_ifindex;
	sa.sll_family    = AF_PACKET;
	sa.sll_protocol  = htons(ETH_P_ALL);

	/* Read ARP request packets and sedn respons */
	while (1) {
		struct arppkt *arp_req;
		char buf[8192];
		ssize_t n;

		if ( (n = read(sock, buf, sizeof(buf))) <= 0) {
			fprintf(stderr, "** Error: ARP reply thread Failed to read packet, exiting\n");
			return NULL;
		}

		arp_req = (struct arppkt *)buf;
		if (n != sizeof(struct arppkt))
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
		if (arp_req->tip != ctx->spoof)
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
	pthread_t t;
	int e;

    /* Get MAC address of spoof interface */
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ctx->ifc);
    if (ioctl(ctx->sock, SIOCGIFHWADDR, &ifr) < 0) {
		fprintf(stderr, "** Error: Failed to get spoof interface MAC address: %s\n", 
			strerror(errno));
		return -1;
    }
	memcpy(ctx->ifmac, ifr.ifr_hwaddr.sa_data, 6);

	pthread_attr_init(&attr);
	if ( (e = pthread_create(&t, &attr, thread_arpreply, (void *)ctx)) != 0) {
		fprintf(stderr, "** Error: Failed to start receiver thread: %s\n", 
			strerror(e));
		return -1;
	}


	
	return 0;

}


/*
 * UDP reader thread
 * Listen for response packet when using a spoofed source IP
 */
/* Argument to thread function */
struct thread_recv_arg {
	struct nfsctx *ctx;

	/* Source port for response */
	uint16_t sport;
};

void *
thread_recv(void *a)
{
	struct thread_recv_arg *arg;
	IPv4_hdr *iph;
	UDP_hdr *udph;
	uint8_t buf[MTU_MAX*2];
	ssize_t len;
	time_t start;
	time_t now;

	arg = (struct thread_recv_arg *)a;
	print(1, arg->ctx, "Receiver thread started\n");
	start = time(NULL);

	if (pthread_mutex_lock(&arg->ctx->lock) != 0) {
		fprintf(stderr, "** Error: Failed to lock mutex\n");
		return NULL;
	}

read_packet:
	print(2, arg->ctx, "Waiting for reply packet\n");

	if ( (len = recv(arg->ctx->readsock, buf, MTU_MAX, 0)) < 0) {

		if (errno == EINTR) {
			fprintf(stderr, "** Error: Timeout after %u seconds (EINTR)\n",
				SPOOF_RECV_TIMEOUT_SEC);
		}
		else {
			fprintf(stderr, "** Error: Received thread failed to receive: %s\n", 
				strerror(errno));
		}
		goto finished;
	}

	print(3, arg->ctx, "Read packet (%lu bytes)\n", len);
	if (arg->ctx->verbose >= 3) {
		printf("Packet Hexdump: ");
		HEXDUMP(buf, len);
	}

	/* Timeout after reading many packets not matching what we wait for */
	now = time(NULL);
	if ((now - start) >= SPOOF_RECV_TIMEOUT_SEC) {
		fprintf(stderr, "** Error: Receive timed out after %u seconds\n",
			SPOOF_RECV_TIMEOUT_SEC);
		goto finished;
	}

	if (len <= (sizeof(Eth_hdr) + sizeof(IPv4_hdr) + sizeof(UDP_hdr))) {
		print(2, arg->ctx, "** Warning: Short response packet, reading again\n");
		goto read_packet;
	}

	iph = (IPv4_hdr *)((uint8_t *)buf + sizeof(Eth_hdr));

	/* Only IPv4 for now */
	if (iph->ip_ver != 4)
		goto read_packet;

	/* Truncated */
	if (len < ntohs(iph->ip_tlen)) {
		print(2, arg->ctx, "** Warning: truncated IP packet, reading again\n");
		goto read_packet;
	}

	print(3, arg->ctx, "Got Valid IPv4 packet\n");

	/* Check addys */
	if ((iph->ip_sadd != arg->ctx->ip) || (iph->ip_dadd != arg->ctx->spoof))

	/* Require UDP */
	if (iph->ip_prot != IP_PROTO_UDP)
		goto read_packet;

	print(3, arg->ctx, "Verified IPv4 addresses\n");

	if (len <= sizeof(Eth_hdr) + sizeof(IPv4_hdr) + ((iph->ip_hlen)*4) + sizeof(UDP_hdr)) {
		print(2, arg->ctx, "** Warning: Short response packet, reading again\n");
		goto read_packet;
	}

	udph = (UDP_hdr *)((uint8_t *)iph + (iph->ip_hlen)*4);
	if ((udph->udp_sprt != arg->sport) && (udph->udp_dprt) != arg->ctx->port_local) {
		goto read_packet;
	}

	/* Set the payload in the receive buffer */
	arg->ctx->recvlen = ntohs(iph->ip_tlen) - (4*iph->ip_hlen) - sizeof(UDP_hdr);
	if (arg->ctx->recvlen > sizeof(arg->ctx->recvbuf)) {
		fprintf(stderr, "** Error: Truncated payload\n");	
		arg->ctx->recvlen = sizeof(arg->ctx->recvbuf);
	}
	memcpy(arg->ctx->recvbuf, (u_char *)((char *)udph + sizeof(UDP_hdr)), 
		arg->ctx->recvlen);

	print(2, arg->ctx, "Received expected UDP datagram with payload of %u bytes\n", 
		arg->ctx->recvlen);

finished:
	if (pthread_mutex_unlock(&arg->ctx->lock) != 0) {
		fprintf(stderr, "** Error: Failed to unlock mutex\n");
		return NULL;
	}

	return NULL;
}


/*
 * Write UDP datagram to network based on settings
 */
ssize_t 
udp_write(struct nfsctx *ctx, uint32_t ip, uint16_t port, uint8_t *data, size_t datalen)
{
	ssize_t ret;

	if (port == 0) {
		fprintf(stderr, "** Error: Destination port is zero\n");
		return -1;
	}

	/* 
	 * Send a raw packet 
	 */
	if (ctx->spoof != 0) {
		uint8_t buf[MTU_MAX+1024];
		pthread_attr_t attr;
		struct thread_recv_arg *arg;
		pthread_t t;
		int e;

		memset(buf, 0x00, sizeof(buf));

		if (rawpkt_add_ipv4(buf, 0x00, rand(), 128, ctx->spoof, ip) < 0) {
			return -1;
		}

		if (rawpkt_add_udp(buf, ctx->port_local, port, data, datalen) < 0) {
			return -1;
		}

		if ((sizeof(IPv4_hdr)+sizeof(UDP_hdr)+datalen) > sizeof(buf)) {
			fprintf(stderr, "** Error: payload data exceeds buffer size\n");
			return -1;
		}

		/* Before we send the packet, start a listening thread 
		 * for the response packet.
		 * Note that there is only one receive buffer, so subsequent
		 * calls to this function without a read in between will mess
		 * things up. This should not be a problem however, since this
		 * is a single threaded app at this point.
		 */

		if ( (arg = calloc(1, sizeof(struct thread_recv_arg))) == NULL) {
			fprintf(stderr, "** Error: Failed to allocate memory\n");
			return -1;
		}

		/* Nothing received yet */
		ctx->recvlen = 0;

		arg->ctx = ctx;
		pthread_attr_init(&attr);
		if ( (e = pthread_create(&t, &attr, thread_recv, (void *)arg)) != 0) {
			fprintf(stderr, "** Error: Failed to start receiver thread: %s\n", 
				strerror(e));
			return -1;
		}
		pthread_attr_destroy(&attr);

		sleep(1);

		print(3, ctx, "Writing raw UDP datagram to the network\n");
		ret = udp_sendto(ctx->sock, ip, port, buf, 
			sizeof(IPv4_hdr)+sizeof(UDP_hdr)+datalen);

		return ret;
	}

	/*
	 * Send the datagram
	 */
	ret = udp_sendto(ctx->sock, ip, port, data, datalen);
	return ret;
}

/*
 * Read UDP datagram based on settings
 */
ssize_t 
udp_read(struct nfsctx *ctx, uint32_t ip, uint16_t port, uint8_t *buf, size_t buflen)
{
	/*
	 * Using raw sockets, check receive buffer
	 */
	if (ctx->spoof != 0) {
		ssize_t ret;

		if (pthread_mutex_lock(&ctx->lock) != 0) {
			fprintf(stderr, "** Error: Failed to unlock mutex\n");
			return -1;
		}

		if (ctx->recvlen == 0) {
			print(2, ctx, "** Error: Receive buffer empty\n");
			ret = -1;
		}

		else {

			ret = ctx->recvlen;
			if (ctx->recvlen > buflen) {
				fprintf(stderr, "** Error: Buffer to small for received payload, truncating\n");
				ret = -1;
			}
			else {
				memcpy(buf, ctx->recvbuf, ctx->recvlen);
			}
		}


		if (pthread_mutex_unlock(&ctx->lock) != 0) {
			fprintf(stderr, "** Error: Failed to unlock mutex\n");
			return -1;
		}

		return ret;
	}


	return udp_recv(ctx->sock, ip, port, buf, buflen);
}


/*
 * Returns the length of received data on success, -1 on error.
 */
ssize_t
udp_recv(int sock, uint32_t ip, uint16_t port, uint8_t *buf, size_t buflen)
{
	ssize_t len;
	struct sockaddr_in sa;
	socklen_t addrlen;

	memset(&sa, 0x00, sizeof(struct sockaddr_in));
	sa.sin_family = PF_INET;
	sa.sin_addr.s_addr = ip;
	sa.sin_port = port;
	addrlen = sizeof(struct sockaddr_in);	

	if ( (len = recvfrom(sock, buf, buflen, 0, (struct sockaddr *)&sa, &addrlen)) == -1) {
		fprintf(stderr, "** Error: Failed to receive: %s\n", strerror(errno));
		return -1;
	}

	return len;
}


/*
 * Send UDP datagram.
 * On success, the length of the response is returned.
 * IP and port in network byte order.
 */
ssize_t
udp_sendto(int sock, uint32_t ip, uint16_t port, uint8_t *buf, size_t buflen)
{
	struct sockaddr_in da;
	socklen_t addrlen;

	memset(&da, 0x00, sizeof(struct sockaddr_in));
	da.sin_family = PF_INET;
	da.sin_addr.s_addr = ip;
	da.sin_port = port;
	addrlen = sizeof(struct sockaddr_in);

	if (sendto(sock, buf, buflen, 0, (struct sockaddr *)&da, addrlen) < 0) {
		return -1;
	}

	return 0;
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

	if ( (sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
		return(-1);

	memset(&usin, 0x00, sizeof(usin));
	usin.sin_family = PF_INET;
	usin.sin_addr.s_addr = ip;
	usin.sin_port = port;

	if (bind(sock, (struct sockaddr *)&usin, sizeof(usin)) < 0) {
		close(sock);
		return(-1);
	}

	return(sock);
}

/*
 * Translate hostname or dotted decimal host address
 * into a network byte ordered IP address.
 * Returns -1 on error.
 */
long
net_inetaddr(const char *host)
{
	long haddr;
	struct hostent *hent;

	if ( (haddr = inet_addr(host)) == -1) {
		if ( (hent = gethostbyname(host)) == NULL)
			return(-1);
		memcpy(&haddr, (hent->h_addr), sizeof(haddr));
	}

	return(haddr);
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
    memset(&sll, 0, sizeof( sll ) );
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

    if ( (sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        fprintf(stderr, "** Error: Failed to open raw socket: %s\n", strerror(errno));
        return -1;
    }

	if (rawsock_bind(sock, ifc, 1) < 0) {
		close(sock);
		return -1;
	}

    return sock;
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

    if ( (fd = socket(AF_INET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        fprintf(stderr, "** Error: Failed to open raw socket: %s\n",
            strerror(errno));
        return(-1);
    }

    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL,
            (void *)&one, (socklen_t)sizeof(one)) < 0) {
        fprintf(stderr, "** Error: Cannot set header included: %s\n",
            strerror(errno));
        return(-1);
    }

	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifc, strlen(ifc)) < 0) {
		fprintf(stderr, "** Error: Could not bind to interface: %s\n",
			strerror(errno));
	}

#if 0
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST,
            (void *)&one, (socklen_t)sizeof(one)) < 0) {
        fprintf(stderr, "** Error: Cannot set broadcast address on socket: %s\n",
            strerror(errno));
        return(-1);
    }
#endif

    return(fd);
}


/*
 * Generates header checksum.
 * W. Richard Stevens TCP/IP illustrated vol. 1 page 145
 */
static unsigned short
chksum(uint16_t *buf, int nwords)
{
    unsigned long sum = 0;

    for(; nwords > 0; nwords--)
        sum += *buf++;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return(~sum);
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
        return(-1);
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

    return(0);
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
             uint8_t *payload, uint16_t paylen)
{
    IPv4_hdr *iph;
    UDP_hdr *udph;
    Pseudo_hdr *phdr;
    uint8_t *pbuf;
    size_t plen;


    plen = sizeof(Pseudo_hdr) + sizeof(UDP_hdr) + paylen + (paylen % 2);

    if ( (pbuf = alloca(plen)) == NULL) {
        fprintf(stderr, "** Error: Failed to allocate memory: %s\n", strerror(errno));
        return(-1);
    }
    memset(pbuf, 0x00, plen);

    iph = (IPv4_hdr *)packet;

    if (packet == NULL) {
        fprintf(stderr, "** Error: rawpkt_add_tcp(): "
            "Received NULL pointer as packet\n");
        return(-1);
    }

    if ((paylen + sizeof(IPv4_hdr) + sizeof(UDP_hdr)) > MTU_MAX) {
        fprintf(stderr, "** Error: Packet (%lu bytes) is greater than "
            "maximum size allowed (%u bytes)\n", (paylen + sizeof(IPv4_hdr) +
            sizeof(UDP_hdr)), MTU_MAX);
        return(-1);
    }

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
    udph->udp_len = htons(sizeof(UDP_hdr)+paylen);
    memcpy(pbuf + sizeof(Pseudo_hdr) + sizeof(UDP_hdr), payload, paylen);

    /* UDP checksum */
#ifdef STUPID_SOLARIS_CHECKSUM_BUG
    udph->udp_sum = sizeof(UDP_hdr) + paylen;
#else
    udph->udp_sum = chksum((unsigned short *)pbuf, (sizeof(Pseudo_hdr) +
        sizeof(UDP_hdr) + paylen + (paylen % 2)) >> 1);
#endif

    /* Copy UDP header to real packet */
    memcpy(packet + sizeof(IPv4_hdr), pbuf + sizeof(Pseudo_hdr),
        sizeof(UDP_hdr) + paylen);

    /* Set remaining IP header values and calculate IP checksum */
    iph = (IPv4_hdr *)packet;
    iph->ip_tlen = SETIPLENFIX(sizeof(IPv4_hdr) + sizeof(UDP_hdr) + paylen);
    iph->ip_prot = IP_PROTO_UDP;
    iph->ip_sum = chksum((unsigned short *)packet,
        (GETIPLENFIX(iph->ip_tlen) +  (paylen % 2))>> 1);

    return(0);
}

