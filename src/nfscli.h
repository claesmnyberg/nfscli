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
 * nfscli.h - Main context structure and configuration
 *
 * Defines struct nfsctx which holds all session state: network config,
 * server info, ports, protocol settings, caches, and statistics.
 */

#ifndef NFSCLI_H
#define NFSCLI_H

#define NFSCLI_VERSION "1.8"

#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/time.h>

#include "net.h"
#include "nfs_cache.h"
#include "nfs_util.h"
#include "rpc.h"

struct nfs_ops;            /* forward declaration */
struct portmap_dump_entry; /* forward declaration for portmap cache */

#define PORT_LOCAL_DEFAULT 516
#define PORT_NFSD_DEFAULT  2049
#define PORT_RPC_DEFAULT   111

/* Tab alignment for formatted output */
#define TABALIGN 48

#define SPOOF_RECV_TIMEOUT_SEC 3
#define UDP_RECV_TIMEOUT_SEC   3

/* Portmap GETPORT reliability status */
#define PMAP_GETPORT_UNKNOWN 0  /* Not yet tested */
#define PMAP_GETPORT_OK      1  /* Working correctly */
#define PMAP_GETPORT_BUGGY   -1 /* Returns stale/wrong registrations */

/* Portmap DUMP availability status */
#define PMAP_DUMP_UNKNOWN 0  /* Not yet tested */
#define PMAP_DUMP_OK      1  /* Available and working */
#define PMAP_DUMP_UNAVAIL -1 /* Restricted or not supported */

/*
 * Network layer - sockets, spoofing, receive buffer
 */
struct nfs_network {
    int sock;               /* UDP/raw socket */
    struct timeval timeout; /* Send/receive timeout */

    /* IP spoofing */
    uint32_t spoof_ip; /* Spoofed IP (network order) */
    char *spoof_str;   /* Spoof IP string */
    char *iface;       /* Interface name */
    uint8_t ifmac[6];  /* HW address of selected interface */

    /* Persistent receiver thread */
    int readsock;
    sem_t recv_sem;             /* Signals packet received */
    pthread_mutex_t recv_mutex; /* Protects recv state below */
    uint16_t expected_sport;    /* Expected source port */
    int recv_waiting;           /* 1 if waiting for packet */
    uint8_t recvbuf[MTU_MAX * 2];
    uint32_t recvlen;
    uint8_t sync_initialized;   /* sem/mutex initialized */

    /* Thread management */
    pthread_t recv_thread;          /* Receiver thread handle */
    pthread_t arp_thread;           /* ARP reply thread handle */
    uint8_t recv_thread_started;    /* 1 if recv_thread was created */
    uint8_t arp_thread_started;     /* 1 if arp_thread was created */
    volatile sig_atomic_t shutdown; /* Signal threads to exit (read w/o lock) */
};

/*
 * Server identification
 */
struct nfs_server {
    char *name;  /* Server hostname/IP string */
    uint32_t ip; /* Server IP (network order) */
};

/*
 * Port configuration
 */
struct nfs_ports {
    uint16_t local;  /* Local port */
    uint16_t rpc;    /* Portmap/RPC port */
    uint16_t nfsd;   /* NFS daemon port */
    uint16_t mountd; /* Mount daemon port */
};

/*
 * Portmap cache and quirks
 */
struct nfs_portmap {
    struct portmap_dump_entry *cache; /* Cached DUMP results */
    uint8_t cache_valid;              /* Cache populated */
    uint8_t discovery_method;         /* 0=none, 1=DUMP, 2=GETPORT */
    uint8_t unreachable;              /* Portmapper not responding */
    int8_t getport_status;            /* PMAP_GETPORT_* reliability status */
    int8_t dump_status;               /* PMAP_DUMP_* availability status */
    uint8_t version_mask;             /* Available versions (bit 2=v2, bit 3=v3) */
    uint8_t version;                  /* Forced version (0=auto, 2=v2, 3=v3) */
    uint8_t mount_perversion_ports;   /* Mount daemon uses different port per version */
};

/*
 * Protocol negotiation and operations
 *
 * Version mask layout:
 *   Bits 1-3: Version available (bit N = version N available)
 *   Bits 4-6: Version tested (bit N+3 = version N tested)
 *   Bit 7:    Full enumeration completed
 */
#define VERSION_AVAIL(v)  (1 << (v))       /* Version v available (v=1,2,3) */
#define VERSION_AVAIL_1   (1 << 1)         /* Version 1 available */
#define VERSION_AVAIL_2   (1 << 2)         /* Version 2 available */
#define VERSION_AVAIL_3   (1 << 3)         /* Version 3 available */
#define VERSION_AVAIL_ALL 0x0E             /* All version bits (v1|v2|v3) */
#define VERSION_TESTED(v) (1 << ((v) + 3)) /* Version v tested (v=1,2,3) */
#define VERSION_TESTED_1  (1 << 4)         /* Version 1 has been tested */
#define VERSION_TESTED_2  (1 << 5)         /* Version 2 has been tested */
#define VERSION_TESTED_3  (1 << 6)         /* Version 3 has been tested */
#define VERSION_MASK_FULL (1 << 7)         /* Full enumeration completed */

/* All versions tested for each protocol */
#define MOUNT_ALL_TESTED (VERSION_TESTED_1 | VERSION_TESTED_2 | VERSION_TESTED_3)
#define NFS_ALL_TESTED   (VERSION_TESTED_2 | VERSION_TESTED_3)

struct nfs_protocol {
    char *machine_name;         /* Machine name for RPC auth */
    uint8_t nfs_version_mask;   /* NFS versions + tested + FULL flags */
    uint8_t nfs_version;        /* NFS version in use */
    uint8_t mount_version_mask; /* Mount versions + tested + FULL flags */
    uint8_t mount_version;      /* Mount version in use */
    struct nfs_ops *ops;        /* NFS operations dispatch table */
};

/*
 * Mount file handle cache entry
 */
struct nfs_mount_fh_entry {
    char *path;
    uint8_t fh[NFS_FHSIZE_MAX];
    int fhlen;
};

/*
 * Mount file handle cache hash table
 */
#define MOUNT_FH_CACHE_BUCKETS 64

struct nfs_mount_fh_cache {
    struct nfs_mount_fh_entry *entries;
    size_t count;
    size_t capacity;
    uint64_t hits;
    uint64_t misses;
    /* Hash table for O(1) lookup by path */
    size_t *hash_buckets[MOUNT_FH_CACHE_BUCKETS]; /* Arrays of indices */
    size_t hash_bucket_counts[MOUNT_FH_CACHE_BUCKETS];
    size_t hash_bucket_caps[MOUNT_FH_CACHE_BUCKETS];
};

/*
 * Caches - structure definitions in nfs_cache.h
 */
struct nfs_caches {
    /* Export list cache */
    char **exports;
    size_t exports_count;

    /* Mount file handle cache */
    struct nfs_mount_fh_cache mount_fh;

    /* Symlink target cache (keyed by FH) - uses cache_hdr for generic LRU */
    struct cache_hdr *symlinks[NFS_SYMLINK_CACHE_BUCKETS];
    size_t symlink_count;
    uint64_t symlink_hits;
    uint64_t symlink_misses;

    /* Attribute cache (keyed by FH, with TTL) - uses cache_hdr for generic LRU */
    struct cache_hdr *attrs[NFS_ATTR_CACHE_BUCKETS];
    size_t attr_count;
    uint64_t attr_hits;
    uint64_t attr_misses;

    /* Directory cache (persists across browse sessions) */
    struct nfs_cache_dir *dir_head;
    struct nfs_cache_dir *dir_tail; /* For O(1) LRU eviction */
    size_t dir_count;
    size_t dir_max;
    /* Hash table for O(1) directory lookup by FH */
#define NFS_DIR_CACHE_BUCKETS 64
    struct nfs_cache_dir *dir_hash[NFS_DIR_CACHE_BUCKETS];

    /* Directory cache enabled flag */
    int enabled;

    /* Directory cache statistics */
    uint64_t lookup_hits;
    uint64_t lookup_misses;
    uint64_t readdir_hits;
    uint64_t readdir_misses;

    /* Lookup result cache (FH + type for completion filtering) */
    struct nfs_lookup_cache_entry lookup_cache[NFS_LOOKUP_CACHE_SIZE];
    size_t lookup_cache_next; /* Next slot to use (ring buffer) */
};

/* Completion modes */
#define COMPLETION_BASIC    0
#define COMPLETION_ENHANCED 1

/*
 * Main NFS CLI context
 */
struct nfsctx {
    /* Output control */
    uint32_t verbose;
    int quiet; /* Suppress error messages (used during completion) */

    /* Browse mode settings */
    int completion; /* COMPLETION_BASIC (default) or COMPLETION_ENHANCED */

    /* Terminal state */
    struct {
        int interactive; /* stdin AND stdout are TTYs */
        int stdin_tty;   /* isatty(STDIN_FILENO) */
        int stdout_tty;  /* isatty(STDOUT_FILENO) */
        int use_colors;  /* Result of shell_use_colors() */
    } term;

    /* Batch command execution */
    char *exec;           /* Commands to run */
    char **batch_saveptr; /* Batch command parsing state */

    /* RPC credentials */
    uint32_t uid;
    uint32_t gid;

    /* Grouped subsystems */
    struct nfs_network net;
    struct nfs_server server;
    struct nfs_ports ports;
    struct nfs_portmap portmap;
    struct nfs_protocol proto;
    struct nfs_caches cache;

    /* Server capabilities (discovered at runtime) */
    struct {
        unsigned int no_lookup_dotdot : 1; /* LOOKUP ".." returns NOENT */
    } server_caps;

    /*
     * RPC socket synchronization for fork scenarios.
     * When a child process needs NFS access concurrently with the parent
     * (e.g., "ls > file.txt"), both share the same UDP socket. A pipe-based
     * token ensures only one process does RPC send+receive at a time.
     */
    int rpc_lock_pipe[2];  /* [0]=read, [1]=write - pipe for token passing */
    int concurrent_fork;   /* Flag: set when child may use NFS concurrently */
};

#endif                                     /* NFSCLI_H */
