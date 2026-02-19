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
 * mount_types.h - Mount protocol type definitions
 *
 * RFC 1094 Appendix A - Mount Protocol (v1)
 * RFC 1813 Appendix I - Mount Protocol (v3)
 */

#ifndef MOUNT_TYPES_H
#define MOUNT_TYPES_H

#include <stdint.h>

#include "nfs_types.h"

/*
 * Mount protocol constants
 */
#define MOUNT_PROGRAM 100005

/* Mount v1 (RFC 1094): Fixed 32-byte file handles */
#define MOUNTV1_FHSIZE 32

/* Mount v3 (RFC 1813): Variable-length file handles, max 64 bytes */
#define MOUNTV3_FHSIZE_MAX 64

/* Mount procedures (same for v1 and v3) */
#define MOUNTPROC_NULL    0
#define MOUNTPROC_MNT     1
#define MOUNTPROC_DUMP    2
#define MOUNTPROC_UMNT    3
#define MOUNTPROC_UMNTALL 4
#define MOUNTPROC_EXPORT  5

/*
 * Mount status codes (RFC 1813)
 */
#define MNT_OK              0     /* Success */
#define MNT_ERR_PERM        1     /* Not owner */
#define MNT_ERR_NOENT       2     /* No such file or directory */
#define MNT_ERR_IO          5     /* I/O error */
#define MNT_ERR_ACCESS      13    /* Permission denied */
#define MNT_ERR_NOTDIR      20    /* Not a directory */
#define MNT_ERR_INVAL       22    /* Invalid argument */
#define MNT_ERR_NAMETOOLONG 63    /* File name too long */
#define MNT_ERR_NOTSUPP     10004 /* Operation not supported */
#define MNT_ERR_SERVERFAULT 10006 /* Server fault */

/* Maximum size of access group list string */
#define MOUNT_EXPORT_GROUP_MAX 4096

/* Maximum number of exports and groups in EXPORT reply to prevent DoS */
#define MOUNT_MAX_EXPORTS           1024
#define MOUNT_MAX_GROUPS_PER_EXPORT 256

/*
 * Export entry - information about an exported filesystem
 */
struct mount_export {
    char name[NAMEMAXLEN];              /* Export path */
    char group[MOUNT_EXPORT_GROUP_MAX]; /* Access groups (space-separated) */
    uint8_t everyone;                   /* Accessible by everyone? */

    /* File handle is filled in when share is actually mounted */
    uint8_t *fh;
    int fhlen;

    struct mount_export *next;
};

/*
 * Mount entry - information about a mounted client
 */
struct mount_entry {
    char hostname[NAMEMAXLEN];  /* Client hostname */
    char directory[NAMEMAXLEN]; /* Mounted directory */
    struct mount_entry *next;
};

/*
 * Mount result - returned by mount operation
 */
struct mount_res {
    int status;             /* MNT_OK or error code */
    uint8_t *fh;            /* File handle (caller must free) */
    int fhlen;              /* File handle length */
    uint32_t *auth_flavors; /* Authentication flavors (v3 only) */
    int num_flavors;        /* Number of auth flavors */
};

/*
 * Export list result - returned by export operation
 */
struct mount_export_res {
    struct mount_export *exports; /* Linked list of exports */
};

/*
 * Dump result - returned by dump operation
 */
struct mount_dump_res {
    struct mount_entry *entries; /* Linked list of mount entries */
};

#endif                           /* MOUNT_TYPES_H */
