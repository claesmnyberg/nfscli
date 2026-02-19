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
 * nfs_types.h - Common NFS data structures for protocol/presentation separation
 *
 * RFC 1094 (NFSv2) and RFC 1813 (NFSv3) data structures
 *
 * These structures are the common output format for both NFSv2 and NFSv3
 * protocol implementations. Protocol functions parse wire format directly
 * into these structures - no conversion between versions needed.
 *
 * Key differences between v2 and v3:
 * - File handles: v2 fixed 32-byte, v3 variable up to 64 bytes
 * - Sizes/offsets: v2 32-bit (max 4GB), v3 64-bit
 * - Timestamps: v2 microseconds, v3 nanoseconds
 * - Error codes: v3 adds 10001-10008 range
 */

#ifndef NFS_TYPES_H
#define NFS_TYPES_H

#include <stdint.h>
#include <stdlib.h> /* for free() in nfs_dir_free() */
#include <string.h> /* for strcmp() in nfs_dirent_cmp() */

/* Maximum lengths (RFC 1813 Section 3.2) */
#define NFS_MAXNAMLEN  255  /* RFC 1813 §3.2.6: filename3 max length */
#define NFS_MAXPATHLEN 1024 /* RFC 1813 §3.2.7: nfspath3 max length */

/* File handle sizes */
#define NFSV2_FHSIZE   32  /* RFC 1094 §2.3.3: always 32 bytes */
#define NFSV3_FHSIZE   64  /* RFC 1813 §3.2.2: max 64 bytes */
#define NFS_FHSIZE_MAX 128 /* Max FH size we support (room for extensions) */

/* Buffer size constants */
#define NAMEMAXLEN 256
#define ATTRBUFLEN 256  /* Buffer size for formatted attribute strings */
#define IOBUFSIZE  1300 /* Keep data in single UDP packet */

/* DoS prevention limit for directory parsing */
#define NFS_READDIR_MAX_ENTRIES 100000

/* XDR encoding (RFC 4506) - see xdr.h for primitives */
#include "xdr.h"

/*
 * Universal file handle - works for both v2 and v3
 * v2: len is always 32
 * v3: len is variable, up to NFSV3_FHSIZE
 */
struct nfs_fh {
    uint8_t data[NFS_FHSIZE_MAX];
    uint32_t len;
};

/*
 * NFS time structure - unified for v2/v3
 * v2 wire format uses microseconds, converted to nanoseconds on parse
 * v3 wire format uses nanoseconds directly
 */
struct nfs_time {
    uint32_t sec;
    uint32_t nsec;
};

/*
 * File attributes - unified v2/v3 output format
 * Both versions parse their wire format directly into this structure
 */
struct nfs_attr {
    uint32_t type;         /* file type: NF3REG, NF3DIR, etc. */
    uint32_t mode;         /* protection mode bits */
    uint32_t nlink;        /* number of hard links */
    uint32_t uid;          /* owner user id */
    uint32_t gid;          /* owner group id */
    uint64_t size;         /* file size in bytes */
    uint64_t used;         /* bytes actually used (v3), blocks*blocksize (v2) */
    uint64_t rdev;         /* device id for special files */
    uint64_t fsid;         /* file system id */
    uint64_t fileid;       /* file id (inode) */
    struct nfs_time atime; /* time of last access */
    struct nfs_time mtime; /* time of last modification */
    struct nfs_time ctime; /* time of last status change */
};

/*
 * Set attributes - input for SETATTR
 * Set the set_* flag to indicate which fields to change.
 * For time fields:
 *   0 = don't change
 *   1 = set to server time (v3) / set to now (v2)
 *   2 = set to specified time (v3 only, v2 always uses 'now')
 */
struct nfs_sattr {
    int set_mode;
    uint32_t mode;
    int set_uid;
    uint32_t uid;
    int set_gid;
    uint32_t gid;
    int set_size;
    uint64_t size;
    int set_atime; /* 0=no, 1=server time, 2=client time */
    struct nfs_time atime;
    int set_mtime; /* 0=no, 1=server time, 2=client time */
    struct nfs_time mtime;
};

/* Time setting modes for sattr */
#define NFS_TIME_DONT_CHANGE   0
#define NFS_TIME_SET_TO_SERVER 1
#define NFS_TIME_SET_TO_CLIENT 2

/*
 * Initialize sattr to "don't change anything"
 */
static inline void
nfs_sattr_init(struct nfs_sattr *sa)
{
    sa->set_mode = 0;
    sa->mode = 0;
    sa->set_uid = 0;
    sa->uid = 0;
    sa->set_gid = 0;
    sa->gid = 0;
    sa->set_size = 0;
    sa->size = 0;
    sa->set_atime = NFS_TIME_DONT_CHANGE;
    sa->atime.sec = 0;
    sa->atime.nsec = 0;
    sa->set_mtime = NFS_TIME_DONT_CHANGE;
    sa->mtime.sec = 0;
    sa->mtime.nsec = 0;
}

/* File types (same values for v2 and v3) */
#define NFS_FTYPE_REG  1 /* regular file */
#define NFS_FTYPE_DIR  2 /* directory */
#define NFS_FTYPE_BLK  3 /* block special device */
#define NFS_FTYPE_CHR  4 /* character special device */
#define NFS_FTYPE_LNK  5 /* symbolic link */
#define NFS_FTYPE_SOCK 6 /* socket */
#define NFS_FTYPE_FIFO 7 /* named pipe (FIFO) */

/*
 * NFSv3 CREATE modes (RFC 1813 Section 3.3.8)
 *
 * UNCHECKED - Create file, truncate if exists (O_CREAT|O_TRUNC)
 * GUARDED   - Fail with NFS3ERR_EXIST if file exists (O_CREAT|O_EXCL)
 * EXCLUSIVE - Atomic create using 8-byte verifier for lock files
 */
#define NFS_CREATE_UNCHECKED 0
#define NFS_CREATE_GUARDED   1
#define NFS_CREATE_EXCLUSIVE 2

/*
 * Directory entry - returned by readdir/readdirplus
 */
struct nfs_dirent {
    uint64_t fileid;              /* file id (inode) */
    char name[NFS_MAXNAMLEN + 1]; /* entry name */
    uint64_t cookie;              /* cookie for next entry */
    struct nfs_fh fh;             /* file handle (readdirplus only) */
    struct nfs_attr attr;         /* attributes (readdirplus only) */
    int has_fh;                   /* fh is valid */
    int has_attr;                 /* attr is valid */
};

/*
 * Directory listing result
 */
struct nfs_dir {
    struct nfs_dirent *entries;
    size_t count;
    size_t capacity;
    int eof;
    struct nfs_attr dir_attr; /* attributes of the directory itself */
    int has_dir_attr;
};

/*
 * Comparison function for sorting directory entries by name.
 * For use with qsort().
 */
static inline int
nfs_dirent_cmp(const void *a, const void *b)
{
    const struct nfs_dirent *ea = a;
    const struct nfs_dirent *eb = b;
    return strcmp(ea->name, eb->name);
}

/*
 * LOOKUP result
 */
struct nfs_lookup_res {
    struct nfs_fh fh;
    struct nfs_attr obj_attr;
    struct nfs_attr dir_attr; /* v3 only, check has_dir_attr */
    int has_obj_attr;
    int has_dir_attr;
};

/*
 * READ result
 *
 * MEMORY OWNERSHIP: The 'buf' field is a heap-allocated buffer that the
 * caller must free. The 'data' field points INTO 'buf' at the start of
 * the actual file data. After freeing 'buf', 'data' becomes invalid.
 *
 * Always use nfs_read_res_free() to release this structure - it frees
 * the buffer and NULLs both pointers to prevent use-after-free.
 */
struct nfs_read_res {
    uint8_t *data;        /* Data pointer - VALID ONLY WHILE buf IS VALID */
    uint32_t count;       /* bytes read */
    int eof;              /* end of file reached */
    uint8_t *buf;         /* Backing buffer - USE nfs_read_res_free() */
    struct nfs_attr attr; /* post-op file attributes */
    int has_attr;
};

/*
 * Free nfs_read_res and invalidate pointers.
 * Safe to call multiple times (idempotent).
 */
static inline void
nfs_read_res_free(struct nfs_read_res *res)
{
    if (res->buf != NULL) {
        free(res->buf);
        res->buf = NULL;
        res->data = NULL;
    }
}

/*
 * CREATE/MKDIR result
 */
struct nfs_create_res {
    struct nfs_fh fh;
    struct nfs_attr attr;
    int has_fh;
    int has_attr;
};

/*
 * SYMLINK result
 */
struct nfs_symlink_res {
    struct nfs_fh fh;         /* New symlink's file handle */
    struct nfs_attr attr;     /* New symlink's attributes */
    struct nfs_attr dir_attr; /* Parent directory's post-op attrs */
    int has_fh;
    int has_attr;
    int has_dir_attr;
};

/*
 * READLINK result
 */
struct nfs_readlink_res {
    char target[NFS_MAXPATHLEN + 1];
    struct nfs_attr attr; /* post-op symlink attributes */
    int has_attr;
};

/*
 * WRITE stable_how values (RFC 1813 Section 3.3.7)
 *
 * NFSv3 introduces write stability levels for performance tuning:
 *   UNSTABLE (0)  - Server may cache; use COMMIT to ensure durability.
 *                   Fastest but requires tracking write verifier.
 *   DATA_SYNC (1) - Data on stable storage before reply; metadata may
 *                   be cached. Good balance for most workloads.
 *   FILE_SYNC (2) - All data and metadata on stable storage before reply.
 *                   Slowest but safest. NFSv2 equivalent behavior.
 */
#define NFS_UNSTABLE  0
#define NFS_DATA_SYNC 1
#define NFS_FILE_SYNC 2

/*
 * WRITE result
 */
struct nfs_write_res {
    uint32_t count;       /* bytes written */
    int committed;        /* NFS_UNSTABLE, NFS_DATA_SYNC, or NFS_FILE_SYNC */
    uint64_t verifier;    /* write verifier (v3 only) */
    struct nfs_attr attr; /* post-op file attributes (WCC data) */
    int has_attr;
};

/*
 * COMMIT result (NFSv3 only)
 *
 * RFC 1813 Section 3.3.21 - COMMIT
 *
 * Forces or flushes data previously written with UNSTABLE to stable
 * storage on the server. Returns a write verifier that changes if
 * the server reboots (indicating uncommitted data may have been lost).
 */
struct nfs_commit_res {
    uint64_t verifier;    /* write verifier for reboot detection */
    struct nfs_attr attr; /* post-op file attributes (WCC data) */
    int has_attr;
};

/*
 * STATFS result (NFSv2) / FSSTAT result (NFSv3)
 *
 * Unified filesystem statistics. v2 reports blocks, v3 reports bytes.
 * For v2: block-based values are converted to bytes using bsize.
 * For v3: block-based values remain 0 (unused).
 */
struct nfs_fsstat_res {
    /* Byte-based (v3 native, v2 converted from blocks) */
    uint64_t tbytes; /* total bytes on filesystem */
    uint64_t fbytes; /* free bytes */
    uint64_t abytes; /* available bytes (non-priv users) */

    /* File counts (v3 only) */
    uint64_t tfiles; /* total file slots */
    uint64_t ffiles; /* free file slots */
    uint64_t afiles; /* available file slots (non-priv) */

    /* Block-based (v2 only, v3 sets to 0) */
    uint32_t bsize;       /* fundamental block size */
    uint32_t tsize;       /* optimum transfer size (v2 only) */
    uint32_t blocks;      /* total blocks */
    uint32_t bfree;       /* free blocks */
    uint32_t bavail;      /* available blocks (non-priv) */

    uint32_t invarsec;    /* seconds values are valid (v3 only) */
    struct nfs_attr attr; /* post-op attributes (v3 only) */
    int has_attr;
};

/*
 * FSINFO result (NFSv3 only)
 *
 * Static filesystem properties for optimal client configuration.
 */
struct nfs_fsinfo_res {
    uint32_t rtmax;             /* maximum read size */
    uint32_t rtpref;            /* preferred read size */
    uint32_t rtmult;            /* suggested read size multiple */
    uint32_t wtmax;             /* maximum write size */
    uint32_t wtpref;            /* preferred write size */
    uint32_t wtmult;            /* suggested write size multiple */
    uint32_t dtpref;            /* preferred READDIR request size */
    uint64_t maxfilesize;       /* maximum file size */
    struct nfs_time time_delta; /* server time granularity */
    uint32_t properties;        /* FSF3_* flags */
    struct nfs_attr attr;       /* post-op attributes */
    int has_attr;
};

/* FSINFO property flags (RFC 1813 Section 3.3.18) */
#define NFS_FSF3_LINK        0x0001 /* server supports hard links */
#define NFS_FSF3_SYMLINK     0x0002 /* server supports symbolic links */
#define NFS_FSF3_HOMOGENEOUS 0x0008 /* PATHCONF valid for all files */
#define NFS_FSF3_CANSETTIME  0x0010 /* server can set times on files */

/*
 * ACCESS result (NFSv3 only)
 *
 * Permission checking - returns a bitmask of allowed operations.
 */
struct nfs_access_res {
    uint32_t access;      /* bitmask of allowed access */
    struct nfs_attr attr; /* post-op attributes */
    int has_attr;
};

/* ACCESS permission bits (RFC 1813 Section 3.3.4) */
#define NFS_ACCESS3_READ    0x0001 /* read data or list directory */
#define NFS_ACCESS3_LOOKUP  0x0002 /* lookup name in directory */
#define NFS_ACCESS3_MODIFY  0x0004 /* rewrite existing file or modify dir */
#define NFS_ACCESS3_EXTEND  0x0008 /* write beyond EOF or add to dir */
#define NFS_ACCESS3_DELETE  0x0010 /* delete file or directory entry */
#define NFS_ACCESS3_EXECUTE 0x0020 /* execute file */

/*
 * PATHCONF result (NFSv3 only)
 *
 * POSIX pathconf(2) information for a path.
 */
struct nfs_pathconf_res {
    uint32_t linkmax;     /* max number of hard links */
    uint32_t name_max;    /* max filename length */
    int no_trunc;         /* server rejects names > name_max */
    int chown_restricted; /* chown restricted to privileged users */
    int case_insensitive; /* case-insensitive name matching */
    int case_preserving;  /* case is preserved in names */
    struct nfs_attr attr; /* post-op attributes */
    int has_attr;
};

/*
 * WCC (Weak Cache Consistency) data for directory-modifying operations.
 * Used by REMOVE, RMDIR, RENAME, LINK, SYMLINK.
 * Contains post-operation attributes for cache updates.
 */
struct nfs_wcc_data {
    struct nfs_attr dir_attr; /* post-op directory attributes */
    int has_dir_attr;
};

/*
 * RENAME result - two directories may be modified
 */
struct nfs_rename_res {
    struct nfs_attr src_dir_attr; /* post-op source directory attributes */
    int has_src_dir_attr;
    struct nfs_attr dst_dir_attr; /* post-op destination directory attributes */
    int has_dst_dir_attr;
};

/*
 * LINK result - file and directory may have updated attributes
 */
struct nfs_link_res {
    struct nfs_attr file_attr; /* post-op file attributes (nlink changed) */
    int has_file_attr;
    struct nfs_attr dir_attr;  /* post-op directory attributes */
    int has_dir_attr;
};

/*
 * Directory listing helper functions
 */
static inline void
nfs_dir_init(struct nfs_dir *dir)
{
    dir->entries = NULL;
    dir->count = 0;
    dir->capacity = 0;
    dir->eof = 0;
    dir->has_dir_attr = 0;
}

static inline void
nfs_dir_free(struct nfs_dir *dir)
{
    if (dir->entries) {
        free(dir->entries);
        dir->entries = NULL;
    }
    dir->count = 0;
    dir->capacity = 0;
    dir->eof = 0;
}

/*
 * NFS error codes (RFC 1094 Section 2.3.1, RFC 1813 Section 2.6)
 *
 * Most codes 1-70 correspond to standard Unix errno values and are
 * shared between v2 and v3. NFSv3 adds the 10001-10008 range for
 * NFS-specific conditions.
 *
 * Notable codes:
 * - STALE (70): File handle no longer valid (server reboot, file deleted)
 * - WFLUSH (99): NFSv2 only - write cache flushed
 * - JUKEBOX (10008): NFSv3 only - media being mounted, retry later
 */
#define NFS_OK             0
#define NFSERR_PERM        1
#define NFSERR_NOENT       2
#define NFSERR_IO          5
#define NFSERR_NXIO        6
#define NFSERR_ACCES       13
#define NFSERR_EXIST       17
#define NFSERR_XDEV        18 /* v3 only */
#define NFSERR_NODEV       19
#define NFSERR_NOTDIR      20
#define NFSERR_ISDIR       21
#define NFSERR_INVAL       22 /* v3 only */
#define NFSERR_FBIG        27
#define NFSERR_NOSPC       28
#define NFSERR_ROFS        30
#define NFSERR_MLINK       31 /* v3 only */
#define NFSERR_NAMETOOLONG 63
#define NFSERR_NOTEMPTY    66
#define NFSERR_DQUOT       69
#define NFSERR_STALE       70
#define NFSERR_REMOTE      71    /* v3 only */
#define NFSERR_WFLUSH      99    /* v2 only */
#define NFSERR_BADHANDLE   10001 /* v3 only */
#define NFSERR_NOT_SYNC    10002 /* v3 only */
#define NFSERR_BAD_COOKIE  10003 /* v3 only */
#define NFSERR_NOTSUPP     10004 /* v3 only */
#define NFSERR_TOOSMALL    10005 /* v3 only */
#define NFSERR_SERVERFAULT 10006 /* v3 only */
#define NFSERR_BADTYPE     10007 /* v3 only */
#define NFSERR_JUKEBOX     10008 /* v3 only */

/* NFSv3 aliases (RFC 1813 naming) */
#define NFS3_OK             NFS_OK
#define NFS3ERR_PERM        NFSERR_PERM
#define NFS3ERR_NOENT       NFSERR_NOENT
#define NFS3ERR_IO          NFSERR_IO
#define NFS3ERR_NXIO        NFSERR_NXIO
#define NFS3ERR_ACCES       NFSERR_ACCES
#define NFS3ERR_EXIST       NFSERR_EXIST
#define NFS3ERR_XDEV        NFSERR_XDEV
#define NFS3ERR_NODEV       NFSERR_NODEV
#define NFS3ERR_NOTDIR      NFSERR_NOTDIR
#define NFS3ERR_ISDIR       NFSERR_ISDIR
#define NFS3ERR_INVAL       NFSERR_INVAL
#define NFS3ERR_FBIG        NFSERR_FBIG
#define NFS3ERR_NOSPC       NFSERR_NOSPC
#define NFS3ERR_ROFS        NFSERR_ROFS
#define NFS3ERR_MLINK       NFSERR_MLINK
#define NFS3ERR_NAMETOOLONG NFSERR_NAMETOOLONG
#define NFS3ERR_NOTEMPTY    NFSERR_NOTEMPTY
#define NFS3ERR_DQUOT       NFSERR_DQUOT
#define NFS3ERR_STALE       NFSERR_STALE
#define NFS3ERR_REMOTE      NFSERR_REMOTE
#define NFS3ERR_BADHANDLE   NFSERR_BADHANDLE
#define NFS3ERR_NOT_SYNC    NFSERR_NOT_SYNC
#define NFS3ERR_BAD_COOKIE  NFSERR_BAD_COOKIE
#define NFS3ERR_NOTSUPP     NFSERR_NOTSUPP
#define NFS3ERR_TOOSMALL    NFSERR_TOOSMALL
#define NFS3ERR_SERVERFAULT NFSERR_SERVERFAULT
#define NFS3ERR_BADTYPE     NFSERR_BADTYPE
#define NFS3ERR_JUKEBOX     NFSERR_JUKEBOX

#endif /* NFS_TYPES_H */
