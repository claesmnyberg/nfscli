/*
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
 *      This product includes software developed by John Cartwright.
 * 4. The name John Cartwright may not be used to endorse or promote
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

/*
 * nfs_cache.h - NFS caching subsystem
 *
 * Provides caching for:
 * - Directory entries (O(1) hash-based lookups)
 * - Symlink targets (immutable, no TTL)
 * - File attributes (with TTL for freshness)
 * - FH type cache (ring buffer for completion filtering)
 */

#ifndef NFS_CACHE_H
#define NFS_CACHE_H

#include "cache_util.h"
#include "nfs_types.h"
#include <stdint.h>
#include <time.h>

/* Forward declarations */
struct nfsctx;

/* Cache configuration */
#define NFS_CACHE_BUCKETS  64  /* Hash table buckets per directory */
#define NFS_CACHE_ATTR_TTL 30  /* Attribute cache TTL in seconds */
#define NFS_CACHE_MAX_DIRS 128 /* Maximum directories to cache */

/*
 * Cached directory entry
 *
 * Supports two-tier caching:
 * - Tier 1 (names): name, fileid (from READDIR) - always populated
 * - Tier 2 (full): fh, ftype, attr (from READDIRPLUS or LOOKUP) - lazy
 *
 * File type (ftype) is stable - once known, doesn't change.
 * Attributes are volatile - subject to TTL expiry.
 */
struct nfs_cache_entry {
    char name[NFS_MAXNAMLEN + 1];
    uint8_t name_len; /* Length of name (for fast comparison) */
    uint64_t fileid;  /* From READDIR (stable) */

    /* Stable data - fetched once, cached until evicted */
    struct nfs_fh fh;
    uint8_t ftype; /* NFS_FTYPE_* (stable once known) */
    int has_fh;
    int has_type;

    /* Volatile data - subject to TTL */
    struct nfs_attr attr;
    int has_attr;
    time_t attr_time; /* When attributes were cached */

    /* Negative cache - entry does not exist (ENOENT) */
    int negative;                 /* 1 if LOOKUP returned ENOENT */
    time_t negative_time;         /* When negative was cached */

    time_t cache_time;            /* When entry was first cached */
    struct nfs_cache_entry *next; /* Hash chain */
};

/*
 * Cached directory - holds entries for one directory
 *
 * Completion states (two-tier):
 * - names_complete: All names/fileids from READDIR are cached
 * - types_complete: All entries have ftype (from READDIRPLUS or LOOKUPs)
 *
 * A directory can be names_complete but not types_complete if populated
 * via READDIR only (lazy fetching mode).
 */
struct nfs_cache_dir {
    struct nfs_fh dir_fh;            /* File handle of this directory */
    uint64_t dir_fileid;             /* File ID for comparison */
    struct nfs_attr dir_attr;        /* Attributes of this directory (for ".") */
    int has_dir_attr;                /* Whether dir_attr is valid */
    struct nfs_cache_entry *buckets[NFS_CACHE_BUCKETS];
    size_t entry_count;
    time_t cache_time;               /* When directory was cached */
    int names_complete;              /* All names from READDIR cached */
    int types_complete;              /* All entries have ftype */
    struct nfs_cache_dir *next;      /* LRU chain (newer) */
    struct nfs_cache_dir *prev;      /* LRU chain (older) */
    struct nfs_cache_dir *hash_next; /* Hash chain for O(1) FH lookup */
};

/*
 * Cache statistics
 */
struct nfs_cache_stats {
    int enabled;              /* Cache enabled flag */
    size_t dir_count;         /* Number of cached directories */
    size_t dir_max;           /* Maximum directories */
    size_t entry_count;       /* Total entries across all dirs */
    size_t entries_with_fh;   /* Entries with file handles */
    size_t entries_with_attr; /* Entries with attributes */
    size_t stale_entries;     /* Entries past TTL */
    size_t complete_dirs;     /* Directories with complete listing */
    time_t oldest_dir;        /* Oldest directory cache time */
    time_t newest_dir;        /* Newest directory cache time */
    uint64_t lookup_hits;     /* Lookup cache hits */
    uint64_t lookup_misses;   /* Lookup cache misses */
    uint64_t readdir_hits;    /* Readdir cache hits */
    uint64_t readdir_misses;  /* Readdir cache misses */
};

/*
 * Look up an entry in the cache
 * Returns 0 on cache hit (out filled), -1 on cache miss, -2 on negative hit (ENOENT)
 */
int nfs_cache_lookup(struct nfsctx *ctx,
    const struct nfs_fh *dirfh, const char *name,
    struct nfs_lookup_res *out);

/*
 * Add an entry to the cache
 */
void nfs_cache_add(struct nfsctx *ctx,
    const struct nfs_fh *dirfh, const char *name,
    const struct nfs_lookup_res *entry);

/*
 * Add a negative cache entry (name does not exist)
 */
void nfs_cache_add_negative(struct nfsctx *ctx,
    const struct nfs_fh *dirfh, const char *name);

/*
 * Add multiple entries from readdir/readdirplus result
 */
void nfs_cache_add_dir(struct nfsctx *ctx,
    const struct nfs_fh *dirfh, const struct nfs_dir *dir);

/*
 * Get directory entries from cache
 * Returns 0 on cache hit (out filled), -1 on cache miss
 * Caller must free out->entries with nfs_dir_free() on success
 *
 * Flags (from nfs.h):
 *   NFS_READDIRPLUS_FULL (0) - Require full data (types_complete)
 *   NFS_READDIRPLUS_NAMES (1) - Accept names only (names_complete)
 */
int nfs_cache_get_dir(struct nfsctx *ctx,
    const struct nfs_fh *dirfh, struct nfs_dir *out, int flags);

/*
 * Invalidate cache for a directory
 */
void nfs_cache_invalidate(struct nfsctx *ctx,
    const struct nfs_fh *dirfh);

/*
 * Invalidate all cached data
 */
void nfs_cache_invalidate_all(struct nfsctx *ctx);

/*
 * Get cache statistics
 * Returns 0 on success, -1 if no cache context
 */
int nfs_cache_get_stats(struct nfsctx *ctx,
    struct nfs_cache_stats *stats);

/*
 * Internal: Find cache for a directory
 */
struct nfs_cache_dir *nfs_cache_find(struct nfsctx *ctx,
    const struct nfs_fh *dirfh);

/*
 * Internal: Create cache for a directory
 */
struct nfs_cache_dir *nfs_cache_create(struct nfsctx *ctx,
    const struct nfs_fh *dirfh);

/*
 * Internal: Free cache entries
 */
void nfs_cache_free_entries(struct nfs_cache_dir *cache);

/*
 * Update cached attributes by file handle.
 * Searches all cached directories for entries matching the FH
 * and updates their attributes. Used after setattr operations.
 */
void nfs_cache_update_attr_by_fh(struct nfsctx *ctx,
    const struct nfs_fh *fh, const struct nfs_attr *attr);

/*
 * ============================================================================
 * Symlink cache - immutable (symlinks don't change target)
 * ============================================================================
 */

#define NFS_SYMLINK_CACHE_BUCKETS 64
#define NFS_SYMLINK_CACHE_MAX     512 /* Max entries before eviction */

/*
 * Symlink target cache entry (immutable - no TTL needed)
 * Uses intrusive cache_hdr for hash chain and LRU tracking.
 */
struct nfs_symlink_entry {
    struct cache_hdr hdr; /* Must be first - hash chain + add_time */
    struct nfs_fh fh;     /* Symlink file handle */
    char *target;         /* Target path (allocated) */
};

/*
 * Look up symlink target in cache.
 * Returns target string on hit, NULL on miss.
 */
const char *nfs_symlink_cache_lookup(struct nfsctx *ctx,
    const struct nfs_fh *fh);

/*
 * Add symlink target to cache.
 */
void nfs_symlink_cache_add(struct nfsctx *ctx,
    const struct nfs_fh *fh, const char *target);

/*
 * Clear symlink cache.
 */
void nfs_symlink_cache_clear(struct nfsctx *ctx);

/*
 * ============================================================================
 * Attribute cache - FH-keyed with TTL
 * ============================================================================
 */

#define NFS_ATTR_CACHE_BUCKETS 128
#define NFS_ATTR_CACHE_MAX     1024 /* Max entries before cleanup */
#define NFS_ATTR_CACHE_TTL     3    /* Seconds before attrs are stale */

/*
 * Attribute cache entry (with TTL for freshness)
 * Uses intrusive cache_hdr for hash chain and LRU tracking.
 * Note: hdr.add_time serves as cache_time for TTL checks.
 */
struct nfs_attr_cache_entry {
    struct cache_hdr hdr; /* Must be first - hash chain + cache_time */
    struct nfs_fh fh;     /* File handle */
    struct nfs_attr attr; /* Cached attributes */
};

/*
 * Look up attributes in cache.
 * Returns pointer to cached attrs on hit (valid for NFS_ATTR_CACHE_TTL),
 * NULL on miss or if stale.
 */
const struct nfs_attr *nfs_attr_cache_lookup(struct nfsctx *ctx,
    const struct nfs_fh *fh);

/*
 * Add or update attributes in cache.
 */
void nfs_attr_cache_add(struct nfsctx *ctx,
    const struct nfs_fh *fh, const struct nfs_attr *attr);

/*
 * Clear entire attribute cache.
 */
void nfs_attr_cache_clear(struct nfsctx *ctx);

/*
 * Get attribute cache statistics.
 */
void nfs_attr_cache_stats(struct nfsctx *ctx,
    size_t *count, uint64_t *hits, uint64_t *misses);

/*
 * ============================================================================
 * FH type cache - ring buffer for completion filtering
 * ============================================================================
 */

/*
 * Recent lookup result cache entry (for completion filtering by type)
 * Size increased to accommodate READDIRPLUS results (typical dir ~50-200 entries)
 */
#define NFS_LOOKUP_CACHE_SIZE 256

struct nfs_lookup_cache_entry {
    char *fh_hex;   /* FH as hex string (for completion matching) */
    uint32_t ftype; /* NFS file type (NFS_FTYPE_REG, NFS_FTYPE_DIR, etc.) */
};

/*
 * Add a file handle and its type to the FH type cache.
 * Used by completion to filter FH suggestions by expected type.
 */
void nfs_fh_type_cache_add(struct nfsctx *ctx,
    const uint8_t *fh, size_t fhlen, uint32_t ftype);

/*
 * Clear the FH type cache.
 */
void nfs_fh_type_cache_clear(struct nfsctx *ctx);

#endif /* NFS_CACHE_H */
