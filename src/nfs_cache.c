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
 * nfs_cache.c - NFS caching subsystem
 *
 * Implements multiple cache layers to reduce NFS round-trips:
 *
 * Directory Cache (nfs_cache_dir):
 *   - Caches READDIRPLUS results: name → (FH, attributes, type)
 *   - Hash table per directory, keyed by directory FH
 *   - Supports "complete" flag for accurate ls without re-reading
 *   - Invalidated on mutating operations (CREATE, REMOVE, RENAME, etc.)
 *
 * Negative Cache (within directory cache):
 *   - Caches LOOKUP failures (ENOENT) to avoid repeated lookups
 *   - Shorter TTL than positive entries (NFS_CACHE_ATTR_TTL)
 *   - Return code -2 from nfs_cache_lookup() = "confirmed non-existent"
 *
 * Attribute Cache (nfs_attr_cache):
 *   - Caches GETATTR results: FH → attributes
 *   - Short TTL (NFS_ATTR_CACHE_TTL seconds)
 *   - LRU eviction when cache exceeds NFS_ATTR_CACHE_MAX entries
 *   - Separate from directory cache for standalone GETATTR calls
 *
 * Symlink Cache (nfs_symlink_cache):
 *   - Caches READLINK results: FH → target path string
 *   - Long TTL (symlinks rarely change in practice)
 *   - LRU eviction at NFS_SYMLINK_CACHE_MAX entries
 *
 * FH Type Cache (ring buffer):
 *   - Small ring buffer tracking recently-seen FH→type mappings
 *   - Used by tab completion to filter files vs directories
 *   - No TTL, just overwrites oldest on new entries
 *
 * Cache Coherency:
 *   - File handles are stable once obtained (cached indefinitely)
 *   - Attributes are volatile (TTL-based expiry)
 *   - Directory listings invalidated on any mutating operation
 *   - Explicit invalidation via nfs_cache_invalidate_*() functions
 *
 * Mount FH Cache is in mount.c (export path → root FH, session-persistent).
 * Parent FH Cache is in nfs_escape.c (child FH → parent FH, for escaping).
 */

#include <stdlib.h>
#include <time.h>

#include "nfs.h"
#include "nfs_cache.h"
#include "nfs_escape.h"
#include "nfscli.h"
#include "print.h"

/* Hex lookup table for fast byte-to-hex conversion */
static const char hex_table[] = "0123456789abcdef";

/* Convert byte array to hex string using lookup table */
static void
bytes_to_hex(const uint8_t *data, size_t len, char *out)
{
    size_t i;
    for (i = 0; i < len; i++) {
        out[i * 2] = hex_table[data[i] >> 4];
        out[i * 2 + 1] = hex_table[data[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

/*
 * Hash function for directory entry names (djb2 algorithm).
 */
static unsigned int
hash_name(const char *name)
{
    unsigned int hash = 5381; /* djb2 magic constant */
    int c;

    while ((c = (unsigned char)*name++) != 0)
        hash = ((hash << 5) + hash) + c;

    return hash % NFS_CACHE_BUCKETS;
}

/*
 * Hash function for file handles (djb2 algorithm).
 */
static unsigned int
hash_fh(const struct nfs_fh *fh)
{
    unsigned int hash = 5381; /* djb2 magic constant */
    uint32_t i;

    for (i = 0; i < fh->len; i++)
        hash = ((hash << 5) + hash) + fh->data[i];

    return hash % NFS_DIR_CACHE_BUCKETS;
}

/*
 * Compare two file handles
 */
static int
fh_equal(const struct nfs_fh *a, const struct nfs_fh *b)
{
    if (a->len != b->len)
        return 0;
    return memcmp(a->data, b->data, a->len) == 0;
}

/*
 * Copy a file handle
 */
static void
fh_copy(struct nfs_fh *dst, const struct nfs_fh *src)
{
    dst->len = src->len;
    memcpy(dst->data, src->data, src->len);
}

/*
 * Find cache for a directory (O(1) hash lookup)
 */
struct nfs_cache_dir *
nfs_cache_find(struct nfsctx *ctx, const struct nfs_fh *dirfh)
{
    struct nfs_cache_dir *cache;
    unsigned int bucket;

    bucket = hash_fh(dirfh);
    for (cache = ctx->cache.dir_hash[bucket]; cache != NULL;
        cache = cache->hash_next) {
        if (fh_equal(&cache->dir_fh, dirfh))
            return cache;
    }
    return NULL;
}

/*
 * Remove directory from hash table
 */
static void
nfs_cache_hash_remove(struct nfsctx *ctx, struct nfs_cache_dir *cache)
{
    unsigned int bucket = hash_fh(&cache->dir_fh);
    struct nfs_cache_dir **pp = &ctx->cache.dir_hash[bucket];

    while (*pp != NULL) {
        if (*pp == cache) {
            *pp = cache->hash_next;
            cache->hash_next = NULL;
            return;
        }
        pp = &(*pp)->hash_next;
    }
}

/*
 * Create cache for a directory
 */
struct nfs_cache_dir *
nfs_cache_create(struct nfsctx *ctx, const struct nfs_fh *dirfh)
{
    struct nfs_cache_dir *cache;
    unsigned int bucket;

    cache = calloc(1, sizeof(*cache));
    if (cache == NULL)
        return NULL;

    fh_copy(&cache->dir_fh, dirfh);
    cache->cache_time = time(NULL);

    /* Initialize dir_max if not set */
    if (ctx->cache.dir_max == 0)
        ctx->cache.dir_max = NFS_CACHE_MAX_DIRS;

    /* Add to front of LRU list (doubly-linked) */
    cache->prev = NULL;
    cache->next = ctx->cache.dir_head;
    if (ctx->cache.dir_head != NULL)
        ctx->cache.dir_head->prev = cache;
    ctx->cache.dir_head = cache;
    if (ctx->cache.dir_tail == NULL)
        ctx->cache.dir_tail = cache;
    ctx->cache.dir_count++;

    /* Add to hash table for O(1) lookup */
    bucket = hash_fh(dirfh);
    cache->hash_next = ctx->cache.dir_hash[bucket];
    ctx->cache.dir_hash[bucket] = cache;

    /* Evict old entries if over limit - O(1) using tail pointer */
    while (ctx->cache.dir_count > ctx->cache.dir_max) {
        struct nfs_cache_dir *victim = ctx->cache.dir_tail;

        if (victim == NULL)
            break; /* Shouldn't happen, but be defensive */

        /* Remove from hash table first */
        nfs_cache_hash_remove(ctx, victim);

        if (victim->prev != NULL) {
            victim->prev->next = NULL;
            ctx->cache.dir_tail = victim->prev;
        } else {
            /* List becomes empty */
            ctx->cache.dir_head = NULL;
            ctx->cache.dir_tail = NULL;
        }

        nfs_cache_free_entries(victim);
        free(victim);
        ctx->cache.dir_count--;
    }

    return cache;
}

/*
 * Free cache entries
 */
void
nfs_cache_free_entries(struct nfs_cache_dir *cache)
{
    size_t i;

    for (i = 0; i < NFS_CACHE_BUCKETS; i++) {
        struct nfs_cache_entry *entry = cache->buckets[i];
        while (entry != NULL) {
            struct nfs_cache_entry *next = entry->next;
            free(entry);
            entry = next;
        }
        cache->buckets[i] = NULL;
    }
    cache->entry_count = 0;
}

/*
 * Look up an entry in the cache
 */
int
nfs_cache_lookup(struct nfsctx *ctx,
    const struct nfs_fh *dirfh, const char *name,
    struct nfs_lookup_res *out)
{
    struct nfs_cache_dir *cache;
    struct nfs_cache_entry *entry;
    unsigned int bucket;
    time_t now;

    if (ctx == NULL || !ctx->cache.enabled) {
        if (ctx != NULL)
            ctx->cache.lookup_misses++;
        return -1;
    }

    cache = nfs_cache_find(ctx, dirfh);
    if (cache == NULL) {
        ctx->cache.lookup_misses++;
        return -1;
    }

    bucket = hash_name(name);
    now = time(NULL);

    size_t name_len = strlen(name);
    for (entry = cache->buckets[bucket]; entry != NULL; entry = entry->next) {
        if (entry->name_len == name_len &&
            memcmp(entry->name, name, name_len) == 0) {
            /* Check for negative cache entry (ENOENT) */
            if (entry->negative) {
                /* Negative entries have short TTL */
                if ((now - entry->negative_time) <= NFS_CACHE_ATTR_TTL) {
                    ctx->cache.lookup_hits++;
                    return -2; /* Negative hit - entry doesn't exist */
                }
                /* Negative entry expired - clear it and treat as miss */
                entry->negative = 0;
                ctx->cache.lookup_misses++;
                return -1;
            }

            /* Must have a file handle for lookup to succeed */
            if (!entry->has_fh) {
                /* Entry from READDIR (no FH) - treat as cache miss */
                ctx->cache.lookup_misses++;
                return -1;
            }

            /* FH is stable - always return it */
            fh_copy(&out->fh, &entry->fh);

            /* Check TTL for attributes (volatile data) */
            if (entry->has_attr &&
                (now - entry->attr_time) <= NFS_CACHE_ATTR_TTL) {
                out->obj_attr = entry->attr;
                out->has_obj_attr = 1;
            } else {
                out->has_obj_attr = 0;
            }
            out->has_dir_attr = 0;
            ctx->cache.lookup_hits++;
            return 0;
        }
    }

    ctx->cache.lookup_misses++;
    return -1;
}

/*
 * Add an entry to the cache
 */
void
nfs_cache_add(struct nfsctx *ctx,
    const struct nfs_fh *dirfh, const char *name,
    const struct nfs_lookup_res *entry)
{
    struct nfs_cache_dir *cache;
    struct nfs_cache_entry *ce;
    unsigned int bucket;

    if (ctx == NULL || !ctx->cache.enabled)
        return;

    cache = nfs_cache_find(ctx, dirfh);
    if (cache == NULL) {
        cache = nfs_cache_create(ctx, dirfh);
        if (cache == NULL)
            return;
    }

    bucket = hash_name(name);
    size_t name_len = strlen(name);

    /* Check if entry already exists */
    for (ce = cache->buckets[bucket]; ce != NULL; ce = ce->next) {
        if (ce->name_len == name_len &&
            memcmp(ce->name, name, name_len) == 0) {
            /*
             * Entry exists - might be negative cache entry being
             * converted to positive. Mark listing incomplete.
             */
            int was_negative = ce->negative;

            /* Update existing entry with FH (stable) */
            fh_copy(&ce->fh, &entry->fh);
            ce->has_fh = 1;
            ce->negative = 0;

            /* Update attributes (volatile) */
            if (entry->has_obj_attr) {
                ce->attr = entry->obj_attr;
                ce->has_attr = 1;
                ce->attr_time = time(NULL);

                /* Type is stable - set once */
                if (!ce->has_type) {
                    ce->ftype = entry->obj_attr.type;
                    ce->has_type = 1;
                }
            }

            /*
             * If entry was negative (ENOENT) and now exists,
             * directory listing is stale.
             */
            if (was_negative) {
                cache->names_complete = 0;
                cache->types_complete = 0;
            }
            return;
        }
    }

    /* Create new entry */
    ce = calloc(1, sizeof(*ce));
    if (ce == NULL)
        return;

    strncpy(ce->name, name, NFS_MAXNAMLEN);
    ce->name[NFS_MAXNAMLEN] = '\0';
    ce->name_len = strlen(ce->name);
    fh_copy(&ce->fh, &entry->fh);
    ce->has_fh = 1;
    ce->cache_time = time(NULL);

    if (entry->has_obj_attr) {
        ce->attr = entry->obj_attr;
        ce->has_attr = 1;
        ce->attr_time = time(NULL);
        ce->ftype = entry->obj_attr.type;
        ce->has_type = 1;
    }

    /* Add to bucket */
    ce->next = cache->buckets[bucket];
    cache->buckets[bucket] = ce;
    cache->entry_count++;

    /*
     * New entry added - directory listing is no longer complete.
     * Next READDIR will refresh from server.
     */
    cache->names_complete = 0;
    cache->types_complete = 0;
}

/*
 * Add a negative cache entry (name does not exist)
 */
void
nfs_cache_add_negative(struct nfsctx *ctx,
    const struct nfs_fh *dirfh, const char *name)
{
    struct nfs_cache_dir *cache;
    struct nfs_cache_entry *ce;
    unsigned int bucket;
    time_t now;

    if (ctx == NULL || !ctx->cache.enabled)
        return;

    cache = nfs_cache_find(ctx, dirfh);
    if (cache == NULL) {
        cache = nfs_cache_create(ctx, dirfh);
        if (cache == NULL)
            return;
    }

    bucket = hash_name(name);
    size_t name_len = strlen(name);
    now = time(NULL);

    /* Check if entry already exists */
    for (ce = cache->buckets[bucket]; ce != NULL; ce = ce->next) {
        if (ce->name_len == name_len &&
            memcmp(ce->name, name, name_len) == 0) {
            /* Mark existing entry as negative */
            ce->negative = 1;
            ce->negative_time = now;
            ce->has_fh = 0;
            ce->has_attr = 0;
            return;
        }
    }

    /* Create new negative entry */
    ce = calloc(1, sizeof(*ce));
    if (ce == NULL)
        return;

    strncpy(ce->name, name, NFS_MAXNAMLEN);
    ce->name[NFS_MAXNAMLEN] = '\0';
    ce->name_len = strlen(ce->name);
    ce->negative = 1;
    ce->negative_time = now;
    ce->cache_time = now;

    /* Add to bucket */
    ce->next = cache->buckets[bucket];
    cache->buckets[bucket] = ce;
    cache->entry_count++;
}

/*
 * Add multiple entries from readdir/readdirplus result
 */
void
nfs_cache_add_dir(struct nfsctx *ctx,
    const struct nfs_fh *dirfh, const struct nfs_dir *dir)
{
    struct nfs_cache_dir *cache;
    size_t i;

    if (ctx == NULL || dir == NULL)
        return;

    /* Don't cache if disabled */
    if (!ctx->cache.enabled)
        return;

    cache = nfs_cache_find(ctx, dirfh);
    if (cache == NULL) {
        cache = nfs_cache_create(ctx, dirfh);
        if (cache == NULL)
            return;
    }

    /* Update cache time on every add */
    cache->cache_time = time(NULL);

    /* Store directory attributes (for "." entry reconstruction) */
    if (dir->has_dir_attr) {
        cache->dir_attr = dir->dir_attr;
        cache->has_dir_attr = 1;
    }

    /* Add all directory entries */
    for (i = 0; i < dir->count; i++) {
        const struct nfs_dirent *de = &dir->entries[i];
        struct nfs_cache_entry *ce;
        unsigned int bucket;

        /* Store "." attributes if not already set from dir_attr */
        if (strcmp(de->name, ".") == 0) {
            if (!cache->has_dir_attr && de->has_attr) {
                cache->dir_attr = de->attr;
                cache->has_dir_attr = 1;
            }
            continue;
        }

        /* Store ".." file handle in parent cache for ceiling escape */
        if (strcmp(de->name, "..") == 0 && de->has_fh) {
            /* Mark as ceiling if ".." equals current dir (blocked) */
            int is_ceiling = nfs_fh_equal(&de->fh, &cache->dir_fh);
            nfs_parent_cache_add(&cache->dir_fh, &de->fh, is_ceiling);
        }
        /* Also add ".." to directory cache so nfs_cache_lookup() hits */

        bucket = hash_name(de->name);

        /* Check if already exists - cap length to max storable */
        size_t de_name_len = strlen(de->name);
        if (de_name_len > NFS_MAXNAMLEN)
            de_name_len = NFS_MAXNAMLEN;
        for (ce = cache->buckets[bucket]; ce != NULL; ce = ce->next) {
            if (ce->name_len == de_name_len &&
                memcmp(ce->name, de->name, de_name_len) == 0)
                break;
        }

        if (ce == NULL) {
            ce = calloc(1, sizeof(*ce));
            if (ce == NULL)
                continue;

            strncpy(ce->name, de->name, NFS_MAXNAMLEN);
            ce->name[NFS_MAXNAMLEN] = '\0';
            ce->name_len = strlen(ce->name);

            ce->next = cache->buckets[bucket];
            cache->buckets[bucket] = ce;
            cache->entry_count++;
        }

        /* Store fileid - always present from READDIR */
        ce->fileid = de->fileid;

        /* Update entry with FH if available */
        if (de->has_fh) {
            fh_copy(&ce->fh, &de->fh);
            ce->has_fh = 1;
        } else if (ce->has_fh) {
            /*
             * New data has no FH but old entry did - invalidate.
             * File may have been deleted/recreated with same name but different FH.
             * Clear the stale data to prevent accidental use.
             */
            memset(&ce->fh, 0, sizeof(ce->fh));
            ce->has_fh = 0;
        }

        /* Update entry with attributes if available */
        if (de->has_attr) {
            ce->attr = de->attr;
            ce->has_attr = 1;
            ce->attr_time = time(NULL);

            /* Type is stable - extract from attributes */
            if (!ce->has_type) {
                ce->ftype = de->attr.type;
                ce->has_type = 1;
            }
        } else if (ce->has_attr) {
            /*
             * New data has no attrs but old entry did - invalidate.
             * This happens in NFSv2 when READDIR (no attrs) runs after
             * READDIRPLUS emulation (with attrs). The old attrs are now
             * stale since the directory was re-read.
             * Clear the stale data to prevent accidental use.
             */
            memset(&ce->attr, 0, sizeof(ce->attr));
            ce->has_attr = 0;
            ce->attr_time = 0;
        }

        /*
         * For "..", we know it's a directory even without LOOKUP attrs.
         * For other entries, leave has_type=0 if we don't have attrs.
         * This ensures types_complete stays false for READDIR-only data,
         * forcing LOOKUPs for NFSv2 when NFS_READDIRPLUS_FULL is requested.
         */
        if (!ce->has_type && strcmp(de->name, "..") == 0) {
            ce->ftype = NFS_FTYPE_DIR;
            ce->has_type = 1;
        }

        if (ce->cache_time == 0)
            ce->cache_time = time(NULL);
    }

    /* Track completion state */
    if (dir->eof) {
        cache->names_complete = 1;

        /* Check if all entries have types (READDIRPLUS or enriched) */
        int all_have_types = 1;
        for (i = 0; i < NFS_CACHE_BUCKETS && all_have_types; i++) {
            struct nfs_cache_entry *ce;
            for (ce = cache->buckets[i]; ce != NULL; ce = ce->next) {
                /* Skip negative entries - they don't represent real files */
                if (ce->negative)
                    continue;
                if (!ce->has_type) {
                    all_have_types = 0;
                    break;
                }
            }
        }
        cache->types_complete = all_have_types;
    }
}

/*
 * Get directory entries from cache
 */
int
nfs_cache_get_dir(struct nfsctx *ctx,
    const struct nfs_fh *dirfh, struct nfs_dir *out, int flags)
{
    struct nfs_cache_dir *cache;
    struct nfs_cache_entry *entry;
    struct nfs_dirent *entries;
    time_t now;
    size_t count, i, bucket;
    int names_only = (flags & NFS_READDIRPLUS_NAMES);

    if (ctx == NULL || out == NULL || !ctx->cache.enabled) {
        if (ctx != NULL)
            ctx->cache.readdir_misses++;
        return -1;
    }

    cache = nfs_cache_find(ctx, dirfh);
    if (cache == NULL) {
        ctx->cache.readdir_misses++;
        return -1;
    }
    /*
     * Check completeness based on what caller needs:
     * - names_only: just need names_complete
     * - full data: need both names_complete and types_complete
     */
    if (!cache->names_complete ||
        (!names_only && !cache->types_complete)) {
        ctx->cache.readdir_misses++;
        return -1;
    }

    /* Check TTL - use same TTL as attributes */
    now = time(NULL);
    if (now - cache->cache_time > NFS_CACHE_ATTR_TTL) {
        ctx->cache.readdir_misses++;
        return -1;
    }

    /* Count entries (need to add "." and ".." back) */
    count = cache->entry_count + 2;

    /* Allocate entries array */
    entries = calloc(count, sizeof(*entries));
    if (entries == NULL)
        return -1;

    /* Add "." entry with cached directory attributes */
    snprintf(entries[0].name, sizeof(entries[0].name), ".");
    fh_copy(&entries[0].fh, &cache->dir_fh);
    entries[0].has_fh = 1;
    if (cache->has_dir_attr) {
        entries[0].fileid = cache->dir_attr.fileid;
        entries[0].attr = cache->dir_attr;
        entries[0].has_attr = 1;
    } else {
        entries[0].fileid = 0;
        entries[0].has_attr = 0;
    }

    /* Add ".." entry - check cache for FH/attrs */
    snprintf(entries[1].name, sizeof(entries[1].name), "..");
    entries[1].has_fh = 0;
    entries[1].has_attr = 0;
    entries[1].fileid = 0;

    /* Look up cached ".." entry */
    bucket = hash_name("..");
    for (entry = cache->buckets[bucket]; entry != NULL; entry = entry->next) {
        if (strcmp(entry->name, "..") == 0) {
            entries[1].fileid = entry->fileid;
            if (entry->has_fh) {
                fh_copy(&entries[1].fh, &entry->fh);
                entries[1].has_fh = 1;
            }
            if (entry->has_attr) {
                entries[1].attr = entry->attr;
                entries[1].has_attr = 1;
            }
            break;
        }
    }

    /* Copy cached entries (skip ".." - already added above, skip negative entries) */
    i = 2;
    for (bucket = 0; bucket < NFS_CACHE_BUCKETS && i < count; bucket++) {
        for (entry = cache->buckets[bucket]; entry != NULL && i < count; entry = entry->next) {
            if (strcmp(entry->name, "..") == 0)
                continue;
            /* Skip negative cache entries - they represent non-existent files */
            if (entry->negative)
                continue;
            entries[i].fileid = entry->fileid;
            snprintf(entries[i].name, sizeof(entries[i].name), "%s", entry->name);
            if (entry->has_fh) {
                fh_copy(&entries[i].fh, &entry->fh);
                entries[i].has_fh = 1;
            }
            if (entry->has_attr) {
                entries[i].attr = entry->attr;
                entries[i].has_attr = 1;
            }
            i++;
        }
    }

    /* Fill output */
    memset(out, 0, sizeof(*out));
    out->entries = entries;
    out->count = i;
    out->capacity = count;
    out->eof = 1;
    if (cache->has_dir_attr) {
        out->dir_attr = cache->dir_attr;
        out->has_dir_attr = 1;
    }

    ctx->cache.readdir_hits++;
    return 0;
}

/*
 * Invalidate cache for a directory
 */
void
nfs_cache_invalidate(struct nfsctx *ctx, const struct nfs_fh *dirfh)
{
    struct nfs_cache_dir *cache;

    if (ctx == NULL)
        return;

    /* Use O(1) hash lookup to find the cache */
    cache = nfs_cache_find(ctx, dirfh);
    if (cache == NULL)
        return;

    /* Remove from hash table */
    nfs_cache_hash_remove(ctx, cache);

    /* Remove from doubly-linked LRU list */
    if (cache->prev != NULL)
        cache->prev->next = cache->next;
    else
        ctx->cache.dir_head = cache->next;

    if (cache->next != NULL)
        cache->next->prev = cache->prev;
    else
        ctx->cache.dir_tail = cache->prev;

    nfs_cache_free_entries(cache);
    free(cache);
    ctx->cache.dir_count--;
}

/*
 * Invalidate all cached directory data
 */
void
nfs_cache_invalidate_all(struct nfsctx *ctx)
{
    struct nfs_cache_dir *cache, *next;
    size_t i;

    if (ctx == NULL)
        return;

    for (cache = ctx->cache.dir_head; cache != NULL; cache = next) {
        next = cache->next;
        nfs_cache_free_entries(cache);
        free(cache);
    }

    ctx->cache.dir_head = NULL;
    ctx->cache.dir_tail = NULL;
    ctx->cache.dir_count = 0;

    /* Clear hash table */
    for (i = 0; i < NFS_DIR_CACHE_BUCKETS; i++)
        ctx->cache.dir_hash[i] = NULL;
}

/*
 * Update cached attributes by file handle.
 * Searches all cached directories for entries matching the FH
 * and updates their attributes.
 */
void
nfs_cache_update_attr_by_fh(struct nfsctx *ctx,
    const struct nfs_fh *fh, const struct nfs_attr *attr)
{
    struct nfs_cache_dir *cache;
    size_t i;

    if (ctx == NULL || fh == NULL || attr == NULL)
        return;

    if (!ctx->cache.enabled)
        return;

    /* Search all cached directories */
    for (cache = ctx->cache.dir_head; cache != NULL; cache = cache->next) {
        /* Check if this is the directory itself */
        if (fh_equal(&cache->dir_fh, fh)) {
            cache->dir_attr = *attr;
            cache->has_dir_attr = 1;
            continue;
        }

        /* Search entries in this directory */
        for (i = 0; i < NFS_CACHE_BUCKETS; i++) {
            struct nfs_cache_entry *entry;
            for (entry = cache->buckets[i]; entry != NULL; entry = entry->next) {
                if (entry->has_fh && fh_equal(&entry->fh, fh)) {
                    entry->attr = *attr;
                    entry->has_attr = 1;
                    entry->attr_time = time(NULL);
                    /* Type is stable - update if not already set */
                    if (!entry->has_type) {
                        entry->ftype = attr->type;
                        entry->has_type = 1;
                    }
                    /* Found it - but keep searching in case it's
                     * cached in multiple directories (e.g., hard links) */
                }
            }
        }
    }
}

/*
 * Get cache statistics
 */
int
nfs_cache_get_stats(struct nfsctx *ctx, struct nfs_cache_stats *stats)
{
    struct nfs_cache_dir *cache;
    time_t now;

    if (stats == NULL)
        return -1;

    memset(stats, 0, sizeof(*stats));

    if (ctx == NULL)
        return -1;

    now = time(NULL);
    stats->enabled = ctx->cache.enabled;
    stats->dir_count = ctx->cache.dir_count;
    stats->dir_max = ctx->cache.dir_max;
    stats->lookup_hits = ctx->cache.lookup_hits;
    stats->lookup_misses = ctx->cache.lookup_misses;
    stats->readdir_hits = ctx->cache.readdir_hits;
    stats->readdir_misses = ctx->cache.readdir_misses;

    /* Iterate through cached directories */
    for (cache = ctx->cache.dir_head; cache != NULL; cache = cache->next) {
        size_t i;

        stats->entry_count += cache->entry_count;
        if (cache->names_complete)
            stats->complete_dirs++;

        /* Track oldest/newest */
        if (stats->oldest_dir == 0 || cache->cache_time < stats->oldest_dir)
            stats->oldest_dir = cache->cache_time;
        if (cache->cache_time > stats->newest_dir)
            stats->newest_dir = cache->cache_time;

        /* Count entries with FH/attr and stale entries */
        for (i = 0; i < NFS_CACHE_BUCKETS; i++) {
            struct nfs_cache_entry *entry;
            for (entry = cache->buckets[i]; entry != NULL; entry = entry->next) {
                if (entry->has_fh)
                    stats->entries_with_fh++;
                if (entry->has_attr)
                    stats->entries_with_attr++;
                /* Attributes are stale based on attr_time */
                if (entry->has_attr &&
                    (now - entry->attr_time) > NFS_CACHE_ATTR_TTL)
                    stats->stale_entries++;
            }
        }
    }

    return 0;
}

/*
 * ============================================================================
 * Symlink cache - caches readlink results by FH (immutable, no TTL needed)
 * ============================================================================
 */

/* Look up symlink in cache */
const char *
nfs_symlink_cache_lookup(struct nfsctx *ctx, const struct nfs_fh *fh)
{
    unsigned int bucket = cache_hash_bytes(fh->data, fh->len,
        NFS_SYMLINK_CACHE_BUCKETS);
    struct cache_hdr *h;

    for (h = ctx->cache.symlinks[bucket]; h != NULL; h = h->hash_next) {
        struct nfs_symlink_entry *e = CACHE_ENTRY(h, struct nfs_symlink_entry);
        if (e->fh.len == fh->len &&
            memcmp(e->fh.data, fh->data, fh->len) == 0)
            return e->target;
    }
    return NULL;
}

/* Add symlink to cache */
void
nfs_symlink_cache_add(struct nfsctx *ctx, const struct nfs_fh *fh,
    const char *target)
{
    unsigned int bucket = cache_hash_bytes(fh->data, fh->len,
        NFS_SYMLINK_CACHE_BUCKETS);
    struct nfs_symlink_entry *e;

    /* Check if already cached */
    if (nfs_symlink_cache_lookup(ctx, fh) != NULL)
        return;

    /* Evict oldest entry if cache is full (LRU) */
    if (ctx->cache.symlink_count >= NFS_SYMLINK_CACHE_MAX) {
        struct cache_hdr **pp = cache_find_oldest(ctx->cache.symlinks,
            NFS_SYMLINK_CACHE_BUCKETS);
        if (pp != NULL) {
            struct cache_hdr *victim = cache_remove_at(pp);
            if (victim != NULL) {
                struct nfs_symlink_entry *ve =
                    CACHE_ENTRY(victim, struct nfs_symlink_entry);
                free(ve->target);
                free(ve);
                ctx->cache.symlink_count--;
            }
        }
    }

    e = malloc(sizeof(*e));
    if (e == NULL)
        return;

    cache_hdr_init(&e->hdr);
    e->fh.len = fh->len;
    memcpy(e->fh.data, fh->data, fh->len);
    e->target = strdup(target);
    if (e->target == NULL) {
        free(e);
        return;
    }

    cache_add_to_bucket(&ctx->cache.symlinks[bucket], &e->hdr);
    ctx->cache.symlink_count++;
}

/* Clear symlink cache */
void
nfs_symlink_cache_clear(struct nfsctx *ctx)
{
    size_t i;
    struct cache_hdr *h, *next;

    for (i = 0; i < NFS_SYMLINK_CACHE_BUCKETS; i++) {
        h = ctx->cache.symlinks[i];
        while (h != NULL) {
            struct nfs_symlink_entry *e =
                CACHE_ENTRY(h, struct nfs_symlink_entry);
            next = h->hash_next;
            free(e->target);
            free(e);
            h = next;
        }
        ctx->cache.symlinks[i] = NULL;
    }
    ctx->cache.symlink_count = 0;
    ctx->cache.symlink_hits = 0;
    ctx->cache.symlink_misses = 0;
}

/*
 * ============================================================================
 * Attribute cache - caches file/directory attributes by FH with TTL
 * ============================================================================
 */

/* Look up attributes in cache (returns NULL if not found or stale) */
const struct nfs_attr *
nfs_attr_cache_lookup(struct nfsctx *ctx, const struct nfs_fh *fh)
{
    unsigned int bucket = cache_hash_bytes(fh->data, fh->len,
        NFS_ATTR_CACHE_BUCKETS);
    struct cache_hdr *h;
    time_t now = time(NULL);

    for (h = ctx->cache.attrs[bucket]; h != NULL; h = h->hash_next) {
        struct nfs_attr_cache_entry *e =
            CACHE_ENTRY(h, struct nfs_attr_cache_entry);
        if (e->fh.len == fh->len &&
            memcmp(e->fh.data, fh->data, fh->len) == 0) {
            /* Check if still valid (hdr.add_time = cache_time) */
            if ((now - h->add_time) < NFS_ATTR_CACHE_TTL)
                return &e->attr;
            /* Stale - treat as miss (will be updated on next add) */
            return NULL;
        }
    }
    return NULL;
}

/*
 * Purge expired entries from attribute cache.
 * Called when cache exceeds size limit.
 */
static void
nfs_attr_cache_purge_expired(struct nfsctx *ctx)
{
    time_t now = time(NULL);
    size_t i;
    struct cache_hdr **pp;
    struct cache_hdr *h;

    for (i = 0; i < NFS_ATTR_CACHE_BUCKETS; i++) {
        pp = &ctx->cache.attrs[i];

        while ((h = *pp) != NULL) {
            if ((now - h->add_time) >= NFS_ATTR_CACHE_TTL) {
                /* Expired - remove */
                *pp = h->hash_next;
                free(CACHE_ENTRY(h, struct nfs_attr_cache_entry));
                ctx->cache.attr_count--;
            } else {
                pp = &h->hash_next;
            }
        }
    }
}

/* Add or update attributes in cache */
void
nfs_attr_cache_add(struct nfsctx *ctx, const struct nfs_fh *fh,
    const struct nfs_attr *attr)
{
    unsigned int bucket = cache_hash_bytes(fh->data, fh->len,
        NFS_ATTR_CACHE_BUCKETS);
    struct cache_hdr *h;
    struct nfs_attr_cache_entry *e;

    /* Look for existing entry to update */
    for (h = ctx->cache.attrs[bucket]; h != NULL; h = h->hash_next) {
        e = CACHE_ENTRY(h, struct nfs_attr_cache_entry);
        if (e->fh.len == fh->len &&
            memcmp(e->fh.data, fh->data, fh->len) == 0) {
            /* Update existing entry */
            e->attr = *attr;
            h->add_time = time(NULL);
            return;
        }
    }

    /* Purge expired entries if cache is too large */
    if (ctx->cache.attr_count >= NFS_ATTR_CACHE_MAX)
        nfs_attr_cache_purge_expired(ctx);

    /* If still over limit, evict oldest entry (LRU) */
    if (ctx->cache.attr_count >= NFS_ATTR_CACHE_MAX) {
        struct cache_hdr **pp = cache_find_oldest(ctx->cache.attrs,
            NFS_ATTR_CACHE_BUCKETS);
        if (pp != NULL) {
            struct cache_hdr *victim = cache_remove_at(pp);
            if (victim != NULL) {
                free(CACHE_ENTRY(victim, struct nfs_attr_cache_entry));
                ctx->cache.attr_count--;
            }
        }
    }

    /* Create new entry */
    e = malloc(sizeof(*e));
    if (e == NULL)
        return;

    cache_hdr_init(&e->hdr);
    e->fh.len = fh->len;
    memcpy(e->fh.data, fh->data, fh->len);
    e->attr = *attr;

    cache_add_to_bucket(&ctx->cache.attrs[bucket], &e->hdr);
    ctx->cache.attr_count++;
}

/* Clear entire attribute cache */
void
nfs_attr_cache_clear(struct nfsctx *ctx)
{
    size_t i;
    struct cache_hdr *h, *next;

    for (i = 0; i < NFS_ATTR_CACHE_BUCKETS; i++) {
        h = ctx->cache.attrs[i];
        while (h != NULL) {
            next = h->hash_next;
            free(CACHE_ENTRY(h, struct nfs_attr_cache_entry));
            h = next;
        }
        ctx->cache.attrs[i] = NULL;
    }
    ctx->cache.attr_count = 0;
    ctx->cache.attr_hits = 0;
    ctx->cache.attr_misses = 0;
}

/* Get attribute cache statistics */
void
nfs_attr_cache_stats(struct nfsctx *ctx, size_t *count,
    uint64_t *hits, uint64_t *misses)
{
    if (count)
        *count = ctx->cache.attr_count;
    if (hits)
        *hits = ctx->cache.attr_hits;
    if (misses)
        *misses = ctx->cache.attr_misses;
}

/*
 * ============================================================================
 * FH type cache - ring buffer of recent lookup results for completion filtering
 * ============================================================================
 */

/*
 * Add a file handle and its type to the lookup cache.
 * Used by completion to filter FH suggestions by expected type.
 */
void
nfs_fh_type_cache_add(struct nfsctx *ctx, const uint8_t *fh, size_t fhlen,
    uint32_t ftype)
{
    struct nfs_lookup_cache_entry *entry;
    char *hex;
    size_t i;

    if (ctx == NULL || fh == NULL || fhlen == 0 || fhlen > NFS_FHSIZE_MAX)
        return;

    /* Convert FH to hex string (overflow check: fhlen <= NFS_FHSIZE_MAX so fhlen*2+1 is safe) */
    if (fhlen > (SIZE_MAX - 1) / 2)
        return;
    hex = malloc(fhlen * 2 + 1);
    if (hex == NULL)
        return;

    bytes_to_hex(fh, fhlen, hex);

    /* Check if this FH is already in the cache */
    for (i = 0; i < NFS_LOOKUP_CACHE_SIZE; i++) {
        if (ctx->cache.lookup_cache[i].fh_hex != NULL &&
            strcmp(ctx->cache.lookup_cache[i].fh_hex, hex) == 0) {
            /* Update type and reuse slot */
            ctx->cache.lookup_cache[i].ftype = ftype;
            free(hex);
            return;
        }
    }

    /* Add to next slot in ring buffer */
    entry = &ctx->cache.lookup_cache[ctx->cache.lookup_cache_next];

    /* Free old entry if present */
    free(entry->fh_hex);

    entry->fh_hex = hex;
    entry->ftype = ftype;

    /* Advance ring buffer pointer */
    ctx->cache.lookup_cache_next =
        (ctx->cache.lookup_cache_next + 1) % NFS_LOOKUP_CACHE_SIZE;
}

/*
 * Clear the FH type cache (e.g., on disconnect).
 */
void
nfs_fh_type_cache_clear(struct nfsctx *ctx)
{
    size_t i;

    if (ctx == NULL)
        return;

    for (i = 0; i < NFS_LOOKUP_CACHE_SIZE; i++) {
        free(ctx->cache.lookup_cache[i].fh_hex);
        ctx->cache.lookup_cache[i].fh_hex = NULL;
        ctx->cache.lookup_cache[i].ftype = 0;
    }
    ctx->cache.lookup_cache_next = 0;
}
