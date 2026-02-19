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
 * cache_util.h - Generic cache utilities
 *
 * Provides shared infrastructure for hash-based caches:
 * - Intrusive cache entry header for hash chains and LRU tracking
 * - Hash functions for strings and byte arrays
 * - Generic LRU eviction helpers
 *
 * Usage: Embed struct cache_hdr as the FIRST field in cache entry structs,
 * then use the helper macros to convert between header and entry pointers.
 */

#ifndef CACHE_UTIL_H
#define CACHE_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/*
 * Intrusive cache entry header.
 * Embed as FIRST member in cache entry structs.
 */
struct cache_hdr {
    struct cache_hdr *hash_next; /* Hash chain pointer */
    time_t add_time;             /* When entry was added (for LRU) */
};

/*
 * Convert between cache_hdr pointer and containing struct pointer.
 * Requires cache_hdr to be the first member of the containing struct.
 */
#define CACHE_ENTRY(hdr, type) ((type *)(hdr))
#define CACHE_HDR(entry)       (&(entry)->hdr)

/*
 * Hash function for byte arrays (djb2 algorithm by Dan Bernstein).
 * Uses magic constant 5381 and multiplier 33 (implemented as shift+add).
 * Returns hash modulo bucket_count.
 */
static inline unsigned int
cache_hash_bytes(const uint8_t *data, size_t len, size_t bucket_count)
{
    unsigned int hash = 5381; /* djb2 magic constant */
    size_t i;

    for (i = 0; i < len; i++)
        hash = ((hash << 5) + hash) + data[i];

    return hash % bucket_count;
}

/*
 * Hash function for null-terminated strings (djb2 algorithm).
 * Returns hash modulo bucket_count.
 */
static inline unsigned int
cache_hash_string(const char *str, size_t bucket_count)
{
    unsigned int hash = 5381;
    int c;

    while ((c = (unsigned char)*str++) != 0)
        hash = ((hash << 5) + hash) + c;

    return hash % bucket_count;
}

/*
 * Find the oldest entry across all hash buckets (LRU eviction).
 * Returns pointer to the cache_hdr** that points to the oldest entry,
 * allowing O(1) removal. Returns NULL if cache is empty.
 *
 * buckets: array of cache_hdr* bucket heads
 * bucket_count: number of buckets
 */
static inline struct cache_hdr **
cache_find_oldest(struct cache_hdr **buckets, size_t bucket_count)
{
    struct cache_hdr **oldest_pp = NULL;
    time_t oldest_time = 0;
    size_t i;

    for (i = 0; i < bucket_count; i++) {
        struct cache_hdr **pp = &buckets[i];
        while (*pp != NULL) {
            if (oldest_pp == NULL || (*pp)->add_time < oldest_time) {
                oldest_pp = pp;
                oldest_time = (*pp)->add_time;
            }
            pp = &(*pp)->hash_next;
        }
    }

    return oldest_pp;
}

/*
 * Remove an entry from hash chain given pointer-to-pointer.
 * pp: pointer to the pointer that points to entry (from cache_find_oldest)
 * Returns the removed cache_hdr* (caller must free the containing struct).
 */
static inline struct cache_hdr *
cache_remove_at(struct cache_hdr **pp)
{
    struct cache_hdr *victim;

    if (pp == NULL || *pp == NULL)
        return NULL;

    victim = *pp;
    *pp = victim->hash_next;
    victim->hash_next = NULL;

    return victim;
}

/*
 * Initialize a cache header for a new entry.
 */
static inline void
cache_hdr_init(struct cache_hdr *hdr)
{
    hdr->hash_next = NULL;
    hdr->add_time = time(NULL);
}

/*
 * Add entry to front of hash bucket.
 */
static inline void
cache_add_to_bucket(struct cache_hdr **bucket, struct cache_hdr *entry)
{
    entry->hash_next = *bucket;
    *bucket = entry;
}

#endif /* CACHE_UTIL_H */
