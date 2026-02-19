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
 * find.h - Find command and visited-set for loop detection
 */

#ifndef FIND_H
#define FIND_H

#include <stdint.h>
#include <stdlib.h>

#include "constants.h"

/*
 * Visited set for tracking fileids during directory traversal.
 * Prevents infinite loops from symlink cycles.
 */
struct visited_set {
    uint64_t *fileids;
    size_t count;
    size_t cap;
};

/* Initialize a visited set */
static inline void
visited_init(struct visited_set *vs)
{
    vs->fileids = NULL;
    vs->count = 0;
    vs->cap = 0;
}

/* Free a visited set */
static inline void
visited_free(struct visited_set *vs)
{
    free(vs->fileids);
    vs->fileids = NULL;
    vs->count = 0;
    vs->cap = 0;
}

/* Check if fileid is in set; if not, add it. Returns 1 if already present. */
static inline int
visited_check_add(struct visited_set *vs, uint64_t fileid)
{
    size_t i;
    size_t newcap;
    uint64_t *newbuf;

    /* Check if already visited */
    for (i = 0; i < vs->count; i++) {
        if (vs->fileids[i] == fileid)
            return 1; /* Already visited */
    }

    /* Add to set */
    if (vs->count >= vs->cap) {
        newcap = vs->cap == 0 ? 32 : vs->cap * 2;
        if (newcap > SIZE_MAX / sizeof(uint64_t))
            return -1; /* Overflow */
        newbuf = realloc(vs->fileids, newcap * sizeof(uint64_t));
        if (newbuf == NULL)
            return -1; /* Error */
        vs->fileids = newbuf;
        vs->cap = newcap;
    }
    vs->fileids[vs->count++] = fileid;
    return 0; /* Newly added */
}

/* Remove most recently added fileid (for backtracking) */
static inline void
visited_pop(struct visited_set *vs)
{
    if (vs->count > 0)
        vs->count--;
}

/*
 * Resolve a directory entry to a path_result.
 * Uses cached readdirplus data when available, falls back to
 * path_resolve for symlinks or missing attributes.
 *
 * Returns 0 on success with res populated, -1 if entry should be skipped.
 */
struct pathctx;
struct nfs_dirent;
struct path_result;

int dirent_resolve(struct pathctx *pctx, const struct nfs_dirent *ent,
    const char *fullpath, struct path_result *res);

#endif /* FIND_H */
