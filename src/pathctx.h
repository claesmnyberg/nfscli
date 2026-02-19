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
 * pathctx.h - Path-based NFS navigation
 *
 * Lightweight path resolution layer over NFS. Resolves path strings
 * directly to NFS file handles using nfs_cache for caching.
 * No vnode abstraction - works directly with NFS primitives.
 */

#ifndef PATHCTX_H
#define PATHCTX_H

#include <limits.h>

#include "nfs_types.h"

struct nfsctx;

/*
 * Mount entry - tracks an NFS export
 */
struct path_mount {
    char *export_path;         /* Export path (e.g., "/home") */
    size_t export_path_len;    /* Cached strlen(export_path) for O(1) access */
    struct nfs_fh root_fh;     /* Root FH from MOUNT */
    struct nfs_fh ceiling_fh;  /* Highest reachable (escape limit) */
    int escaped;               /* Escaped above export root */
    int depth;                 /* Path components in export_path */
    struct path_mount *parent; /* Parent mount (longest prefix), for hierarchy */
    struct path_mount *next;
};

/*
 * Path context - navigation state for a session
 */
struct pathctx {
    struct nfsctx *nfs;

    /* Mount table */
    struct path_mount *mounts;
    int mount_count;

    /* Current position */
    struct nfs_fh cwd_fh;
    struct nfs_fh home_fh;
    struct nfs_fh prev_fh;
    char cwd_path[PATH_MAX];

    /* Active mount (where cwd is) */
    struct path_mount *cwd_mount;

    /*
     * Global ceiling - true filesystem root FH.
     * Set when any mount successfully escapes to root.
     * Used as starting point for ALL absolute path lookups.
     */
    struct nfs_fh ceiling_fh;
    int has_ceiling; /* ceiling_fh is valid (reached true root) */
};

/*
 * Path resolution result
 */
struct path_result {
    struct nfs_fh fh;            /* Target FH */
    struct nfs_attr attr;        /* Target attributes */
    int has_attr;                /* attr is valid */

    struct nfs_fh parent_fh;     /* Parent directory FH */
    char basename[NAME_MAX + 1]; /* Final path component */
    int has_parent;              /* parent_fh/basename valid */
};

/*
 * Resolution flags
 */
#define PATH_FOLLOW      0x01 /* Follow final symlink */
#define PATH_WANT_PARENT 0x02 /* Populate parent_fh + basename */

/*
 * Initialization and cleanup
 */

/* Create path context with initial mount */
int pathctx_init(struct pathctx *ctx, struct nfsctx *nfs,
    const char *export_path, const struct nfs_fh *root_fh);

/* Destroy path context */
void pathctx_destroy(struct pathctx *ctx);

/*
 * Path resolution - the core operations
 */

/* Resolve path to FH (and optionally parent) */
int path_resolve(struct pathctx *ctx, const char *path, int flags,
    struct path_result *out);

/*
 * Navigation
 */

/* Change current directory */
int pathctx_chdir(struct pathctx *ctx, const char *path);

/* Change to previous directory (cd -) */
int pathctx_chdir_prev(struct pathctx *ctx);

/* Change to home directory */
int pathctx_chdir_home(struct pathctx *ctx);

/* Get current path string */
const char *pathctx_pwd(struct pathctx *ctx);

/* Get current directory FH */
const struct nfs_fh *pathctx_cwd_fh(struct pathctx *ctx);

/* Set current position as home */
void pathctx_set_home(struct pathctx *ctx);

/*
 * Mount operations
 */

/* Mount another export */
int pathctx_mount(struct pathctx *ctx, const char *export_path,
    const struct nfs_fh *root_fh);

/* Unmount an export */
int pathctx_unmount(struct pathctx *ctx, const char *export_path);

/* Find mount for a path */
struct path_mount *pathctx_find_mount(struct pathctx *ctx, const char *path);

/* Probe for root escape (cd .. above export root) */
int pathctx_probe_escape(struct pathctx *ctx, struct path_mount *mnt);

/*
 * Tab completion
 */

/* Complete path prefix, returns NULL-terminated array */
char **pathctx_complete(struct pathctx *ctx, const char *prefix,
    int dirs_only, int files_only);

/* Free completion results */
void pathctx_complete_free(char **list);

/*
 * Path utilities (stateless)
 */

/* Normalize path (resolve ., .., //) */
int path_normalize(const char *in, char *out, size_t len);

/* Join directory and name */
int path_join(const char *dir, const char *name, char *out, size_t len);

/* Get basename of path */
const char *path_basename(const char *path);

/* Get dirname of path (writes to out buffer) */
int path_dirname(const char *path, char *out, size_t len);

/* Check if path is absolute */
int path_is_absolute(const char *path);

/* Count path components */
int path_count_components(const char *path);

/* Get length of path prefix with n components */
size_t path_prefix_len(const char *path, int n);

/*
 * Walk a path from a starting FH using LOOKUP calls.
 * Does not require a pathctx - just does raw LOOKUPs.
 * Returns 0 on success with result in out_fh, -1 on error.
 */
int path_walk(struct nfsctx *nfs, const struct nfs_fh *start_fh,
    const char *path, struct nfs_fh *out_fh);

/* Maximum symlink hops during resolution */
#define PATH_MAX_SYMLINK_HOPS 40

#endif /* PATHCTX_H */
