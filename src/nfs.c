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
 * nfs.c - Unified NFS dispatcher
 *
 * Dispatches NFS operations through ctx->proto.ops, which is set on first use
 * to point to either nfsv2_unified_ops or nfsv3_unified_ops.
 */

#include "nfs.h"
#include "nfs_cache.h"
#include "nfs_ops.h"
#include "nfscli.h"
#include "portmap.h"

/* Forward declaration */
void init_nfs_version(struct nfsctx *ctx);

/* External declarations for version-specific NULL procedures */
extern int nfsv2_null(struct nfsctx *ctx);
extern int nfsv3_null(struct nfsctx *ctx);

/* External declaration for NFSv3 COMMIT procedure */
extern int nfsv3_commit(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint64_t offset, uint32_t count, struct nfs_commit_res *out);

/* External declaration for NFSv3 write with stability mode */
extern int nfsv3_write_stable(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint64_t offset, const uint8_t *data, uint32_t count,
    int stability, struct nfs_write_res *out);

static inline int
nfs_ensure_ops(struct nfsctx *ctx)
{
    if (ctx->proto.ops == NULL)
        init_nfs_version(ctx);

    /* If ops is still NULL, no NFS service is available */
    if (ctx->proto.ops == NULL) {
        if (!ctx->quiet)
            fprintf(stderr, "** Error: NFS service unavailable\n");
        errno = ENOTSUP;
        return -1;
    }
    return 0;
}

/*
 * Validate file handle length for the current NFS version.
 * NFSv2: FH must be exactly 32 bytes
 * NFSv3: FH must be 1-64 bytes
 * Returns 0 on success, -1 on error with errno and error message.
 * Note: Caller must call nfs_ensure_ops() first.
 */
static int
nfs_validate_fh(struct nfsctx *ctx, const struct nfs_fh *fh)
{
    if (fh == NULL || fh->len == 0) {
        if (!ctx->quiet)
            fprintf(stderr, "** Error: Invalid file handle (empty)\n");
        errno = EINVAL;
        return -1;
    }

    if (ctx->proto.nfs_version == 2) {
        if (fh->len != NFSV2_FHSIZE) {
            if (!ctx->quiet)
                fprintf(stderr, "** Error: Invalid file handle length %u "
                                "(NFSv2 requires exactly %d bytes)\n",
                    fh->len, NFSV2_FHSIZE);
            errno = EINVAL;
            return -1;
        }
    } else {
        /* NFSv3 */
        if (fh->len > NFSV3_FHSIZE) {
            if (!ctx->quiet)
                fprintf(stderr, "** Error: Invalid file handle length %u "
                                "(NFSv3 max is %d bytes)\n",
                    fh->len, NFSV3_FHSIZE);
            errno = EINVAL;
            return -1;
        }
    }

    return 0;
}

/*
 * Get attributes for a file.
 *
 * RFC 1094 (v2) Section 2.3.5 - NFSPROC_GETATTR (procedure 1)
 * RFC 1813 (v3) Section 3.3.1 - NFSPROC3_GETATTR (procedure 1)
 *
 * Retrieves file attributes without following symbolic links.
 * Returns 0 on success, -1 on error with errno set.
 * Attributes returned are not guaranteed to be consistent with each other
 * if the file is being modified concurrently.
 *
 * Common errno values: ESTALE (stale handle), EIO (server error).
 */
int
nfs_getattr(struct nfsctx *ctx, const struct nfs_fh *fh, struct nfs_attr *out)
{
    const struct nfs_attr *cached;
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, fh) < 0)
        return -1;

    /* Check attribute cache first */
    if (ctx->cache.enabled) {
        cached = nfs_attr_cache_lookup(ctx, fh);
        if (cached != NULL) {
            ctx->cache.attr_hits++;
            *out = *cached;
            return 0;
        }
        ctx->cache.attr_misses++;
    }

    /* Cache miss - call protocol */
    ret = ctx->proto.ops->getattr(ctx, fh, out);

    /* Update caches on success */
    if (ret == 0) {
        if (ctx->cache.enabled)
            nfs_attr_cache_add(ctx, fh, out);
        nfs_cache_update_attr_by_fh(ctx, fh, out);
    }

    return ret;
}

/*
 * Set attributes (mode) for a file.
 *
 * RFC 1094 (v2) Section 2.3.6 - NFSPROC_SETATTR (procedure 2)
 * RFC 1813 (v3) Section 3.3.2 - NFSPROC3_SETATTR (procedure 2)
 *
 * The SETATTR operation is NOT guaranteed to be atomic. If the server
 * crashes during the operation, some attributes may be set while others
 * are not (RFC 1813). NFSv3 supports a guard mechanism (sattrguard3)
 * to conditionally set attributes only if ctime matches, but this
 * implementation does not use the guard.
 *
 * Setting size to 0 truncates the file. Setting mode affects permission
 * bits only (not file type).
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: EROFS (read-only), EACCES (permission denied).
 */
int
nfs_setattr(struct nfsctx *ctx, const struct nfs_fh *fh,
    const struct nfs_sattr *sattr)
{
    struct nfs_attr new_attr;
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, fh) < 0)
        return -1;

    memset(&new_attr, 0, sizeof(new_attr));
    ret = ctx->proto.ops->setattr(ctx, fh, sattr, &new_attr);

    /* Update caches with new attributes on success */
    if (ret == 0 && new_attr.type != 0) {
        nfs_cache_update_attr_by_fh(ctx, fh, &new_attr);
        if (ctx->cache.enabled)
            nfs_attr_cache_add(ctx, fh, &new_attr);
    }

    return ret;
}

/*
 * Lookup a name in a directory.
 *
 * RFC 1094 (v2) Section 2.3.7 - NFSPROC_LOOKUP (procedure 4)
 * RFC 1813 (v3) Section 3.3.3 - NFSPROC3_LOOKUP (procedure 3)
 *
 * Searches a directory for a name and returns the file handle and
 * attributes. The name must not contain '/'. Looking up "." returns
 * the directory's own handle. Looking up ".." returns the parent
 * directory's handle (or the same handle at filesystem root).
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: ENOENT (not found), ENOTDIR (not a directory),
 * EACCES (permission denied), ESTALE (stale handle).
 */
int
nfs_lookup(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, struct nfs_lookup_res *out)
{
    int ret;
    int cache_ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, dirfh) < 0)
        return -1;

    /* Check cache first */
    cache_ret = nfs_cache_lookup(ctx, dirfh, name, out);
    if (cache_ret == 0) {
        /* Positive cache hit */
        /* Add to FH type cache for completion filtering */
        if (out->has_obj_attr) {
            nfs_fh_type_cache_add(ctx, out->fh.data, out->fh.len,
                out->obj_attr.type);
            /* Populate attribute cache */
            if (ctx->cache.enabled)
                nfs_attr_cache_add(ctx, &out->fh, &out->obj_attr);
        }
        return 0;
    } else if (cache_ret == -2) {
        /* Negative cache hit - entry doesn't exist */
        errno = ENOENT;
        return -1;
    }

    /* Cache miss - call protocol */
    ret = ctx->proto.ops->lookup(ctx, dirfh, name, out);

    /* Defense-in-depth: verify FH bounds from protocol response */
    if (ret == 0 && out->fh.len > NFS_FHSIZE_MAX) {
        errno = EPROTO;
        return -1;
    }

    if (ret == 0) {
        /* Populate caches on success */
        nfs_cache_add(ctx, dirfh, name, out);
        /* Add to FH type cache for completion filtering */
        if (out->has_obj_attr) {
            nfs_fh_type_cache_add(ctx, out->fh.data, out->fh.len,
                out->obj_attr.type);
            /* Populate attribute cache */
            if (ctx->cache.enabled)
                nfs_attr_cache_add(ctx, &out->fh, &out->obj_attr);
        }
        /* Also cache directory attributes if returned */
        if (out->has_dir_attr && ctx->cache.enabled)
            nfs_attr_cache_add(ctx, dirfh, &out->dir_attr);
    } else if (errno == ENOENT) {
        /* Cache negative result - entry doesn't exist */
        nfs_cache_add_negative(ctx, dirfh, name);
    } else if (errno == ESTALE || errno == EBADF) {
        /* Invalidate directory cache on stale/bad handle */
        nfs_cache_invalidate(ctx, dirfh);
    }

    return ret;
}

/*
 * Read symbolic link target.
 *
 * RFC 1094 (v2) Section 2.3.9 - NFSPROC_READLINK (procedure 5)
 * RFC 1813 (v3) Section 3.3.5 - NFSPROC3_READLINK (procedure 5)
 *
 * Returns the contents of a symbolic link (the target path).
 * The target path is NOT validated - it may point to a non-existent file.
 * Maximum path length is NFS_MAXPATHLEN (1024 bytes).
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: EINVAL (not a symlink), ESTALE (stale handle).
 */
int
nfs_readlink(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_readlink_res *out)
{
    const char *cached;
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, fh) < 0)
        return -1;

    /* Check cache first (if caching enabled) */
    if (ctx->cache.enabled) {
        cached = nfs_symlink_cache_lookup(ctx, fh);
        if (cached != NULL) {
            ctx->cache.symlink_hits++;
            strncpy(out->target, cached, sizeof(out->target) - 1);
            out->target[sizeof(out->target) - 1] = '\0';
            return 0;
        }
        ctx->cache.symlink_misses++;
    }

    ret = ctx->proto.ops->readlink(ctx, fh, out);
    if (ret == 0 && ctx->cache.enabled) {
        /* Cache the result */
        nfs_symlink_cache_add(ctx, fh, out->target);
    }
    return ret;
}

/*
 * Read from a file.
 *
 * RFC 1094 (v2) Section 2.3.10 - NFSPROC_READ (procedure 6)
 * RFC 1813 (v3) Section 3.3.6 - NFSPROC3_READ (procedure 6)
 *
 * Reads data from a file starting at offset. NFSv2 uses 32-bit offsets
 * (max 4GB), NFSv3 uses 64-bit offsets. The actual bytes read may be
 * less than count if EOF is reached or server limits apply.
 * NFSv3 returns post-operation file attributes and EOF indicator.
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: EACCES (permission denied), EISDIR (is directory),
 * ESTALE (stale handle).
 */
int
nfs_read(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint64_t offset, uint32_t count, struct nfs_read_res *out)
{
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, fh) < 0)
        return -1;

    ret = ctx->proto.ops->read(ctx, fh, offset, count, out);

    /* Update caches with returned attributes (atime may have changed) */
    if (ret == 0 && out != NULL && out->has_attr) {
        nfs_cache_update_attr_by_fh(ctx, fh, &out->attr);
        if (ctx->cache.enabled)
            nfs_attr_cache_add(ctx, fh, &out->attr);
    }

    return ret;
}

/*
 * Write to a file.
 *
 * RFC 1094 (v2) Section 2.3.11 - NFSPROC_WRITE (procedure 8)
 * RFC 1813 (v3) Section 3.3.7 - NFSPROC3_WRITE (procedure 7)
 *
 * Writes data to a file starting at offset. This implementation uses
 * FILE_SYNC stability (synchronous write to stable storage).
 *
 * NFSv3 stability levels (stable_how):
 *   UNSTABLE (0)  - Server may buffer; use COMMIT to ensure durability
 *   DATA_SYNC (1) - Data on stable storage, metadata may be buffered
 *   FILE_SYNC (2) - Data and metadata on stable storage before returning
 *
 * NFSv3 returns a write verifier to detect server reboots between
 * UNSTABLE writes and COMMIT. This implementation always uses FILE_SYNC
 * so the verifier is not needed.
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: ENOSPC (disk full), EDQUOT (quota exceeded),
 * EROFS (read-only), EACCES (permission denied).
 */
int
nfs_write(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint64_t offset, const uint8_t *data, uint32_t count,
    struct nfs_write_res *out)
{
    struct nfs_write_res local_res;
    struct nfs_write_res *res;
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, fh) < 0)
        return -1;

    /* Use local storage if caller doesn't want result, so we can still cache */
    res = (out != NULL) ? out : &local_res;
    memset(res, 0, sizeof(*res));

    ret = ctx->proto.ops->write(ctx, fh, offset, data, count, res);

    /* Update caches with returned attributes (size/mtime changed) */
    if (ret == 0 && res->has_attr) {
        nfs_cache_update_attr_by_fh(ctx, fh, &res->attr);
        if (ctx->cache.enabled)
            nfs_attr_cache_add(ctx, fh, &res->attr);
    }

    return ret;
}

/*
 * Create a file.
 *
 * RFC 1094 (v2) Section 2.3.12 - NFSPROC_CREATE (procedure 9)
 * RFC 1813 (v3) Section 3.3.8 - NFSPROC3_CREATE (procedure 8)
 *
 * Creates a regular file in a directory. NFSv3 supports three modes:
 *   UNCHECKED (0) - Create or truncate if exists
 *   GUARDED (1)   - Fail if file exists (default)
 *   EXCLUSIVE (2) - Atomic create using verifier; for lock files
 *
 * NFSv2 ignores create_mode (behavior is server-dependent).
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: EEXIST (exists, GUARDED mode), ENOTDIR,
 * EACCES (permission denied), ENAMETOOLONG, ENOSPC, EROFS.
 */
int
nfs_create(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, uint32_t mode, int create_mode,
    struct nfs_create_res *out)
{
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, dirfh) < 0)
        return -1;

    ret = ctx->proto.ops->create(ctx, dirfh, name, mode, create_mode, out);

    /* Defense-in-depth: verify FH bounds from protocol response */
    if (ret == 0 && out->has_fh && out->fh.len > NFS_FHSIZE_MAX) {
        errno = EPROTO;
        return -1;
    }

    /* Update caches with new file instead of just invalidating */
    if (ret == 0) {
        if (out->has_fh || out->has_attr) {
            /* Add new entry to directory cache */
            struct nfs_lookup_res lu;
            memset(&lu, 0, sizeof(lu));
            if (out->has_fh) {
                lu.fh = out->fh;
                lu.has_obj_attr = out->has_attr;
                if (out->has_attr)
                    lu.obj_attr = out->attr;
            }
            nfs_cache_add(ctx, dirfh, name, &lu);
            /* Add to attribute cache */
            if (out->has_fh && out->has_attr && ctx->cache.enabled)
                nfs_attr_cache_add(ctx, &out->fh, &out->attr);
        } else {
            /* No info returned - invalidate to force refresh */
            nfs_cache_invalidate(ctx, dirfh);
        }
    }

    return ret;
}

/*
 * Remove a file.
 *
 * RFC 1094 (v2) Section 2.3.13 - NFSPROC_REMOVE (procedure 10)
 * RFC 1813 (v3) Section 3.3.12 - NFSPROC3_REMOVE (procedure 12)
 *
 * Removes a non-directory entry from a directory. The file's data is not
 * freed until no processes have it open (link count reaches 0 and no
 * references remain). The operation is atomic with respect to other ops.
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: ENOENT (not found), EACCES (permission denied),
 * EISDIR (is directory - use rmdir), EROFS (read-only).
 */
int
nfs_remove(struct nfsctx *ctx, const struct nfs_fh *dirfh, const char *name)
{
    struct nfs_wcc_data wcc;
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, dirfh) < 0)
        return -1;

    memset(&wcc, 0, sizeof(wcc));
    ret = ctx->proto.ops->remove(ctx, dirfh, name, &wcc);

    /* Invalidate parent directory cache on success, update dir attrs if available */
    if (ret == 0) {
        nfs_cache_invalidate(ctx, dirfh);
        if (wcc.has_dir_attr)
            nfs_cache_update_attr_by_fh(ctx, dirfh, &wcc.dir_attr);
    }

    return ret;
}

/*
 * Rename a file or directory.
 *
 * RFC 1094 (v2) Section 2.3.14 - NFSPROC_RENAME (procedure 11)
 * RFC 1813 (v3) Section 3.3.14 - NFSPROC3_RENAME (procedure 14)
 *
 * Atomically renames srcname in srcfh directory to dstname in dstfh directory.
 * If dstname already exists, it is removed first (atomically replaced).
 * Renaming "." or ".." is not allowed. If dstname exists and is a directory,
 * it must be empty for replacement. This operation is atomic - dstname is
 * never left in an intermediate state.
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: ENOENT (source not found), EACCES (permission denied),
 * EXDEV (cross-filesystem), ENOTEMPTY (destination dir not empty).
 */
int
nfs_rename(struct nfsctx *ctx, const struct nfs_fh *srcfh,
    const char *srcname, const struct nfs_fh *dstfh, const char *dstname)
{
    struct nfs_rename_res res;
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, srcfh) < 0 || nfs_validate_fh(ctx, dstfh) < 0)
        return -1;

    memset(&res, 0, sizeof(res));
    ret = ctx->proto.ops->rename(ctx, srcfh, srcname, dstfh, dstname, &res);

    /* Invalidate both directory caches on success, update attrs if available */
    if (ret == 0) {
        nfs_cache_invalidate(ctx, srcfh);
        nfs_cache_invalidate(ctx, dstfh);
        if (res.has_src_dir_attr)
            nfs_cache_update_attr_by_fh(ctx, srcfh, &res.src_dir_attr);
        if (res.has_dst_dir_attr)
            nfs_cache_update_attr_by_fh(ctx, dstfh, &res.dst_dir_attr);
    }

    return ret;
}

/*
 * Create a hard link.
 *
 * RFC 1094 (v2) Section 2.3.15 - NFSPROC_LINK (procedure 12)
 * RFC 1813 (v3) Section 3.3.11 - NFSPROC3_LINK (procedure 11)
 *
 * Creates a new directory entry (name) in dirfh that references the
 * same file as fh. Increases the link count of the file by one.
 * Both fh and dirfh must be on the same filesystem. Hard links to
 * directories are not permitted. The file handle fh remains valid
 * after the operation.
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: EXDEV (cross-filesystem), EEXIST (name exists),
 * EACCES (permission denied), EMLINK (too many links), EISDIR (is dir).
 */
int
nfs_link(struct nfsctx *ctx, const struct nfs_fh *fh,
    const struct nfs_fh *dirfh, const char *name)
{
    struct nfs_link_res res;
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, fh) < 0 || nfs_validate_fh(ctx, dirfh) < 0)
        return -1;

    memset(&res, 0, sizeof(res));
    ret = ctx->proto.ops->link(ctx, fh, dirfh, name, &res);

    /* Update cache with new link instead of just invalidating */
    if (ret == 0) {
        /* Add new link to cache (same FH as source file) */
        struct nfs_lookup_res lu;
        memset(&lu, 0, sizeof(lu));
        lu.fh = *fh;
        lu.has_obj_attr = res.has_file_attr;
        if (res.has_file_attr)
            lu.obj_attr = res.file_attr;
        nfs_cache_add(ctx, dirfh, name, &lu);

        /* Update file attrs (nlink changed) */
        if (res.has_file_attr)
            nfs_cache_update_attr_by_fh(ctx, fh, &res.file_attr);
        /* Update directory attrs */
        if (res.has_dir_attr)
            nfs_cache_update_attr_by_fh(ctx, dirfh, &res.dir_attr);
    }

    return ret;
}

/*
 * Create a symbolic link.
 *
 * RFC 1094 (v2) Section 2.3.16 - NFSPROC_SYMLINK (procedure 13)
 * RFC 1813 (v3) Section 3.3.10 - NFSPROC3_SYMLINK (procedure 10)
 *
 * Creates a symbolic link with the given name in dirfh, pointing to target.
 * The target path is stored as-is and not validated (may be absolute or
 * relative, and may point to a non-existent file). Mode bits on symlinks
 * are typically ignored by Unix filesystems (symlinks are always mode 0777).
 * NFSv2 does not return the new symlink's handle (must use LOOKUP).
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: EEXIST (name exists), EACCES (permission denied),
 * ENAMETOOLONG, ENOSPC (no space), EROFS (read-only).
 */
int
nfs_symlink(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, const char *target, uint32_t mode)
{
    struct nfs_symlink_res res;
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, dirfh) < 0)
        return -1;

    memset(&res, 0, sizeof(res));
    ret = ctx->proto.ops->symlink(ctx, dirfh, name, target, mode, &res);

    /* Update cache with new symlink instead of just invalidating */
    if (ret == 0) {
        if (res.has_fh || res.has_attr) {
            /* Add new entry to cache */
            struct nfs_lookup_res lu;
            memset(&lu, 0, sizeof(lu));
            if (res.has_fh) {
                lu.fh = res.fh;
                lu.has_obj_attr = res.has_attr;
                if (res.has_attr)
                    lu.obj_attr = res.attr;
            }
            nfs_cache_add(ctx, dirfh, name, &lu);
        } else {
            /* No info returned - invalidate to force refresh */
            nfs_cache_invalidate(ctx, dirfh);
        }
        if (res.has_dir_attr)
            nfs_cache_update_attr_by_fh(ctx, dirfh, &res.dir_attr);
    }

    return ret;
}

/*
 * Create a directory.
 *
 * RFC 1094 (v2) Section 2.3.17 - NFSPROC_MKDIR (procedure 14)
 * RFC 1813 (v3) Section 3.3.9 - NFSPROC3_MKDIR (procedure 9)
 *
 * Creates a new directory with the given name in dirfh. The new directory
 * is created with entries "." and ".." automatically. The effective mode
 * is (mode & ~umask) where umask is server-side.
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: EEXIST (name exists), EACCES (permission denied),
 * ENOSPC (no space), EROFS (read-only), ENAMETOOLONG, EDQUOT (quota).
 */
int
nfs_mkdir(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, uint32_t mode, struct nfs_create_res *out)
{
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, dirfh) < 0)
        return -1;

    ret = ctx->proto.ops->mkdir(ctx, dirfh, name, mode, out);

    /* Defense-in-depth: verify FH bounds from protocol response */
    if (ret == 0 && out->has_fh && out->fh.len > NFS_FHSIZE_MAX) {
        errno = EPROTO;
        return -1;
    }

    /* Update caches with new directory instead of just invalidating */
    if (ret == 0) {
        if (out->has_fh || out->has_attr) {
            struct nfs_lookup_res lu;
            memset(&lu, 0, sizeof(lu));
            if (out->has_fh) {
                lu.fh = out->fh;
                lu.has_obj_attr = out->has_attr;
                if (out->has_attr)
                    lu.obj_attr = out->attr;
            }
            nfs_cache_add(ctx, dirfh, name, &lu);
            /* Add to attribute cache */
            if (out->has_fh && out->has_attr && ctx->cache.enabled)
                nfs_attr_cache_add(ctx, &out->fh, &out->attr);
        } else {
            nfs_cache_invalidate(ctx, dirfh);
        }
    }

    return ret;
}

/*
 * Remove a directory.
 *
 * RFC 1094 (v2) Section 2.3.18 - NFSPROC_RMDIR (procedure 15)
 * RFC 1813 (v3) Section 3.3.13 - NFSPROC3_RMDIR (procedure 13)
 *
 * Removes an empty directory from the parent directory. The directory
 * must contain only "." and ".." entries. Removing "." or ".." is not
 * permitted. After removal, cached file handles for this dir become stale.
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: ENOENT (not found), ENOTDIR (not a dir - use remove),
 * ENOTEMPTY (not empty), EACCES (permission denied), EROFS (read-only).
 */
int
nfs_rmdir(struct nfsctx *ctx, const struct nfs_fh *dirfh, const char *name)
{
    struct nfs_wcc_data wcc;
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, dirfh) < 0)
        return -1;

    memset(&wcc, 0, sizeof(wcc));
    ret = ctx->proto.ops->rmdir(ctx, dirfh, name, &wcc);

    /* Invalidate parent directory cache on success, update dir attrs if available */
    if (ret == 0) {
        nfs_cache_invalidate(ctx, dirfh);
        if (wcc.has_dir_attr)
            nfs_cache_update_attr_by_fh(ctx, dirfh, &wcc.dir_attr);
    }

    return ret;
}

/*
 * Read directory entries.
 *
 * RFC 1094 (v2) Section 2.3.19 - NFSPROC_READDIR (procedure 16)
 * RFC 1813 (v3) Section 3.3.16 - NFSPROC3_READDIR (procedure 16)
 *
 * Returns a list of directory entries (names and file IDs). Entries "."
 * and ".." are always included. Entry order is filesystem-dependent.
 * This implementation collects all entries before returning.
 *
 * Note: READDIR only returns names and file IDs, not attributes or file
 * handles. Use READDIRPLUS (NFSv3) or LOOKUP to get full information.
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: ENOTDIR (not a dir), EACCES (permission denied),
 * ESTALE (stale handle).
 */
int
nfs_readdir(struct nfsctx *ctx, const struct nfs_fh *fh, struct nfs_dir *out)
{
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, fh) < 0)
        return -1;

    /* Check cache first - READDIR only needs names */
    if (nfs_cache_get_dir(ctx, fh, out, NFS_READDIRPLUS_NAMES) == 0)
        return 0;

    /* Cache miss or bypass - call protocol */
    ret = ctx->proto.ops->readdir(ctx, fh, out);

    if (ret == 0)
        nfs_cache_add_dir(ctx, fh, out);
    else if (errno == ESTALE || errno == EBADF)
        nfs_cache_invalidate(ctx, fh);

    return ret;
}

/*
 * Read directory entries with attributes.
 *
 * RFC 1813 (v3) Section 3.3.17 - NFSPROC3_READDIRPLUS (procedure 17)
 * (No NFSv2 equivalent - emulated via READDIR + LOOKUP)
 *
 * Returns directory entries with file handles and attributes in a single
 * operation. This is significantly more efficient than READDIR followed
 * by LOOKUP/GETATTR for each entry (reduces round-trips from N+1 to ~1).
 * NFSv3 READDIRPLUS may omit file handles or attributes for some entries
 * if the server cannot provide them efficiently (has_fh/has_attr flags).
 *
 * NFSv2 emulation: This implementation synthesizes READDIRPLUS behavior
 * for NFSv2 by calling READDIR then LOOKUP for each entry (N+1 RPCs).
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: ENOTDIR, EACCES (permission denied), ESTALE.
 */
int
nfs_readdirplus(struct nfsctx *ctx, const struct nfs_fh *fh, struct nfs_dir *out,
    int flags)
{
    size_t i;
    int ret;
    int skip_lookups;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, fh) < 0)
        return -1;

    /* Check cache first - especially important for v2 emulation */
    if (nfs_cache_get_dir(ctx, fh, out, flags) == 0)
        return 0;

    /* v3 has native readdirplus - flags don't matter (same cost) */
    if (ctx->proto.ops->readdirplus != NULL) {
        int need_full = !(flags & NFS_READDIRPLUS_NAMES);

        ret = ctx->proto.ops->readdirplus(ctx, fh, out);
        if (ret == 0) {
            /*
             * Server may omit FH/attrs for some entries (RFC allows this).
             * Fill in missing data via LOOKUP if caller needs full info.
             */
            if (need_full) {
                struct nfs_dirent *ent;

                for (i = 0; i < out->count; i++) {
                    ent = &out->entries[i];

                    /* Skip . and .. - handled separately */
                    if (strcmp(ent->name, ".") == 0 ||
                        strcmp(ent->name, "..") == 0)
                        continue;

                    if (!ent->has_fh || !ent->has_attr) {
                        struct nfs_lookup_res lu;
                        memset(&lu, 0, sizeof(lu));
                        if (nfs_lookup(ctx, fh, ent->name, &lu) == 0) {
                            if (!ent->has_fh) {
                                ent->fh = lu.fh;
                                ent->has_fh = 1;
                            }
                            if (!ent->has_attr && lu.has_obj_attr) {
                                ent->attr = lu.obj_attr;
                                ent->has_attr = 1;
                            }
                        }
                    }
                }
            }

            nfs_cache_add_dir(ctx, fh, out);
            /* Populate attribute cache and FH type cache from all entries */
            if (ctx->cache.enabled) {
                struct nfs_dirent *ent;

                for (i = 0; i < out->count; i++) {
                    ent = &out->entries[i];
                    if (ent->has_fh && ent->has_attr) {
                        nfs_attr_cache_add(ctx, &ent->fh, &ent->attr);
                        /* Add to FH type cache for completion filtering */
                        nfs_fh_type_cache_add(ctx, ent->fh.data, ent->fh.len,
                            ent->attr.type);
                    }
                }
                /* Also cache directory attributes */
                if (out->has_dir_attr)
                    nfs_attr_cache_add(ctx, fh, &out->dir_attr);
            }
        } else if (errno == ESTALE || errno == EBADF) {
            nfs_cache_invalidate(ctx, fh);
        }
        return ret;
    }

    /* v2: emulate readdirplus via readdir + lookup */
    ret = ctx->proto.ops->readdir(ctx, fh, out);
    if (ret < 0) {
        if (errno == ESTALE || errno == EBADF)
            nfs_cache_invalidate(ctx, fh);
        return ret;
    }

    /*
     * Skip LOOKUPs if caller only needs names (e.g., short ls format).
     * Entries will have names but no FH/attrs (has_fh=0, has_attr=0).
     */
    skip_lookups = (flags & NFS_READDIRPLUS_NAMES);

    /* Augment each entry with file handle and attributes via LOOKUP */
    for (i = 0; i < out->count && !skip_lookups; i++) {
        struct nfs_dirent *ent = &out->entries[i];
        struct nfs_lookup_res lu;

        /* "." is the current directory - copy the dir fh */
        if (strcmp(ent->name, ".") == 0) {
            memcpy(ent->fh.data, fh->data, fh->len);
            ent->fh.len = fh->len;
            ent->has_fh = 1;
            /* Attributes will be fetched via GETATTR in shell layer */
            continue;
        }

        memset(&lu, 0, sizeof(lu));

        /* Use nfs_lookup which checks cache first */
        if (nfs_lookup(ctx, fh, ent->name, &lu) == 0) {
            memcpy(ent->fh.data, lu.fh.data, lu.fh.len);
            ent->fh.len = lu.fh.len;
            ent->has_fh = 1;

            if (lu.has_obj_attr) {
                memcpy(&ent->attr, &lu.obj_attr, sizeof(ent->attr));
                ent->has_attr = 1;
            }

            /* If ".." returned same FH as current dir, we're at root */
            if (strcmp(ent->name, "..") == 0 &&
                lu.fh.len == fh->len &&
                memcmp(lu.fh.data, fh->data, fh->len) == 0) {
                /* Use directory's own attributes for ".." at root */
                if (!ent->has_attr && out->has_dir_attr) {
                    ent->attr = out->dir_attr;
                    ent->has_attr = 1;
                }
            }
        } else if (strcmp(ent->name, "..") == 0) {
            /* LOOKUP("..") failed - use current dir fh (top level) */
            memcpy(ent->fh.data, fh->data, fh->len);
            ent->fh.len = fh->len;
            ent->has_fh = 1;
            /* Attributes will be fetched via GETATTR in shell layer */
        }
    }

    /* Populate directory cache with all entries */
    nfs_cache_add_dir(ctx, fh, out);

    /* Populate attribute cache from all entries */
    if (ctx->cache.enabled) {
        for (i = 0; i < out->count; i++) {
            struct nfs_dirent *ent = &out->entries[i];
            if (ent->has_fh && ent->has_attr)
                nfs_attr_cache_add(ctx, &ent->fh, &ent->attr);
        }
        if (out->has_dir_attr)
            nfs_attr_cache_add(ctx, fh, &out->dir_attr);
    }

    return 0;
}

/*
 * Create a special device node (NFSv3 only).
 *
 * RFC 1813 (v3) Section 3.3.11 - NFSPROC3_MKNOD (procedure 11)
 * (Not available in NFSv2 - returns -1 with errno=ENOTSUP)
 *
 * Creates a special file (device node, FIFO, or socket) in dirfh.
 * Type values (ftype3):
 *   NF3CHR (2) - Character device (requires major/minor)
 *   NF3BLK (3) - Block device (requires major/minor)
 *   NF3SOCK (5) - Unix domain socket
 *   NF3FIFO (6) - Named pipe (FIFO)
 *
 * Device numbers (major/minor) are only meaningful for NF3CHR and NF3BLK.
 * Creating device nodes typically requires root privileges on the server.
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: EEXIST (name exists), EACCES (permission denied),
 * ENOTSUP (not supported - NFSv2 or filesystem), EROFS (read-only).
 */
int
nfs_mknod(struct nfsctx *ctx, const struct nfs_fh *dirfh,
    const char *name, int type, uint32_t mode,
    uint32_t major, uint32_t minor, struct nfs_create_res *out)
{
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;

    if (ctx->proto.ops->mknod == NULL) {
        errno = ENOTSUP;
        return -1;
    }

    if (nfs_validate_fh(ctx, dirfh) < 0)
        return -1;

    ret = ctx->proto.ops->mknod(ctx, dirfh, name, type, mode, major, minor, out);

    /* Defense-in-depth: verify FH bounds from protocol response */
    if (ret == 0 && out->has_fh && out->fh.len > NFS_FHSIZE_MAX) {
        errno = EPROTO;
        return -1;
    }

    /* Update cache with new node instead of just invalidating */
    if (ret == 0) {
        if (out->has_fh || out->has_attr) {
            struct nfs_lookup_res lu;
            memset(&lu, 0, sizeof(lu));
            if (out->has_fh) {
                lu.fh = out->fh;
                lu.has_obj_attr = out->has_attr;
                if (out->has_attr)
                    lu.obj_attr = out->attr;
            }
            nfs_cache_add(ctx, dirfh, name, &lu);
        } else {
            nfs_cache_invalidate(ctx, dirfh);
        }
    }

    return ret;
}

/*
 * Get filesystem statistics (v2: STATFS, v3: FSSTAT).
 *
 * RFC 1094 (v2) Section 2.3.18 - NFSPROC_STATFS (procedure 17)
 * RFC 1813 (v3) Section 3.3.18 - NFSPROC3_FSSTAT (procedure 18)
 *
 * Returns filesystem usage statistics including space and inode counts.
 * NFSv2 returns block-based values, NFSv3 returns byte-based values.
 * The unified result struct includes both (v2 converts to bytes, v3 zeros
 * block fields).
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: ESTALE (stale handle), EIO (I/O error).
 */
int
nfs_statfs(struct nfsctx *ctx, const struct nfs_fh *fh, struct nfs_fsstat_res *out)
{
    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, fh) < 0)
        return -1;

    if (ctx->proto.ops->statfs == NULL) {
        errno = ENOTSUP;
        return -1;
    }

    return ctx->proto.ops->statfs(ctx, fh, out);
}

/*
 * Get filesystem information (NFSv3 only).
 *
 * RFC 1813 (v3) Section 3.3.19 - NFSPROC3_FSINFO (procedure 19)
 * (Not available in NFSv2 - returns -1 with errno=ENOTSUP)
 *
 * Returns static filesystem properties: optimal read/write sizes,
 * maximum file size, time granularity, and capability flags.
 * Clients typically call this once after mount to tune I/O parameters.
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: ESTALE (stale handle), ENOTSUP (v2).
 */
int
nfs_fsinfo(struct nfsctx *ctx, const struct nfs_fh *fh, struct nfs_fsinfo_res *out)
{
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, fh) < 0)
        return -1;

    if (ctx->proto.ops->fsinfo == NULL) {
        errno = ENOTSUP;
        return -1;
    }

    ret = ctx->proto.ops->fsinfo(ctx, fh, out);
    return ret;
}

/*
 * Check access permissions (NFSv3 only).
 *
 * RFC 1813 (v3) Section 3.3.4 - NFSPROC3_ACCESS (procedure 4)
 * (Not available in NFSv2 - returns -1 with errno=ENOTSUP)
 *
 * Checks access permissions more accurately than mode bits alone.
 * The server evaluates the client's credentials against the file's
 * permissions including ACLs and security labels. Returns a bitmask
 * of allowed operations.
 *
 * access_mask bits (request): NFS_ACCESS3_READ, LOOKUP, MODIFY, EXTEND,
 * DELETE, EXECUTE. Result's access field contains allowed subset.
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: ESTALE (stale handle), ENOTSUP (v2).
 */
int
nfs_access(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint32_t access_mask, struct nfs_access_res *out)
{
    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, fh) < 0)
        return -1;

    if (ctx->proto.ops->access == NULL) {
        errno = ENOTSUP;
        return -1;
    }

    return ctx->proto.ops->access(ctx, fh, access_mask, out);
}

/*
 * Get path configuration (NFSv3 only).
 *
 * RFC 1813 (v3) Section 3.3.20 - NFSPROC3_PATHCONF (procedure 20)
 * (Not available in NFSv2 - returns -1 with errno=ENOTSUP)
 *
 * Returns POSIX pathconf(2) information for a path: maximum link count,
 * maximum filename length, and various filesystem behavior flags
 * (case sensitivity, chown restrictions, name truncation).
 * Returns 0 on success, -1 on error with errno set.
 *
 * Common errno values: ESTALE (stale handle), ENOTSUP (v2).
 */
int
nfs_pathconf(struct nfsctx *ctx, const struct nfs_fh *fh,
    struct nfs_pathconf_res *out)
{
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, fh) < 0)
        return -1;

    if (ctx->proto.ops->pathconf == NULL) {
        errno = ENOTSUP;
        return -1;
    }

    ret = ctx->proto.ops->pathconf(ctx, fh, out);
    return ret;
}

/*
 * NULL - NFS connectivity test.
 *
 * Dispatches to version-specific NULL procedure (v2 or v3).
 * Returns 0 on success, -1 on error.
 */
int
nfs_null(struct nfsctx *ctx)
{
    if (nfs_ensure_ops(ctx) < 0)
        return -1;

    if (ctx->proto.nfs_version == 2)
        return nfsv2_null(ctx);
    else
        return nfsv3_null(ctx);
}

/*
 * COMMIT - Commit cached data to stable storage (NFSv3 only).
 *
 * Forces previously written UNSTABLE data to stable storage.
 * Returns 0 on success, -1 on error (or ENOTSUP for NFSv2).
 */
int
nfs_commit(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint64_t offset, uint32_t count, struct nfs_commit_res *out)
{
    if (nfs_ensure_ops(ctx) < 0)
        return -1;

    if (ctx->proto.nfs_version == 2) {
        /* NFSv2 has no COMMIT - all writes are synchronous */
        if (!ctx->quiet)
            fprintf(stderr, "** Error: COMMIT not supported in NFSv2\n");
        errno = ENOTSUP;
        return -1;
    }

    if (nfs_validate_fh(ctx, fh) < 0)
        return -1;

    return nfsv3_commit(ctx, fh, offset, count, out);
}

/*
 * Write to a file with explicit stability mode (NFSv3 only).
 *
 * stability values:
 *   NFS_UNSTABLE  (0) - Server may buffer; use COMMIT afterward
 *   NFS_DATA_SYNC (1) - Data on stable storage before returning
 *   NFS_FILE_SYNC (2) - Data and metadata on stable storage
 *
 * NFSv2 always uses FILE_SYNC equivalent; stability parameter is ignored.
 * Returns 0 on success, -1 on error with errno set.
 */
int
nfs_write_stable(struct nfsctx *ctx, const struct nfs_fh *fh,
    uint64_t offset, const uint8_t *data, uint32_t count,
    int stability, struct nfs_write_res *out)
{
    struct nfs_write_res local_res;
    struct nfs_write_res *res;
    int ret;

    if (nfs_ensure_ops(ctx) < 0)
        return -1;
    if (nfs_validate_fh(ctx, fh) < 0)
        return -1;

    /* Use local storage if caller doesn't want result, so we can still cache */
    res = (out != NULL) ? out : &local_res;
    memset(res, 0, sizeof(*res));

    /* NFSv2: always FILE_SYNC, use standard write path */
    if (ctx->proto.nfs_version == 2)
        ret = ctx->proto.ops->write(ctx, fh, offset, data, count, res);
    else
        ret = nfsv3_write_stable(ctx, fh, offset, data, count, stability, res);

    /* Update caches with returned attributes (size/mtime changed) */
    if (ret == 0 && res->has_attr) {
        nfs_cache_update_attr_by_fh(ctx, fh, &res->attr);
        if (ctx->cache.enabled)
            nfs_attr_cache_add(ctx, fh, &res->attr);
    }

    return ret;
}

/*
 * Update ops table based on current NFS version
 */
void
update_nfs_ops(struct nfsctx *ctx)
{
    if (ctx == NULL)
        return;
    ctx->proto.ops = (ctx->proto.nfs_version == 2) ? &nfsv2_unified_ops : &nfsv3_unified_ops;
}

/*
 * Check if NFS service is available.
 * Probes the server if not already done.
 * Returns 1 if NFS is available, 0 if not.
 */
int
nfs_service_available(struct nfsctx *ctx)
{
    if (ctx == NULL)
        return 0;

    /* Try to initialize if not done */
    if (ctx->proto.ops == NULL)
        init_nfs_version(ctx);

    return (ctx->proto.ops != NULL);
}

/*
 * Set NFS protocol version.
 * Also queries portmap for the port if changing to a different version.
 * Returns version on success, 0 if version unavailable (mask says no),
 * -1 on invalid input.
 */
int
set_nfs_version(struct nfsctx *ctx, uint8_t version)
{
    uint16_t port;

    if (ctx == NULL || version < 2 || version > 3) {
        errno = EINVAL;
        return -1;
    }

    /* If mask is populated, validate against it */
    if (ctx->proto.nfs_version_mask != 0) {
        if (!(ctx->proto.nfs_version_mask & VERSION_AVAIL(version)))
            return 0; /* Version not available */
    }

    /* Set version (mask==0 means no discovery yet, trust user) */
    ctx->proto.nfs_version = version;
    update_nfs_ops(ctx);

    /* Query portmap for the port of this specific version */
    port = portmap_getport(ctx, PMAP_PROG_NFS, version);
    if (port != 0)
        ctx->ports.nfsd = port;

    return version;
}

/*
 * Set highest supported NFS protocol version
 */
int
set_highest_nfs_version(struct nfsctx *ctx)
{
    uint8_t version;
    uint8_t mask;

    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Mask out flags to get version bits only (bits 2-3) */
    mask = ctx->proto.nfs_version_mask & VERSION_AVAIL_ALL;
    if (mask == 0)
        return 0; /* No versions available */

    for (version = 3; version > 1; version--) {
        if (mask & VERSION_AVAIL(version)) {
            ctx->proto.nfs_version = version;
            update_nfs_ops(ctx);
            return version;
        }
    }

    return 0;
}

/*
 * Initialize NFS protocol version by querying portmapper.
 * Probes versions 2, 3 via GETPORT and sets version mask.
 * If mask is already populated (e.g. from rpcinfo), just selects highest.
 */
void
init_nfs_version(struct nfsctx *ctx)
{
    uint16_t port;

    if (ctx == NULL)
        return;

    /* If version already set explicitly, nothing to do */
    if (ctx->proto.nfs_version != 0)
        return;

    /* If mask already populated (e.g. from rpcinfo), select highest */
    if (ctx->proto.nfs_version_mask != 0) {
        set_highest_nfs_version(ctx);
        return;
    }

    /* Probe NFS versions 2, 3 */
    ctx->proto.nfs_version_mask = portmap_probe(ctx, PMAP_PROG_NFS, 2, 3, &port);

    /* Only mark as fully probed if we found at least one version.
     * This allows retry on subsequent calls if portmap was unreachable. */
    if (ctx->proto.nfs_version_mask & VERSION_AVAIL_ALL) {
        ctx->proto.nfs_version_mask |= VERSION_MASK_FULL;
        if (ctx->ports.nfsd == 0)
            ctx->ports.nfsd = port;
    }
    set_highest_nfs_version(ctx);
}
