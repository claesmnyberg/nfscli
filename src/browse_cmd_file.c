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
 * browse_cmd_file.c - File commands for browse shell
 *
 * Commands: cat, stat, readlink, get, put, rm, ln, touch, truncate
 * Also exports: can_read, autouid_switch, autouid_restore (shared helpers)
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "browse_cmd.h"
#include "browse_ctx.h"
#include "cmdparse.h"
#include "display.h"
#include "idmap.h"
#include "nfs.h"
#include "nfscli.h"
#include "pathctx.h"
#include "transfer.h"

/*
 * Check if we have read permission on a file with current credentials.
 * Returns 1 if we can read, 0 if not.
 */
int
can_read(struct browse_ctx *bctx, const struct nfs_attr *attr)
{
    struct nfsctx *ctx = bctx->nfs;
    uint32_t mode = attr->mode;
    uint32_t gids[IDMAP_MAX_GROUPS];
    int ngids;
    int i;

    /* Check owner */
    if (ctx->uid == attr->uid)
        return (mode & 0400) != 0;

    /* Check primary group */
    if (ctx->gid == attr->gid)
        return (mode & 0040) != 0;

    /* Check supplementary groups from idmap */
    if (bctx->idmap.loaded) {
        ngids = idmap_get_user_groups(&bctx->idmap, ctx->uid, gids, IDMAP_MAX_GROUPS);
        for (i = 0; i < ngids; i++) {
            if (gids[i] == attr->gid)
                return (mode & 0040) != 0;
        }
    }

    /* Check other */
    return (mode & 0004) != 0;
}

/*
 * If autouid is enabled and we can't read with current credentials,
 * switch to the file owner's uid. Call before read operations.
 * Returns original uid (caller should restore after operation).
 */
uint32_t
autouid_switch(struct browse_ctx *bctx, const struct nfs_attr *attr)
{
    uint32_t orig_uid = bctx->nfs->uid;

    if (!bctx->autouid)
        return orig_uid;

    if (can_read(bctx, attr))
        return orig_uid;

    /* Switch to owner's uid */
    bctx->nfs->uid = attr->uid;
    return orig_uid;
}

/*
 * Restore uid after autouid operation.
 */
void
autouid_restore(struct browse_ctx *bctx, uint32_t orig_uid)
{
    bctx->nfs->uid = orig_uid;
}

int
bcmd_cat(struct browse_ctx *bctx, int argc, char **argv)
{
    FILE *pipe_input = bctx->pipe_input;
    struct path_result res;
    struct parsed_args pa;
    uint32_t orig_uid;
    int64_t ret;
    int i;
    char buf[8192];
    size_t n;

    if (parse_cmdline_shell(argc, argv, "", 0, PARSED_ARGS_MAX, &pa) < 0)
        return 0;

    /* If no files specified but stdin is redirected, copy stdin to stdout */
    if (pa.nargs == 0 && pipe_input != NULL) {
        while ((n = fread(buf, 1, sizeof(buf), pipe_input)) > 0) {
            if (fwrite(buf, 1, n, stdout) != n) {
                fprintf(stderr, "cat: write error\n");
                return -1;
            }
        }
        return 0;
    }

    if (pa.nargs == 0) {
        fprintf(stderr, "cat: missing operand\n");
        fprintf(stderr, "Try 'cat --help' for more information.\n");
        return 0;
    }

    for (i = 0; i < pa.nargs; i++) {
        if (path_resolve(bctx->pctx, pa.args[i], PATH_FOLLOW, &res) < 0) {
            fprintf(stderr, "cat: %s: %s\n", pa.args[i], strerror(errno));
            continue;
        }

        if (!res.has_attr) {
            if (nfs_getattr(bctx->nfs, &res.fh, &res.attr) < 0) {
                fprintf(stderr, "cat: %s: %s\n", pa.args[i], strerror(errno));
                continue;
            }
        }

        /* Check it's a regular file */
        if (res.attr.type != NFS_FTYPE_REG) {
            fprintf(stderr, "cat: %s: Not a regular file\n", pa.args[i]);
            continue;
        }

        /* Auto-switch uid if needed for read access */
        orig_uid = autouid_switch(bctx, &res.attr);

        /* Download to stdout, checking for binary content */
        ret = transfer_download(bctx->nfs, res.fh.data, res.fh.len, 0, stdout,
            DL_CHECK_BINARY);
        if (ret == DL_BINARY) {
            fprintf(stderr, "cat: %s: Binary file (not shown)\n", pa.args[i]);
        } else if (ret < 0) {
            fprintf(stderr, "cat: %s: %s\n", pa.args[i], strerror(errno));
        }

        /* Restore original uid */
        autouid_restore(bctx, orig_uid);
    }

    return 0;
}

/*
 * Display file attributes in stat-like format.
 */
static int
stat_one_file(struct browse_ctx *bctx, const char *path)
{
    struct path_result res;
    char modebuf[16];
    char timebuf[32];
    const char *typestr;
    const char *uname;
    const char *gname;
    struct tm *tm;
    uint32_t major, minor;
    time_t t;

    /* Resolve path */
    if (path_resolve(bctx->pctx, path, 0, &res) < 0) {
        fprintf(stderr, "stat: %s: %s\n", path, strerror(errno));
        return -1;
    }

    if (!res.has_attr) {
        if (nfs_getattr(bctx->nfs, &res.fh, &res.attr) < 0) {
            fprintf(stderr, "stat: %s: %s\n", path, strerror(errno));
            return -1;
        }
    }

    /* Determine type string */
    switch (res.attr.type) {
    case NFS_FTYPE_REG:
        typestr = "regular file";
        break;
    case NFS_FTYPE_DIR:
        typestr = "directory";
        break;
    case NFS_FTYPE_LNK:
        typestr = "symbolic link";
        break;
    case NFS_FTYPE_BLK:
        typestr = "block device";
        break;
    case NFS_FTYPE_CHR:
        typestr = "character device";
        break;
    case NFS_FTYPE_SOCK:
        typestr = "socket";
        break;
    case NFS_FTYPE_FIFO:
        typestr = "FIFO";
        break;
    default:
        typestr = "unknown";
        break;
    }

    /* Print stat-like output */
    printf("  File: %s\n", path);

    /* For symlinks, show target */
    if (res.attr.type == NFS_FTYPE_LNK) {
        struct nfs_readlink_res rlres;
        if (nfs_readlink(bctx->nfs, &res.fh, &rlres) == 0)
            printf("  Type: %s -> %s\n", typestr, rlres.target);
        else
            printf("  Type: %s\n", typestr);
    } else {
        printf("  Type: %s\n", typestr);
    }
    printf("  Size: %lu\n", (unsigned long)res.attr.size);
    printf("  Mode: %04o/%s\n",
        res.attr.mode & 07777,
        fmt_mode(res.attr.mode & 07777, modebuf));

    uname = idmap_uid_to_name(&bctx->idmap, res.attr.uid);
    gname = idmap_gid_to_name(&bctx->idmap, res.attr.gid);
    if (uname)
        printf("   Uid: %d (%s)\n", (int32_t)res.attr.uid, uname);
    else
        printf("   Uid: %d\n", (int32_t)res.attr.uid);
    if (gname)
        printf("   Gid: %d (%s)\n", (int32_t)res.attr.gid, gname);
    else
        printf("   Gid: %d\n", (int32_t)res.attr.gid);
    printf(" Links: %u\n", res.attr.nlink);

    if (res.attr.type == NFS_FTYPE_BLK || res.attr.type == NFS_FTYPE_CHR) {
        decode_rdev(bctx->nfs, res.attr.rdev, &major, &minor);
        printf("Device: %u, %u\n", major, minor);
    }

    t = res.attr.atime.sec;
    tm = localtime(&t);
    if (tm == NULL)
        snprintf(timebuf, sizeof(timebuf), "?");
    else
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
    printf("Access: %s\n", timebuf);

    t = res.attr.mtime.sec;
    tm = localtime(&t);
    if (tm == NULL)
        snprintf(timebuf, sizeof(timebuf), "?");
    else
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
    printf("Modify: %s\n", timebuf);

    t = res.attr.ctime.sec;
    tm = localtime(&t);
    if (tm == NULL)
        snprintf(timebuf, sizeof(timebuf), "?");
    else
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
    printf("Change: %s\n", timebuf);

    return 0;
}

int
bcmd_stat(struct browse_ctx *bctx, int argc, char **argv)
{
    struct parsed_args pa;
    int i;

    if (parse_cmdline_shell(argc, argv, "", 1, PARSED_ARGS_MAX, &pa) < 0)
        return 0;

    for (i = 0; i < pa.nargs; i++) {
        if (i > 0)
            printf("\n");
        stat_one_file(bctx, pa.args[i]);
    }

    return 0;
}

int
bcmd_readlink(struct browse_ctx *bctx, int argc, char **argv)
{
    struct parsed_args pa;
    struct path_result res;
    struct nfs_readlink_res rlres;
    int i;

    if (parse_cmdline_shell(argc, argv, "", 1, PARSED_ARGS_MAX, &pa) < 0)
        return 0;

    for (i = 0; i < pa.nargs; i++) {
        /* Resolve without following symlinks */
        if (path_resolve(bctx->pctx, pa.args[i], 0, &res) < 0) {
            fprintf(stderr, "readlink: %s: %s\n", pa.args[i], strerror(errno));
            continue;
        }

        /* Check if it's a symlink */
        if (!res.has_attr) {
            if (nfs_getattr(bctx->nfs, &res.fh, &res.attr) < 0) {
                fprintf(stderr, "readlink: %s: %s\n", pa.args[i], strerror(errno));
                continue;
            }
        }

        if (res.attr.type != NFS_FTYPE_LNK) {
            fprintf(stderr, "readlink: %s: Not a symbolic link\n", pa.args[i]);
            continue;
        }

        /* Read the link target */
        if (nfs_readlink(bctx->nfs, &res.fh, &rlres) < 0) {
            fprintf(stderr, "readlink: %s: %s\n", pa.args[i], strerror(errno));
            continue;
        }

        printf("%s\n", rlres.target);
    }

    return 0;
}

int
bcmd_get(struct browse_ctx *bctx, int argc, char **argv)
{
    struct parsed_args pa;
    struct path_result res;
    const char *localname;
    FILE *fp;
    int64_t bytes;
    uint32_t orig_uid = 0;
    int uid_switched = 0;
    int saved_errno;

    if (parse_cmdline_shell(argc, argv, "", 1, 2, &pa) < 0)
        return 0;

    /* Use specified local name or extract from path */
    if (pa.nargs >= 2)
        localname = pa.args[1];
    else
        localname = path_basename(pa.args[0]);

    /* Check for empty filename */
    if (localname[0] == '\0') {
        fprintf(stderr, "get: must specify a filename\n");
        return -1;
    }

    /* Resolve path, following symlinks */
    if (path_resolve(bctx->pctx, pa.args[0], PATH_FOLLOW, &res) < 0) {
        fprintf(stderr, "get: %s: %s\n", pa.args[0], strerror(errno));
        return 0;
    }

    if (!res.has_attr) {
        if (nfs_getattr(bctx->nfs, &res.fh, &res.attr) < 0) {
            fprintf(stderr, "get: %s: %s\n", pa.args[0], strerror(errno));
            return 0;
        }
    }

    /* Check it's a regular file */
    if (res.attr.type != NFS_FTYPE_REG) {
        fprintf(stderr, "get: %s: Not a regular file\n", pa.args[0]);
        return -1;
    }

    /* Auto-switch uid if needed for read access */
    orig_uid = autouid_switch(bctx, &res.attr);
    uid_switched = 1;

    /* Open local file */
    fp = fopen(localname, "wb");
    if (fp == NULL) {
        fprintf(stderr, "get: %s: %s\n", localname, strerror(errno));
        goto out;
    }

    /* Download */
    printf("Downloading %s -> %s\n", pa.args[0], localname);
    bytes = transfer_download(bctx->nfs, res.fh.data, res.fh.len, 0, fp, DL_PROGRESS);
    saved_errno = errno;
    if (fclose(fp) != 0 && bytes >= 0) {
        printf("\n*** get: %s: fclose failed: %s\n", localname, strerror(errno));
        goto out;
    }

    if (bytes < 0) {
        printf("\n*** get: %s: %s\n", pa.args[0], strerror(saved_errno));
        goto out;
    }

    printf("\n%ld bytes downloaded\n", (long)bytes);

out:
    if (uid_switched)
        autouid_restore(bctx, orig_uid);
    return 0;
}

int
bcmd_put(struct browse_ctx *bctx, int argc, char **argv)
{
    struct parsed_args pa;
    struct path_result res;
    struct nfs_create_res create_res;
    const char *localname;
    const char *remotename;
    FILE *fp;
    int64_t bytes;
    int saved_errno;
    int force;

    if (parse_cmdline_shell(argc, argv, "f", 1, 2, &pa) < 0)
        return 0;

    force = strchr(pa.opts, 'f') != NULL;
    localname = pa.args[0];

    /* Use specified remote name or extract from local path */
    if (pa.nargs >= 2)
        remotename = pa.args[1];
    else
        remotename = path_basename(localname);

    /* Check for empty remote filename */
    if (remotename[0] == '\0') {
        fprintf(stderr, "put: must specify a remote filename\n");
        return -1;
    }

    /* Open local file */
    fp = fopen(localname, "rb");
    if (fp == NULL) {
        fprintf(stderr, "put: %s: %s\n", localname, strerror(errno));
        return 0;
    }

    /* Resolve parent directory */
    if (path_resolve(bctx->pctx, remotename, PATH_WANT_PARENT, &res) < 0) {
        fprintf(stderr, "put: %s: %s\n", remotename, strerror(errno));
        fclose(fp);
        return 0;
    }

    if (!res.has_parent) {
        fprintf(stderr, "put: %s: parent not found\n", remotename);
        fclose(fp);
        return 0;
    }

    /* Create the file */
    memset(&create_res, 0, sizeof(create_res));
    if (nfs_create(bctx->nfs, &res.parent_fh,
            res.basename, 0644, force ? NFS_CREATE_UNCHECKED : NFS_CREATE_GUARDED,
            &create_res) < 0) {
        fprintf(stderr, "put: %s: %s\n", remotename, strerror(errno));
        fclose(fp);
        return 0;
    }

    /*
     * NFSv3 CREATE may not return file handle (RFC 1813).
     * If not returned, do a LOOKUP to get it.
     */
    if (!create_res.has_fh) {
        struct nfs_lookup_res lu;
        memset(&lu, 0, sizeof(lu));
        if (nfs_lookup(bctx->nfs, &res.parent_fh, res.basename, &lu) < 0) {
            fprintf(stderr, "put: %s: %s\n", remotename, strerror(errno));
            fclose(fp);
            return 0;
        }
        nfs_fh_copy(&create_res.fh, &lu.fh);
    }

    /* Upload */
    printf("Uploading %s -> %s\n", localname, res.basename);
    bytes = transfer_upload(bctx->nfs, create_res.fh.data, create_res.fh.len, 0, fp);
    saved_errno = errno;
    fclose(fp);

    if (bytes < 0) {
        printf("\n*** put: %s: %s\n", localname, strerror(saved_errno));
        return 0;
    }

    printf("%ld bytes uploaded\n", (long)bytes);
    return 0;
}

/*
 * Recursive delete helper for rm -r.
 * Returns 0 on success, -1 on error.
 */
static int
rm_recursive(struct browse_ctx *bctx, struct nfs_fh *parent_fh,
    const char *name, const char *path, int force)
{
    struct nfs_lookup_res lu;
    struct nfs_dir dir;
    size_t i;

    /* Look up the entry to get its file handle and type */
    memset(&lu, 0, sizeof(lu));
    if (nfs_lookup(bctx->nfs, parent_fh, name, &lu) < 0) {
        if (!force || errno != ENOENT)
            fprintf(stderr, "rm: %s: %s\n", path, strerror(errno));
        return -1;
    }

    /* Get attributes if not returned by lookup */
    if (!lu.has_obj_attr) {
        if (nfs_getattr(bctx->nfs, &lu.fh, &lu.obj_attr) < 0) {
            if (!force)
                fprintf(stderr, "rm: %s: %s\n", path, strerror(errno));
            return -1;
        }
    }

    /* If it's not a directory, just remove it */
    if (lu.obj_attr.type != NFS_FTYPE_DIR) {
        if (nfs_remove(bctx->nfs, parent_fh, name) < 0) {
            if (!force || errno != ENOENT)
                fprintf(stderr, "rm: %s: %s\n", path, strerror(errno));
            return -1;
        }
        return 0;
    }

    /* It's a directory - read and delete contents first */
    nfs_dir_init(&dir);
    if (nfs_readdir(bctx->nfs, &lu.fh, &dir) < 0) {
        fprintf(stderr, "rm: %s: %s\n", path, strerror(errno));
        return -1;
    }

    for (i = 0; i < dir.count; i++) {
        struct nfs_dirent *ent = &dir.entries[i];
        char subpath[PATH_MAX];

        /* Skip . and .. */
        if (strcmp(ent->name, ".") == 0 || strcmp(ent->name, "..") == 0)
            continue;

        /* Build subpath, skip entry if path would be truncated */
        if (snprintf(subpath, sizeof(subpath), "%s/%s", path, ent->name)
            >= (int)sizeof(subpath)) {
            fprintf(stderr, "rm: %s/%s: path too long\n", path, ent->name);
            continue;
        }
        rm_recursive(bctx, &lu.fh, ent->name, subpath, force);
    }

    nfs_dir_free(&dir);

    /* Now remove the empty directory */
    if (nfs_rmdir(bctx->nfs, parent_fh, name) < 0) {
        if (!force || errno != ENOENT)
            fprintf(stderr, "rm: %s: %s\n", path, strerror(errno));
        return -1;
    }

    return 0;
}

int
bcmd_rm(struct browse_ctx *bctx, int argc, char **argv)
{
    struct parsed_args pa;
    struct path_result res;
    int force = 0;
    int recursive = 0;
    int i;

    if (parse_cmdline_shell(argc, argv, "rf", 1, PARSED_ARGS_MAX, &pa) < 0)
        return 0;

    if (strchr(pa.opts, 'f'))
        force = 1;
    if (strchr(pa.opts, 'r'))
        recursive = 1;

    for (i = 0; i < pa.nargs; i++) {
        if (path_resolve(bctx->pctx, pa.args[i], PATH_WANT_PARENT, &res) < 0) {
            if (!force || errno != ENOENT)
                fprintf(stderr, "rm: %s: %s\n", pa.args[i], strerror(errno));
            continue;
        }
        if (!res.has_parent) {
            if (!force)
                fprintf(stderr, "rm: %s: parent not found\n", pa.args[i]);
            continue;
        }

        if (recursive) {
            rm_recursive(bctx, &res.parent_fh, res.basename, pa.args[i], force);
        } else {
            if (nfs_remove(bctx->nfs, &res.parent_fh, res.basename) < 0) {
                if (!force || errno != ENOENT)
                    fprintf(stderr, "rm: %s: %s\n", pa.args[i], strerror(errno));
            }
        }
    }

    return 0;
}

int
bcmd_ln(struct browse_ctx *bctx, int argc, char **argv)
{
    struct parsed_args pa;
    struct path_result res;
    int symlink_mode;

    if (parse_cmdline_shell(argc, argv, "s", 2, 2, &pa) < 0)
        return 0;

    symlink_mode = (strchr(pa.opts, 's') != NULL);

    /* Resolve link-name parent directory */
    if (path_resolve(bctx->pctx, pa.args[1], PATH_WANT_PARENT, &res) < 0) {
        fprintf(stderr, "ln: %s: %s\n", pa.args[1], strerror(errno));
        return 0;
    }
    if (!res.has_parent) {
        fprintf(stderr, "ln: %s: parent not found\n", pa.args[1]);
        return 0;
    }

    if (symlink_mode) {
        /* Symbolic link: target path is stored as-is */
        if (nfs_symlink(bctx->nfs, &res.parent_fh,
                res.basename, pa.args[0], 0777) < 0) {
            fprintf(stderr, "ln: %s: %s\n", pa.args[1], strerror(errno));
            return 0;
        }
    } else {
        /* Hard link: target must exist */
        struct path_result target_res;

        if (path_resolve(bctx->pctx, pa.args[0], PATH_FOLLOW, &target_res) < 0) {
            fprintf(stderr, "ln: %s: %s\n", pa.args[0], strerror(errno));
            return 0;
        }

        if (nfs_link(bctx->nfs, &target_res.fh, &res.parent_fh, res.basename) < 0)
            fprintf(stderr, "ln: %s: %s\n", pa.args[1], strerror(errno));
    }

    return 0;
}

/*
 * Touch a single file - create if missing, update timestamps if exists.
 */
static int
touch_one_file(struct browse_ctx *bctx, const char *path)
{
    struct path_result res;
    struct nfs_fh fh;
    struct nfs_sattr sattr;
    const struct nfs_fh *fh_ptr;

    /* Try to resolve existing file */
    if (path_resolve(bctx->pctx, path, 0, &res) < 0) {
        struct nfs_create_res create_res;

        if (errno != ENOENT) {
            fprintf(stderr, "touch: %s: %s\n", path, strerror(errno));
            return -1;
        }

        /* File doesn't exist - create it */
        if (path_resolve(bctx->pctx, path, PATH_WANT_PARENT, &res) < 0) {
            fprintf(stderr, "touch: %s: %s\n", path, strerror(errno));
            return -1;
        }
        if (!res.has_parent) {
            fprintf(stderr, "touch: %s: parent not found\n", path);
            return -1;
        }

        /* Create empty file with default permissions */
        memset(&create_res, 0, sizeof(create_res));
        if (nfs_create(bctx->nfs, &res.parent_fh,
                res.basename, 0644, NFS_CREATE_GUARDED, &create_res) < 0) {
            fprintf(stderr, "touch: %s: %s\n", path, strerror(errno));
            return -1;
        }

        /*
         * NFSv3 CREATE may not return file handle (RFC 1813).
         * If not returned, do a LOOKUP to get it.
         */
        if (!create_res.has_fh) {
            struct nfs_lookup_res lu;
            memset(&lu, 0, sizeof(lu));
            if (nfs_lookup(bctx->nfs, &res.parent_fh, res.basename, &lu) < 0) {
                fprintf(stderr, "touch: %s: %s\n", path, strerror(errno));
                return -1;
            }
            nfs_fh_copy(&create_res.fh, &lu.fh);
        }

        /* Use the newly created file's handle for timestamp update */
        fh = create_res.fh;
        fh_ptr = &fh;
    } else {
        fh_ptr = &res.fh;
    }

    nfs_sattr_init(&sattr);
    sattr.set_atime = NFS_TIME_SET_TO_SERVER;
    sattr.set_mtime = NFS_TIME_SET_TO_SERVER;

    /* Update times */
    if (nfs_setattr(bctx->nfs, fh_ptr, &sattr) < 0) {
        fprintf(stderr, "touch: %s: %s\n", path, strerror(errno));
        return -1;
    }

    return 0;
}

int
bcmd_touch(struct browse_ctx *bctx, int argc, char **argv)
{
    struct parsed_args pa;
    int i;

    if (parse_cmdline_shell(argc, argv, "", 1, PARSED_ARGS_MAX, &pa) < 0)
        return 0;

    for (i = 0; i < pa.nargs; i++)
        touch_one_file(bctx, pa.args[i]);

    return 0;
}

int
bcmd_truncate(struct browse_ctx *bctx, int argc, char **argv)
{
    struct nfs_sattr sattr;
    struct parsed_args pa;
    struct path_result res;
    const char *size_str;
    const char *path;
    char *endp;

    if (parse_cmdline_shell(argc, argv, "", 2, 2, &pa) < 0)
        return 0;

    size_str = pa.args[0];
    path = pa.args[1];

    nfs_sattr_init(&sattr);
    sattr.set_size = 1;
    errno = 0;
    sattr.size = strtoull(size_str, &endp, 10);
    if (endp == size_str || *endp != '\0' || errno != 0) {
        fprintf(stderr, "truncate: invalid size: %s\n", size_str);
        return -1;
    }

    /* Resolve path */
    if (path_resolve(bctx->pctx, path, 0, &res) < 0) {
        fprintf(stderr, "truncate: %s: %s\n", path, strerror(errno));
        return 0;
    }

    /* Set size */
    if (nfs_setattr(bctx->nfs, &res.fh, &sattr) < 0)
        fprintf(stderr, "truncate: %s: %s\n", path, strerror(errno));

    return 0;
}
