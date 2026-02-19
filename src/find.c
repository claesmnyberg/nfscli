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
 * find.c - find command for browse shell
 *
 * Simplified find with implicit AND for all filters:
 *   find [path...] [options]
 *
 * Options:
 *   -name pattern   - filename glob match
 *   -iname pattern  - filename glob match (case-insensitive)
 *   -type c         - file type (b,c,d,f,l,p,s)
 *   -perm mode      - permission match (exact, -mode=all, /mode=any)
 *   -user uid       - owner UID
 *   -group gid      - group GID
 *   -size [+-]n[ckMG] - file size
 *   -mtime [+-]n    - modification time in days
 *   -maxdepth n     - limit recursion depth
 *   -ls             - print in ls -la format
 *   -print          - print pathname (default)
 *
 * All filters are implicitly ANDed together.
 */

#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "browse_cmd.h"
#include "browse_ctx.h"
#include "display.h"
#include "find.h"
#include "nfs.h"
#include "nfs_types.h"
#include "nfs_util.h"
#include "pathctx.h"
#include "str.h"

#define BROWSE_MAX_FILE_ARGS 64

/* Interrupt flag from browse.c */
extern volatile sig_atomic_t browse_interrupted;

/*
 * Find options - all filters implicitly ANDed
 */
struct find_opts {
    /* Filters */
    const char *name_pattern;         /* -name */
    const char *iname_pattern;        /* -iname (original) */
    char iname_lc[NFS_MAXNAMLEN + 1]; /* -iname lowercased (cached) */
    int type_char;                    /* -type: 'f', 'd', etc. or 0 if not set */
    int has_perm;
    uint32_t perm_mask;
    int perm_mode;                    /* 0=exact, 1=all bits, 2=any bit */
    int has_user;
    uint32_t user_id;
    int has_group;
    uint32_t group_id;
    int has_size;
    int64_t size_value;
    int size_cmp;        /* -1=less, 0=exact, +1=greater */
    int has_mtime;
    int64_t mtime_value; /* in seconds */
    int mtime_cmp;       /* -1=newer, 0=exact, +1=older */

    /* Global options */
    int maxdepth; /* -1 = unlimited */
    time_t now;   /* Cached time for -mtime comparisons */

    /* Output action */
    int use_ls; /* -ls format */
};

/*
 * Parse size argument: [+-]n[ckMG]
 */
static int
parse_size_arg(const char *arg, int64_t *size_out, int *cmp_out)
{
    const char *p = arg;
    int64_t mult = 512;
    char *endptr;
    int64_t n;

    *cmp_out = 0;
    if (*p == '+') {
        *cmp_out = 1;
        p++;
    } else if (*p == '-') {
        *cmp_out = -1;
        p++;
    }

    errno = 0;
    n = strtoll(p, &endptr, 10);
    if (endptr == p || n < 0 || errno == ERANGE)
        return -1;

    switch (*endptr) {
    case '\0':
        mult = 512;
        break;
    case 'c':
        mult = 1;
        if (endptr[1] != '\0')
            return -1;
        break;
    case 'k':
        mult = 1024;
        if (endptr[1] != '\0')
            return -1;
        break;
    case 'M':
        mult = 1024 * 1024;
        if (endptr[1] != '\0')
            return -1;
        break;
    case 'G':
        mult = 1024LL * 1024 * 1024;
        if (endptr[1] != '\0')
            return -1;
        break;
    default:
        return -1;
    }

    *size_out = n * mult;
    return 0;
}

/*
 * Parse time argument: [+-]n
 */
static int
parse_time_arg(const char *arg, int64_t *time_out, int *cmp_out)
{
    const char *p = arg;
    char *endptr;
    int64_t n;

    *cmp_out = 0;
    if (*p == '+') {
        *cmp_out = 1;
        p++;
    } else if (*p == '-') {
        *cmp_out = -1;
        p++;
    }

    errno = 0;
    n = strtoll(p, &endptr, 10);
    if (endptr == p || *endptr != '\0' || n < 0 || errno == ERANGE)
        return -1;

    *time_out = n;
    return 0;
}

/*
 * Check if entry matches all filters (implicit AND)
 */
static int
find_match(struct find_opts *opts, const char *basename, struct nfs_attr *attr)
{
    /* -name */
    if (opts->name_pattern) {
        if (fnmatch(opts->name_pattern, basename, 0) != 0)
            return 0;
    }

    /* -iname (case-insensitive) - pattern already lowercased in opts->iname_lc */
    if (opts->iname_pattern) {
        char lc_name[NFS_MAXNAMLEN + 1];
        size_t i;

        for (i = 0; basename[i] && i < NFS_MAXNAMLEN; i++)
            lc_name[i] = (char)tolower((unsigned char)basename[i]);
        lc_name[i] = '\0';

        if (fnmatch(opts->iname_lc, lc_name, 0) != 0)
            return 0;
    }

    /* -type */
    if (opts->type_char) {
        uint32_t expected;
        switch (opts->type_char) {
        case 'f':
            expected = NFS_FTYPE_REG;
            break;
        case 'd':
            expected = NFS_FTYPE_DIR;
            break;
        case 'l':
            expected = NFS_FTYPE_LNK;
            break;
        case 'c':
            expected = NFS_FTYPE_CHR;
            break;
        case 'b':
            expected = NFS_FTYPE_BLK;
            break;
        case 'p':
            expected = NFS_FTYPE_FIFO;
            break;
        case 's':
            expected = NFS_FTYPE_SOCK;
            break;
        default:
            return 0;
        }
        if (attr->type != expected)
            return 0;
    }

    /* -perm */
    if (opts->has_perm) {
        uint32_t mode = attr->mode & 07777;
        if (opts->perm_mode == 0) {
            if (mode != opts->perm_mask)
                return 0;
        } else if (opts->perm_mode == 1) {
            if ((mode & opts->perm_mask) != opts->perm_mask)
                return 0;
        } else {
            if ((mode & opts->perm_mask) == 0)
                return 0;
        }
    }

    /* -user */
    if (opts->has_user) {
        if (attr->uid != opts->user_id)
            return 0;
    }

    /* -group */
    if (opts->has_group) {
        if (attr->gid != opts->group_id)
            return 0;
    }

    /* -size */
    if (opts->has_size) {
        int64_t file_size = (int64_t)attr->size;
        if (opts->size_cmp == 0) {
            if (file_size != opts->size_value)
                return 0;
        } else if (opts->size_cmp > 0) {
            if (file_size <= opts->size_value)
                return 0;
        } else {
            if (file_size >= opts->size_value)
                return 0;
        }
    }

    /* -mtime */
    if (opts->has_mtime) {
        time_t mtime = (time_t)attr->mtime.sec;
        time_t age = opts->now - mtime;

        if (opts->mtime_cmp == 0) {
            if (age < opts->mtime_value || age >= opts->mtime_value + 86400)
                return 0;
        } else if (opts->mtime_cmp > 0) {
            if (age <= opts->mtime_value)
                return 0;
        } else {
            if (age >= opts->mtime_value)
                return 0;
        }
    }

    return 1;
}

/*
 * Print entry in -ls format
 */
static void
print_ls(const char *path, struct nfs_attr *attr)
{
    char modebuf[16];
    char timebuf[32];
    uint64_t blocks;

    blocks = (attr->used + 511) / 512;

    if (str_time_ls(timebuf, sizeof(timebuf), attr->mtime.sec) == NULL)
        snprintf(timebuf, sizeof(timebuf), "?");

    printf("%7llu %7llu %c%s %3u %5u %5u %10llu %s %s\n",
        (unsigned long long)attr->fileid,
        (unsigned long long)blocks,
        filetype_char(attr->type),
        fmt_mode(attr->mode & 07777, modebuf),
        attr->nlink,
        attr->uid,
        attr->gid,
        (unsigned long long)attr->size,
        timebuf,
        path);
}

/*
 * Resolve a directory entry to a path_result.
 * Uses cached readdirplus data when available, falls back to
 * path_resolve for symlinks or missing attributes.
 *
 * Returns 0 on success with res populated, -1 if entry should be skipped.
 */
int
dirent_resolve(struct pathctx *pctx, const struct nfs_dirent *ent,
    const char *fullpath, struct path_result *res)
{
    if (ent->has_fh && ent->has_attr && ent->attr.type != NFS_FTYPE_LNK) {
        /* Use cached attrs from readdirplus */
        nfs_fh_copy(&res->fh, &ent->fh);
        res->attr = ent->attr;
        res->has_attr = 1;
        return 0;
    }

    /* Symlink or missing attrs - need path resolution */
    if (path_resolve(pctx, fullpath, PATH_FOLLOW, res) < 0)
        return -1;

    if (!res->has_attr) {
        if (nfs_getattr(pctx->nfs, &res->fh, &res->attr) < 0)
            return -1;
        res->has_attr = 1;
    }

    return 0;
}

/*
 * Recursive find implementation
 */
static int
find_recurse(struct pathctx *pctx, const struct nfs_fh *dir_fh, uint64_t dir_fileid,
    const char *path, struct find_opts *opts, struct visited_set *vs, int depth)
{
    struct nfs_dir nfs_dir = {0};
    size_t i;
    struct nfs_dirent *ent;
    char fullpath[NFS_MAXPATHLEN];
    struct path_result res;

    if (browse_interrupted)
        return -1;

    if (depth > MAX_RECURSION_DEPTH)
        return 0;

    if (opts->maxdepth >= 0 && depth > opts->maxdepth)
        return 0;

    if (visited_check_add(vs, dir_fileid) != 0)
        return 0;

    if (nfs_readdirplus(pctx->nfs, dir_fh, &nfs_dir, 0) < 0) {
        visited_pop(vs);
        return -1;
    }

    for (i = 0; i < nfs_dir.count && !browse_interrupted; i++) {
        ent = &nfs_dir.entries[i];

        if (strcmp(ent->name, ".") == 0 || strcmp(ent->name, "..") == 0)
            continue;

        if (path_join(path, ent->name, fullpath, sizeof(fullpath)) < 0)
            continue;

        if (dirent_resolve(pctx, ent, fullpath, &res) < 0)
            continue;

        if (find_match(opts, ent->name, &res.attr)) {
            if (opts->use_ls)
                print_ls(fullpath, &res.attr);
            else
                printf("%s\n", fullpath);
        }

        if (res.attr.type == NFS_FTYPE_DIR)
            find_recurse(pctx, &res.fh, res.attr.fileid, fullpath, opts, vs, depth + 1);
    }

    nfs_dir_free(&nfs_dir);
    visited_pop(vs);
    return 0;
}

/*
 * Parse find command arguments into opts structure.
 * Populates paths array with non-option arguments.
 * Returns 0 on success, -1 on error (with message printed).
 */
static int
parse_find_opts(int argc, char **argv, struct find_opts *opts,
    const char **paths, int *npaths)
{
    int i;
    char c;
    const char *modestr;
    char *endptr;
    long val;
    int64_t days;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-name") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "find: -name requires an argument\n");
                return -1;
            }
            opts->name_pattern = argv[i];
        } else if (strcmp(argv[i], "-iname") == 0) {
            size_t j;
            if (++i >= argc) {
                fprintf(stderr, "find: -iname requires an argument\n");
                return -1;
            }
            opts->iname_pattern = argv[i];
            /* Pre-compute lowercase pattern for efficiency */
            for (j = 0; opts->iname_pattern[j] && j < NFS_MAXNAMLEN; j++)
                opts->iname_lc[j] = (char)tolower((unsigned char)opts->iname_pattern[j]);
            opts->iname_lc[j] = '\0';
        } else if (strcmp(argv[i], "-type") == 0) {
            if (++i >= argc || argv[i][1] != '\0') {
                fprintf(stderr, "find: -type requires a single character\n");
                return -1;
            }
            c = argv[i][0];
            if (c != 'b' && c != 'c' && c != 'd' && c != 'f' &&
                c != 'l' && c != 'p' && c != 's') {
                fprintf(stderr, "find: invalid type '%c' (use b,c,d,f,l,p,s)\n", c);
                return -1;
            }
            opts->type_char = c;
        } else if (strcmp(argv[i], "-perm") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "find: -perm requires an argument\n");
                return -1;
            }
            modestr = argv[i];
            if (modestr[0] == '-') {
                opts->perm_mode = 1;
                modestr++;
            } else if (modestr[0] == '/') {
                opts->perm_mode = 2;
                modestr++;
            } else {
                opts->perm_mode = 0;
            }
            errno = 0;
            val = strtol(modestr, &endptr, 8);
            if (endptr == modestr || *endptr != '\0' ||
                val < 0 || val > 07777 || errno != 0) {
                fprintf(stderr, "find: invalid permission '%s'\n", argv[i]);
                return -1;
            }
            opts->perm_mask = (uint32_t)val;
            opts->has_perm = 1;
        } else if (strcmp(argv[i], "-user") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "find: -user requires an argument\n");
                return -1;
            }
            errno = 0;
            val = strtol(argv[i], &endptr, 10);
            if (endptr == argv[i] || *endptr != '\0' || val < 0 || errno != 0) {
                fprintf(stderr, "find: invalid user '%s'\n", argv[i]);
                return -1;
            }
            opts->user_id = (uint32_t)val;
            opts->has_user = 1;
        } else if (strcmp(argv[i], "-group") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "find: -group requires an argument\n");
                return -1;
            }
            errno = 0;
            val = strtol(argv[i], &endptr, 10);
            if (endptr == argv[i] || *endptr != '\0' || val < 0 || errno != 0) {
                fprintf(stderr, "find: invalid group '%s'\n", argv[i]);
                return -1;
            }
            opts->group_id = (uint32_t)val;
            opts->has_group = 1;
        } else if (strcmp(argv[i], "-size") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "find: -size requires an argument\n");
                return -1;
            }
            if (parse_size_arg(argv[i], &opts->size_value, &opts->size_cmp) < 0) {
                fprintf(stderr, "find: invalid size '%s'\n", argv[i]);
                return -1;
            }
            opts->has_size = 1;
        } else if (strcmp(argv[i], "-mtime") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "find: -mtime requires an argument\n");
                return -1;
            }
            if (parse_time_arg(argv[i], &days, &opts->mtime_cmp) < 0) {
                fprintf(stderr, "find: invalid mtime '%s'\n", argv[i]);
                return -1;
            }
            opts->mtime_value = days * 24 * 60 * 60;
            opts->has_mtime = 1;
        } else if (strcmp(argv[i], "-maxdepth") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "find: -maxdepth requires an argument\n");
                return -1;
            }
            if (str_to_int(argv[i], &opts->maxdepth, 0, INT_MAX) < 0) {
                fprintf(stderr, "find: invalid maxdepth '%s'\n", argv[i]);
                return -1;
            }
        } else if (strcmp(argv[i], "-ls") == 0) {
            opts->use_ls = 1;
        } else if (strcmp(argv[i], "-print") == 0) {
            /* Default action, ignore */
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "find: unknown option '%s'\n", argv[i]);
            return -1;
        } else {
            if (*npaths < BROWSE_MAX_FILE_ARGS)
                paths[(*npaths)++] = argv[i];
        }
    }

    /* Default to current directory if no paths specified */
    if (*npaths == 0) {
        paths[0] = ".";
        *npaths = 1;
    }

    return 0;
}

/*
 * find command: find [path...] [options]
 */
int
bcmd_find(struct browse_ctx *bctx, int argc, char **argv)
{
    struct pathctx *pctx = bctx->pctx;
    struct find_opts opts = {0};
    struct visited_set vs;
    const char *paths[BROWSE_MAX_FILE_ARGS];
    int npaths = 0;
    int i;
    const char *bname;

    opts.maxdepth = -1;
    opts.now = time(NULL);

    if (parse_find_opts(argc, argv, &opts, paths, &npaths) < 0)
        return -1;

    visited_init(&vs);

    for (i = 0; i < npaths && !browse_interrupted; i++) {
        struct path_result res;
        if (path_resolve(pctx, paths[i], PATH_FOLLOW, &res) < 0) {
            fprintf(stderr, "*** %s: No such file or directory\n", paths[i]);
            continue;
        }

        /* Get attrs if we don't have them */
        if (!res.has_attr) {
            if (nfs_getattr(pctx->nfs, &res.fh, &res.attr) < 0)
                continue;
            res.has_attr = 1;
        }

        /* Check starting path itself */
        bname = strrchr(paths[i], '/');
        bname = bname ? bname + 1 : paths[i];
        if (find_match(&opts, bname, &res.attr)) {
            if (opts.use_ls)
                print_ls(paths[i], &res.attr);
            else
                printf("%s\n", paths[i]);
        }

        if (res.attr.type == NFS_FTYPE_DIR)
            find_recurse(pctx, &res.fh, res.attr.fileid, paths[i], &opts, &vs, 0);
    }

    visited_free(&vs);
    return 0;
}
