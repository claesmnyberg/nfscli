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
 * browse_cmd_dir.c - Directory commands for browse shell
 *
 * Commands: pwd, ls, cd, mkdir, rmdir, df, mv
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ansicolors.h"
#include "browse_cmd.h"
#include "browse_ctx.h"
#include "cmdparse.h"
#include "display.h"
#include "idmap.h"
#include "nfs.h"
#include "nfscli.h"
#include "pathctx.h"
#include "str.h"

/* Spacing between columns in ls short format output */
#define LS_COLUMN_SPACING 2

/*
 * Print a single file entry in ls -l format.
 */
static void
print_file_entry(struct browse_ctx *bctx, const struct nfs_fh *fh,
    const struct nfs_attr *attr, const char *name,
    int human_readable, int use_colors, int numeric_ids)
{
    char modebuf[16];
    char sizebuf[STR_HSIZE_BUFLEN];
    char timebuf[32];
    char uidbuf[16], gidbuf[16];
    const char *uname, *gname;
    const char *link_target;
    struct nfs_readlink_res linkres;
    uint32_t major, minor;

    if (str_time_ls(timebuf, sizeof(timebuf), attr->mtime.sec) == NULL)
        snprintf(timebuf, sizeof(timebuf), "?");

    /* Size (or major,minor for devices) */
    if (attr->type == NFS_FTYPE_BLK || attr->type == NFS_FTYPE_CHR) {
        decode_rdev(bctx->nfs, attr->rdev, &major, &minor);
        snprintf(sizebuf, sizeof(sizebuf), "%u, %2u", major, minor);
    } else if (human_readable) {
        STR_HSIZE(attr->size, sizebuf);
    } else {
        snprintf(sizebuf, sizeof(sizebuf), "%lu", (unsigned long)attr->size);
    }

    /* Get symlink target */
    link_target = NULL;
    memset(&linkres, 0, sizeof(linkres));
    if (attr->type == NFS_FTYPE_LNK && fh != NULL) {
        if (nfs_readlink(bctx->nfs, fh, &linkres) == 0)
            link_target = linkres.target;
    }

    /* Get username/groupname or fall back to numeric */
    if (numeric_ids) {
        uname = NULL;
        gname = NULL;
    } else {
        uname = idmap_uid_to_name(&bctx->idmap, attr->uid);
        gname = idmap_gid_to_name(&bctx->idmap, attr->gid);
    }
    if (uname == NULL) {
        snprintf(uidbuf, sizeof(uidbuf), "%d", (int32_t)attr->uid);
        uname = uidbuf;
    }
    if (gname == NULL) {
        snprintf(gidbuf, sizeof(gidbuf), "%d", (int32_t)attr->gid);
        gname = gidbuf;
    }

    printf("%c%s %2u %-8s %-8s %8s %s %s%s%s%s%s\n",
        filetype_char(attr->type),
        fmt_mode(attr->mode & 07777, modebuf),
        attr->nlink,
        uname,
        gname,
        sizebuf,
        timebuf,
        use_colors ? color_for_type(attr) : "",
        name,
        link_target ? " -> " : "",
        link_target ? link_target : "",
        use_colors ? COLOR_RESET : "");
}

/*
 * Print a single file/directory entry (used by ls for -d, non-directory targets).
 * Handles both short and long format output.
 */
static void
ls_print_entry(struct browse_ctx *bctx, const struct nfs_fh *fh,
    const struct nfs_attr *attr, const char *name, int long_format,
    int human_readable, int use_colors, int numeric_ids)
{
    if (long_format) {
        print_file_entry(bctx, fh, attr, name, human_readable,
            use_colors, numeric_ids);
    } else {
        if (use_colors)
            printf("%s%s%s\n", color_for_type(attr), name, COLOR_RESET);
        else
            printf("%s\n", name);
    }
}

/*
 * List a single directory's contents.
 */
static void
ls_list_dir(struct browse_ctx *bctx, const struct nfs_fh *dir_fh,
    const char *dir_path, int long_format, int show_all, int human_readable,
    int use_colors, int numeric_ids, int follow_symlinks)
{
    struct nfs_dir dir;
    struct nfs_attr dir_attr;
    struct nfs_dirent *ent;
    uint32_t orig_uid;
    size_t i;
    int is_dotdot;
    int visible_count;

    /* Auto-switch uid if needed for read access on directory */
    orig_uid = bctx->nfs->uid;
    if (nfs_getattr(bctx->nfs, dir_fh, &dir_attr) == 0)
        orig_uid = autouid_switch(bctx, &dir_attr);

    /* Read directory - use names-only for short format (skip LOOKUPs in v2) */
    nfs_dir_init(&dir);
    if (nfs_readdirplus(bctx->nfs, dir_fh, &dir,
            long_format ? NFS_READDIRPLUS_FULL : NFS_READDIRPLUS_NAMES) < 0) {
        fprintf(stderr, "ls: %s\n", strerror(errno));
        nfs_dir_free(&dir);
        autouid_restore(bctx, orig_uid);
        return;
    }

    /* Sort for consistent display */
    if (dir.count > 1)
        qsort(dir.entries, dir.count, sizeof(*dir.entries), nfs_dirent_cmp);

    /* Handle . and .. attributes for NFSv2 emulation */
    for (i = 0; i < dir.count; i++) {
        ent = &dir.entries[i];

        if (!ent->has_attr && ent->name[0] == '.' &&
            (ent->name[1] == '\0' || (ent->name[1] == '.' && ent->name[2] == '\0'))) {
            is_dotdot = (ent->name[1] == '.');

            if (!is_dotdot) {
                /* "." - get attributes for this directory */
                if (nfs_getattr(bctx->nfs, dir_fh, &ent->attr) == 0)
                    ent->has_attr = 1;
            } else {
                /* ".." - lookup parent and get its attributes */
                struct nfs_lookup_res lres;
                if (nfs_lookup(bctx->nfs, dir_fh, "..", &lres) == 0) {
                    if (lres.has_obj_attr) {
                        ent->attr = lres.obj_attr;
                        ent->has_attr = 1;
                    } else if (nfs_getattr(bctx->nfs, &lres.fh, &ent->attr) == 0) {
                        ent->has_attr = 1;
                    }
                }
            }
        }
    }

    /* Print entries */
    if (long_format) {
        for (i = 0; i < dir.count; i++) {
            ent = &dir.entries[i];

            /* Skip hidden files unless -a */
            if (!show_all && ent->name[0] == '.')
                continue;

            /* Fetch missing attrs via LOOKUP+GETATTR if needed */
            if (!ent->has_attr) {
                if (ent->has_fh) {
                    if (nfs_getattr(bctx->nfs, &ent->fh, &ent->attr) == 0)
                        ent->has_attr = 1;
                } else {
                    /* No FH (READDIR fallback) - need to LOOKUP first */
                    struct nfs_lookup_res lres;
                    if (nfs_lookup(bctx->nfs, dir_fh, ent->name, &lres) == 0) {
                        ent->fh = lres.fh;
                        ent->has_fh = 1;
                        if (lres.has_obj_attr) {
                            ent->attr = lres.obj_attr;
                            ent->has_attr = 1;
                        } else if (nfs_getattr(bctx->nfs, &ent->fh, &ent->attr) == 0) {
                            ent->has_attr = 1;
                        }
                    }
                }
            }

            if (ent->has_attr) {
                struct nfs_attr *display_attr = &ent->attr;
                struct nfs_fh *display_fh = ent->has_fh ? &ent->fh : NULL;
                struct path_result link_res;
                char entry_path[PATH_MAX];

                /* Follow symlinks if -L specified */
                if (follow_symlinks && ent->attr.type == NFS_FTYPE_LNK) {
                    snprintf(entry_path, sizeof(entry_path), "%s/%s",
                        dir_path, ent->name);
                    if (path_resolve(bctx->pctx, entry_path, PATH_FOLLOW,
                            &link_res) == 0) {
                        if (!link_res.has_attr)
                            nfs_getattr(bctx->nfs, &link_res.fh, &link_res.attr);
                        display_attr = &link_res.attr;
                        display_fh = NULL; /* Suppress -> target display */
                    }
                }

                print_file_entry(bctx, display_fh, display_attr, ent->name,
                    human_readable, use_colors, numeric_ids);
            } else {
                printf("?????????? ?? ????? ????? ???????? ???????????? %s\n",
                    ent->name);
            }
        }
    } else {
        /* Short format - print in columns */
        visible_count = 0;

        /* Count visible entries */
        for (i = 0; i < dir.count; i++) {
            if (show_all || dir.entries[i].name[0] != '.')
                visible_count++;
        }

        if (visible_count > 0) {
            int twidth, max_len, col_width, num_cols, num_rows;
            int j, row, col, idx, len, is_last;
            int *indices;

            /* Overflow check before malloc */
            if ((size_t)visible_count > SIZE_MAX / sizeof(int)) {
                fprintf(stderr, "** Error: Too many directory entries\n");
                goto done;
            }

            /* Build index array of visible entries */
            indices = malloc(visible_count * sizeof(int));
            if (indices == NULL)
                goto done;

            j = 0;
            for (i = 0; i < dir.count; i++) {
                if (show_all || dir.entries[i].name[0] != '.')
                    indices[j++] = i;
            }

            /* Find maximum name length */
            max_len = 0;
            for (j = 0; j < visible_count; j++) {
                len = strlen(dir.entries[indices[j]].name);
                if (len > max_len)
                    max_len = len;
            }

            /* Calculate column layout */
            col_width = max_len + LS_COLUMN_SPACING;
            twidth = term_width();
            num_cols = twidth / col_width;
            if (num_cols < 1)
                num_cols = 1;
            num_rows = (visible_count + num_cols - 1) / num_cols;

            /* Print in column-major order */
            for (row = 0; row < num_rows; row++) {
                for (col = 0; col < num_cols; col++) {
                    idx = col * num_rows + row;
                    if (idx < visible_count) {
                        ent = &dir.entries[indices[idx]];
                        is_last = (col == num_cols - 1 || idx + num_rows >= visible_count);

                        if (use_colors && ent->has_attr) {
                            if (is_last)
                                printf("%s%s%s", color_for_type(&ent->attr),
                                    ent->name, COLOR_RESET);
                            else
                                printf("%s%-*s%s", color_for_type(&ent->attr),
                                    col_width, ent->name, COLOR_RESET);
                        } else {
                            if (is_last)
                                printf("%s", ent->name);
                            else
                                printf("%-*s", col_width, ent->name);
                        }
                    }
                }
                printf("\n");
            }

            free(indices);
        }
    done:;
    }

    nfs_dir_free(&dir);
    autouid_restore(bctx, orig_uid);
}

int
bcmd_pwd(struct browse_ctx *bctx, int argc, char **argv)
{
    const char *cwd;

    (void)argc;
    (void)argv;

    cwd = pathctx_pwd(bctx->pctx);
    if (cwd == NULL) {
        fprintf(stderr, "pwd: %s\n", strerror(errno));
        return 0;
    }

    printf("%s\n", cwd);
    return 0;
}

int
bcmd_ls(struct browse_ctx *bctx, int argc, char **argv)
{
    struct nfs_attr resolved_attr;
    struct parsed_args pa;
    int long_format = 0;
    int show_all = 0;
    int human_readable = 0;
    int follow_symlinks = 0;
    int dir_itself = 0;
    int numeric_ids = 0;
    int use_colors = 0;
    int i;
    int printed_header = 0;
    int multi_args;

    if (parse_cmdline_shell(argc, argv, "lahLdn", 0, PARSED_ARGS_MAX, &pa) < 0)
        return 0;

    if (strchr(pa.opts, 'l'))
        long_format = 1;
    if (strchr(pa.opts, 'a'))
        show_all = 1;
    if (strchr(pa.opts, 'h'))
        human_readable = 1;
    if (strchr(pa.opts, 'L'))
        follow_symlinks = 1;
    if (strchr(pa.opts, 'd'))
        dir_itself = 1;
    if (strchr(pa.opts, 'n'))
        numeric_ids = 1;

    /* Enable colors when stdout is a terminal, but not in fast completion mode */
    use_colors = bctx->nfs->term.use_colors &&
        (bctx->nfs->proto.nfs_version == 3 ||
            bctx->nfs->completion != COMPLETION_BASIC);

    multi_args = (pa.nargs > 1);

    /* No arguments - list cwd */
    if (pa.nargs == 0) {
        if (dir_itself) {
            if (nfs_getattr(bctx->nfs, &bctx->pctx->cwd_fh, &resolved_attr) == 0)
                ls_print_entry(bctx, &bctx->pctx->cwd_fh, &resolved_attr, ".",
                    long_format, human_readable, use_colors, numeric_ids);
        } else {
            ls_list_dir(bctx, &bctx->pctx->cwd_fh, bctx->pctx->cwd_path,
                long_format, show_all, human_readable, use_colors, numeric_ids,
                follow_symlinks);
        }
        return 0;
    }

    /* Process each argument */
    for (i = 0; i < pa.nargs; i++) {
        struct path_result res;
        int flags = follow_symlinks ? PATH_FOLLOW : 0;

        if (path_resolve(bctx->pctx, pa.args[i], flags, &res) < 0) {
            fprintf(stderr, "ls: %s: %s\n", pa.args[i], strerror(errno));
            continue;
        }

        /* Get attributes */
        if (!res.has_attr) {
            if (nfs_getattr(bctx->nfs, &res.fh, &res.attr) < 0) {
                fprintf(stderr, "ls: %s: %s\n", pa.args[i], strerror(errno));
                continue;
            }
            res.has_attr = 1;
        }
        resolved_attr = res.attr;

        /* If -d specified, show directory itself (not contents) */
        if (dir_itself) {
            ls_print_entry(bctx, &res.fh, &resolved_attr, pa.args[i],
                long_format, human_readable, use_colors, numeric_ids);
            continue;
        }

        /* If target is not a directory, show its attributes */
        if (resolved_attr.type != NFS_FTYPE_DIR) {
            ls_print_entry(bctx, &res.fh, &resolved_attr, path_basename(pa.args[i]),
                long_format, human_readable, use_colors, numeric_ids);
            continue;
        }

        /* It's a directory - list contents */
        if (multi_args) {
            if (printed_header)
                printf("\n");
            printf("%s:\n", pa.args[i]);
            printed_header = 1;
        }

        ls_list_dir(bctx, &res.fh, pa.args[i], long_format, show_all,
            human_readable, use_colors, numeric_ids, follow_symlinks);
    }

    return 0;
}

int
bcmd_cd(struct browse_ctx *bctx, int argc, char **argv)
{
    struct parsed_args pa;
    const char *cwd;
    int print_path = 0;

    if (parse_cmdline_shell(argc, argv, "", 0, 1, &pa) < 0)
        return 0;

    if (pa.nargs == 0) {
        pathctx_chdir_home(bctx->pctx);
    } else {
        if (strcmp(pa.args[0], "-") == 0) {
            print_path = 1;
            if (pathctx_chdir_prev(bctx->pctx) < 0) {
                fprintf(stderr, "cd: %s: %s\n", pa.args[0], strerror(errno));
                return 0;
            }
        } else {
            if (pathctx_chdir(bctx->pctx, pa.args[0]) < 0) {
                fprintf(stderr, "cd: %s: %s\n", pa.args[0], strerror(errno));
                return 0;
            }
        }

        if (print_path) {
            cwd = pathctx_pwd(bctx->pctx);
            if (cwd != NULL)
                printf("%s\n", cwd);
        }
    }

    return 0;
}

/*
 * Create directory, optionally creating parent directories (-p).
 */
static int
mkdir_one(struct browse_ctx *bctx, const char *path, int create_parents)
{
    struct path_result res;
    struct nfs_create_res mkdir_res;
    char pathcopy[NFS_MAXPATHLEN];
    char *p, *slash;

    /* Try simple case first */
    if (path_resolve(bctx->pctx, path, PATH_WANT_PARENT, &res) == 0 && res.has_parent) {
        memset(&mkdir_res, 0, sizeof(mkdir_res));
        if (nfs_mkdir(bctx->nfs, &res.parent_fh, res.basename, 0755, &mkdir_res) < 0) {
            if (!(create_parents && errno == EEXIST)) {
                fprintf(stderr, "mkdir: %s: %s\n", path, strerror(errno));
                return -1;
            }
        }
        return 0;
    }

    /* Parent doesn't exist - if -p, create parents recursively */
    if (!create_parents) {
        fprintf(stderr, "mkdir: %s: %s\n", path, strerror(errno));
        return -1;
    }

    /* Create each component of the path */
    snprintf(pathcopy, sizeof(pathcopy), "%s", path);
    p = pathcopy;
    if (*p == '/')
        p++;

    while ((slash = strchr(p, '/')) != NULL || *p) {
        if (slash)
            *slash = '\0';

        /* Try to create this component */
        if (path_resolve(bctx->pctx, pathcopy, PATH_WANT_PARENT, &res) == 0 &&
            res.has_parent) {
            memset(&mkdir_res, 0, sizeof(mkdir_res));
            if (nfs_mkdir(bctx->nfs, &res.parent_fh, res.basename, 0755,
                    &mkdir_res) < 0) {
                if (errno != EEXIST) {
                    fprintf(stderr, "mkdir: %s: %s\n", pathcopy,
                        strerror(errno));
                    return -1;
                }
            }
        }

        if (slash) {
            *slash = '/';
            p = slash + 1;
        } else {
            break;
        }
    }

    return 0;
}

int
bcmd_mkdir(struct browse_ctx *bctx, int argc, char **argv)
{
    struct parsed_args pa;
    int i;
    int create_parents = 0;

    if (parse_cmdline_shell(argc, argv, "p", 1, PARSED_ARGS_MAX, &pa) < 0)
        return 0;

    if (strchr(pa.opts, 'p'))
        create_parents = 1;

    for (i = 0; i < pa.nargs; i++)
        mkdir_one(bctx, pa.args[i], create_parents);

    return 0;
}

int
bcmd_rmdir(struct browse_ctx *bctx, int argc, char **argv)
{
    struct parsed_args pa;
    struct path_result res;
    int i;

    if (parse_cmdline_shell(argc, argv, "", 1, PARSED_ARGS_MAX, &pa) < 0)
        return 0;

    for (i = 0; i < pa.nargs; i++) {
        if (path_resolve(bctx->pctx, pa.args[i], PATH_WANT_PARENT, &res) < 0) {
            fprintf(stderr, "rmdir: %s: %s\n", pa.args[i], strerror(errno));
            continue;
        }
        if (!res.has_parent) {
            fprintf(stderr, "rmdir: %s: parent not found\n", pa.args[i]);
            continue;
        }

        if (nfs_rmdir(bctx->nfs, &res.parent_fh, res.basename) < 0)
            fprintf(stderr, "rmdir: %s: %s\n", pa.args[i], strerror(errno));
    }

    return 0;
}

/*
 * Format a size value for df output.
 */
static void
df_fmt_size(char *buf, size_t buflen, uint64_t val, int human, int kilo)
{
    if (human)
        str_hsize(val, buf, buflen);
    else if (kilo)
        snprintf(buf, buflen, "%lu", (unsigned long)(val / 1024));
    else
        snprintf(buf, buflen, "%lu", (unsigned long)val);
}

/*
 * Print filesystem stats for a single mount point.
 */
static void
df_print_mount(struct browse_ctx *bctx, const char *path, const uint8_t *fh,
    int fhlen, int human, int kilo, int w, int header_printed)
{
    struct nfs_fsstat_res st;
    struct nfs_fh statfs_fh;
    uint64_t used_bytes;
    char s_total[24], s_used[24], s_avail[24];
    char pathbuf[32];

    nfs_fh_from_buf(&statfs_fh, fh, fhlen);
    if (nfs_statfs(bctx->nfs, &statfs_fh, &st) < 0)
        return;

    /* Guard against underflow if server reports fbytes > tbytes */
    used_bytes = (st.fbytes <= st.tbytes) ? st.tbytes - st.fbytes : 0;

    df_fmt_size(s_total, sizeof(s_total), st.tbytes, human, kilo);
    df_fmt_size(s_used, sizeof(s_used), used_bytes, human, kilo);
    df_fmt_size(s_avail, sizeof(s_avail), st.abytes, human, kilo);

    if (!header_printed) {
        printf("%-24s %*s %*s %*s %5s\n", "Filesystem", w,
            kilo ? "1K-blocks" : "Size", w, "Used", w, "Avail", "Use%");
    }

    /* Truncate path if too long */
    if (strlen(path) > 24) {
        snprintf(pathbuf, sizeof(pathbuf), "...%s", path + strlen(path) - 20);
        path = pathbuf;
    }

    printf("%-24s %*s %*s %*s %4d%%\n", path, w, s_total, w, s_used, w, s_avail,
        st.tbytes ? (int)((used_bytes * 100) / st.tbytes) : 0);
}

int
bcmd_df(struct browse_ctx *bctx, int argc, char **argv)
{
    struct nfs_mount_fh_cache *cache = &bctx->nfs->cache.mount_fh;
    struct nfs_fsstat_res target_st, mount_st;
    struct path_result res;
    struct parsed_args pa;
    struct nfs_fh tmp_fh;
    char pathbuf[NFS_MAXPATHLEN];
    const char *lookup_path;
    const char *mount_path;
    const char *pwd;
    size_t best_len;
    size_t mlen;
    size_t i;
    int human, kilo, w;
    int found;

    if (parse_cmdline_shell(argc, argv, "hk", 0, 1, &pa) < 0)
        return 0;

    human = strchr(pa.opts, 'h') != NULL;
    kilo = strchr(pa.opts, 'k') != NULL;
    w = human ? 8 : (kilo ? 12 : 16);

    if (pa.nargs > 0) {
        /* Show stats for specific path - determine lookup path */
        if (pa.args[0][0] == '/') {
            if (path_normalize(pa.args[0], pathbuf, sizeof(pathbuf)) < 0) {
                fprintf(stderr, "df: invalid path\n");
                return 0;
            }
            lookup_path = pathbuf;
        } else {
            pwd = pathctx_pwd(bctx->pctx);
            if (pwd == NULL) {
                lookup_path = NULL;
            } else {
                snprintf(pathbuf, sizeof(pathbuf), "%s", pwd);
                lookup_path = pathbuf;
            }
        }

        /* Check if path exactly matches a known mount */
        if (lookup_path != NULL) {
            for (i = 0; i < cache->count; i++) {
                if (strcmp(lookup_path, cache->entries[i].path) == 0) {
                    df_print_mount(bctx, cache->entries[i].path,
                        cache->entries[i].fh, cache->entries[i].fhlen,
                        human, kilo, w, 0);
                    return 0;
                }
            }
        }

        /* Path isn't an exact mount match - resolve and find containing mount */
        if (path_resolve(bctx->pctx, pa.args[0], 0, &res) < 0) {
            fprintf(stderr, "df: %s: %s\n", pa.args[0], strerror(errno));
            return 0;
        }

        mount_path = pa.args[0];
        best_len = 0;
        found = 0;

        /* Try prefix matching */
        if (lookup_path != NULL) {
            for (i = 0; i < cache->count; i++) {
                mlen = strlen(cache->entries[i].path);
                if (mlen > best_len &&
                    strncmp(lookup_path, cache->entries[i].path, mlen) == 0 &&
                    (lookup_path[mlen] == '\0' || lookup_path[mlen] == '/')) {
                    best_len = mlen;
                    mount_path = cache->entries[i].path;
                    found = 1;
                }
            }
        }

        /* FSSTAT comparison for relative paths */
        if (!found && cache->count > 0) {
            if (nfs_statfs(bctx->nfs, &res.fh, &target_st) == 0) {
                for (i = 0; i < cache->count; i++) {
                    nfs_fh_from_buf(&tmp_fh, cache->entries[i].fh,
                        cache->entries[i].fhlen);
                    if (nfs_statfs(bctx->nfs, &tmp_fh, &mount_st) == 0) {
                        if (mount_st.tbytes == target_st.tbytes) {
                            mount_path = cache->entries[i].path;
                            break;
                        }
                    }
                }
            }
        }

        df_print_mount(bctx, mount_path, res.fh.data, res.fh.len,
            human, kilo, w, 0);
        return 0;
    }

    /* Show stats for all known mounts */
    if (cache->entries == NULL || cache->count == 0) {
        const struct nfs_fh *cwd_fh = pathctx_cwd_fh(bctx->pctx);
        if (cwd_fh == NULL) {
            fprintf(stderr, "df: No current directory\n");
            return 0;
        }
        df_print_mount(bctx, "/", cwd_fh->data, cwd_fh->len, human, kilo, w, 0);
    } else {
        found = 0; /* Reuse as header_printed */
        for (i = 0; i < cache->count; i++) {
            df_print_mount(bctx, cache->entries[i].path,
                cache->entries[i].fh, cache->entries[i].fhlen,
                human, kilo, w, found);
            found = 1;
        }
    }

    return 0;
}

int
bcmd_mv(struct browse_ctx *bctx, int argc, char **argv)
{
    struct parsed_args pa;
    struct path_result src_res, dst_res;
    char src_name_buf[NFS_MAXNAMLEN + 1], dst_name_buf[NFS_MAXNAMLEN + 1];

    if (parse_cmdline_shell(argc, argv, "", 2, 2, &pa) < 0)
        return 0;

    /* Resolve source parent */
    if (path_resolve(bctx->pctx, pa.args[0], PATH_WANT_PARENT, &src_res) < 0) {
        fprintf(stderr, "mv: %s: %s\n", pa.args[0], strerror(errno));
        return 0;
    }
    if (!src_res.has_parent) {
        fprintf(stderr, "mv: %s: parent not found\n", pa.args[0]);
        return 0;
    }
    snprintf(src_name_buf, sizeof(src_name_buf), "%s", src_res.basename);

    /* Resolve destination parent */
    if (path_resolve(bctx->pctx, pa.args[1], PATH_WANT_PARENT, &dst_res) < 0) {
        fprintf(stderr, "mv: %s: %s\n", pa.args[1], strerror(errno));
        return 0;
    }
    if (!dst_res.has_parent) {
        fprintf(stderr, "mv: %s: parent not found\n", pa.args[1]);
        return 0;
    }
    snprintf(dst_name_buf, sizeof(dst_name_buf), "%s", dst_res.basename);

    if (nfs_rename(bctx->nfs, &src_res.parent_fh, src_name_buf,
            &dst_res.parent_fh, dst_name_buf) < 0)
        fprintf(stderr, "mv: %s -> %s: %s\n", pa.args[0], pa.args[1],
            strerror(errno));

    return 0;
}
