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
 * browse_cmd_misc.c - Miscellaneous commands for browse shell
 *
 * Commands: help, echo, set, id, chmod, chown, mknod
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "browse.h"
#include "browse_cmd.h"
#include "browse_ctx.h"
#include "cmdparse.h"
#include "display.h"
#include "idmap.h"
#include "nfs.h"
#include "nfscli.h"
#include "pathctx.h"

int
bcmd_help(struct browse_ctx *bctx, int argc, char **argv)
{
    const struct browse_cmd *cmds;
    int i;
    size_t w;

    (void)bctx;

    cmds = browse_get_cmds();
    printf("\n");

    /* Print help for specific command */
    if (argc == 2) {
        for (i = 0; cmds[i].name != NULL; i++) {
            if (strcmp(cmds[i].name, argv[1]) == 0) {
                printf("%s\n", cmds[i].help_short);
                printf("Usage: %s %s\n", cmds[i].name, cmds[i].syntax);
                printf("%s\n", cmds[i].help_long);
                return 0;
            }
        }
        fprintf(stderr, "Command '%s' not found\n", argv[1]);
    }

    /* Print all commands */
    printf("Browse mode commands:\n");
    for (i = 0; cmds[i].name != NULL; i++) {
        w = printf("%s ", cmds[i].name);
        while (w++ < 20)
            printf(".");
        printf(" %s\n", cmds[i].help_short);
    }
    printf("\n");

    return 0;
}

/*
 * Process backslash escapes in a string (for echo -e).
 * Returns malloc'd string with escapes processed, or NULL on error.
 */
static char *
echo_process_escapes(const char *s)
{
    size_t len;
    char *out;
    char *p;
    const char *q;

    len = strlen(s);
    out = malloc(len + 1);
    if (out == NULL)
        return NULL;

    p = out;
    q = s;

    while (*q) {
        if (*q != '\\') {
            *p++ = *q++;
            continue;
        }
        q++;
        if (*q == '\0') {
            *p++ = '\\';
            break;
        }
        switch (*q) {
        case '\\':
            *p++ = '\\';
            break;
        case 'n':
            *p++ = '\n';
            break;
        case 'r':
            *p++ = '\r';
            break;
        case 't':
            *p++ = '\t';
            break;
        case '0': {
            /*
             * Octal escape: \0, \0n, \0nn, \0nnn (1-3 octal digits after \0).
             * Note: \0 alone or \0 followed by non-octal produces NUL (0),
             * which will terminate the C string. This matches POSIX echo -e
             * behavior and is documented/expected.
             */
            unsigned int val = 0;
            int digits = 0;
            q++;
            while (digits < 3 && *q >= '0' && *q <= '7') {
                val = val * 8 + (*q - '0');
                q++;
                digits++;
            }
            *p++ = (char)val;
            continue;
        }
        case 'x': {
            unsigned int val = 0;
            int digits = 0;
            q++;
            while (digits < 2) {
                if (*q >= '0' && *q <= '9')
                    val = val * 16 + (*q - '0');
                else if (*q >= 'a' && *q <= 'f')
                    val = val * 16 + (*q - 'a' + 10);
                else if (*q >= 'A' && *q <= 'F')
                    val = val * 16 + (*q - 'A' + 10);
                else
                    break;
                q++;
                digits++;
            }
            if (digits > 0)
                *p++ = (char)val;
            else
                *p++ = 'x';
            continue;
        }
        default:
            *p++ = '\\';
            *p++ = *q;
            break;
        }
        q++;
    }
    *p = '\0';
    return out;
}

int
bcmd_echo(struct browse_ctx *bctx, int argc, char **argv)
{
    int no_newline = 0;
    int interpret_escapes = 0;
    int i;
    int first = 1;
    const char *p;

    (void)bctx;

    /* Parse options - stop at first non-option or "--" */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }
        if (argv[i][0] != '-')
            break;
        p = argv[i] + 1;
        if (*p == '\0')
            break;
        while (*p) {
            if (*p == 'n')
                no_newline = 1;
            else if (*p == 'e')
                interpret_escapes = 1;
            else
                goto print_args;
            p++;
        }
    }

print_args:
    for (; i < argc; i++) {
        if (!first)
            putchar(' ');
        first = 0;

        if (interpret_escapes) {
            char *processed = echo_process_escapes(argv[i]);
            if (processed) {
                fputs(processed, stdout);
                free(processed);
            } else {
                fputs(argv[i], stdout);
            }
        } else {
            fputs(argv[i], stdout);
        }
    }

    if (!no_newline)
        putchar('\n');

    return 0;
}

/*
 * Print a single setting with dotted alignment.
 */
static void
set_print(const char *name, const char *value, const char *note)
{
    int w;

    w = printf("%s ", name);
    while (w < 18) {
        putchar('.');
        w++;
    }
    if (note && *note)
        printf(" %s (%s)\n", value, note);
    else
        printf(" %s\n", value);
}

int
bcmd_set(struct browse_ctx *bctx, int argc, char **argv)
{
    struct nfsctx *ctx = bctx->nfs;
    char numbuf[16];
    int show_all;
    int is_v3;
    const char *name;
    const char *value;
    const char *uname;
    const char *gname;

    show_all = (argc == 1);
    name = (argc >= 2) ? argv[1] : NULL;
    value = (argc >= 3) ? argv[2] : NULL;

    /* Show or set autouid */
    if (show_all || (name && strcmp(name, "autouid") == 0)) {
        if (value) {
            if (strcmp(value, "on") == 0 || strcmp(value, "1") == 0)
                bctx->autouid = 1;
            else if (strcmp(value, "off") == 0 || strcmp(value, "0") == 0)
                bctx->autouid = 0;
            else {
                fprintf(stderr, "set: autouid: expected 'on' or 'off'\n");
                return 0;
            }
        }
        set_print("autouid", bctx->autouid ? "on" : "off", NULL);
        if (!show_all)
            return 0;
    }

    /* Show or set completion */
    if (show_all || (name && strcmp(name, "completion") == 0)) {
        is_v3 = (ctx->proto.nfs_version >= 3);

        if (value) {
            if (is_v3) {
                printf("Completion is not configurable for NFS v3\n");
                return 0;
            }
            if (strcmp(value, "basic") == 0)
                ctx->completion = COMPLETION_BASIC;
            else if (strcmp(value, "enhanced") == 0)
                ctx->completion = COMPLETION_ENHANCED;
            else {
                fprintf(stderr, "set: completion: expected 'basic' or 'enhanced'\n");
                return 0;
            }
        }
        if (is_v3) {
            set_print("completion", "NFS v3", NULL);
        } else {
            set_print("completion",
                ctx->completion == COMPLETION_ENHANCED ? "enhanced" : "basic",
                NULL);
        }
        if (!show_all)
            return 0;
    }

    /* Show or set uid (accepts username or user:group) */
    if (show_all || (name && strcmp(name, "uid") == 0)) {
        if (value) {
            char valuebuf[64];
            char *colon;
            char *endptr;
            long v;
            uint32_t lookup_uid;

            strncpy(valuebuf, value, sizeof(valuebuf) - 1);
            valuebuf[sizeof(valuebuf) - 1] = '\0';

            colon = strchr(valuebuf, ':');
            if (colon) {
                const char *grp;
                *colon = '\0';
                grp = colon + 1;
                if (*grp) {
                    errno = 0;
                    v = strtol(grp, &endptr, 10);
                    if (errno == 0 && *endptr == '\0' && v >= 0 &&
                        (unsigned long)v <= UINT32_MAX) {
                        ctx->gid = (uint32_t)v;
                    } else {
                        uint32_t gid = idmap_name_to_gid(&bctx->idmap, grp);
                        if (gid == (uint32_t)-1) {
                            fprintf(stderr, "set: unknown group: %s\n", grp);
                            return 0;
                        }
                        ctx->gid = gid;
                    }
                }
            }

            if (valuebuf[0]) {
                errno = 0;
                v = strtol(valuebuf, &endptr, 10);
                if (errno == 0 && *endptr == '\0' && v >= 0 &&
                    (unsigned long)v <= UINT32_MAX) {
                    ctx->uid = (uint32_t)v;
                } else {
                    lookup_uid = idmap_name_to_uid(&bctx->idmap, valuebuf);
                    if (lookup_uid == (uint32_t)-1) {
                        fprintf(stderr, "set: unknown user: %s\n", valuebuf);
                        return 0;
                    }
                    ctx->uid = lookup_uid;
                }
            }
        }
        uname = idmap_uid_to_name(&bctx->idmap, ctx->uid);
        if (uname == NULL && ctx->uid == 0)
            uname = "root";
        if (uname) {
            snprintf(numbuf, sizeof(numbuf), "%u (%s)", ctx->uid, uname);
        } else {
            snprintf(numbuf, sizeof(numbuf), "%u", ctx->uid);
        }
        set_print("uid", numbuf, NULL);
        if (!show_all)
            return 0;
    }

    /* Show or set gid */
    if (show_all || (name && strcmp(name, "gid") == 0)) {
        if (value) {
            char *endptr;
            long v;
            uint32_t gid;
            errno = 0;
            v = strtol(value, &endptr, 10);
            if (errno == 0 && *endptr == '\0' && v >= 0 &&
                (unsigned long)v <= UINT32_MAX) {
                ctx->gid = (uint32_t)v;
            } else {
                gid = idmap_name_to_gid(&bctx->idmap, value);
                if (gid == (uint32_t)-1) {
                    fprintf(stderr, "set: unknown group: %s\n", value);
                    return 0;
                }
                ctx->gid = gid;
            }
        }
        gname = idmap_gid_to_name(&bctx->idmap, ctx->gid);
        if (gname == NULL && ctx->gid == 0)
            gname = "root";
        if (gname) {
            snprintf(numbuf, sizeof(numbuf), "%u (%s)", ctx->gid, gname);
        } else {
            snprintf(numbuf, sizeof(numbuf), "%u", ctx->gid);
        }
        set_print("gid", numbuf, NULL);
        if (!show_all)
            return 0;
    }

    if (name && !show_all) {
        fprintf(stderr, "set: unknown setting: %s\n", name);
        fprintf(stderr, "Valid settings: autouid, completion, uid, gid\n");
    }

    return 0;
}

int
bcmd_id(struct browse_ctx *bctx, int argc, char **argv)
{
    struct nfsctx *ctx = bctx->nfs;
    const char *uname, *gname, *grpname;
    uint32_t gids[IDMAP_MAX_GROUPS];
    int ngids, i;
    int show_all = 0;
    int first;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0)
            show_all = 1;
    }

    uname = idmap_uid_to_name(&bctx->idmap, ctx->uid);
    gname = idmap_gid_to_name(&bctx->idmap, ctx->gid);

    if (uname == NULL && ctx->uid == 0)
        uname = "root";
    if (gname == NULL && ctx->gid == 0)
        gname = "root";

    if (uname)
        printf("uid=%u(%s)", ctx->uid, uname);
    else
        printf("uid=%u", ctx->uid);

    if (gname)
        printf(" gid=%u(%s)", ctx->gid, gname);
    else
        printf(" gid=%u", ctx->gid);

    if (show_all) {
        ngids = idmap_get_user_groups(&bctx->idmap, ctx->uid, gids, IDMAP_MAX_GROUPS);
        if (ngids > 0) {
            printf(" groups=");
            first = 1;
            for (i = 0; i < ngids; i++) {
                grpname = idmap_gid_to_name(&bctx->idmap, gids[i]);
                if (grpname == NULL && gids[i] == 0)
                    grpname = "root";
                if (!first)
                    printf(",");
                if (grpname)
                    printf("%u(%s)", gids[i], grpname);
                else
                    printf("%u", gids[i]);
                first = 0;
            }
        }
    }

    printf("\n");
    return 0;
}

int
bcmd_chmod(struct browse_ctx *bctx, int argc, char **argv)
{
    struct parsed_args pa;
    struct nfs_sattr sattr;
    const char *modestr;
    struct path_result res;
    uint32_t mode;
    int i;

    if (parse_cmdline_shell(argc, argv, "", 2, PARSED_ARGS_MAX, &pa) < 0)
        return 0;

    modestr = pa.args[0];

    if (parse_mode(modestr, &mode) < 0) {
        fprintf(stderr, "chmod: invalid mode: %s\n", modestr);
        return -1;
    }

    for (i = 1; i < pa.nargs; i++) {
        if (path_resolve(bctx->pctx, pa.args[i], 0, &res) < 0) {
            fprintf(stderr, "chmod: %s: %s\n", pa.args[i], strerror(errno));
            continue;
        }

        nfs_sattr_init(&sattr);
        sattr.set_mode = 1;
        sattr.mode = mode;
        if (nfs_setattr(bctx->nfs, &res.fh, &sattr) < 0)
            fprintf(stderr, "chmod: %s: %s\n", pa.args[i], strerror(errno));
    }

    return 0;
}

/*
 * Parse uid/gid string for chown.
 */
static int
parse_id(struct browse_ctx *bctx, const char *str, uint32_t *out,
    const char *name, int is_gid)
{
    char *endp;
    uint32_t id;

    if (strcmp(str, "-2") == 0) {
        *out = (uint32_t)-2;
        return 0;
    }

    if (str[0] == '-') {
        fprintf(stderr, "chown: invalid %s: %s (only -2 allowed)\n", name, str);
        return -1;
    }

    if (bctx->idmap.loaded) {
        if (is_gid)
            id = idmap_name_to_gid(&bctx->idmap, str);
        else
            id = idmap_name_to_uid(&bctx->idmap, str);
        if (id != (uint32_t)-1) {
            *out = id;
            return 0;
        }
    }

    errno = 0;
    *out = strtoul(str, &endp, 10);
    if (endp == str || *endp != '\0' || errno != 0) {
        fprintf(stderr, "chown: invalid %s: %s\n", name, str);
        return -1;
    }

    return 0;
}

int
bcmd_chown(struct browse_ctx *bctx, int argc, char **argv)
{
    struct nfs_sattr sattr;
    struct parsed_args pa;
    char *owner_copy;
    char *colon;
    int i;

    if (parse_cmdline_shell(argc, argv, "", 2, PARSED_ARGS_MAX, &pa) < 0)
        return 0;

    /* Copy owner string since we may modify it to split owner:group */
    owner_copy = strdup(pa.args[0]);
    if (owner_copy == NULL) {
        fprintf(stderr, "chown: out of memory\n");
        return -1;
    }

    nfs_sattr_init(&sattr);

    colon = strchr(owner_copy, ':');
    if (colon != NULL) {
        *colon = '\0';
        if (*owner_copy != '\0') {
            sattr.set_uid = 1;
            if (parse_id(bctx, owner_copy, &sattr.uid, "uid", 0) < 0) {
                free(owner_copy);
                return -1;
            }
        }
        if (*(colon + 1) != '\0') {
            sattr.set_gid = 1;
            if (parse_id(bctx, colon + 1, &sattr.gid, "gid", 1) < 0) {
                free(owner_copy);
                return -1;
            }
        }
    } else {
        sattr.set_uid = 1;
        if (parse_id(bctx, owner_copy, &sattr.uid, "uid", 0) < 0) {
            free(owner_copy);
            return -1;
        }
    }

    free(owner_copy);

    for (i = 1; i < pa.nargs; i++) {
        struct path_result res;

        if (path_resolve(bctx->pctx, pa.args[i], 0, &res) < 0) {
            fprintf(stderr, "chown: %s: %s\n", pa.args[i], strerror(errno));
            continue;
        }

        if (nfs_setattr(bctx->nfs, &res.fh, &sattr) < 0)
            fprintf(stderr, "chown: %s: %s\n", pa.args[i], strerror(errno));
    }

    return 0;
}

int
bcmd_mknod(struct browse_ctx *bctx, int argc, char **argv)
{
    struct path_result res;
    struct nfs_create_res create_res;
    const char *type_str;
    const char *path;
    uint32_t mode = 0644;
    uint32_t major = 0, minor = 0;
    int type;
    int needs_devnums;
    char *ep;

    if (argc < 3) {
        fprintf(stderr, "Usage: mknod <type> <name> [<mode>] [<major> <minor>]\n");
        fprintf(stderr, "Types: chr, blk, sock, fifo\n");
        return 0;
    }

    if (bctx->nfs->proto.nfs_version < 3) {
        fprintf(stderr, "mknod: requires NFSv3\n");
        return 0;
    }

    type_str = argv[1];
    path = argv[2];

    if (strcmp(type_str, "chr") == 0) {
        type = NFS_FTYPE_CHR;
        needs_devnums = 1;
    } else if (strcmp(type_str, "blk") == 0) {
        type = NFS_FTYPE_BLK;
        needs_devnums = 1;
    } else if (strcmp(type_str, "fifo") == 0) {
        type = NFS_FTYPE_FIFO;
        needs_devnums = 0;
    } else if (strcmp(type_str, "sock") == 0) {
        type = NFS_FTYPE_SOCK;
        needs_devnums = 0;
    } else {
        fprintf(stderr, "mknod: unknown type '%s' (use chr, blk, sock, fifo)\n",
            type_str);
        return 0;
    }

    if (argc >= 4) {
        errno = 0;
        mode = strtoul(argv[3], &ep, 8);
        if (ep == argv[3] || *ep != '\0' || errno != 0) {
            fprintf(stderr, "mknod: invalid mode '%s'\n", argv[3]);
            return 0;
        }
    }

    if (needs_devnums) {
        if (argc < 6) {
            fprintf(stderr, "mknod: %s requires major and minor numbers\n",
                type_str);
            return 0;
        }
        errno = 0;
        major = strtoul(argv[4], &ep, 0);
        if (ep == argv[4] || *ep != '\0' || errno != 0) {
            fprintf(stderr, "mknod: invalid major '%s'\n", argv[4]);
            return 0;
        }
        errno = 0;
        minor = strtoul(argv[5], &ep, 0);
        if (ep == argv[5] || *ep != '\0' || errno != 0) {
            fprintf(stderr, "mknod: invalid minor '%s'\n", argv[5]);
            return 0;
        }
    } else if (argc > 4) {
        fprintf(stderr, "mknod: %s does not use major/minor numbers\n",
            type_str);
        return 0;
    }

    if (path_resolve(bctx->pctx, path, PATH_WANT_PARENT, &res) < 0) {
        fprintf(stderr, "mknod: %s: %s\n", path, strerror(errno));
        return 0;
    }
    if (!res.has_parent) {
        fprintf(stderr, "mknod: %s: parent not found\n", path);
        return 0;
    }

    memset(&create_res, 0, sizeof(create_res));
    if (nfs_mknod(bctx->nfs, &res.parent_fh, res.basename, type, mode,
            major, minor, &create_res) < 0) {
        fprintf(stderr, "mknod: %s: %s\n", path, strerror(errno));
        return 0;
    }

    return 0;
}
