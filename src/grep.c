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
 * grep.c - grep command for browse shell
 */

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "browse_cmd.h"
#include "browse_ctx.h"
#include "cmdparse.h"
#include "constants.h"
#include "find.h"
#include "nfs.h"
#include "nfs_types.h"
#include "pathctx.h"
#include "transfer.h"

#define GREP_BUFSIZE LOCAL_BUFSIZE
#define GREP_MAXLINE LOCAL_MAXLINE

/* Interrupt flag from browse.c */
extern volatile sig_atomic_t browse_interrupted;

/* Grep options */
struct grep_opts {
    const char *pattern;
    int case_insensitive; /* -i */
    int invert_match;     /* -v */
    int line_numbers;     /* -n */
    int recursive;        /* -r */
    int multiple_files;   /* Print filename prefix */
};

/*
 * Case-insensitive strstr
 */
static char *
strcasestr_local(const char *haystack, const char *needle)
{
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);
    size_t i;

    if (nlen == 0)
        return (char *)haystack;
    if (nlen > hlen)
        return NULL;

    for (i = 0; i <= hlen - nlen; i++) {
        if (strncasecmp(haystack + i, needle, nlen) == 0)
            return (char *)(haystack + i);
    }
    return NULL;
}

/*
 * Check if line matches pattern
 */
static int
line_matches(const char *line, struct grep_opts *opts)
{
    int found;

    if (opts->case_insensitive)
        found = (strcasestr_local(line, opts->pattern) != NULL);
    else
        found = (strstr(line, opts->pattern) != NULL);

    if (opts->invert_match)
        return !found;
    return found;
}

/*
 * Grep a single file (from pipe input or NFS)
 */
static int
grep_file(struct pathctx *pctx, const struct nfs_fh *fh, FILE *pipe_in,
    const char *filename, struct grep_opts *opts)
{
    char line[GREP_MAXLINE];
    int linenum = 0;
    int found_any = 0;

    if (pipe_in != NULL) {
        /* Read from pipe input */
        while (fgets(line, sizeof(line), pipe_in) != NULL) {
            linenum++;
            /* Remove trailing newline for matching, but keep for output */
            size_t len = strlen(line);
            int had_newline = (len > 0 && line[len - 1] == '\n');
            if (had_newline)
                line[len - 1] = '\0';

            if (line_matches(line, opts)) {
                found_any = 1;
                if (opts->multiple_files && filename)
                    printf("%s:", filename);
                if (opts->line_numbers)
                    printf("%d:", linenum);
                printf("%s", line);
                if (had_newline)
                    printf("\n");
            }
        }
    } else if (fh != NULL) {
        /* Read from NFS file */
        uint64_t offset = 0;
        char linebuf[GREP_MAXLINE];
        size_t linepos = 0;
        int warned_binary = 0;

        for (;;) {
            struct nfs_read_res res;
            size_t i;

            memset(&res, 0, sizeof(res));
            if (nfs_read(pctx->nfs, fh, offset, GREP_BUFSIZE, &res) < 0)
                break;
            if (res.count == 0) {
                nfs_read_res_free(&res);
                break;
            }

            /* Sanity check: data pointer must be valid */
            if (res.data == NULL) {
                nfs_read_res_free(&res);
                break;
            }

            /* Check for binary content in first chunk */
            if (offset == 0 && !warned_binary) {
                for (i = 0; i < res.count && i < 512; i++) {
                    if (res.data[i] == 0) {
                        warned_binary = 1;
                        break;
                    }
                }
            }

            /* Process buffer, extracting lines */
            for (i = 0; i < res.count; i++) {
                uint8_t c = res.data[i];
                if (c == '\n') {
                    linebuf[linepos] = '\0';
                    linenum++;
                    if (line_matches(linebuf, opts)) {
                        if (warned_binary) {
                            /* Binary file with match - print once and stop */
                            printf("Binary file %s matches\n",
                                filename ? filename : "(stdin)");
                            nfs_read_res_free(&res);
                            return 1;
                        }
                        found_any = 1;
                        if (opts->multiple_files && filename)
                            printf("%s:", filename);
                        if (opts->line_numbers)
                            printf("%d:", linenum);
                        printf("%s\n", linebuf);
                    }
                    linepos = 0;
                } else if (linepos < sizeof(linebuf) - 1) {
                    linebuf[linepos++] = c;
                }
            }

            offset += res.count;
            if (res.eof) {
                nfs_read_res_free(&res);
                break;
            }
            nfs_read_res_free(&res);
        }

        /* Handle last line without newline */
        if (linepos > 0) {
            linebuf[linepos] = '\0';
            linenum++;
            if (line_matches(linebuf, opts)) {
                if (warned_binary) {
                    printf("Binary file %s matches\n",
                        filename ? filename : "(stdin)");
                    return 1;
                }
                found_any = 1;
                if (opts->multiple_files && filename)
                    printf("%s:", filename);
                if (opts->line_numbers)
                    printf("%d:", linenum);
                printf("%s\n", linebuf);
            }
        }
    }

    return found_any;
}

/*
 * Recursive grep implementation
 */
static int
grep_recurse(struct pathctx *pctx, const struct nfs_fh *dir_fh, uint64_t dir_fileid,
    const char *path, struct grep_opts *opts, struct visited_set *vs, int depth)
{
    struct nfs_dir nfs_dir = {0};
    size_t i;
    int found_any = 0;
    struct nfs_dirent *ent;
    char fullpath[NFS_MAXPATHLEN];
    struct path_result res;

    /* Check for Ctrl-C interrupt */
    if (browse_interrupted)
        return 0;

    if (depth > MAX_RECURSION_DEPTH)
        return 0;

    /* Check for loop */
    if (visited_check_add(vs, dir_fileid) != 0)
        return 0;

    if (nfs_readdirplus(pctx->nfs, dir_fh, &nfs_dir, 0) < 0) {
        visited_pop(vs);
        return 0;
    }

    for (i = 0; i < nfs_dir.count && !browse_interrupted; i++) {
        ent = &nfs_dir.entries[i];

        if (strcmp(ent->name, ".") == 0 || strcmp(ent->name, "..") == 0)
            continue;

        if (path_join(path, ent->name, fullpath, sizeof(fullpath)) < 0)
            continue;

        if (dirent_resolve(pctx, ent, fullpath, &res) < 0)
            continue;

        if (res.attr.type == NFS_FTYPE_DIR) {
            found_any |= grep_recurse(pctx, &res.fh, res.attr.fileid, fullpath, opts, vs, depth + 1);
        } else if (res.attr.type == NFS_FTYPE_REG) {
            found_any |= grep_file(pctx, &res.fh, NULL, fullpath, opts);
        }
    }

    nfs_dir_free(&nfs_dir);
    visited_pop(vs);
    return found_any;
}

/*
 * grep command: grep [-i] [-v] [-n] [-r] pattern [file...]
 */
int
bcmd_grep(struct browse_ctx *bctx, int argc, char **argv)
{
    struct pathctx *pctx = bctx->pctx;
    FILE *pipe_input = bctx->pipe_input;
    struct grep_opts opts = {0};
    struct visited_set vs;
    const char *files[BROWSE_MAX_FILE_ARGS];
    int nfiles = 0;
    int i;
    int found_any = 0;

    /* Parse arguments */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            opts.case_insensitive = 1;
        } else if (strcmp(argv[i], "-v") == 0) {
            opts.invert_match = 1;
        } else if (strcmp(argv[i], "-n") == 0) {
            opts.line_numbers = 1;
        } else if (strcmp(argv[i], "-r") == 0) {
            opts.recursive = 1;
        } else if (argv[i][0] == '-' && argv[i][1] != '\0') {
            /* Handle combined options like -in or -rn */
            const char *p = argv[i] + 1;
            while (*p) {
                switch (*p) {
                case 'i':
                    opts.case_insensitive = 1;
                    break;
                case 'v':
                    opts.invert_match = 1;
                    break;
                case 'n':
                    opts.line_numbers = 1;
                    break;
                case 'r':
                    opts.recursive = 1;
                    break;
                default:
                    fprintf(stderr, "*** Unknown option: -%c\n", *p);
                    return -1;
                }
                p++;
            }
        } else if (opts.pattern == NULL) {
            opts.pattern = argv[i];
        } else {
            if (nfiles < BROWSE_MAX_FILE_ARGS)
                files[nfiles++] = argv[i];
        }
    }

    if (opts.pattern == NULL) {
        fprintf(stderr, "grep: missing pattern operand\n");
        fprintf(stderr, "Usage: grep [-ivnr] pattern [file...]\n");
        errno = 0;
        return -1;
    }

    /* If no files and have pipe input, grep from pipe */
    if (nfiles == 0 && pipe_input != NULL) {
        return grep_file(pctx, NULL, pipe_input, NULL, &opts);
    }

    /* If no files and no pipe input, default to current dir for -r */
    if (nfiles == 0) {
        if (opts.recursive) {
            files[0] = ".";
            nfiles = 1;
        } else {
            fprintf(stderr, "grep: missing file operand\n");
            errno = 0;
            return -1;
        }
    }

    opts.multiple_files = (nfiles > 1) || opts.recursive;

    visited_init(&vs);

    for (i = 0; i < nfiles; i++) {
        struct path_result res;

        if (path_resolve(pctx, files[i], PATH_FOLLOW, &res) < 0) {
            fprintf(stderr, "*** %s: No such file or directory\n", files[i]);
            continue;
        }

        /* Get attributes if needed */
        if (!res.has_attr) {
            if (nfs_getattr(pctx->nfs, &res.fh, &res.attr) < 0) {
                fprintf(stderr, "*** %s: Cannot get attributes\n", files[i]);
                continue;
            }
            res.has_attr = 1;
        }

        if (res.attr.type == NFS_FTYPE_DIR) {
            if (opts.recursive) {
                found_any |= grep_recurse(pctx, &res.fh, res.attr.fileid,
                    files[i], &opts, &vs, 0);
            } else {
                fprintf(stderr, "*** %s: Is a directory\n", files[i]);
            }
        } else if (res.attr.type == NFS_FTYPE_REG) {
            found_any |= grep_file(pctx, &res.fh, NULL, files[i], &opts);
        } else {
            fprintf(stderr, "*** %s: Not a regular file\n", files[i]);
        }
    }

    visited_free(&vs);
    return 0;
}
