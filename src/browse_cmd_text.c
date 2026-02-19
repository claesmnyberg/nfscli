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
 * browse_cmd_text.c - Text utility commands for browse shell (head, tail, wc, strings, xxd)
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "browse_cmd.h"
#include "browse_ctx.h"
#include "cmdparse.h"
#include "constants.h"
#include "nfs.h"
#include "nfs_types.h"
#include "pathctx.h"
#include "str.h"

#define TEXT_BUFSIZE LOCAL_BUFSIZE
#define TEXT_MAXLINE LOCAL_MAXLINE

/* Interrupt flag from browse.c */
extern volatile sig_atomic_t browse_interrupted;

/*
 * Read file content into a callback function, line by line
 * Returns number of lines processed, or -1 on error
 */
static int
process_lines(struct pathctx *pctx, const struct nfs_fh *fh, FILE *pipe_in,
    void (*callback)(const char *line, int linenum, void *ctx), void *ctx)
{
    char line[TEXT_MAXLINE];
    int linenum = 0;

    if (pipe_in != NULL) {
        size_t len;

        while (!browse_interrupted && fgets(line, sizeof(line), pipe_in) != NULL) {
            linenum++;
            len = strlen(line);
            if (len > 0 && line[len - 1] == '\n')
                line[len - 1] = '\0';
            callback(line, linenum, ctx);
        }
    } else if (fh != NULL) {
        char linebuf[TEXT_MAXLINE];
        struct nfs_read_res res;
        uint64_t offset = 0;
        size_t linepos = 0;
        size_t i;
        uint8_t c;

        for (;;) {
            /* Check for Ctrl-C interrupt */
            if (browse_interrupted)
                break;

            memset(&res, 0, sizeof(res));
            if (nfs_read(pctx->nfs, fh, offset, TEXT_BUFSIZE, &res) < 0)
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

            for (i = 0; i < res.count && !browse_interrupted; i++) {
                c = res.data[i];
                if (c == '\n') {
                    linebuf[linepos] = '\0';
                    linenum++;
                    callback(linebuf, linenum, ctx);
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
            callback(linebuf, linenum, ctx);
        }
    }

    return linenum;
}

/*
 * Read raw bytes from file
 * Returns bytes read, or -1 on error
 */
static int
process_bytes(struct pathctx *pctx, const struct nfs_fh *fh, FILE *pipe_in,
    void (*callback)(const uint8_t *data, size_t len, void *ctx), void *ctx)
{
    struct nfs_read_res res;
    uint8_t buf[TEXT_BUFSIZE];
    uint64_t offset;
    size_t total = 0;
    size_t n;

    if (pipe_in != NULL) {
        while (!browse_interrupted && (n = fread(buf, 1, sizeof(buf), pipe_in)) > 0) {
            callback(buf, n, ctx);
            total += n;
        }
    } else if (fh != NULL) {
        offset = 0;
        for (;;) {
            /* Check for Ctrl-C interrupt */
            if (browse_interrupted)
                break;

            memset(&res, 0, sizeof(res));
            if (nfs_read(pctx->nfs, fh, offset, TEXT_BUFSIZE, &res) < 0)
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

            callback(res.data, res.count, ctx);
            total += res.count;

            offset += res.count;
            if (res.eof) {
                nfs_read_res_free(&res);
                break;
            }
            nfs_read_res_free(&res);
        }
    }

    return (int)total;
}

/*
 * Generic file iterator for text commands.
 * Handles path resolution, attribute fetching, type checking, and spacing.
 * Callback is called for each successfully resolved regular file.
 * Returns 0 on success, -1 if no files processed.
 */
typedef int (*file_processor)(struct pathctx *pctx, const struct nfs_fh *fh,
    const char *filename, int multiple, void *ctx);

static int
foreach_file(struct pathctx *pctx, const char **files, int nfiles,
    file_processor proc, void *ctx)
{
    int i, processed = 0;

    for (i = 0; i < nfiles; i++) {
        struct path_result res;

        if (path_resolve(pctx, files[i], PATH_FOLLOW, &res) < 0) {
            fprintf(stderr, "%s: No such file or directory\n", files[i]);
            continue;
        }

        if (!res.has_attr) {
            if (nfs_getattr(pctx->nfs, &res.fh, &res.attr) < 0) {
                fprintf(stderr, "%s: Cannot get attributes\n", files[i]);
                continue;
            }
        }

        if (res.attr.type != NFS_FTYPE_REG) {
            fprintf(stderr, "%s: Not a regular file\n", files[i]);
            continue;
        }

        proc(pctx, &res.fh, files[i], nfiles > 1, ctx);
        processed++;

        if (i < nfiles - 1 && nfiles > 1)
            printf("\n");
    }

    return processed > 0 ? 0 : -1;
}

/*
 * HEAD command
 */

struct head_ctx {
    int max_lines;
    int count;
};

static void
head_callback(const char *line, int linenum, void *ctx)
{
    struct head_ctx *hc = ctx;
    (void)linenum;
    if (hc->count < hc->max_lines) {
        printf("%s\n", line);
        hc->count++;
    }
}

static void
head_file(struct pathctx *pctx, const struct nfs_fh *fh, FILE *pipe_in,
    const char *filename, int nlines, int multiple)
{
    struct head_ctx hc;

    hc.max_lines = nlines;
    hc.count = 0;

    if (multiple && filename)
        printf("==> %s <==\n", filename);

    process_lines(pctx, fh, pipe_in, head_callback, &hc);
}

/* Wrapper matching file_processor signature */
static int
head_file_proc(struct pathctx *pctx, const struct nfs_fh *fh,
    const char *filename, int multiple, void *ctx)
{
    int *nlines = ctx;
    head_file(pctx, fh, NULL, filename, *nlines, multiple);
    return 0;
}

/*
 * head command: head [-n lines] [file...]
 */
int
bcmd_head(struct browse_ctx *bctx, int argc, char **argv)
{
    struct pathctx *pctx = bctx->pctx;
    FILE *pipe_input = bctx->pipe_input;
    int nlines = 10;
    const char *files[BROWSE_MAX_FILE_ARGS];
    int nfiles = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            i++;
            if (str_to_int(argv[i], &nlines, 1, INT_MAX) < 0)
                nlines = 10;
        } else if (argv[i][0] != '-') {
            if (nfiles < BROWSE_MAX_FILE_ARGS)
                files[nfiles++] = argv[i];
        } else {
            fprintf(stderr, "head: unknown option: %s\n", argv[i]);
            errno = 0;
            return -1;
        }
    }

    if (nfiles == 0 && pipe_input != NULL) {
        head_file(pctx, NULL, pipe_input, NULL, nlines, 0);
        return 0;
    }

    if (nfiles == 0) {
        fprintf(stderr, "head: missing file operand\n");
        errno = 0;
        return -1;
    }

    return foreach_file(pctx, files, nfiles, head_file_proc, &nlines);
}

/*
 * TAIL command
 */

struct tail_ctx {
    char **lines; /* Circular buffer */
    int max_lines;
    int count;
    int head;     /* Next write position */
};

static void
tail_callback(const char *line, int linenum, void *ctx)
{
    struct tail_ctx *tc = ctx;
    char *dup;
    (void)linenum;

    dup = strdup(line);
    if (dup == NULL)
        return; /* Skip line on allocation failure */

    free(tc->lines[tc->head]);
    tc->lines[tc->head] = dup;
    tc->head = (tc->head + 1) % tc->max_lines;
    tc->count++;
}

static int
tail_file(struct pathctx *pctx, const struct nfs_fh *fh, FILE *pipe_in,
    const char *filename, int nlines, int multiple)
{
    struct tail_ctx tc;
    int i, start, n;

    tc.lines = calloc(nlines, sizeof(char *));
    if (tc.lines == NULL)
        return -1;
    tc.max_lines = nlines;
    tc.count = 0;
    tc.head = 0;

    if (multiple && filename)
        printf("==> %s <==\n", filename);

    process_lines(pctx, fh, pipe_in, tail_callback, &tc);

    /* Output the last N lines */
    n = (tc.count < nlines) ? tc.count : nlines;
    start = (tc.count < nlines) ? 0 : tc.head;

    for (i = 0; i < n; i++) {
        int idx = (start + i) % nlines;
        if (tc.lines[idx])
            printf("%s\n", tc.lines[idx]);
    }

    for (i = 0; i < nlines; i++)
        free(tc.lines[i]);
    free(tc.lines);

    return 0;
}

/* Wrapper matching file_processor signature */
static int
tail_file_proc(struct pathctx *pctx, const struct nfs_fh *fh,
    const char *filename, int multiple, void *ctx)
{
    int *nlines = ctx;
    return tail_file(pctx, fh, NULL, filename, *nlines, multiple);
}

/*
 * tail command: tail [-n lines] [file...]
 */
int
bcmd_tail(struct browse_ctx *bctx, int argc, char **argv)
{
    struct pathctx *pctx = bctx->pctx;
    FILE *pipe_input = bctx->pipe_input;
    int nlines = 10;
    const char *files[BROWSE_MAX_FILE_ARGS];
    int nfiles = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            i++;
            if (str_to_int(argv[i], &nlines, 1, INT_MAX) < 0)
                nlines = 10;
        } else if (argv[i][0] != '-') {
            if (nfiles < BROWSE_MAX_FILE_ARGS)
                files[nfiles++] = argv[i];
        } else {
            fprintf(stderr, "tail: unknown option: %s\n", argv[i]);
            errno = 0;
            return -1;
        }
    }

    if (nfiles == 0 && pipe_input != NULL) {
        return tail_file(pctx, NULL, pipe_input, NULL, nlines, 0);
    }

    if (nfiles == 0) {
        fprintf(stderr, "tail: missing file operand\n");
        errno = 0;
        return -1;
    }

    return foreach_file(pctx, files, nfiles, tail_file_proc, &nlines);
}

/*
 * WC command
 */

struct wc_ctx {
    uint64_t lines;
    uint64_t words;
    uint64_t bytes;
    int in_word;
};

static void
wc_byte_callback(const uint8_t *data, size_t len, void *ctx)
{
    struct wc_ctx *wc = ctx;
    size_t i;
    uint8_t c;

    wc->bytes += len;

    for (i = 0; i < len; i++) {
        c = data[i];

        if (c == '\n')
            wc->lines++;

        if (isspace(c)) {
            wc->in_word = 0;
        } else {
            if (!wc->in_word) {
                wc->words++;
                wc->in_word = 1;
            }
        }
    }
}

struct wc_opts {
    int show_lines;
    int show_words;
    int show_bytes;
    uint64_t total_lines;
    uint64_t total_words;
    uint64_t total_bytes;
};

static int
wc_file(struct pathctx *pctx, const struct nfs_fh *fh, FILE *pipe_in,
    const char *filename, struct wc_opts *opts)
{
    struct wc_ctx wc = {0};

    process_bytes(pctx, fh, pipe_in, wc_byte_callback, &wc);

    opts->total_lines += wc.lines;
    opts->total_words += wc.words;
    opts->total_bytes += wc.bytes;

    if (opts->show_lines)
        printf("%8lu ", (unsigned long)wc.lines);
    if (opts->show_words)
        printf("%8lu ", (unsigned long)wc.words);
    if (opts->show_bytes)
        printf("%8lu ", (unsigned long)wc.bytes);
    if (filename)
        printf("%s", filename);
    printf("\n");

    return 0;
}

/* Wrapper matching file_processor signature */
static int
wc_file_proc(struct pathctx *pctx, const struct nfs_fh *fh,
    const char *filename, int multiple, void *ctx)
{
    (void)multiple;
    return wc_file(pctx, fh, NULL, filename, ctx);
}

/*
 * wc command: wc [-l] [-w] [-c] [file...]
 */
int
bcmd_wc(struct browse_ctx *bctx, int argc, char **argv)
{
    struct pathctx *pctx = bctx->pctx;
    FILE *pipe_input = bctx->pipe_input;
    struct wc_opts opts;
    const char *files[BROWSE_MAX_FILE_ARGS];
    const char *p;
    int nfiles = 0;
    int i, ret;

    memset(&opts, 0, sizeof(opts));

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            opts.show_lines = 1;
        } else if (strcmp(argv[i], "-w") == 0) {
            opts.show_words = 1;
        } else if (strcmp(argv[i], "-c") == 0) {
            opts.show_bytes = 1;
        } else if (argv[i][0] == '-' && argv[i][1] != '\0') {
            /* Handle combined options like -lwc */
            p = argv[i] + 1;
            while (*p) {
                switch (*p) {
                case 'l':
                    opts.show_lines = 1;
                    break;
                case 'w':
                    opts.show_words = 1;
                    break;
                case 'c':
                    opts.show_bytes = 1;
                    break;
                default:
                    fprintf(stderr, "wc: unknown option: -%c\n", *p);
                    errno = 0;
                    return -1;
                }
                p++;
            }
        } else if (argv[i][0] != '-') {
            if (nfiles < BROWSE_MAX_FILE_ARGS)
                files[nfiles++] = argv[i];
        }
    }

    /* Default: show all */
    if (!opts.show_lines && !opts.show_words && !opts.show_bytes) {
        opts.show_lines = opts.show_words = opts.show_bytes = 1;
    }

    if (nfiles == 0 && pipe_input != NULL) {
        return wc_file(pctx, NULL, pipe_input, NULL, &opts);
    }

    if (nfiles == 0) {
        fprintf(stderr, "wc: missing file operand\n");
        errno = 0;
        return -1;
    }

    ret = foreach_file(pctx, files, nfiles, wc_file_proc, &opts);

    /* Print total if multiple files */
    if (nfiles > 1) {
        if (opts.show_lines)
            printf("%8lu ", (unsigned long)opts.total_lines);
        if (opts.show_words)
            printf("%8lu ", (unsigned long)opts.total_words);
        if (opts.show_bytes)
            printf("%8lu ", (unsigned long)opts.total_bytes);
        printf("total\n");
    }

    return ret;
}

/*
 * STRINGS command
 */

struct strings_ctx {
    int min_len;
    char buf[4096];
    size_t pos;
    uint64_t offset;
};

static void
strings_flush(struct strings_ctx *sc)
{
    if (sc->pos >= (size_t)sc->min_len) {
        sc->buf[sc->pos] = '\0';
        printf("%s\n", sc->buf);
    }
    sc->pos = 0;
}

static void
strings_byte_callback(const uint8_t *data, size_t len, void *ctx)
{
    struct strings_ctx *sc = ctx;
    size_t i;
    uint8_t c;

    for (i = 0; i < len; i++) {
        c = data[i];

        if (isprint(c) || c == '\t') {
            if (sc->pos < sizeof(sc->buf) - 1)
                sc->buf[sc->pos++] = c;
        } else {
            strings_flush(sc);
        }
        sc->offset++;
    }
}

static int
strings_file(struct pathctx *pctx, const struct nfs_fh *fh, FILE *pipe_in,
    const char *filename, int min_len, int multiple)
{
    struct strings_ctx sc = {0};
    sc.min_len = min_len;

    if (multiple && filename)
        printf("==> %s <==\n", filename);

    process_bytes(pctx, fh, pipe_in, strings_byte_callback, &sc);
    strings_flush(&sc); /* Flush any remaining string */

    return 0;
}

/* Wrapper matching file_processor signature */
static int
strings_file_proc(struct pathctx *pctx, const struct nfs_fh *fh,
    const char *filename, int multiple, void *ctx)
{
    int *min_len = ctx;
    return strings_file(pctx, fh, NULL, filename, *min_len, multiple);
}

/*
 * strings command: strings [-n min] [file...]
 */
int
bcmd_strings(struct browse_ctx *bctx, int argc, char **argv)
{
    struct pathctx *pctx = bctx->pctx;
    FILE *pipe_input = bctx->pipe_input;
    int min_len = 4;
    const char *files[BROWSE_MAX_FILE_ARGS];
    int nfiles = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            i++;
            if (str_to_int(argv[i], &min_len, 1, INT_MAX) < 0)
                min_len = 4;
        } else if (argv[i][0] != '-') {
            if (nfiles < BROWSE_MAX_FILE_ARGS)
                files[nfiles++] = argv[i];
        } else {
            fprintf(stderr, "strings: unknown option: %s\n", argv[i]);
            errno = 0;
            return -1;
        }
    }

    if (nfiles == 0 && pipe_input != NULL) {
        return strings_file(pctx, NULL, pipe_input, NULL, min_len, 0);
    }

    if (nfiles == 0) {
        fprintf(stderr, "strings: missing file operand\n");
        errno = 0;
        return -1;
    }

    return foreach_file(pctx, files, nfiles, strings_file_proc, &min_len);
}

/*
 * XXD command
 */

struct xxd_ctx {
    uint64_t offset;
    uint8_t line[16];
    size_t line_pos;
};

static void
xxd_flush_line(struct xxd_ctx *xc)
{
    size_t i;
    uint8_t c;

    if (xc->line_pos == 0)
        return;

    /* Offset */
    printf("%08lx: ", (unsigned long)(xc->offset - xc->line_pos));

    /* Hex bytes */
    for (i = 0; i < 16; i++) {
        if (i < xc->line_pos)
            printf("%02x", xc->line[i]);
        else
            printf("  ");
        if (i % 2 == 1)
            printf(" ");
    }

    /* ASCII */
    printf(" ");
    for (i = 0; i < xc->line_pos; i++) {
        c = xc->line[i];
        printf("%c", isprint(c) ? c : '.');
    }
    printf("\n");

    xc->line_pos = 0;
}

static void
xxd_byte_callback(const uint8_t *data, size_t len, void *ctx)
{
    struct xxd_ctx *xc = ctx;
    size_t i;

    for (i = 0; i < len; i++) {
        xc->line[xc->line_pos++] = data[i];
        xc->offset++;

        if (xc->line_pos == 16)
            xxd_flush_line(xc);
    }
}

static int
xxd_file(struct pathctx *pctx, const struct nfs_fh *fh, FILE *pipe_in,
    const char *filename, int multiple)
{
    struct xxd_ctx xc = {0};

    if (multiple && filename)
        printf("==> %s <==\n", filename);

    process_bytes(pctx, fh, pipe_in, xxd_byte_callback, &xc);
    xxd_flush_line(&xc); /* Flush any remaining bytes */

    return 0;
}

/* Wrapper matching file_processor signature */
static int
xxd_file_proc(struct pathctx *pctx, const struct nfs_fh *fh,
    const char *filename, int multiple, void *ctx)
{
    (void)ctx;
    return xxd_file(pctx, fh, NULL, filename, multiple);
}

/*
 * xxd command: xxd [file...]
 */
int
bcmd_xxd(struct browse_ctx *bctx, int argc, char **argv)
{
    struct pathctx *pctx = bctx->pctx;
    FILE *pipe_input = bctx->pipe_input;
    const char *files[BROWSE_MAX_FILE_ARGS];
    int nfiles = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            if (nfiles < BROWSE_MAX_FILE_ARGS)
                files[nfiles++] = argv[i];
        } else {
            fprintf(stderr, "xxd: unknown option: %s\n", argv[i]);
            errno = 0;
            return -1;
        }
    }

    if (nfiles == 0 && pipe_input != NULL) {
        return xxd_file(pctx, NULL, pipe_input, NULL, 0);
    }

    if (nfiles == 0) {
        fprintf(stderr, "xxd: missing file operand\n");
        errno = 0;
        return -1;
    }

    return foreach_file(pctx, files, nfiles, xxd_file_proc, NULL);
}
