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
 * display.c - Display and formatting utilities
 *
 * Terminal utilities, attribute formatting, and directory listing
 * helpers for the interactive shell modes.
 */

#include <errno.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#ifndef NO_READLINE
#include <term.h>
#endif

#include "ansicolors.h"
#include "display.h"
#include "nfs.h"
#include "nfs_util.h"
#include "nfscli.h"
#include "str.h"

/*
 * Get terminal width, defaulting to 80 if unavailable.
 */
int
term_width(void)
{
    struct winsize ws;

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        return ws.ws_col;
    return 80;
}

/*
 * Check if colors should be used.
 * Returns true if stdout is a terminal that supports colors.
 */
int
term_use_colors(void)
{
#ifndef NO_READLINE
    int err;
    char *setaf;
#endif

    if (!isatty(STDOUT_FILENO))
        return 0;

#ifndef NO_READLINE
    /* Query terminfo for color support */
    if (setupterm(NULL, STDOUT_FILENO, &err) != 0 || err <= 0)
        return 0;

    /* Terminal must support setting foreground colors */
    setaf = tigetstr("setaf");
    if (setaf == NULL || setaf == (char *)(intptr_t)-1)
        return 0;
#endif

    return 1;
}

/*
 * Compare names for qsort().
 * Works for any struct with const char *name as first member.
 */
int
name_cmp(const void *a, const void *b)
{
    const char *const *name_a = a;
    const char *const *name_b = b;
    return strcmp(*name_a, *name_b);
}

/*
 * Get ANSI color string for file type.
 * Returns color escape sequence (e.g., COLOR_BBLUE for directories).
 */
const char *
color_for_type(const struct nfs_attr *attr)
{
    switch (attr->type) {
    case NFS_FTYPE_DIR:
        return COLOR_BBLUE;
    case NFS_FTYPE_LNK:
        return COLOR_BCYAN;
    case NFS_FTYPE_BLK:
    case NFS_FTYPE_CHR:
        return COLOR_BYELLOW;
    case NFS_FTYPE_SOCK:
    case NFS_FTYPE_FIFO:
        return COLOR_BMAGENTA;
    case NFS_FTYPE_REG:
        if (attr->mode & 0111)
            return COLOR_BGREEN;
        /* FALLTHROUGH */
    default:
        return COLOR_RESET;
    }
}

/*
 * Print strings in columns (caller must sort if desired).
 */
void
print_columns(char **names, size_t count)
{
    int terminal_width, col_width, num_cols, num_rows;
    size_t i, max_len, len, idx;
    int row, col;

    if (count == 0)
        return;

    /* Find maximum name length */
    max_len = 0;
    for (i = 0; i < count; i++) {
        len = strlen(names[i]);
        if (len > max_len)
            max_len = len;
    }

    /* Column width includes 2 spaces for padding */
    col_width = max_len + 2;
    terminal_width = term_width();

    /* Calculate columns and rows */
    num_cols = terminal_width / col_width;
    if (num_cols < 1)
        num_cols = 1;
    num_rows = (count + num_cols - 1) / num_cols;

    /* Print in column-major order (down, then across) */
    for (row = 0; row < num_rows; row++) {
        for (col = 0; col < num_cols; col++) {
            idx = col * num_rows + row;
            if (idx < count) {
                if (col == num_cols - 1 || idx + num_rows >= count) {
                    /* Last column or last entry - no padding */
                    printf("%s", names[idx]);
                } else {
                    printf("%-*s", col_width, names[idx]);
                }
            }
        }
        printf("\n");
    }
}

/*
 * File type character for ls -l style output
 */
char
filetype_char(uint32_t type)
{
    switch (type) {
    case NFS_FTYPE_REG:
        return '-';
    case NFS_FTYPE_DIR:
        return 'd';
    case NFS_FTYPE_BLK:
        return 'b';
    case NFS_FTYPE_CHR:
        return 'c';
    case NFS_FTYPE_LNK:
        return 'l';
    case NFS_FTYPE_SOCK:
        return 's';
    case NFS_FTYPE_FIFO:
        return 'p';
    default:
        return '?';
    }
}

/*
 * Mode string in rwxrwxrwx format
 */
char *
fmt_mode(uint32_t mode, char *buf)
{
    buf[0] = (mode & 0400) ? 'r' : '-';
    buf[1] = (mode & 0200) ? 'w' : '-';
    buf[2] = (mode & 0100) ? ((mode & 04000) ? 's' : 'x') : ((mode & 04000) ? 'S' : '-');
    buf[3] = (mode & 0040) ? 'r' : '-';
    buf[4] = (mode & 0020) ? 'w' : '-';
    buf[5] = (mode & 0010) ? ((mode & 02000) ? 's' : 'x') : ((mode & 02000) ? 'S' : '-');
    buf[6] = (mode & 0004) ? 'r' : '-';
    buf[7] = (mode & 0002) ? 'w' : '-';
    buf[8] = (mode & 0001) ? ((mode & 01000) ? 't' : 'x') : ((mode & 01000) ? 'T' : '-');
    buf[9] = '\0';
    return buf;
}

/*
 * Decode rdev into major/minor based on NFS version.
 * NFSv3: major/minor are separate 32-bit fields, stored as (major << 32) | minor.
 * NFSv2: Single 32-bit value with Linux-style encoding.
 *
 * Linux encoding: (major << 8) | minor for traditional 8-bit major/minor.
 * Linux 2.6+ uses a more complex scheme for minor >= 256, but the simple
 * encoding is backward compatible and covers 99%+ of real devices.
 */
void
decode_rdev(struct nfsctx *ctx, uint64_t rdev,
    uint32_t *major, uint32_t *minor)
{
    if (ctx->proto.nfs_version >= 3) {
        /* NFSv3: major in upper 32 bits, minor in lower 32 bits */
        *major = (uint32_t)(rdev >> 32);
        *minor = (uint32_t)(rdev & 0xFFFFFFFF);
    } else {
        /* NFSv2: Linux-style encoding in 32-bit value */
        *major = (rdev >> 8) & 0xFF;
        *minor = rdev & 0xFF;
    }
}

/*
 * Format attributes into a human-readable string
 * Always shows: type+mode nlink uid gid size mtime [name]
 * With ATTRSTR_LONG: adds ATIME/CTIME labels and FSID/FID at end
 */
char *
fmt_attr(struct nfsctx *ctx, const struct nfs_attr *attr,
    uint32_t opts, const char *name, char *buf, size_t buflen)
{
#define NAMEALIGN 32
    char modebuf[16];
    char timebuf[32];
    char atimebuf[32];
    char ctimebuf[32];
    char sizebuf[STR_HSIZE_BUFLEN];
    char namebuf[NAMEMAXLEN];
    uint32_t major, minor;
    size_t namelen;
    size_t pad;
    int n;

    (void)ctx;
    if (buf == NULL || buflen < 64)
        return NULL;

    /* Type and mode */
    n = snprintf(buf, buflen, "%c%s",
        filetype_char(attr->type),
        fmt_mode(attr->mode & 07777, modebuf));
    if (n < 0 || (size_t)n >= buflen)
        return buf;

    /* Number of links */
    n += snprintf(buf + n, buflen - n, "%4u ", attr->nlink);
    if ((size_t)n >= buflen)
        return buf;

    /* UID, GID (signed to show -2 for nobody/root-squash) */
    n += snprintf(buf + n, buflen - n, "  %-5d %-5d ", (int32_t)attr->uid, (int32_t)attr->gid);
    if ((size_t)n >= buflen)
        return buf;

    /* Size (or major,minor for devices) */
    if (attr->type == NFS_FTYPE_BLK || attr->type == NFS_FTYPE_CHR) {
        decode_rdev(ctx, attr->rdev, &major, &minor);
        n += snprintf(buf + n, buflen - n, "%3u, %2u ", major, minor);
    } else {
        n += snprintf(buf + n, buflen - n, "%6s  ", STR_HSIZE(attr->size, sizebuf));
    }
    if ((size_t)n >= buflen)
        return buf;

    /* Time fields */
    if (opts & ATTRSTR_LONG) {
        /* Extended format: ATIME:<time> MTIME:<time> CTIME:<time> */
        if (str_time(atimebuf, sizeof(atimebuf), attr->atime.sec) == NULL)
            snprintf(atimebuf, sizeof(atimebuf), "?");
        if (str_time(timebuf, sizeof(timebuf), attr->mtime.sec) == NULL)
            snprintf(timebuf, sizeof(timebuf), "?");
        if (str_time(ctimebuf, sizeof(ctimebuf), attr->ctime.sec) == NULL)
            snprintf(ctimebuf, sizeof(ctimebuf), "?");
        n += snprintf(buf + n, buflen - n, " ATIME:%s MTIME:%s CTIME:%s ",
            atimebuf, timebuf, ctimebuf);
        if ((size_t)n >= buflen)
            return buf;
    } else {
        /* Basic format: just mtime in ls-style */
        if (str_time_ls(timebuf, sizeof(timebuf), attr->mtime.sec) == NULL)
            snprintf(timebuf, sizeof(timebuf), "?");
        n += snprintf(buf + n, buflen - n, "%s ", timebuf);
        if ((size_t)n >= buflen)
            return buf;
    }

    /* Name with optional coloring and underscore padding */
    if (name && n < (int)buflen - 1) {
        if (opts & ATTRSTR_COLORS) {
            snprintf(namebuf, sizeof(namebuf), "%s%s%s",
                color_for_type(attr), name, COLOR_RESET);
        } else {
            snprintf(namebuf, sizeof(namebuf), "%s", name);
        }

        /* Add name with space prefix */
        n += snprintf(buf + n, buflen - n, " %s ", namebuf);
        if ((size_t)n >= buflen)
            return buf;

        /* Pad with underscores to NAMEALIGN (unless NOPAD) */
        if (!(opts & ATTRSTR_NOPAD)) {
            namelen = strlen(name);
            if (namelen < NAMEALIGN && n < (int)buflen - 1) {
                for (pad = namelen; pad < NAMEALIGN && n < (int)buflen - 1; pad++)
                    buf[n++] = '_';
                buf[n] = '\0';
            }
        }
    }

    /* FSID/FID (only with ATTRSTR_LONG) */
    if ((opts & ATTRSTR_LONG) && (size_t)n < buflen) {
        (void)snprintf(buf + n, buflen - n, " FSID:0x%lx FID:0x%-8lx",
            (unsigned long)attr->fsid, (unsigned long)attr->fileid);
    }

    return buf;
#undef NAMEALIGN
}

/*
 * Read and print directory contents
 */
int
list_dir(struct nfsctx *ctx, uint32_t opts,
    const uint8_t *fh, int fhlen)
{
    struct nfs_fh dirfh;
    struct nfs_dir dir;
    size_t i;
    int ret;

    (void)opts;
    nfs_fh_from_buf(&dirfh, fh, fhlen);
    memset(&dir, 0, sizeof(dir));

    ret = nfs_readdir(ctx, &dirfh, &dir);
    if (ret < 0)
        return ret;

    /* Sort for consistent display */
    if (dir.count > 1)
        qsort(dir.entries, dir.count, sizeof(*dir.entries), nfs_dirent_cmp);

    /* Print entries */
    for (i = 0; i < dir.count; i++) {
        struct nfs_dirent *ent = &dir.entries[i];
        printf("FID:%016lx %s\n", (unsigned long)ent->fileid, ent->name);
    }

    /* Free entries */
    nfs_dir_free(&dir);
    return 0;
}

/*
 * Read and print directory contents with attributes
 */
int
list_dir_plus(struct nfsctx *ctx, uint32_t opts,
    const uint8_t *fh, int fhlen)
{
    struct nfs_fh dirfh;
    struct nfs_dir dir;
    char attrbuf[ATTRBUFLEN];
    char fhbuf[512];
    size_t i;
    int ret;

    nfs_fh_from_buf(&dirfh, fh, fhlen);
    memset(&dir, 0, sizeof(dir));

    ret = nfs_readdirplus(ctx, &dirfh, &dir, NFS_READDIRPLUS_FULL);
    if (ret < 0)
        return ret;

    /* Sort for consistent display */
    if (dir.count > 1)
        qsort(dir.entries, dir.count, sizeof(*dir.entries), nfs_dirent_cmp);

    /* Print entries */
    for (i = 0; i < dir.count; i++) {
        struct nfs_dirent *ent = &dir.entries[i];

        if (!ent->has_attr && ent->has_fh) {
            /* No attributes but have file handle - fetch via GETATTR */
            if (nfs_getattr(ctx, &ent->fh, &ent->attr) == 0)
                ent->has_attr = 1;
        }

        /* Skip entries with no useful info (no attrs AND no FH) */
        if (!ent->has_attr && !ent->has_fh)
            continue;

        if (ent->has_attr) {
            fmt_attr(ctx, &ent->attr, opts, ent->name, attrbuf, sizeof(attrbuf));
            printf("%s", attrbuf);
        } else {
            /* Has FH but GETATTR failed - just print name */
            printf("%s ", ent->name);
        }

        /* Print file handle at end */
        if (ent->has_fh) {
            str_hex(ent->fh.data, ent->fh.len, fhbuf, sizeof(fhbuf));
            printf("FH:%s", fhbuf);
        }

        printf("\n");
    }

    /* Free entries */
    nfs_dir_free(&dir);
    return 0;
}

/*
 * Read and print directory contents - version-aware.
 * Uses READDIR on v2 (returns names only), READDIRPLUS on v3 (with attrs).
 */
int
list_dir_auto(struct nfsctx *ctx, uint32_t opts, const uint8_t *fh, int fhlen)
{
    if (ctx->proto.nfs_version < 3)
        return list_dir(ctx, opts, fh, fhlen);
    return list_dir_plus(ctx, opts, fh, fhlen);
}
