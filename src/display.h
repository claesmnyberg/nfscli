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
 * display.h - Display and formatting utilities
 *
 * Provides terminal utilities, attribute formatting, and directory
 * listing helpers for the interactive shell modes.
 */

#ifndef DISPLAY_H
#define DISPLAY_H

#include <stdint.h>
#include <stdio.h>

#include "nfs_types.h"

struct nfsctx;

/*
 * Attribute string formatting options
 */
#define ATTRSTR_LONG   0x01
#define ATTRSTR_COLORS 0x02
#define ATTRSTR_NOPAD  0x04

/* Aliases for readdirplus options */
#define READDIRPLUS_OPT_LONG   ATTRSTR_LONG
#define READDIRPLUS_OPT_COLORS ATTRSTR_COLORS

/*
 * Terminal utilities
 */

/* Get terminal width, defaulting to 80 if unavailable */
int term_width(void);

/* Check if colors should be used (stdout is a terminal) */
int term_use_colors(void);

/* Print strings in columns (caller must sort if desired) */
void print_columns(char **names, size_t count);

/* Compare names for qsort() - works with arrays of char* or structs with name as first member */
int name_cmp(const void *a, const void *b);

/* Get ANSI color string for file type (e.g., blue for directories) */
const char *color_for_type(const struct nfs_attr *attr);

/*
 * Utility functions for formatting
 */

/* File type character for ls -l style output (d, -, l, b, c, s, p) */
char filetype_char(uint32_t type);

/* Mode string in rwxrwxrwx format - writes to buf, returns buf */
char *fmt_mode(uint32_t mode, char *buf);

/*
 * Decode rdev into major/minor based on NFS version.
 * NFSv3: major/minor are separate 32-bit fields stored in rdev.
 * NFSv2: Linux-style encoding (major << 8 | minor) in 32-bit value.
 */
void decode_rdev(struct nfsctx *ctx, uint64_t rdev,
    uint32_t *major, uint32_t *minor);

/*
 * Format attributes into a human-readable string
 * Returns pointer to buf on success, NULL on error
 */
char *fmt_attr(struct nfsctx *ctx, const struct nfs_attr *attr,
    uint32_t opts, const char *name, char *buf, size_t buflen);

/*
 * Read and print directory contents (shell command)
 * Uses READDIR procedure
 */
int list_dir(struct nfsctx *ctx, uint32_t opts,
    const uint8_t *fh, int fhlen);

/*
 * Read and print directory contents with attributes (shell command)
 * Uses READDIRPLUS for v3, falls back to READDIR+GETATTR for v2
 */
int list_dir_plus(struct nfsctx *ctx, uint32_t opts,
    const uint8_t *fh, int fhlen);

/*
 * Read and print directory contents - version-aware.
 * Uses READDIR on v2 (returns names only), READDIRPLUS on v3 (with attrs).
 */
int list_dir_auto(struct nfsctx *ctx, uint32_t opts,
    const uint8_t *fh, int fhlen);

#endif /* DISPLAY_H */
