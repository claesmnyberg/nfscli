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
 * transfer.h - File transfer operations
 *
 * Provides file download/upload with progress, binary detection,
 * and helper functions for file I/O operations.
 */

#ifndef TRANSFER_H
#define TRANSFER_H

#include <stdint.h>
#include <stdio.h>

struct nfsctx;

/*
 * Flags for transfer_download:
 *   bit 0 (1): show progress dots
 *   bit 1 (2): print newline before first byte of content
 *   bit 2 (4): check for binary content, return DL_BINARY if detected
 */
#define DL_NONE         0
#define DL_PROGRESS     1
#define DL_NEWLINE      2
#define DL_CHECK_BINARY 4

/* Special return value for binary detection */
#define DL_BINARY (-2)

/*
 * Download from NFS file handle to a FILE*.
 * Returns bytes transferred on success, -1 on error, DL_BINARY if binary detected.
 */
int64_t transfer_download(struct nfsctx *ctx, const uint8_t *fh, size_t fhlen,
    uint64_t offset, FILE *fp, int flags);

/*
 * Upload from FILE* to NFS file handle.
 * Returns bytes transferred on success, -1 on error.
 */
int64_t transfer_upload(struct nfsctx *ctx, const uint8_t *fh, size_t fhlen,
    uint64_t offset, FILE *fp);

/*
 * Lookup a file in a directory and download its contents to a FILE*.
 * Useful for "cat /path/file" style operations.
 * Returns bytes read on success (0 for empty files), -1 on error.
 */
int64_t transfer_cat_path(struct nfsctx *ctx, const uint8_t *dirfh, size_t dirfhlen,
    const char *name, FILE *fp, int flags);

/*
 * Read and print symbolic link target
 */
int transfer_readlink(struct nfsctx *ctx, const uint8_t *fh, size_t fhlen);

#endif /* TRANSFER_H */
