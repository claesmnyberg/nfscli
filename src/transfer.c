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
 * transfer.c - File transfer operations
 *
 * Provides file download/upload with progress, binary detection,
 * and helper functions for file I/O operations.
 */

#include <stdlib.h>
#include <string.h>

#include "constants.h"
#include "nfs.h"
#include "nfs_util.h"
#include "nfscli.h"
#include "transfer.h"

/*
 * Check if data looks like text (printable ASCII)
 */
static int
is_text_data(const uint8_t *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        uint8_t c = buf[i];
        if (c >= ASCII_PRINTABLE_MIN && c <= ASCII_PRINTABLE_MAX)
            continue;
        if (c == '\t' || c == '\n' || c == '\r')
            continue;
        return 0;
    }
    return 1;
}

/*
 * Download from NFS file handle to a FILE*.
 * Returns bytes transferred on success, -1 on error, DL_BINARY if binary detected.
 */
int64_t
transfer_download(struct nfsctx *ctx, const uint8_t *fh, size_t fhlen,
    uint64_t offset, FILE *fp, int flags)
{
    struct nfs_fh nfh;
    struct nfs_read_res res;
    uint64_t tot = 0;
    int first = 1;

    nfs_fh_from_buf(&nfh, fh, fhlen);

    do {
        memset(&res, 0, sizeof(res));
        if (nfs_read(ctx, &nfh, offset, IOBUFSIZE, &res) < 0)
            return -1;

        if (ctx->proto.nfs_version == 2 && res.count == 0) {
            nfs_read_res_free(&res);
            break;
        }

        /* Check first chunk for binary content if requested */
        if (first && (flags & DL_CHECK_BINARY) && res.count > 0) {
            if (!is_text_data(res.data, res.count)) {
                nfs_read_res_free(&res);
                return DL_BINARY;
            }
        }

        if (first && res.count > 0 && (flags & DL_NEWLINE)) {
            if (fputc('\n', fp) == EOF) {
                nfs_read_res_free(&res);
                return -1;
            }
        }
        first = 0;

        if (res.count > 0 && fwrite(res.data, res.count, 1, fp) != 1) {
            nfs_read_res_free(&res);
            return -1;
        }

        if (flags & DL_PROGRESS) {
            printf(".");
            fflush(stdout);
        }

        offset += res.count; /* Use actual bytes received, not requested */
        tot += res.count;
        nfs_read_res_free(&res);
    } while (!res.eof);

    if (ferror(fp))
        return -1;

    return (int64_t)tot;
}

/*
 * Upload from FILE* to NFS file handle.
 * Uses UNSTABLE writes for NFSv3 (with auto-COMMIT) for performance.
 * Returns bytes transferred on success, -1 on error.
 */
int64_t
transfer_upload(struct nfsctx *ctx, const uint8_t *fh, size_t fhlen,
    uint64_t offset, FILE *fp)
{
    uint8_t buf[IOBUFSIZE];
    struct nfs_fh nfh;
    struct nfs_write_res write_res;
    uint64_t start_offset = offset;
    uint64_t tot = 0;
    uint64_t write_verf = 0;
    int have_verf = 0;
    size_t n;
    int stability;
    int use_commit;

    /* Build nfs_fh from raw handle */
    nfs_fh_from_buf(&nfh, fh, fhlen);

    /*
     * NFSv3: Use UNSTABLE writes for performance, then COMMIT at end.
     * NFSv2: Always FILE_SYNC (nfs_write_stable handles this).
     */
    if (ctx->proto.nfs_version >= 3) {
        stability = NFS_UNSTABLE;
        use_commit = 1;
    } else {
        stability = NFS_FILE_SYNC;
        use_commit = 0;
    }

    while ((n = fread(buf, 1, IOBUFSIZE, fp)) > 0) {
        memset(&write_res, 0, sizeof(write_res));
        if (nfs_write_stable(ctx, &nfh, offset, buf, n, stability, &write_res) < 0)
            return -1;

        /*
         * Capture write verifier from first write (OPAQUE 8-byte value).
         * Server returns same verifier on COMMIT if no reboot occurred.
         */
        if (use_commit && !have_verf) {
            write_verf = write_res.verifier;
            have_verf = 1;
        }

        printf(".");
        fflush(stdout);
        offset += n;
        tot += n;
    }

    if (ferror(fp))
        return -1;

    /* NFSv3: Commit all UNSTABLE writes to stable storage */
    if (use_commit && tot > 0) {
        struct nfs_commit_res commit_res;
        memset(&commit_res, 0, sizeof(commit_res));
        /* count=0 means "commit entire file from offset" (RFC 1813) */
        if (nfs_commit(ctx, &nfh, start_offset, 0, &commit_res) < 0) {
            /* COMMIT failed - data may not be on stable storage */
            return -1;
        }

        /*
         * Compare verifiers for mismatch (indicates server reboot).
         * RFC 1813 says verifier is opaque 8 bytes, but since both values
         * are stored in uint64_t and come from the same server, direct
         * comparison works correctly regardless of byte order.
         */
        if (have_verf && commit_res.verifier != write_verf) {
            struct nfs_attr attr;
            fprintf(stderr, "\n*** Warning: Server may have rebooted during upload\n");
            fprintf(stderr, "*** Write verf=0x%016llx, commit verf=0x%016llx\n",
                (unsigned long long)write_verf,
                (unsigned long long)commit_res.verifier);

            /* Verify file size with GETATTR */
            memset(&attr, 0, sizeof(attr));
            if (nfs_getattr(ctx, &nfh, &attr) == 0) {
                uint64_t expected = start_offset + tot;
                if (attr.size >= expected) {
                    fprintf(stderr, "*** Verifying file size... "
                                    "expected %llu, got %llu - OK\n",
                        (unsigned long long)expected,
                        (unsigned long long)attr.size);
                } else {
                    fprintf(stderr, "*** File may be incomplete "
                                    "(expected %llu, got %llu bytes)\n",
                        (unsigned long long)expected,
                        (unsigned long long)attr.size);
                }
            }
        }
    }

    return (int64_t)tot;
}

/*
 * Lookup a file in a directory and download its contents to a FILE*.
 * Useful for "cat /path/file" style operations.
 * Returns bytes read on success (0 for empty files), -1 on error.
 */
int64_t
transfer_cat_path(struct nfsctx *ctx, const uint8_t *dirfh, size_t dirfhlen,
    const char *name, FILE *fp, int flags)
{
    struct nfs_fh dfh;
    struct nfs_lookup_res lu;

    nfs_fh_from_buf(&dfh, dirfh, dirfhlen);
    memset(&lu, 0, sizeof(lu));
    if (nfs_lookup(ctx, &dfh, name, &lu) < 0)
        return -1;

    return transfer_download(ctx, lu.fh.data, lu.fh.len, 0, fp, flags);
}

/*
 * Read and print symbolic link target
 */
int
transfer_readlink(struct nfsctx *ctx, const uint8_t *fh, size_t fhlen)
{
    struct nfs_fh nfh;
    struct nfs_readlink_res res;
    int ret;

    nfs_fh_from_buf(&nfh, fh, fhlen);
    memset(&res, 0, sizeof(res));

    ret = nfs_readlink(ctx, &nfh, &res);
    if (ret < 0)
        return ret;

    printf("%s\n", res.target);
    return 0;
}
