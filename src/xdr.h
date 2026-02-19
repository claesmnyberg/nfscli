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
 * xdr.h - XDR (External Data Representation) primitives
 *
 * XDR (RFC 4506, originally RFC 1832) is Sun's canonical data encoding
 * for RPC. Key properties:
 *
 *   - Big-endian byte order (network byte order)
 *   - 4-byte alignment for all data items
 *   - Implicit typing (structure known from RPC program definition)
 *
 * Data types used in NFS/RPC:
 *
 *   uint32      4 bytes, unsigned, big-endian
 *   uint64      8 bytes, unsigned, big-endian (hyper)
 *   opaque<n>   Fixed-length: n bytes + padding to 4-byte boundary
 *   opaque<>    Variable-length: 4-byte length + data + padding
 *   string<>    Variable-length: 4-byte length + UTF-8 data + padding
 *
 * Example: string "hello" (5 bytes) encodes as:
 *   [00 00 00 05] [h e l l] [o 00 00 00] = 12 bytes total
 *    └─ length ─┘ └──── data + padding ────┘
 *
 * Key macros:
 *   XDR_UNIT       Size of one XDR unit (4 bytes)
 *   XDR_ALIGN(n)   Round n up to next 4-byte boundary
 *   XDR_VARLEN(n)  Wire size of variable-length item: 4 + ALIGN(n)
 *
 * All functions use memcpy to avoid alignment issues on ARM/SPARC.
 */

#ifndef XDR_H
#define XDR_H

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

/*
 * XDR constants (RFC 4506 Section 3)
 */
#define XDR_UNIT 4 /* XDR basic unit size (4 bytes) */

/*
 * Maximum safe XDR length before alignment calculation.
 * This prevents integer overflow when computing XDR_ALIGN(len).
 * Value is (2^29 - 1) = 536870911, chosen so that XDR_ALIGN(len)
 * cannot overflow a 32-bit unsigned integer.
 */
#define XDR_LEN_MAX 0x1FFFFFFFU

/*
 * XDR alignment macros
 */

/* Align size up to XDR boundary (4 bytes) */
#define XDR_ALIGN(siz) (((siz) + (XDR_UNIT - 1)) & ~(XDR_UNIT - 1))

/* Size of XDR variable-length opaque/string: length prefix + padded data
 * NOTE: Validate len against protocol maximums BEFORE using this macro
 * to prevent overflow. This macro assumes len is already validated. */
#define XDR_VARLEN(len) (XDR_UNIT + XDR_ALIGN(len))

/*
 * XDR primitive read functions (alignment-safe)
 *
 * These read values from a buffer without assuming alignment.
 * Use for parsing XDR data from network buffers.
 */

/* Read uint32 from buffer (network byte order -> host) */
static inline uint32_t
xdr_get_u32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return ntohl(v);
}

/* Read uint64 from buffer (network byte order -> host) */
static inline uint64_t
xdr_get_u64(const uint8_t *p)
{
    return ((uint64_t)xdr_get_u32(p) << 32) | xdr_get_u32(p + 4);
}

/*
 * XDR primitive write functions (alignment-safe)
 *
 * These write values to a buffer without assuming alignment.
 * Use for building XDR data in network buffers.
 */

/* Write uint32 to buffer (host -> network byte order) */
static inline void
xdr_put_u32(uint8_t *p, uint32_t v)
{
    v = htonl(v);
    memcpy(p, &v, sizeof(v));
}

/* Write uint64 to buffer (host -> network byte order) */
static inline void
xdr_put_u64(uint8_t *p, uint64_t v)
{
    xdr_put_u32(p, (uint32_t)(v >> 32));
    xdr_put_u32(p + 4, (uint32_t)(v & 0xFFFFFFFF));
}

/*
 * XDR compound type builders
 *
 * Build variable-length XDR types into buffer.
 * Return pointer past written data.
 */

/* Build XDR string (length + padded data) */
static inline uint8_t *
xdr_build_string(uint8_t *pt, const char *str)
{
    uint32_t len = strlen(str);
    xdr_put_u32(pt, len);
    pt += XDR_UNIT;
    memcpy(pt, str, len);
    pt += XDR_ALIGN(len);
    return pt;
}

/* Build XDR opaque data with length prefix */
static inline uint8_t *
xdr_build_opaque(uint8_t *pt, const uint8_t *data, uint32_t len)
{
    xdr_put_u32(pt, len);
    pt += XDR_UNIT;
    memcpy(pt, data, len);
    pt += XDR_ALIGN(len);
    return pt;
}

/* Build XDR uint32, return pointer past written data */
static inline uint8_t *
xdr_build_u32(uint8_t *pt, uint32_t val)
{
    xdr_put_u32(pt, val);
    return pt + XDR_UNIT;
}

/* Build XDR uint64, return pointer past written data */
static inline uint8_t *
xdr_build_u64(uint8_t *pt, uint64_t val)
{
    xdr_put_u64(pt, val);
    return pt + 8;
}

/*
 * XDR compound type parsers
 *
 * Parse variable-length XDR types from buffer with bounds checking.
 * Return pointer past parsed data, or NULL on error.
 */

/* Parse XDR uint32 with bounds check */
static inline uint8_t *
xdr_parse_u32(uint8_t *pt, uint8_t *end, uint32_t *out)
{
    if (pt + XDR_UNIT > end)
        return NULL;
    *out = xdr_get_u32(pt);
    return pt + XDR_UNIT;
}

/* Parse XDR uint64 with bounds check */
static inline uint8_t *
xdr_parse_u64(uint8_t *pt, uint8_t *end, uint64_t *out)
{
    if (pt + 8 > end)
        return NULL;
    *out = xdr_get_u64(pt);
    return pt + 8;
}

/* Parse XDR string into buffer (NUL-terminated) */
static inline uint8_t *
xdr_parse_string(uint8_t *pt, uint8_t *end, char *buf, size_t buflen)
{
    uint32_t len;
    uint32_t copy_len;
    uint32_t len_padded;

    if (pt + XDR_UNIT > end)
        return NULL;
    len = xdr_get_u32(pt);
    pt += XDR_UNIT;

    /* Validate length BEFORE XDR_ALIGN to prevent overflow */
    if (len > XDR_LEN_MAX)
        return NULL;
    len_padded = XDR_ALIGN(len);

    /* Check bounds with aligned length */
    if (pt + len_padded > end)
        return NULL;

    copy_len = len;
    if (copy_len >= buflen)
        copy_len = buflen - 1;
    memcpy(buf, pt, copy_len);
    buf[copy_len] = '\0';

    /* Skip past original wire length (XDR padded) */
    return pt + len_padded;
}

/* Parse XDR opaque into buffer with length output */
static inline uint8_t *
xdr_parse_opaque(uint8_t *pt, uint8_t *end, uint8_t *buf, size_t buflen,
    uint32_t *len_out)
{
    uint32_t len;
    uint32_t len_padded;

    if (pt + XDR_UNIT > end)
        return NULL;
    len = xdr_get_u32(pt);
    pt += XDR_UNIT;

    /* Validate length BEFORE XDR_ALIGN to prevent overflow */
    if (len > buflen || len > 0x1FFFFFFF)
        return NULL;
    len_padded = XDR_ALIGN(len);

    /* Check bounds with aligned length */
    if (pt + len_padded > end)
        return NULL;

    memcpy(buf, pt, len);
    if (len_out)
        *len_out = len;

    return pt + len_padded;
}

/*
 * Sanitize a string in-place by replacing control characters with '.'.
 * Strips ASCII control chars (0x00-0x1F, 0x7F) and C1 control (0x80-0x9F)
 * which includes CSI (0x9B) used for terminal escapes.
 * Preserves printable ASCII and UTF-8 sequences (0xA0+).
 * Use on server-provided strings to prevent terminal escape injection.
 */
static inline void
xdr_sanitize_string(char *str)
{
    unsigned char *p = (unsigned char *)str;

    while (*p) {
        if (*p < 0x20 || *p == 0x7F || (*p >= 0x80 && *p <= 0x9F))
            *p = '.';
        p++;
    }
}

#endif /* XDR_H */
