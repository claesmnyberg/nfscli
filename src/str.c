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
 * str.c - String utilities
 *
 * Formatting functions for timestamps, durations, sizes, permissions,
 * file handles (hex), and other string conversions.
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "str.h"

/*
 * Create time stamp from seconds counter
 */
char *
str_time(char *buf, size_t buflen, time_t secs)
{
    struct tm *tm;
    time_t caltime;

    caltime = secs;

    if ((tm = localtime(&caltime)) == NULL)
        return (NULL);

    if (strftime(buf, buflen, "%Y-%m-%d %H:%M:%S", tm) == 0)
        return (NULL);

    return buf;
}

/*
 * Create ls-style time stamp (like "Sep  5 17:47" or "Sep  5  2024")
 * Shows time for files from current year, year for older files
 *
 * Uses a static cache for time(NULL) to avoid repeated syscalls when
 * formatting many files (e.g., during ls or find operations).
 * Cache is refreshed at most once per second.
 */
char *
str_time_ls(char *buf, size_t buflen, time_t secs)
{
    struct tm *tm;
    struct tm now_tm;
    time_t now;
    time_t caltime;
    time_t six_months_ago;

    /* Cache time(NULL) to avoid repeated syscalls during batch operations */
    static time_t cached_now = 0;
    static time_t last_check = 0;

    caltime = secs;

    /*
     * Refresh cache only when caltime differs from last, which indicates
     * we're processing a new file. This avoids syscall per file while
     * still updating when time may have advanced significantly.
     */
    if (cached_now == 0 || caltime > last_check + 60 || caltime < last_check - 60) {
        cached_now = time(NULL);
        last_check = caltime;
    }
    now = cached_now;

    if ((tm = localtime(&caltime)) == NULL)
        return (NULL);

    if (localtime_r(&now, &now_tm) == NULL)
        return (NULL);

    /* Show time if within last 6 months, otherwise show year */
    six_months_ago = now - (6 * 30 * 24 * 60 * 60);

    if (caltime > six_months_ago && caltime <= now) {
        if (strftime(buf, buflen, "%b %e %H:%M", tm) == 0)
            return (NULL);
    } else {
        if (strftime(buf, buflen, "%b %e  %Y", tm) == 0)
            return (NULL);
    }

    return buf;
}

/*
 * Convert seconds into hh:mm:ss string
 */
char *
str_hhmmss(time_t sec, char *buf, size_t buflen)
{
    time_t h, m;

    if (sec < 0)
        sec = 0;

    h = sec / 3600;
    sec -= h * 3600;
    m = sec / 60;
    sec -= m * 60;

    snprintf(buf, buflen, "%02lld:%02lld:%02lld",
        (long long)h, (long long)m, (long long)sec);
    return (buf);
}

/*
 * Convert seconds into human-readable duration string.
 * Shows two most significant units: "2d 5h", "3h 45m", "5m 30s", "45s"
 */
char *
str_duration(time_t sec, char *buf, size_t buflen)
{
    uint32_t d, h, m, s;

    if (sec < 0)
        sec = 0;

    d = sec / 86400;
    sec -= d * 86400;
    h = sec / 3600;
    sec -= h * 3600;
    m = sec / 60;
    s = sec - m * 60;

    if (d > 0)
        snprintf(buf, buflen, "%ud %uh", d, h);
    else if (h > 0)
        snprintf(buf, buflen, "%uh %um", h, m);
    else if (m > 0)
        snprintf(buf, buflen, "%um %us", m, s);
    else
        snprintf(buf, buflen, "%us", s);

    return buf;
}

/*
 * Split string into tokens using space as delimiter.
 * Handles double and single quoted strings (quotes are removed).
 * Pointers to the strings are stored at strv, where max
 * indicates the maximum number of pointers to store, including
 * the terminating NULL pointer.
 * Returns the number of valid string pointers set in strv.
 * Note that delimiter and quote characters found in str are
 * replaced/removed as needed.
 */
size_t
str_to_argv(char *str, char **strv, size_t maxv)
{
    char *src = str;
    char *dst;
    size_t i;
    char quote;

    if ((str == NULL) || (strv == NULL) || (maxv == 0))
        return (0);

    i = 0;

    /* Skip leading whitespace */
    while (*src != '\0' && isspace((unsigned char)*src))
        src++;

    while (*src != '\0' && (i < (maxv - 1))) {
        /* Start of token */
        strv[i++] = src;
        dst = src;

        while (*src != '\0') {
            if (*src == '"' || *src == '\'') {
                /* Start of quoted section */
                quote = *src++;
                while (*src != '\0' && *src != quote)
                    *dst++ = *src++;
                if (*src == quote)
                    src++;  /* Skip closing quote */
            } else if (isspace((unsigned char)*src)) {
                /* End of token */
                break;
            } else {
                /* Regular character */
                *dst++ = *src++;
            }
        }

        /* Null-terminate this token */
        if (*src != '\0') {
            src++;  /* Skip the space delimiter */
            *dst = '\0';
            /* Skip additional whitespace */
            while (*src != '\0' && isspace((unsigned char)*src))
                src++;
        } else {
            *dst = '\0';
        }
    }

    strv[i] = (char *)NULL;
    return (i);
}

/*
 * Create hexadecimal representation of string and store in buf.
 * Returns a pointer to buf on success, NULL on error.
 */
char *
str_hex(const uint8_t *str, size_t len, char *buf, size_t buflen)
{
    static const char hex[] = "0123456789abcdef";
    size_t i, j;

    /* Check for overflow: need len*2+1 bytes (including NUL) */
    if (len > SIZE_MAX / 2 || buflen <= len * 2) {
        fprintf(stderr, "** Error: buffer size too small\n");
        return NULL;
    }

    for (i = 0, j = 0; i < len; i++) {
        buf[j++] = hex[str[i] >> 4];
        buf[j++] = hex[str[i] & 0x0f];
    }
    buf[j] = '\0';

    return buf;
}

/*
 * Create a printable string from buffer and replace non
 * printable characters with a dot '.'.
 * Returns a pointer to buf on success, NULL on error.
 */
char *
str_printable(const uint8_t *str, size_t len, char *buf, size_t buflen)
{
    size_t i;

    if (buflen <= len) {
        fprintf(stderr, "** Error: buffer size too small\n");
        return NULL;
    }

    for (i = 0; i < len; i++)
        buf[i] = isprint(str[i]) ? (char)str[i] : '.';

    buf[i] = '\0';
    return buf;
}

/*
 * Convert a single hex character to its numeric value.
 * Returns -1 on invalid input.
 */
static int
hex_digit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/*
 * Convert hexadecimal string to bytes.
 * Returns the number of bytes on success, -1 on error.
 */
int
str_hex2bin(const char *str, uint8_t *buf, size_t buflen)
{
    size_t i;
    size_t j;
    size_t len;
    int hi, lo;

    len = strlen(str);

    if (len % 2 != 0) {
        fprintf(stderr, "Hexadecimal string must be of even length\n");
        return -1;
    }

    if ((len / 2) > buflen) {
        fprintf(stderr, "Hexadecimal string exceeds buffer length\n");
        return -1;
    }

    for (i = 0, j = 0; i < len; i += 2, j++) {
        hi = hex_digit(str[i]);
        lo = hex_digit(str[i + 1]);

        if (hi < 0 || lo < 0) {
            fprintf(stderr, "Invalid hexadecimal character at index %zu: '%c'\n",
                (hi < 0) ? i : i + 1, (hi < 0) ? str[i] : str[i + 1]);
            return -1;
        }

        buf[j] = (uint8_t)((hi << 4) | lo);
    }

    /* j is guaranteed <= buflen which is <= INT_MAX in practice */
    if (j > (size_t)INT_MAX)
        return -1;
    return (int)j;
}

/*
 * Convert size to human readable string.
 * Caller provides buffer (recommend at least 24 bytes).
 */
char *
str_hsize(size_t size, char *buf, size_t buflen)
{
    double num;
    const char *suffix;

    if (size >= 1024UL * 1024 * 1024) {
        num = (double)size / (1024.0 * 1024 * 1024);
        suffix = "GB";
    } else if (size >= 1024UL * 1024) {
        num = (double)size / (1024.0 * 1024);
        suffix = "MB";
    } else if (size >= 1024) {
        num = (double)size / 1024.0;
        suffix = "KB";
    } else {
        snprintf(buf, buflen, "%zuB", size);
        return buf;
    }

    snprintf(buf, buflen, "%.1f%s", num, suffix);
    return buf;
}

/*
 * Parse integer string with validation.
 * Returns 0 on success, -1 on error (invalid format, overflow, out of range).
 * On error, *result is unchanged.
 */
int
str_to_int(const char *s, int *result, int min, int max)
{
    char *endp;
    long val;

    if (s == NULL || *s == '\0')
        return -1;

    errno = 0;
    val = strtol(s, &endp, 10);

    /* Check for conversion errors */
    if (endp == s || *endp != '\0')
        return -1;

    /* Check for overflow */
    if (errno == ERANGE)
        return -1;

    /* Check range */
    if (val < min || val > max)
        return -1;

    *result = (int)val;
    return 0;
}
