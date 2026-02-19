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
 * constants.h - Shared constants used across multiple source files
 *
 * Centralizes buffer sizes, limits, and other constants to avoid
 * duplicate definitions and ensure consistency.
 */

#ifndef CONSTANTS_H
#define CONSTANTS_H

/*
 * I/O buffer sizes for file operations (cat, grep, find)
 * Note: IOBUFSIZE in nfs_types.h is for NFS packets (1300 bytes).
 * These are for local buffering where larger sizes are beneficial.
 */
#define LOCAL_BUFSIZE 8192 /* Local I/O buffer size */
#define LOCAL_MAXLINE 4096 /* Maximum line length for text processing */

/*
 * Directory traversal limits
 */
#define MAX_RECURSION_DEPTH 100 /* Maximum depth for find/grep recursion */

/*
 * Time constants
 */
#define SECONDS_PER_DAY 86400

/*
 * ASCII character range constants
 */
#define ASCII_PRINTABLE_MIN 0x20 /* Space - first printable ASCII */
#define ASCII_PRINTABLE_MAX 0x7e /* Tilde - last printable ASCII */

#endif                           /* CONSTANTS_H */
