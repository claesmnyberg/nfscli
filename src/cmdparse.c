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
 * cmdparse.c - Command line argument parsing
 *
 * Provides utilities for parsing command arguments in interactive shells.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmdparse.h"

/* Message style flags */
#define MSG_STYLE_INTERNAL 0 /* "*** Unknown option: -x" */
#define MSG_STYLE_SHELL    1 /* "cmd: invalid option -- 'x'" */

/*
 * Internal parsing function with configurable message style.
 */
static int
parse_cmdline_internal(int argc, char **argv, const char *valid_opts,
    int min_args, int max_args, struct parsed_args *out, int msg_style)
{
    int i;
    int opts_done = 0;
    size_t optlen = 0;
    const char *p;
    const char *cmdname = argv[0];

    memset(out, 0, sizeof(*out));

    for (i = 1; i < argc; i++) {
        if (!opts_done && strcmp(argv[i], "--") == 0) {
            opts_done = 1;
            continue;
        }

        if (!opts_done && argv[i][0] == '-' && argv[i][1] != '\0') {
            if (argv[i][1] == '-') {
                if (msg_style == MSG_STYLE_SHELL) {
                    fprintf(stderr, "%s: unrecognized option '%s'\n", cmdname, argv[i]);
                    fprintf(stderr, "Try '%s --help' for more information.\n", cmdname);
                } else {
                    fprintf(stderr, "*** Unknown option: %s\n", argv[i]);
                }
                errno = EINVAL;
                return -1;
            }
            for (p = &argv[i][1]; *p; p++) {
                if (strchr(valid_opts, *p) == NULL) {
                    if (msg_style == MSG_STYLE_SHELL) {
                        fprintf(stderr, "%s: invalid option -- '%c'\n", cmdname, *p);
                        fprintf(stderr, "Try '%s --help' for more information.\n", cmdname);
                    } else {
                        fprintf(stderr, "*** Unknown option: -%c\n", *p);
                    }
                    errno = EINVAL;
                    return -1;
                }
                if (strchr(out->opts, *p) == NULL) {
                    if (optlen >= sizeof(out->opts) - 1) {
                        fprintf(stderr, "*** Too many options\n");
                        errno = EINVAL;
                        return -1;
                    }
                    out->opts[optlen++] = *p;
                }
            }
        } else {
            if (out->nargs >= max_args) {
                if (msg_style == MSG_STYLE_SHELL) {
                    fprintf(stderr, "%s: extra operand '%s'\n", cmdname, argv[i]);
                    fprintf(stderr, "Try '%s --help' for more information.\n", cmdname);
                } else {
                    fprintf(stderr, "*** Too many arguments\n");
                }
                errno = EINVAL;
                return -1;
            }
            if (out->nargs >= PARSED_ARGS_MAX) {
                if (msg_style == MSG_STYLE_SHELL) {
                    fprintf(stderr, "%s: too many operands\n", cmdname);
                } else {
                    fprintf(stderr, "*** Too many arguments (internal limit)\n");
                }
                errno = EINVAL;
                return -1;
            }
            out->args[out->nargs++] = argv[i];
        }
    }

    if (out->nargs < min_args) {
        if (msg_style == MSG_STYLE_SHELL) {
            fprintf(stderr, "%s: missing operand\n", cmdname);
            fprintf(stderr, "Try '%s --help' for more information.\n", cmdname);
        } else {
            fprintf(stderr, "*** Missing argument(s)\n");
        }
        errno = EINVAL;
        return -1;
    }

    return 0;
}

/*
 * Parse command line arguments, allowing options in any position.
 * Supports combined options (e.g., -lc) and '--' to end option processing.
 *
 * argc, argv   - command line arguments (argv[0] is command name)
 * valid_opts   - string of valid option characters (e.g., "lc")
 * min_args     - minimum required positional arguments
 * max_args     - maximum allowed positional arguments
 * out          - parsed result (opts string and args array)
 *
 * Returns 0 on success, -1 on error (prints error message).
 */
int
parse_cmdline(int argc, char **argv, const char *valid_opts,
    int min_args, int max_args, struct parsed_args *out)
{
    return parse_cmdline_internal(argc, argv, valid_opts,
        min_args, max_args, out, MSG_STYLE_INTERNAL);
}

/*
 * Parse command line with shell-style error messages.
 * Same as parse_cmdline but prints errors like Unix commands:
 *   "cmd: missing operand"
 *   "cmd: invalid option -- 'x'"
 */
int
parse_cmdline_shell(int argc, char **argv, const char *valid_opts,
    int min_args, int max_args, struct parsed_args *out)
{
    return parse_cmdline_internal(argc, argv, valid_opts,
        min_args, max_args, out, MSG_STYLE_SHELL);
}

/*
 * Parse an octal mode string.
 * Returns 0 on success, -1 on error (message printed, errno=0).
 */
int
parse_mode(const char *modestr, uint32_t *mode_out)
{
    char *ep;

    errno = 0;
    *mode_out = strtoul(modestr, &ep, 8);
    if (ep == modestr || *ep != '\0' || errno != 0) {
        fprintf(stderr, "*** Invalid mode (octal): %s\n", modestr);
        errno = 0;
        return -1;
    }
    return 0;
}

/*
 * Parse unsigned 32-bit integer string.
 * Returns 0 on success, -1 on error (invalid format, overflow).
 */
int
parse_u32(const char *s, uint32_t *result)
{
    char *endp;
    unsigned long val;

    if (s == NULL || *s == '\0')
        return -1;

    errno = 0;
    val = strtoul(s, &endp, 0);

    if (endp == s || *endp != '\0')
        return -1;

    if (errno == ERANGE || val > UINT32_MAX)
        return -1;

    *result = (uint32_t)val;
    return 0;
}

/*
 * Parse unsigned 64-bit integer string.
 * Returns 0 on success, -1 on error (invalid format, overflow).
 */
int
parse_u64(const char *s, uint64_t *result)
{
    char *endp;
    unsigned long long val;

    if (s == NULL || *s == '\0')
        return -1;

    errno = 0;
    val = strtoull(s, &endp, 0);

    if (endp == s || *endp != '\0')
        return -1;

    if (errno == ERANGE)
        return -1;

    *result = (uint64_t)val;
    return 0;
}
