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
 * cmdparse.h - Command line argument parsing
 *
 * Provides utilities for parsing command arguments in interactive shells.
 */

#ifndef CMDPARSE_H
#define CMDPARSE_H

#include <stdint.h>

/*
 * Maximum positional arguments
 */
#define PARSED_ARGS_MAX 256

/*
 * Maximum file/path arguments for browse shell commands
 */
#define BROWSE_MAX_FILE_ARGS 64

/*
 * Parsed command line result
 */
struct parsed_args {
    char opts[32];                     /* collected option chars, e.g. "lc" */
    const char *args[PARSED_ARGS_MAX]; /* positional arguments */
    int nargs;
};

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
int parse_cmdline(int argc, char **argv, const char *valid_opts,
    int min_args, int max_args, struct parsed_args *out);

/*
 * Parse command line with shell-style error messages.
 * Same as parse_cmdline but prints errors like Unix commands:
 *   "cmd: missing operand"
 *   "cmd: invalid option -- 'x'"
 */
int parse_cmdline_shell(int argc, char **argv, const char *valid_opts,
    int min_args, int max_args, struct parsed_args *out);

/*
 * Parse an octal mode string.
 * Returns 0 on success, -1 on error (message printed, errno=0).
 */
int parse_mode(const char *modestr, uint32_t *mode_out);

/*
 * Parse unsigned integer strings.
 * Return 0 on success, -1 on error (invalid format, overflow).
 */
int parse_u32(const char *s, uint32_t *result);
int parse_u64(const char *s, uint64_t *result);

#endif /* CMDPARSE_H */
