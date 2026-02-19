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
 * browse_pipe.h - Pipeline and execution support for browse shell
 */

#ifndef BROWSE_PIPE_H
#define BROWSE_PIPE_H

/* Forward declarations */
struct browse_ctx;

/*
 * Output sink types
 */
#define SINK_STDOUT 0 /* Real stdout */
#define SINK_NULL   1 /* Discard (/dev/null) */
#define SINK_NFS    2 /* Stream to NFS file */

/*
 * NFS I/O redirection (stdin, stdout, stderr)
 */
struct nfs_io {
    const char *stdin_path;  /* NULL if stdin not redirected from NFS */
    const char *stdout_path; /* NULL if stdout not redirected to NFS */
    int stdout_append;
    const char *stderr_path; /* NULL if stderr not redirected to NFS */
    int stderr_append;
};

/*
 * Find unquoted pipe character in command line.
 * Returns pointer to '|' or NULL if not found.
 */
char *find_unquoted_pipe(char *line);

/*
 * Execute a command or pipeline with output to specified sink.
 *
 * Handles:
 *   - Single commands
 *   - Pipelines (cmd1 | cmd2 | cmd3)
 *   - Shell escapes (!cmd)
 *   - Output to stdout, /dev/null, or NFS file
 *
 * For pipelines, non-final stages run in child processes.
 * Final stage behavior depends on sink:
 *   - SINK_STDOUT: runs in parent (preserves state)
 *   - SINK_NULL: runs in parent
 *   - SINK_NFS: runs in child (parent streams to NFS)
 */
int browse_execute_pipeline(struct browse_ctx *bctx, char *line,
    int (*execute_fn)(struct browse_ctx *, int, char **),
    int sink_type, struct nfs_io *io);

#endif /* BROWSE_PIPE_H */
