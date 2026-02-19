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
 * browse_redir.h - Redirection support for browse shell
 *
 * Redirection model:
 *   [n]< file      - read fd n from file (default n=0)
 *   [n]> file      - write fd n to file (default n=1)
 *   [n]>> file     - append fd n to file (default n=1)
 *   [n]>&m         - duplicate fd m to fd n
 *   /dev/null      - special null target
 */

#ifndef BROWSE_REDIR_H
#define BROWSE_REDIR_H

#include <limits.h>

/* Forward declarations */
struct browse_ctx;

/* Maximum number of redirections per command */
#define REDIR_MAX 8

/*
 * Redirection operators
 */
#define REDIR_NONE   0 /* No redirection */
#define REDIR_IN     1 /* < file */
#define REDIR_OUT    2 /* > file */
#define REDIR_APPEND 3 /* >> file */
#define REDIR_DUP    4 /* >&n */

/*
 * Target types
 */
#define REDIR_TARGET_FILE 0 /* Regular file */
#define REDIR_TARGET_NULL 1 /* /dev/null */
#define REDIR_TARGET_FD   2 /* Another fd (for >&n) */

/*
 * Single redirection
 */
struct redir {
    int op;                /* REDIR_IN, REDIR_OUT, REDIR_APPEND, REDIR_DUP */
    int src_fd;            /* Source fd (0, 1, 2) */
    int target_type;       /* REDIR_TARGET_FILE, _NULL, or _FD */
    int target_fd;         /* Target fd for REDIR_DUP */
    char target[PATH_MAX]; /* Target filename (empty for /dev/null) */
    int saved_fd;          /* Saved original fd for restore, -1 if not saved */
};

/*
 * Collection of redirections for a command
 */
struct redir_state {
    struct redir redirs[REDIR_MAX];
    int count;
};

/*
 * Initialize redir_state
 */
void redir_init(struct redir_state *rs);

/*
 * Parse and strip all redirections from command line.
 * Modifies line in place, fills redir_state.
 */
void parse_redirections(char *line, struct redir_state *rs);

/*
 * Apply all redirections (dup2 etc).
 * Returns 0 on success, -1 on error.
 */
int redir_apply(struct redir_state *rs);

/*
 * Restore all redirections to original state.
 */
void redir_restore(struct redir_state *rs);

/*
 * Find output redirection targeting an NFS file for specified fd.
 * Returns pointer to the redir, or NULL if none.
 */
struct redir *redir_get_nfs_target(struct redir_state *rs, int fd);

/*
 * Find input redirection from an NFS file.
 * Returns pointer to the redir, or NULL if none.
 */
struct redir *redir_get_nfs_source(struct redir_state *rs);

/*
 * Check if we can write to a remote NFS path.
 * Returns 0 if OK, -1 on error (with message printed).
 */
int check_nfs_write_access(struct browse_ctx *bctx, const char *path, int append_mode);

/*
 * Check if we can read from a remote NFS path.
 * Returns 0 if OK, -1 on error (with message printed).
 */
int check_nfs_read_access(struct browse_ctx *bctx, const char *path);

/*
 * Setup NFS I/O based on parsed redirections.
 * Checks access permissions for all NFS targets.
 * Returns 0 on success, -1 if access check failed (skip command).
 */
struct nfs_io;
int browse_setup_nfs_io(struct browse_ctx *bctx, struct redir_state *redir,
    struct nfs_io *nfs_io, int *sink_type);

/*
 * Check if any NFS I/O is configured in the redir_state.
 */
int browse_has_nfs_io(struct redir_state *redir);

#endif /* BROWSE_REDIR_H */
