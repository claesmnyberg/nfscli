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
 * browse_redir.c - Redirection support for browse shell
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "browse_ctx.h"
#include "browse_pipe.h"
#include "browse_redir.h"
#include "nfs.h"
#include "nfscli.h"
#include "pathctx.h"

/*
 * Initialize redir_state.
 */
void
redir_init(struct redir_state *rs)
{
    int i;

    memset(rs, 0, sizeof(*rs));
    for (i = 0; i < REDIR_MAX; i++)
        rs->redirs[i].saved_fd = -1;
}

/*
 * Remove a token from line and trim surrounding whitespace.
 */
static void
redir_remove_token(char *line, char *p, size_t len)
{
    size_t remaining;

    /* Validate bounds before memmove */
    if (p < line || len == 0)
        return;

    /* Ensure p + len doesn't exceed the string bounds */
    remaining = strlen(p);
    if (len > remaining)
        return;

    memmove(p, p + len, strlen(p + len) + 1);

    /* Trim leading whitespace left behind */
    while (p > line && *(p - 1) == ' ') {
        memmove(p - 1, p, strlen(p) + 1);
        p--;
    }

    /* Trim trailing whitespace */
    while (*p == ' ')
        memmove(p, p + 1, strlen(p));
}

/*
 * Add a redirection to the state.
 * Returns 0 on success, -1 if full.
 */
static int
redir_add(struct redir_state *rs, int op, int src_fd,
    int target_type, int target_fd, const char *target)
{
    struct redir *r;

    if (rs->count >= REDIR_MAX)
        return -1;

    r = &rs->redirs[rs->count++];
    r->op = op;
    r->src_fd = src_fd;
    r->target_type = target_type;
    r->target_fd = target_fd;
    r->saved_fd = -1;

    if (target != NULL && target_type == REDIR_TARGET_FILE) {
        snprintf(r->target, PATH_MAX, "%s", target);
    } else {
        r->target[0] = '\0';
    }
    return 0;
}

/*
 * Parse redirection target starting at q.
 * Returns chars consumed, or 0 if no valid target.
 */
static size_t
parse_redir_target(char *q, int op, int src_fd, struct redir_state *rs)
{
    /* Check for >&n (fd duplication) */
    if (op == REDIR_OUT && q[0] == '&' && q[1] >= '0' && q[1] <= '2') {
        redir_add(rs, REDIR_DUP, src_fd, REDIR_TARGET_FD, q[1] - '0', NULL);
        return 2;
    }

    /* Check for /dev/null */
    if (strncmp(q, "/dev/null", 9) == 0 &&
        (q[9] == '\0' || q[9] == ' ' || q[9] == '|')) {
        redir_add(rs, op, src_fd, REDIR_TARGET_NULL, -1, NULL);
        return 9;
    }

    /* Regular filename (may be quoted) */
    if (*q != '\0' && *q != '|' && *q != ' ') {
        char *start = q;
        char *end;
        char *dst;
        char target[PATH_MAX];
        size_t consumed;
        char quote = 0;

        /* Check for quoted filename */
        if (*q == '"' || *q == '\'') {
            quote = *q;
            start = ++q;
        }

        /* Find end of filename */
        end = start;
        dst = target;
        while (*end != '\0' && dst < target + PATH_MAX - 1) {
            if (quote) {
                if (*end == quote) {
                    end++;  /* Skip closing quote */
                    break;
                }
            } else {
                if (*end == ' ' || *end == '|')
                    break;
            }
            *dst++ = *end++;
        }
        *dst = '\0';

        consumed = end - q + (quote ? 1 : 0);  /* Include opening quote */
        if (dst > target) {
            redir_add(rs, op, src_fd, REDIR_TARGET_FILE, -1, target);
            return consumed;
        }
    }

    return 0;
}

/*
 * Try to parse a redirection at position p.
 * Returns number of chars consumed if successful, 0 otherwise.
 * Updates *src_fd_out and *op_out with parsed values.
 */
static size_t
try_parse_redir(char *p, int *src_fd_out, int *op_out, char **target_start)
{
    int src_fd = STDOUT_FILENO;
    int op;
    char *q;

    /* Check for fd prefix (0, 1, or 2) */
    if (*p >= '0' && *p <= '2' && (p[1] == '>' || p[1] == '<')) {
        src_fd = *p - '0';
        p++;
    }

    /* Determine operator */
    if (p[0] == '>' && p[1] == '>') {
        op = REDIR_APPEND;
        q = p + 2;
    } else if (p[0] == '>') {
        op = REDIR_OUT;
        q = p + 1;
    } else if (p[0] == '<') {
        op = REDIR_IN;
        src_fd = STDIN_FILENO;
        q = p + 1;
    } else {
        return 0;
    }

    /* Skip optional whitespace */
    while (*q == ' ')
        q++;

    *src_fd_out = src_fd;
    *op_out = op;
    *target_start = q;
    return 1; /* Found operator */
}

/*
 * Parse and strip all redirections from command line.
 * Supports: [n]>file, [n]>>file, [n]>/dev/null, [n]>&m, [n]<file
 * Modifies line in place, fills redir_state.
 */
void
parse_redirections(char *line, struct redir_state *rs)
{
    char *p;
    int in_single, in_double;

    redir_init(rs);

    /* Multiple passes to handle all redirections */
    for (;;) {
        int found = 0;
        in_single = in_double = 0;

        for (p = line; *p != '\0'; p++) {
            if (*p == '\'' && !in_double) {
                in_single = !in_single;
            } else if (*p == '"' && !in_single) {
                in_double = !in_double;
            } else if (!in_single && !in_double) {
                char *start = p;
                char *target_start;
                int src_fd, op;
                size_t consumed;

                if (!try_parse_redir(p, &src_fd, &op, &target_start))
                    continue;

                consumed = parse_redir_target(target_start, op, src_fd, rs);
                if (consumed > 0) {
                    redir_remove_token(line, start,
                        (target_start + consumed) - start);
                    found = 1;
                    break;
                }
            }
        }
        if (!found)
            break;
    }
}

/*
 * Apply all redirections.
 * Saves original fds and performs dup2 as needed.
 * Returns 0 on success, -1 on error.
 */
int
redir_apply(struct redir_state *rs)
{
    int i;

    for (i = 0; i < rs->count; i++) {
        struct redir *r = &rs->redirs[i];
        int new_fd = -1;

        /* Save original fd */
        r->saved_fd = dup(r->src_fd);
        if (r->saved_fd < 0)
            return -1;

        /* Determine target fd */
        switch (r->target_type) {
        case REDIR_TARGET_NULL:
            new_fd = open("/dev/null",
                (r->op == REDIR_IN) ? O_RDONLY : O_WRONLY);
            if (new_fd < 0) {
                close(r->saved_fd);
                r->saved_fd = -1;
                return -1;
            }
            break;

        case REDIR_TARGET_FD:
            /* dup2 from target_fd to src_fd */
            if (dup2(r->target_fd, r->src_fd) < 0) {
                close(r->saved_fd);
                r->saved_fd = -1;
                return -1;
            }
            continue; /* no new_fd to close */

        case REDIR_TARGET_FILE:
            /*
             * File redirections are handled separately via NFS capture.
             * Don't apply them here - just skip.
             */
            close(r->saved_fd);
            r->saved_fd = -1;
            continue;

        default:
            continue;
        }

        /* Redirect */
        if (dup2(new_fd, r->src_fd) < 0) {
            close(new_fd);
            close(r->saved_fd);
            r->saved_fd = -1;
            return -1;
        }
        close(new_fd);
    }

    return 0;
}

/*
 * Restore all redirections to original state.
 */
void
redir_restore(struct redir_state *rs)
{
    int i;

    for (i = rs->count - 1; i >= 0; i--) {
        struct redir *r = &rs->redirs[i];
        if (r->saved_fd >= 0) {
            (void)dup2(r->saved_fd, r->src_fd);
            close(r->saved_fd);
            r->saved_fd = -1;
        }
    }
}

/*
 * Find output redirection targeting an NFS file for specified fd.
 * Returns pointer to the redir, or NULL if none.
 */
struct redir *
redir_get_nfs_target(struct redir_state *rs, int fd)
{
    int i;

    for (i = 0; i < rs->count; i++) {
        struct redir *r = &rs->redirs[i];
        if (r->src_fd == fd &&
            r->target_type == REDIR_TARGET_FILE &&
            (r->op == REDIR_OUT || r->op == REDIR_APPEND))
            return r;
    }
    return NULL;
}

/*
 * Find input redirection from an NFS file.
 * Returns pointer to the redir, or NULL if none.
 */
struct redir *
redir_get_nfs_source(struct redir_state *rs)
{
    int i;

    for (i = 0; i < rs->count; i++) {
        struct redir *r = &rs->redirs[i];
        if (r->src_fd == STDIN_FILENO &&
            r->target_type == REDIR_TARGET_FILE &&
            r->op == REDIR_IN)
            return r;
    }
    return NULL;
}

/*
 * Ensure we have file attributes.
 */
static void
ensure_attrs(struct browse_ctx *bctx, struct path_result *pres)
{
    if (!pres->has_attr)
        nfs_getattr(bctx->nfs, &pres->fh, &pres->attr);
}

/*
 * Check NFSv3 ACCESS permissions on a file handle.
 * Returns 0 if access granted, -1 if denied (with message printed).
 */
static int
check_nfsv3_access(struct browse_ctx *bctx, const struct nfs_fh *fh,
    uint32_t access_mask, const char *path, const char *suffix)
{
    struct nfs_access_res access_res;
    int ret;

    if (bctx->nfs->proto.nfs_version != 3)
        return 0;

    ret = nfs_access(bctx->nfs, fh, access_mask, &access_res);
    if (ret == 0 && (access_res.access & access_mask) == 0) {
        fprintf(stderr, "*** %s: Permission denied%s\n", path,
            suffix ? suffix : "");
        return -1;
    }
    return 0;
}

/*
 * Check that a path resolves to a regular file.
 * Returns 0 if OK, -1 on error (with message printed).
 */
static int
check_regular_file(struct browse_ctx *bctx, struct path_result *pres,
    const char *path)
{
    ensure_attrs(bctx, pres);
    if (pres->attr.type != NFS_FTYPE_REG) {
        fprintf(stderr, "*** %s: Not a regular file\n", path);
        return -1;
    }
    return 0;
}

/*
 * Check if we can write to a remote NFS path.
 * For append mode, file must exist and be writable.
 * For truncate mode, parent dir must be writable.
 * Returns 0 if OK, -1 on error (with message printed).
 */
int
check_nfs_write_access(struct browse_ctx *bctx, const char *path, int append_mode)
{
    struct path_result pres;
    uint32_t write_access = NFS_ACCESS3_MODIFY | NFS_ACCESS3_EXTEND;

    if (append_mode) {
        /* Check if file exists - if so, verify it's writable */
        if (path_resolve(bctx->pctx, path, PATH_FOLLOW, &pres) == 0) {
            if (check_regular_file(bctx, &pres, path) < 0)
                return -1;
            return check_nfsv3_access(bctx, &pres.fh, write_access,
                path, NULL);
        }
        /* File doesn't exist - fall through to check parent dir */
    }

    /* Parent must exist for truncate/create */
    if (path_resolve(bctx->pctx, path, PATH_WANT_PARENT, &pres) < 0) {
        fprintf(stderr, "*** %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (!pres.has_parent) {
        fprintf(stderr, "*** %s: Parent directory not found\n", path);
        return -1;
    }

    return check_nfsv3_access(bctx, &pres.parent_fh, write_access,
        path, " (parent dir)");
}

/*
 * Check if we can read from a remote NFS path.
 * File must exist, be a regular file, and be readable.
 * Returns 0 if OK, -1 on error (with message printed).
 */
int
check_nfs_read_access(struct browse_ctx *bctx, const char *path)
{
    struct path_result pres;

    if (path_resolve(bctx->pctx, path, PATH_FOLLOW, &pres) < 0) {
        fprintf(stderr, "*** %s: %s\n", path, strerror(errno));
        return -1;
    }

    if (check_regular_file(bctx, &pres, path) < 0)
        return -1;

    return check_nfsv3_access(bctx, &pres.fh, NFS_ACCESS3_READ, path, NULL);
}

/*
 * Setup NFS I/O based on parsed redirections.
 * Checks access permissions for all NFS targets.
 *
 * Returns:
 *   0  - success, proceed with command execution
 *  -1  - access check failed, skip this command
 */
int
browse_setup_nfs_io(struct browse_ctx *bctx, struct redir_state *redir,
    struct nfs_io *nfs_io, int *sink_type)
{
    struct redir *stdin_source, *stdout_target, *stderr_target;

    stdin_source = redir_get_nfs_source(redir);
    stdout_target = redir_get_nfs_target(redir, STDOUT_FILENO);
    stderr_target = redir_get_nfs_target(redir, STDERR_FILENO);

    memset(nfs_io, 0, sizeof(*nfs_io));

    /* Handle stdin from NFS */
    if (stdin_source != NULL) {
        nfs_io->stdin_path = stdin_source->target;
        if (check_nfs_read_access(bctx, nfs_io->stdin_path) < 0)
            return -1;
    }

    /* Determine output sink */
    if (stdout_target != NULL) {
        *sink_type = SINK_NFS;
        nfs_io->stdout_path = stdout_target->target;
        nfs_io->stdout_append = (stdout_target->op == REDIR_APPEND);
        if (check_nfs_write_access(bctx, nfs_io->stdout_path,
                nfs_io->stdout_append) < 0)
            return -1;
    } else {
        *sink_type = SINK_STDOUT;
    }

    /* Handle stderr to NFS */
    if (stderr_target != NULL) {
        nfs_io->stderr_path = stderr_target->target;
        nfs_io->stderr_append = (stderr_target->op == REDIR_APPEND);
        if (check_nfs_write_access(bctx, nfs_io->stderr_path,
                nfs_io->stderr_append) < 0)
            return -1;
    }

    return 0;
}

/*
 * Check if any NFS I/O is configured.
 */
int
browse_has_nfs_io(struct redir_state *redir)
{
    return (redir_get_nfs_source(redir) != NULL ||
        redir_get_nfs_target(redir, STDOUT_FILENO) != NULL ||
        redir_get_nfs_target(redir, STDERR_FILENO) != NULL);
}
