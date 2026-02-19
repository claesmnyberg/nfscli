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
 * browse_pipe.c - Pipeline and execution support for browse shell
 *
 * Unified execution model:
 *   [input] -> command -> [stdout sink]
 *                      -> [stderr sink]
 *
 * Pipelines use concurrent execution with real pipes.
 * Non-final stages run in child processes.
 * Final stage behavior depends on sink type.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "browse_ctx.h"
#include "browse_pipe.h"
#include "nfs.h"
#include "nfscli.h"
#include "nfs_util.h"
#include "pathctx.h"
#include "str.h"

#define PIPE_MAX_STAGES 16
#define STREAM_CHUNK    8192

/*
 * State for NFS I/O streaming processes.
 */
struct stream_state {
    pid_t stdin_reader;
    pid_t stderr_writer;
    int saved_stdin;
    int saved_stderr;
};

/* Forward declarations */
static int stream_to_nfs(struct browse_ctx *bctx, int fd,
    const char *path, int append);
static int stream_from_nfs(struct browse_ctx *bctx, int fd, const char *path);

/*
 * Wait for child process, retrying on EINTR.
 * This prevents temporary zombies during signal handling.
 * ECHILD means child was already reaped (e.g., by SIGCHLD handler).
 */
static void
wait_for_child(pid_t pid)
{
    while (waitpid(pid, NULL, 0) < 0) {
        if (errno == EINTR)
            continue;
        break; /* ECHILD or other error - child gone or doesn't exist */
    }
}

/*
 * Find unquoted pipe character in command line.
 * Handles single quotes, double quotes, and backslash escapes.
 */
char *
find_unquoted_pipe(char *line)
{
    char *p;
    int in_single = 0;
    int in_double = 0;
    int escaped = 0;

    for (p = line; *p != '\0'; p++) {
        if (escaped) {
            escaped = 0;
            continue;
        }
        if (*p == '\\') {
            escaped = 1;
            continue;
        }
        if (*p == '\'' && !in_double) {
            in_single = !in_single;
        } else if (*p == '"' && !in_single) {
            in_double = !in_double;
        } else if (*p == '|' && !in_single && !in_double) {
            return p;
        }
    }
    return NULL;
}

/*
 * Skip leading whitespace.
 */
static char *
skip_ws(char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    return s;
}

/*
 * Write all data to file descriptor, handling partial writes and EINTR.
 * Returns 0 on success, -1 on error.
 */
static int
write_all(int fd, const void *buf, size_t count)
{
    const char *p;
    size_t remaining;
    ssize_t n;

    p = buf;
    remaining = count;

    while (remaining > 0) {
        n = write(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            /* Should not happen for pipes/files, but prevent infinite loop */
            errno = EIO;
            return -1;
        }
        p += n;
        remaining -= n;
    }
    return 0;
}

/*
 * Get or create file handle for NFS output file.
 * On success, copies file handle to fh, sets initial offset, and returns 0.
 * On failure, prints error message and returns -1.
 */
static int
get_output_fh(struct browse_ctx *bctx, const char *path,
    struct nfs_fh *fh, uint64_t *offset_out, int append)
{
    struct path_result pres;
    struct nfs_create_res create_res;
    struct nfs_lookup_res lu;
    struct nfs_attr attr;

    *offset_out = 0;

    /* For append mode, try to resolve existing file first */
    if (append) {
        if (path_resolve(bctx->pctx, path, PATH_FOLLOW, &pres) == 0) {
            nfs_fh_copy(fh, &pres.fh);
            if (nfs_getattr(bctx->nfs, fh, &attr) < 0) {
                /* File exists but can't get size - don't silently overwrite */
                fprintf(stderr, "*** %s: cannot get file size for append: %s\n",
                    path, strerror(errno));
                return -1;
            }
            *offset_out = attr.size;
            return 0;
        }
        /* File doesn't exist, fall through to create it */
    }

    /* Resolve parent directory */
    if (path_resolve(bctx->pctx, path, PATH_WANT_PARENT, &pres) < 0 ||
        !pres.has_parent) {
        fprintf(stderr, "*** %s: %s\n", path, strerror(errno));
        return -1;
    }

    /* Create the file */
    if (nfs_create(bctx->nfs, &pres.parent_fh, pres.basename,
            0644, NFS_CREATE_UNCHECKED, &create_res) < 0) {
        fprintf(stderr, "*** %s: %s\n", path, strerror(errno));
        return -1;
    }

    /*
     * NFSv3 CREATE may not return file handle (RFC 1813).
     * If not returned, do a LOOKUP to get it.
     */
    if (create_res.has_fh) {
        nfs_fh_copy(fh, &create_res.fh);
    } else {
        memset(&lu, 0, sizeof(lu));
        if (nfs_lookup(bctx->nfs, &pres.parent_fh, pres.basename, &lu) < 0) {
            fprintf(stderr, "*** %s: lookup after create failed: %s\n",
                path, strerror(errno));
            return -1;
        }
        nfs_fh_copy(fh, &lu.fh);
    }

    return 0;
}

/*
 * Stream data from fd to NFS file.
 * Returns 0 on success, -1 on error.
 */
static int
stream_to_nfs(struct browse_ctx *bctx, int fd, const char *path, int append)
{
    struct nfs_fh fh;
    struct nfs_sattr sattr;
    uint64_t offset;
    char buf[STREAM_CHUNK];
    ssize_t n;

    /* Get file handle and initial offset */
    if (get_output_fh(bctx, path, &fh, &offset, append) < 0)
        return -1;

    /* Truncate file if not appending */
    if (!append) {
        nfs_sattr_init(&sattr);
        sattr.set_size = 1;
        sattr.size = 0;
        if (nfs_setattr(bctx->nfs, &fh, &sattr) < 0) {
            fprintf(stderr, "*** %s: truncate failed: %s\n",
                path, strerror(errno));
            return -1;
        }
    }

    /* Read from fd and write to NFS */
    for (;;) {
        n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "*** %s: read failed: %s\n",
                path, strerror(errno));
            return -1;
        }
        if (n == 0)
            break;

        if (nfs_write(bctx->nfs, &fh, offset, (uint8_t *)buf, n, NULL) < 0) {
            fprintf(stderr, "*** %s: write failed at offset %lu: %s\n",
                path, (unsigned long)offset, strerror(errno));
            return -1;
        }
        offset += n;
    }

    return 0;
}

/*
 * Stream data from NFS file to fd.
 * Returns 0 on success, -1 on error.
 */
static int
stream_from_nfs(struct browse_ctx *bctx, int fd, const char *path)
{
    struct path_result pres;
    struct nfs_read_res res;
    uint64_t offset;
    int eof_seen;

    if (path_resolve(bctx->pctx, path, PATH_FOLLOW, &pres) < 0) {
        fprintf(stderr, "*** %s: %s\n", path, strerror(errno));
        return -1;
    }

    offset = 0;
    eof_seen = 0;

    while (!eof_seen) {
        memset(&res, 0, sizeof(res));
        if (nfs_read(bctx->nfs, &pres.fh, offset, STREAM_CHUNK, &res) < 0) {
            fprintf(stderr, "*** %s: read failed: %s\n", path, strerror(errno));
            return -1;
        }

        if (res.count == 0) {
            nfs_read_res_free(&res);
            break;
        }

        if (write_all(fd, res.data, res.count) < 0) {
            fprintf(stderr, "*** %s: write failed: %s\n", path, strerror(errno));
            nfs_read_res_free(&res);
            return -1;
        }

        offset += res.count;
        eof_seen = res.eof;
        nfs_read_res_free(&res);
    }

    return 0;
}

/*
 * Run shell escape via exec.
 * Does not return on success.
 */
static void
exec_shell(const char *cmd)
{
    execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
    _exit(127);
}

/*
 * Run built-in command in child, then exit.
 * Does not return.
 */
static void
exec_builtin(struct browse_ctx *bctx, char *cmd,
    int (*execute_fn)(struct browse_ctx *, int, char **))
{
    char *argv[BROWSE_MAXARGS];
    int argc;

    argc = str_to_argv(cmd, argv, BROWSE_MAXARGS - 1);
    if (argc > 0) {
        /*
         * Set up pipe_input so built-in commands can read from stdin.
         * For non-first pipeline stages, stdin has been connected to
         * the previous stage's output pipe via dup2().
         */
        bctx->pipe_input = fdopen(STDIN_FILENO, "r");
        execute_fn(bctx, argc, argv);
        if (bctx->pipe_input != NULL) {
            fclose(bctx->pipe_input);
            bctx->pipe_input = NULL;
        }
    }

    /* Flush both streams before _exit to ensure output reaches pipes */
    fflush(stdout);
    fflush(stderr);
    _exit(0);
}

/*
 * Run command in parent process.
 */
static void
run_in_parent(struct browse_ctx *bctx, char *cmd,
    int (*execute_fn)(struct browse_ctx *, int, char **))
{
    char *argv[BROWSE_MAXARGS];
    int argc;
    int ret;

    if (cmd[0] == '!') {
        ret = system(cmd + 1);
        (void)ret;
    } else {
        argc = str_to_argv(cmd, argv, BROWSE_MAXARGS - 1);
        if (argc > 0)
            execute_fn(bctx, argc, argv);
    }
}

/*
 * Initialize stream state structure.
 */
static void
stream_state_init(struct stream_state *ss)
{
    ss->stdin_reader = -1;
    ss->stderr_writer = -1;
    ss->saved_stdin = -1;
    ss->saved_stderr = -1;
}

/*
 * Set up stdin streaming from NFS file.
 * Forks a child process to read from NFS and write to a pipe.
 * Parent's stdin is redirected to read from that pipe.
 */
static void
setup_nfs_stdin(struct browse_ctx *bctx, const char *path,
    struct stream_state *ss)
{
    int pipefd[2];
    pid_t pid;
    int saved;

    if (pipe(pipefd) < 0)
        return;

    /* Flush before fork to prevent duplicated buffered output */
    fflush(stdout);
    fflush(stderr);

    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }

    if (pid == 0) {
        /* Child: read from NFS, write to pipe */
        close(pipefd[0]);
        stream_from_nfs(bctx, pipefd[1], path);
        close(pipefd[1]);
        _exit(0);
    }

    /* Parent: save stdin and redirect from pipe */
    ss->stdin_reader = pid;
    close(pipefd[1]);

    saved = dup(STDIN_FILENO);
    if (saved < 0) {
        close(pipefd[0]);
        return;
    }

    if (dup2(pipefd[0], STDIN_FILENO) < 0) {
        close(saved);
        close(pipefd[0]);
        return;
    }

    ss->saved_stdin = saved;
    close(pipefd[0]);
}

/*
 * Set up stderr streaming to NFS file.
 * Forks a child process to read from a pipe and write to NFS.
 * Parent's stderr is redirected to write to that pipe.
 */
static void
setup_nfs_stderr(struct browse_ctx *bctx, const char *path, int append,
    struct stream_state *ss)
{
    int pipefd[2];
    pid_t pid;
    int saved;

    if (pipe(pipefd) < 0)
        return;

    /* Flush before fork to prevent duplicated buffered output */
    fflush(stdout);
    fflush(stderr);

    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }

    if (pid == 0) {
        /* Child: read from pipe, write to NFS */
        close(pipefd[1]);
        stream_to_nfs(bctx, pipefd[0], path, append);
        close(pipefd[0]);
        _exit(0);
    }

    /* Parent: save stderr and redirect to pipe */
    ss->stderr_writer = pid;
    close(pipefd[0]);

    saved = dup(STDERR_FILENO);
    if (saved < 0) {
        close(pipefd[1]);
        return;
    }

    if (dup2(pipefd[1], STDERR_FILENO) < 0) {
        close(saved);
        close(pipefd[1]);
        return;
    }

    ss->saved_stderr = saved;
    close(pipefd[1]);
}

/*
 * Restore streams and wait for streaming processes.
 */
static void
cleanup_nfs_streams(struct stream_state *ss)
{
    /* Restore stdin */
    if (ss->saved_stdin >= 0) {
        dup2(ss->saved_stdin, STDIN_FILENO);
        close(ss->saved_stdin);
        ss->saved_stdin = -1;
    }
    if (ss->stdin_reader > 0) {
        wait_for_child(ss->stdin_reader);
        ss->stdin_reader = -1;
    }

    /* Flush and restore stderr */
    if (ss->saved_stderr >= 0) {
        fflush(stderr);
        dup2(ss->saved_stderr, STDERR_FILENO);
        close(ss->saved_stderr);
        ss->saved_stderr = -1;
    }
    if (ss->stderr_writer > 0) {
        wait_for_child(ss->stderr_writer);
        ss->stderr_writer = -1;
    }
}

/*
 * Check if command is a shell escape (external command).
 * Shell escapes start with '!' and run via system shell.
 */
static int
cmd_is_shell_escape(const char *cmd)
{
    return cmd[0] == '!';
}

/*
 * Execute single command with stdout to /dev/null.
 */
static void
execute_to_null(struct browse_ctx *bctx, char *cmd,
    int (*execute_fn)(struct browse_ctx *, int, char **))
{
    int null_fd;
    int saved;

    null_fd = open("/dev/null", O_WRONLY);
    if (null_fd < 0)
        return;

    /* Save stdout before redirecting */
    saved = dup(STDOUT_FILENO);
    if (saved < 0) {
        /* Cannot save stdout - abort to avoid losing it permanently */
        close(null_fd);
        return;
    }

    if (dup2(null_fd, STDOUT_FILENO) < 0) {
        close(null_fd);
        close(saved);
        return;
    }
    close(null_fd);

    run_in_parent(bctx, cmd, execute_fn);

    /* Restore stdout */
    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);
}

/*
 * Execute single command with stdout to NFS file.
 * Forks a child to run the command, parent reads output and streams to NFS.
 *
 * Note: Caller must set bctx->nfs->concurrent_fork = 1 before calling,
 * and reset it after all forked children have exited.
 */
static void
execute_to_nfs(struct browse_ctx *bctx, char *cmd,
    int (*execute_fn)(struct browse_ctx *, int, char **),
    const char *path, int append)
{
    int pipefd[2];
    pid_t pid;

    if (pipe(pipefd) < 0)
        return;

    /*
     * Flush before fork to prevent buffered output from previous
     * commands being inherited by child and written to the pipe.
     */
    fflush(stdout);
    fflush(stderr);

    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }

    if (pid == 0) {
        /* Child: run command with stdout redirected to pipe */

        /* Shell escapes use external programs - close NFS socket */
        if (cmd_is_shell_escape(cmd) && bctx->nfs->net.sock >= 0)
            close(bctx->nfs->net.sock);

        close(pipefd[0]);

        if (dup2(pipefd[1], STDOUT_FILENO) < 0)
            _exit(1);
        close(pipefd[1]);

        if (cmd[0] == '!')
            exec_shell(cmd + 1);
        else
            exec_builtin(bctx, cmd, execute_fn);
        /* Does not return */
    }

    /* Parent: read from pipe, write to NFS */
    close(pipefd[1]);
    stream_to_nfs(bctx, pipefd[0], path, append);
    close(pipefd[0]);
    wait_for_child(pid);
}

/*
 * Execute final pipeline stage in parent (preserves state changes like cd).
 */
static void
execute_final_stage(struct browse_ctx *bctx, char *cmd,
    int (*execute_fn)(struct browse_ctx *, int, char **),
    int pipe_read_fd, int sink_type)
{
    char *argv[BROWSE_MAXARGS];
    int argc;
    int stdin_saved;
    int stdout_saved;
    int null_fd;
    int ret;

    /* Save and redirect stdin */
    stdin_saved = dup(STDIN_FILENO);
    if (stdin_saved < 0)
        return;

    if (dup2(pipe_read_fd, STDIN_FILENO) < 0) {
        close(stdin_saved);
        return;
    }

    /* Optionally redirect stdout to /dev/null */
    stdout_saved = -1;
    if (sink_type == SINK_NULL) {
        null_fd = open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            stdout_saved = dup(STDOUT_FILENO);
            if (stdout_saved >= 0) {
                if (dup2(null_fd, STDOUT_FILENO) < 0) {
                    close(stdout_saved);
                    stdout_saved = -1;
                }
            }
            close(null_fd);
        }
    }

    /* Execute the command */
    if (cmd[0] == '!') {
        ret = system(cmd + 1);
        (void)ret;
    } else {
        argc = str_to_argv(cmd, argv, BROWSE_MAXARGS - 1);
        if (argc > 0) {
            /*
             * Close any existing pipe_input before creating a new one.
             * This can happen when NFS stdin streaming is active and
             * browse_execute_pipeline already set pipe_input.
             */
            if (bctx->pipe_input != NULL) {
                fclose(bctx->pipe_input);
                bctx->pipe_input = NULL;
            }
            bctx->pipe_input = fdopen(STDIN_FILENO, "r");
            if (bctx->pipe_input != NULL) {
                execute_fn(bctx, argc, argv);
                fclose(bctx->pipe_input);
                bctx->pipe_input = NULL;
            } else {
                /* fdopen failed - execute without pipe_input */
                execute_fn(bctx, argc, argv);
            }
        }
    }

    /* Restore stdout if redirected */
    if (stdout_saved >= 0) {
        fflush(stdout);
        dup2(stdout_saved, STDOUT_FILENO);
        close(stdout_saved);
    }

    /* Restore stdin */
    dup2(stdin_saved, STDIN_FILENO);
    close(stdin_saved);
}

/*
 * Close all pipe file descriptors.
 */
static void
close_all_pipes(int pipes[][2], int count)
{
    int i;

    for (i = 0; i < count; i++) {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }
}

/*
 * Execute a multi-stage pipeline.
 *
 * Pipeline modes:
 *
 * 1. Output to NFS (final_in_child = true):
 *    cmd1 | cmd2 | cmd3 > file
 *    - All stages run in child processes
 *    - Parent reads final stage output and streams to NFS
 *    - Requires nstages pipes (one for each stage's output)
 *
 * 2. Output to stdout/null (final_in_child = false):
 *    cmd1 | cmd2 | cmd3
 *    - All but final stage run in child processes
 *    - Final stage runs in parent (preserves state changes like cd)
 *    - Requires nstages-1 pipes (between stages)
 *
 * Note: Caller must set bctx->nfs->concurrent_fork = 1 before calling,
 * and reset it after all forked children have exited.
 */
static void
execute_pipeline(struct browse_ctx *bctx, char **stages, int nstages,
    int (*execute_fn)(struct browse_ctx *, int, char **),
    int sink_type, struct nfs_io *io)
{
    int pipes[PIPE_MAX_STAGES][2];
    pid_t pids[PIPE_MAX_STAGES];
    int final_in_child;
    int num_pipes;
    int stages_to_fork;
    int i;
    int j;
    char *cmd;

    /* Determine execution mode */
    final_in_child = (sink_type == SINK_NFS && io != NULL &&
        io->stdout_path != NULL);

    /*
     * Calculate number of pipes needed:
     * - final_in_child: nstages (last pipe carries final output to parent)
     * - final_in_parent: nstages-1 (pipes between child stages only)
     */
    num_pipes = final_in_child ? nstages : nstages - 1;
    stages_to_fork = final_in_child ? nstages : nstages - 1;

    /* Bounds check */
    if (num_pipes > PIPE_MAX_STAGES || stages_to_fork > PIPE_MAX_STAGES)
        return;

    /* Create all pipes upfront */
    for (i = 0; i < num_pipes; i++) {
        if (pipe(pipes[i]) < 0) {
            /* Clean up already-created pipes */
            while (--i >= 0) {
                close(pipes[i][0]);
                close(pipes[i][1]);
            }
            return;
        }
    }

    /*
     * Flush before forking to prevent buffered output from previous
     * commands being inherited by children and written to the pipes.
     */
    fflush(stdout);
    fflush(stderr);

    /* Fork child processes for pipeline stages */
    for (i = 0; i < stages_to_fork; i++) {
        pids[i] = fork();

        if (pids[i] < 0) {
            /* Fork failed - clean up and exit */
            close_all_pipes(pipes, num_pipes);
            for (j = 0; j < i; j++)
                wait_for_child(pids[j]);
            return;
        }

        if (pids[i] == 0) {
            /* Child process */
            cmd = stages[i];

            /* Shell escapes use external programs - close NFS socket */
            if (cmd_is_shell_escape(cmd) && bctx->nfs->net.sock >= 0)
                close(bctx->nfs->net.sock);

            /* Connect stdin to previous stage's output (if not first stage) */
            if (i > 0) {
                if (dup2(pipes[i - 1][0], STDIN_FILENO) < 0)
                    _exit(1);
            }

            /* Connect stdout to this stage's output pipe */
            if (dup2(pipes[i][1], STDOUT_FILENO) < 0)
                _exit(1);

            /* Close all pipe fds - we've dup2'd what we need */
            close_all_pipes(pipes, num_pipes);

            /* Execute the command */
            if (cmd[0] == '!')
                exec_shell(cmd + 1);
            else
                exec_builtin(bctx, cmd, execute_fn);
            /* Does not return */
        }
    }

    /* Parent process - handle based on mode */
    if (final_in_child) {
        /*
         * All stages forked to children. Close all write ends and
         * intermediate read ends, then stream final output to NFS.
         */
        for (i = 0; i < num_pipes; i++) {
            close(pipes[i][1]);
            if (i < num_pipes - 1)
                close(pipes[i][0]);
        }

        stream_to_nfs(bctx, pipes[num_pipes - 1][0], io->stdout_path,
            io->stdout_append);
        close(pipes[num_pipes - 1][0]);
    } else {
        /*
         * Final stage runs in parent. Close all write ends and
         * intermediate read ends, keeping only the input for final stage.
         */
        for (i = 0; i < num_pipes; i++) {
            close(pipes[i][1]);
            if (i < num_pipes - 1)
                close(pipes[i][0]);
        }

        execute_final_stage(bctx, stages[nstages - 1], execute_fn,
            pipes[num_pipes - 1][0], sink_type);
        close(pipes[num_pipes - 1][0]);
    }

    /* Wait for all child processes */
    for (i = 0; i < stages_to_fork; i++)
        wait_for_child(pids[i]);
}

/*
 * Determine if any forking operations will occur.
 * Used to decide whether to enable RPC locking.
 */
static int
will_fork(int nstages, int sink_type, struct nfs_io *io)
{
    /* Pipelines require forking for non-final stages */
    if (nstages > 1)
        return 1;

    /* NFS I/O streaming requires forking */
    if (io != NULL) {
        /* NFS stdin or stderr streaming */
        if (io->stdin_path != NULL || io->stderr_path != NULL)
            return 1;
        /* Single command output to NFS file */
        if (sink_type == SINK_NFS && io->stdout_path != NULL)
            return 1;
    }

    return 0;
}

/*
 * Execute a command or pipeline with I/O to specified sinks.
 *
 * Handles:
 *   - Single commands (run in parent or child depending on sink)
 *   - Pipelines (cmd1 | cmd2 | cmd3)
 *   - Shell escapes (!cmd)
 *   - NFS I/O redirection (stdin from NFS, stdout/stderr to NFS)
 */
int
browse_execute_pipeline(struct browse_ctx *bctx, char *line,
    int (*execute_fn)(struct browse_ctx *, int, char **),
    int sink_type, struct nfs_io *io)
{
    char *stages[PIPE_MAX_STAGES];
    struct stream_state ss;
    char *p;
    char *start;
    char *cmd;
    int nstages;
    int need_rpc_lock;

    stream_state_init(&ss);

    /* Split command line into pipeline stages first to determine fork needs */
    nstages = 0;
    start = line;
    while (nstages < PIPE_MAX_STAGES - 1) {
        p = find_unquoted_pipe(start);
        if (p == NULL)
            break;
        *p = '\0';
        stages[nstages++] = skip_ws(start);
        start = p + 1;
    }
    stages[nstages++] = skip_ws(start);

    /*
     * Enable RPC locking if we'll fork any processes that might do NFS.
     * This prevents races on the shared UDP socket when multiple processes
     * (parent and children) make concurrent RPC calls.
     */
    need_rpc_lock = will_fork(nstages, sink_type, io);
    if (need_rpc_lock)
        bctx->nfs->concurrent_fork = 1;

    /* Set up NFS streaming for stdin/stderr if requested */
    if (io != NULL) {
        if (io->stdin_path != NULL) {
            setup_nfs_stdin(bctx, io->stdin_path, &ss);
            /* Make redirected stdin available to commands as pipe_input */
            if (ss.saved_stdin >= 0) {
                bctx->pipe_input = fdopen(STDIN_FILENO, "r");
                /* If fdopen fails, pipe_input stays NULL, which is handled */
            }
        }
        if (io->stderr_path != NULL)
            setup_nfs_stderr(bctx, io->stderr_path, io->stderr_append, &ss);
    }

    /* Execute based on pipeline complexity */
    if (nstages == 1) {
        /* Single command */
        cmd = stages[0];
        if (*cmd != '\0') {
            if (sink_type == SINK_STDOUT) {
                run_in_parent(bctx, cmd, execute_fn);
            } else if (sink_type == SINK_NULL) {
                execute_to_null(bctx, cmd, execute_fn);
            } else if (sink_type == SINK_NFS && io != NULL &&
                io->stdout_path != NULL) {
                execute_to_nfs(bctx, cmd, execute_fn, io->stdout_path,
                    io->stdout_append);
            }
        }
    } else {
        /* Multi-stage pipeline */
        execute_pipeline(bctx, stages, nstages, execute_fn, sink_type, io);
    }

    /* Clean up pipe_input before restoring stdin */
    if (bctx->pipe_input != NULL) {
        fclose(bctx->pipe_input);
        bctx->pipe_input = NULL;
    }

    /* Wait for NFS streaming children and restore file descriptors */
    cleanup_nfs_streams(&ss);

    /* Disable RPC locking now that all children have exited */
    if (need_rpc_lock)
        bctx->nfs->concurrent_fork = 0;

    return 0;
}
