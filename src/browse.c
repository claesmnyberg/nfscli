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
 * browse.c - Interactive filesystem browser
 *
 * Provides the "browse" command for interactive navigation of NFS exports.
 * Uses readline for command editing and tab completion.
 */

#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef NO_READLINE
#include <readline/history.h>
#include <readline/readline.h>
/*
 * Note: rl_done is declared as 'extern int' in readline.h, not volatile.
 * While not technically async-signal-safe, using rl_done in signal handlers
 * is standard practice in readline-based applications and works reliably.
 */
#endif

#include "ansicolors.h"
#include "browse.h"
#include "browse_cmd.h"
#include "browse_ctx.h"
#include "browse_expand.h"
#include "browse_pipe.h"
#include "browse_redir.h"
#include "cmdparse.h"
#include "completion.h"
#include "display.h"
#include "idmap.h"
#include "mount.h"
#include "nfs.h"
#include "nfs_escape.h"
#include "nfscli.h"
#include "nfsh.h"
#include "pathctx.h"
#include "portmap.h"
#include "str.h"
#include "transfer.h"

/*
 * Navigate to a file's parent directory and extract the filename.
 * Helper for try_pathctx_for_path().
 * Returns 0 on success, -1 on error.
 */
static int
navigate_to_file_parent(struct pathctx *pctx, const char *path,
    char **out_filename)
{
    char *pathcopy;
    char *last_slash;
    const char *parent_dir;

    pathcopy = strdup(path);
    if (pathcopy == NULL)
        return -1;

    last_slash = strrchr(pathcopy, '/');
    if (last_slash == NULL) {
        free(pathcopy);
        return -1;
    }

    /* Extract filename for caller */
    if (out_filename) {
        *out_filename = strdup(last_slash + 1);
        if (*out_filename == NULL) {
            free(pathcopy);
            return -1;
        }
    }

    /* Determine parent directory path */
    if (last_slash != pathcopy) {
        *last_slash = '\0';
        parent_dir = pathcopy;
    } else {
        parent_dir = "/";
    }

    /* Navigate to parent */
    if (pathctx_chdir(pctx, parent_dir) < 0) {
        if (out_filename) {
            free(*out_filename);
            *out_filename = NULL;
        }
        free(pathcopy);
        return -1;
    }

    free(pathcopy);
    return 0;
}

/*
 * Try to create a path context for browsing a path.
 * Creates context, mounts at mount_path with root_fh, navigates to nav_path.
 * If nav_path is a file, navigates to its parent directory and sets
 * *out_filename to the filename (caller must free).
 * Returns pathctx on success (caller owns), NULL on failure.
 */
static struct pathctx *
try_pathctx_for_path(struct nfsctx *ctx, const uint8_t *root_fh, int root_fhlen,
    const char *mount_path, const char *nav_path, char **out_filename)
{
    struct pathctx *pctx = NULL;
    struct nfs_fh fh;
    struct path_result res;
    const char *effective_nav_path = nav_path;
    const char *result_path;
    int saved_errno;

    if (out_filename)
        *out_filename = NULL;

    /* Allocate and initialize path context */
    pctx = malloc(sizeof(*pctx));
    if (pctx == NULL)
        return NULL;

    nfs_fh_from_buf(&fh, root_fh, root_fhlen);

    if (pathctx_init(pctx, ctx, mount_path, &fh) < 0)
        goto fail;

    /*
     * If requesting "/" but we can't reach true root, fail.
     * pathctx_init calls pathctx_probe_escape which attempts escape.
     */
    if (nav_path != NULL && strcmp(nav_path, "/") == 0 &&
        strcmp(mount_path, "/") != 0 && !pctx->has_ceiling) {
        errno = ENOENT;
        goto fail;
    }

    /*
     * Check if mount_path starts with nav_path (e.g., mount=/usr/bin, nav=/usr).
     * If so, navigate to ceiling (/) to get target directory content.
     */
    if (nav_path != NULL && nav_path[0] != '\0') {
        size_t nav_len = strlen(nav_path);
        size_t mount_len = strlen(mount_path);
        if (mount_len > nav_len &&
            strncmp(mount_path, nav_path, nav_len) == 0 &&
            (nav_len == 1 || mount_path[nav_len] == '/')) {
            effective_nav_path = "/";
        }
    }

    /* No navigation needed */
    if (effective_nav_path == NULL || effective_nav_path[0] == '\0')
        return pctx;

    /* Resolve target path */
    if (path_resolve(pctx, effective_nav_path, 0, &res) < 0)
        goto fail;

    /* Get attributes if needed */
    if (!res.has_attr) {
        if (nfs_getattr(ctx, &res.fh, &res.attr) < 0)
            goto fail;
        res.has_attr = 1;
    }

    if (res.attr.type == NFS_FTYPE_DIR) {
        /* Directory - navigate there */
        if (pathctx_chdir(pctx, effective_nav_path) < 0)
            goto fail;

        /* Verify we reached the requested path */
        result_path = pathctx_pwd(pctx);
        if (result_path != NULL && strcmp(result_path, nav_path) != 0) {
            errno = ENOENT;
            goto fail;
        }
    } else {
        /* File - navigate to parent, extract filename */
        if (navigate_to_file_parent(pctx, effective_nav_path, out_filename) < 0)
            goto fail;
    }

    return pctx;

fail:
    saved_errno = errno;
    if (pctx) {
        pathctx_destroy(pctx);
        free(pctx);
    }
    errno = saved_errno;
    return NULL;
}

/* Forward declarations */
static int browse_execute(struct browse_ctx *, int, char **);

/* Globals */
static int browse_cmds_sorted = 0;                           /* Commands sorted on first browse invocation */
#ifndef NO_READLINE
static struct completion_cmd *browse_completion_cmds = NULL; /* Completion cmd array */
#endif

/* Interrupt flag for long-running commands (Ctrl-C) */
volatile sig_atomic_t browse_interrupted = 0;

/* Command table */
static struct browse_cmd browse_cmds[] = {
    {"!<command>", "",
        "Execute (local) shell command",
        "",
        NULL, BCMD_META},

    {"cat", "<file>...",
        "Display file contents",
        "    file  -  File(s) to display\n",
        bcmd_cat, 0},

    {"cd", "[<dir>]",
        "Change directory",
        "    dir  -  Directory to change to\n\n"
        "With no argument, return to the starting directory.\n",
        bcmd_cd, 0},

    {"chmod", "<mode> <path>...",
        "Change file/directory permissions",
        "    mode  -  Permissions (octal)\n"
        "    path  -  Files or directories\n\n"
        "    chmod 644 *.txt      - Make all .txt files readable\n",
        bcmd_chmod, 0},

    {"chown", "<owner[:group]> <path>...",
        "Change file/directory ownership",
        "    owner  -  User ID (numeric)\n"
        "    group  -  Group ID (numeric, optional)\n"
        "    path   -  Files or directories\n\n"
        "Examples:\n"
        "    chown 1000 file      - Change owner to uid 1000\n"
        "    chown 1000:100 file  - Change owner and group\n"
        "    chown :100 file      - Change group only\n"
        "    chown 1000 *.c       - Change owner of all .c files\n",
        bcmd_chown, 0},

    {"df", "[-h] [-k] [<path>]",
        "Show filesystem space usage",
        "    -h    -  Human-readable sizes\n"
        "    -k    -  Show sizes in kilobytes\n"
        "    path  -  Show only for this path (default: all known mounts)\n",
        bcmd_df, 0},

    {"echo", "[-n] [-e] [<string>...]",
        "Display a line of text",
        "    -n      -  Do not output trailing newline\n"
        "    -e      -  Interpret backslash escapes:\n"
        "               \\\\  backslash, \\n newline, \\r carriage return\n"
        "               \\t tab, \\0NNN octal, \\xHH hex\n"
        "    string  -  Text to display\n\n"
        "Examples:\n"
        "    echo hello world           - Print 'hello world'\n"
        "    echo -n no newline         - Print without trailing newline\n"
        "    echo -e 'line1\\nline2'    - Print with embedded newline\n"
        "    echo foo > /tmp/test       - Write 'foo' to remote file\n",
        bcmd_echo, 0},

    {"exit", "",
        "Exit filesystem browser",
        "",
        NULL, BCMD_META},

    {"find", "[<path>...] [<expression>]",
        "Search for files in directory hierarchy",
        "Tests (all must match):\n"
        "    -name <glob>         -  Match filename against glob pattern\n"
        "    -iname <glob>        -  Case-insensitive filename match\n"
        "    -type <t>            -  File type: b=block, c=char, d=dir, f=file, l=symlink, p=fifo, s=socket\n"
        "    -user <uid>          -  Match files owned by UID\n"
        "    -group <gid>         -  Match files owned by GID\n"
        "    -perm <mode>         -  Permission bits: exact, -mode (all), /mode (any)\n"
        "    -size <[+-]n[ckMG]>  -  File size: +n (larger), -n (smaller), n (exact)\n"
        "    -mtime <[+-]n>       -  Modified n days ago: +n (older), -n (newer)\n\n"
        "Actions:\n"
        "    -print               -  Print pathname (default if no action)\n"
        "    -ls                  -  Print in ls -la format\n\n"
        "Options:\n"
        "    -maxdepth <n>        -  Maximum recursion depth\n\n"
        "Examples:\n"
        "    find . -name \"*.c\"                 Find all .c files\n"
        "    find . -mtime -1                   Modified in last 24 hours\n"
        "    find . -size +1M                   Files larger than 1MB\n"
        "    find / -user 0 -perm -4000 -ls     Root-owned SUID files\n",
        bcmd_find, 0},

    {"get", "<file> [<local-file>]",
        "Download file",
        "    file        -  Remote file to download\n"
        "    local-file  -  Local filename (default: same as remote)\n",
        bcmd_get, 0},

    {"grep", "[-i] [-v] [-n] [-r] <pattern> [<file>...]",
        "Search for pattern in files",
        "    -i       -  Case insensitive search\n"
        "    -v       -  Invert match (show non-matching lines)\n"
        "    -n       -  Show line numbers\n"
        "    -r       -  Recursive search in directories\n"
        "    pattern  -  Substring to search for\n"
        "    file     -  Files to search (default: stdin from pipe)\n\n"
        "Examples:\n"
        "    grep password /etc/passwd   - Search in single file\n"
        "    grep -r secret .            - Recursive search\n"
        "    ls -la | grep foo           - Search in piped output\n",
        bcmd_grep, 0},

    {"head", "[-n <lines>] [<file>...]",
        "Output first lines of files",
        "    -n     -  Number of lines (default: 10)\n"
        "    file   -  Files to read (default: stdin from pipe)\n\n"
        "Examples:\n"
        "    head /etc/passwd            - First 10 lines\n"
        "    head -n 5 /etc/hosts        - First 5 lines\n"
        "    cat file | head -n 20       - First 20 lines from pipe\n",
        bcmd_head, 0},

    {"help", "[<command>]",
        "Show command help",
        "    command  -  Command name\n",
        bcmd_help, BCMD_META},

    {"id", "[-a]",
        "Show current uid/gid",
        "    -a    -  show all groups from /etc/group\n",
        bcmd_id, 0},

    {"ls", "[<path> ...] [-a] [-d] [-h] [-l] [-L] [-n]",
        "List directory contents",
        "    path  -  Files or directories to list\n\n"
        "    -a    -  Show hidden files\n"
        "    -d    -  List directory itself, not contents\n"
        "    -h    -  Human-readable sizes\n"
        "    -l    -  Long format\n"
        "    -L    -  Follow symlinks to directories\n"
        "    -n    -  Show numeric uid/gid (with -l)\n\n"
        "    ls -la /export/home  -  Long listing with hidden files\n"
        "    ls -ld /etc          -  Show /etc directory attributes\n"
        "    ls *.c               -  List all .c files (glob expansion)\n",
        bcmd_ls, 0},

    {"ln", "[-s] <src-path> <dst-path>",
        "Create link to file",
        "    -s        -  Create symbolic link (default: hard link)\n"
        "    src-path  -  Target file (hard link) or path (symbolic link)\n"
        "    dst-path  -  Name of the new link\n\n"
        "    ln /etc/passwd passwd    -  Hard link to /etc/passwd\n"
        "    ln -s ../lib mylib       -  Symbolic link with relative target\n"
        "    ln -s /usr/bin/vim vi    -  Symbolic link with absolute target\n\n"
        "Hard links require target to exist and be on same filesystem.\n"
        "Symbolic links store target path as-is (can be relative or absolute).\n",
        bcmd_ln, 0},

    {"mkdir", "[-p] <dir>...",
        "Create directories",
        "    -p    -  Create parent directories as needed\n"
        "    dir   -  Directories to create\n",
        bcmd_mkdir, 0},

    {"mknod", "<type> <name> [<mode>] [<major> <minor>]",
        "Create special file (NFSv3 only)",
        "    type   -  chr|blk|sock|fifo\n"
        "    name   -  Path to create\n"
        "    mode   -  Permissions (default: 0644)\n"
        "    major  -  Major device number (chr/blk only)\n"
        "    minor  -  Minor device number (chr/blk only)\n\n"
        "Examples:\n"
        "    mknod sock mysocket\n"
        "    mknod fifo mypipe 0600\n"
        "    mknod blk mydev 0660 8 0\n",
        bcmd_mknod, 0},

    {"mv", "<src-path> <dst-path>",
        "Rename/move file or directory",
        "    src-path  -  Source path\n"
        "    dst-path  -  Destination path\n\n"
        "    mv old.txt new.txt   -  Rename file\n"
        "    mv file.txt subdir/  -  Move file into directory\n\n"
        "Cross-filesystem moves are not supported.\n",
        bcmd_mv, 0},

    {"put", "[-f] <local-file> [<file>]",
        "Upload file",
        "    -f          -  Force overwrite if file exists\n"
        "    local-file  -  Local file to upload\n"
        "    file        -  Remote filename (default: same as local)\n",
        bcmd_put, 0},

    {"pwd", "",
        "Print working directory",
        "",
        bcmd_pwd, 0},

    {"readlink", "<path>...",
        "Print symbolic link target",
        "    path  -  Symbolic link(s) to read\n\n"
        "Examples:\n"
        "    readlink mylink      - Show where mylink points\n"
        "    readlink /etc/*      - Show all symlink targets in /etc\n",
        bcmd_readlink, 0},

    {"rm", "[-rf] <path>...",
        "Remove file(s) or directories",
        "    -r    -  Recursive (remove directories and contents)\n"
        "    -f    -  Ignore missing files\n"
        "    path  -  File(s) or directory(s) to remove\n",
        bcmd_rm, 0},

    {"rmdir", "<dir>...",
        "Remove directories",
        "    dir  -  Directories to remove (must be empty)\n",
        bcmd_rmdir, 0},

    {"set", "[<name> [<value>]]",
        "Display or change browse settings",
        "    name   -  Setting name (autouid, completion, uid, gid)\n"
        "    value  -  New value\n\n"
        "Settings:\n"
        "    autouid     -  on|off (auto-switch uid for read operations, default: on)\n"
        "    completion  -  basic|enhanced (NFSv2 only)\n"
        "                   basic: low detail, less network traffic\n"
        "                   enhanced: full detail, more network traffic\n"
        "    uid         -  numeric or username (RPC credential user ID)\n"
        "    gid         -  numeric or groupname (RPC credential group ID)\n\n"
        "Examples:\n"
        "    set                      - Show all settings\n"
        "    set autouid off          - Disable automatic uid switching\n"
        "    set uid 1000             - Set RPC uid to 1000\n"
        "    set uid nobody           - Set RPC uid by name\n"
        "    set uid root:sys         - Set RPC uid and gid by name\n",
        bcmd_set, 0},

    {"stat", "<path>...",
        "Show file/directory attributes",
        "    path  -  Files or directories to stat\n",
        bcmd_stat, 0},

    {"strings", "[-n <min>] [<file>...]",
        "Extract printable strings from files",
        "    -n     -  Minimum string length (default: 4)\n"
        "    file   -  Files to read (default: stdin from pipe)\n\n"
        "Examples:\n"
        "    strings /bin/ls             - Extract strings from binary\n"
        "    strings -n 8 file           - Only strings 8+ chars long\n",
        bcmd_strings, 0},

    {"tail", "[-n <lines>] [<file>...]",
        "Output last lines of files",
        "    -n     -  Number of lines (default: 10)\n"
        "    file   -  Files to read (default: stdin from pipe)\n\n"
        "Examples:\n"
        "    tail /var/log/messages      - Last 10 lines\n"
        "    tail -n 50 logfile          - Last 50 lines\n"
        "    cat file | tail -n 5        - Last 5 lines from pipe\n",
        bcmd_tail, 0},

    {"touch", "<path>...",
        "Update file access and modification times",
        "    path  -  Files to touch (created if missing)\n\n"
        "    touch newfile        -  Create empty file\n"
        "    touch existing.txt   -  Update timestamps\n\n"
        "Sets atime and mtime to current server time.\n",
        bcmd_touch, 0},

    {"truncate", "<size> <path>",
        "Truncate or extend file to specified size",
        "    size  -  New file size in bytes\n"
        "    path  -  File to truncate\n\n"
        "Examples:\n"
        "    truncate 0 file     - Empty the file\n"
        "    truncate 1024 file  - Set file size to 1024 bytes\n",
        bcmd_truncate, 0},

    {"wc", "[-l] [-w] [-c] [<file>...]",
        "Print line, word, and byte counts",
        "    -l     -  Print line count only\n"
        "    -w     -  Print word count only\n"
        "    -c     -  Print byte count only\n"
        "    file   -  Files to read (default: stdin from pipe)\n\n"
        "Examples:\n"
        "    wc /etc/passwd              - Lines, words, bytes\n"
        "    wc -l *.c                   - Count lines in .c files\n"
        "    cat file | wc               - Count from pipe\n",
        bcmd_wc, 0},

    {"xxd", "[<file>...]",
        "Hex dump of files",
        "    file   -  Files to dump (default: stdin from pipe)\n\n"
        "Examples:\n"
        "    xxd /bin/ls                 - Hex dump of binary\n"
        "    cat file | xxd              - Hex dump from pipe\n",
        bcmd_xxd, 0},

    {NULL, NULL, NULL, NULL, NULL, 0}};

/*
 * Get command table (for help command in browse_cmd_misc.c)
 */
const struct browse_cmd *
browse_get_cmds(void)
{
    return browse_cmds;
}

/*
 * Check if --help is present in argv
 */
static int
has_help_flag(int argc, char **argv)
{
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0)
            return 1;
    }
    return 0;
}

/*
 * Print command usage and help
 */
static void
print_command_help(const struct browse_cmd *cmd)
{
    printf("Usage: %s %s\n", cmd->name, cmd->syntax);
    printf("%s\n", cmd->help_short);
    if (cmd->help_long[0] != '\0')
        printf("%s", cmd->help_long);
}

static int
browse_execute(struct browse_ctx *bctx, int argc, char **argv)
{
    char **exp_argv = NULL;
    int exp_argc = 0;
    int i, ret = 0;

    /* Handle exit command */
    if (strcmp(argv[0], "exit") == 0) {
        bctx->running = 0;
        return 0;
    }

    /* Expand globs in arguments */
    exp_argv = expand_globs(bctx, argc, argv, &exp_argc);
    if (exp_argv != NULL) {
        argc = exp_argc;
        argv = exp_argv;
    }

    /* Find and execute command */
    for (i = 0; browse_cmds[i].name != NULL; i++) {
        if (strcmp(argv[0], browse_cmds[i].name) == 0) {
            if (browse_cmds[i].func == NULL) {
                /* Entry exists but has no handler (e.g. help-only entries) */
                goto done;
            }
            /* Handle --help for non-meta commands */
            if (!(browse_cmds[i].flags & BCMD_META) && has_help_flag(argc, argv)) {
                print_command_help(&browse_cmds[i]);
                goto done;
            }
            if (browse_cmds[i].func(bctx, argc, argv) < 0) {
                /* Only print wrapper error if errno is set (command didn't report error) */
                if (errno != 0)
                    fprintf(stderr, "%s: %s\n", browse_cmds[i].name, strerror(errno));
                ret = -1;
                goto done;
            }
            goto done;
        }
    }

    fprintf(stderr, "*** Unknown command '%s', type 'help' for help\n", argv[0]);
    ret = -1;

done:
    if (exp_argv != NULL)
        free_expanded_argv(exp_argv, exp_argc);
    return ret;
}

/*
 * SIGINT handler for browse shell
 * - During command execution: sets browse_interrupted flag
 * - During readline: cancels current line and returns to prompt
 *
 * This handler is async-signal-safe: it only sets volatile sig_atomic_t flags.
 * We avoid using rl_done as it's not properly async-signal-safe per POSIX.
 * Save and restore errno to avoid interfering with interrupted system calls.
 */
static void
browse_sigint_handler(int sig)
{
    int saved_errno = errno;
    (void)sig;
    browse_interrupted = 1;
    errno = saved_errno;
}

static int
browse_shell(struct browse_ctx *bctx)
{
    char pathbuf[NFS_MAXPATHLEN];
    char prompt[NFS_MAXPATHLEN + 128];
    char buf[BROWSE_MAXLINE];
    int saved_quiet;
    struct sigaction sa, old_sa;
    char *linecopy;

    /* Suppress NFS errors - commands provide user-friendly messages */
    saved_quiet = bctx->nfs->quiet;
    bctx->nfs->quiet = 1;

    /* Install SIGINT handler for Ctrl-C */
    sa.sa_handler = browse_sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* No SA_RESTART - let SIGINT interrupt blocking calls */
    sigaction(SIGINT, &sa, &old_sa);

    /* Initialize browse_interrupted after installing handler for clean startup */
    browse_interrupted = 0;

    bctx->running = 1;

    /* If browsed to a file, try to cat it; fall back to ls -l if binary */
    if (bctx->initial_file != NULL) {
        struct path_result res;
        int64_t ret = -1;
        int show_ls = 1;

        /* Try to cat the file if it's a regular file */
        if (path_resolve(bctx->pctx, bctx->initial_file, PATH_FOLLOW, &res) == 0) {
            if (!res.has_attr)
                nfs_getattr(bctx->nfs, &res.fh, &res.attr);
            if (res.attr.type == NFS_FTYPE_REG) {
                ret = transfer_download(bctx->nfs, res.fh.data, res.fh.len, 0, stdout,
                    DL_CHECK_BINARY);
                if (ret >= 0)
                    show_ls = 0; /* Successfully printed text content */
            }
        }

        /* Fall back to ls -l if binary or not a regular file */
        if (show_ls) {
            char *argv[4];
            int is_hidden = (bctx->initial_file[0] == '.');

            argv[0] = "ls";
            argv[1] = is_hidden ? "-al" : "-l";
            argv[2] = bctx->initial_file;
            argv[3] = NULL;
            browse_execute(bctx, 3, argv);
        }

        free(bctx->initial_file);
        bctx->initial_file = NULL;
    }

    while (bctx->running) {
        char *cmd;

        /* Check for pending batch commands (from nfsh command buffer) */
        if (bctx->nfs->batch_saveptr != NULL) {
            cmd = strtok_r(NULL, ";", bctx->nfs->batch_saveptr);
            if (cmd != NULL) {
                /* Skip leading whitespace */
                while (*cmd == ' ' || *cmd == '\t')
                    cmd++;
                /* Skip comments and empty lines */
                if (*cmd != '\0' && *cmd != '#') {
                    linecopy = strdup(cmd);
                    if (linecopy != NULL) {
                        browse_execute_pipeline(bctx, linecopy, browse_execute,
                            SINK_STDOUT, NULL);
                        free(linecopy);
                    }
                }
                continue;
            }
        }

        /* Interactive mode - read from terminal */

        /* Build prompt with server and current path */
        if (!bctx->nfs->term.interactive) {
            prompt[0] = '\0';
        } else {
            char path_display[64];
            const size_t max_path = 50;

            const char *pwd = pathctx_pwd(bctx->pctx);
            if (pwd == NULL)
                pathbuf[0] = '\0';
            else
                snprintf(pathbuf, sizeof(pathbuf), "%s", pwd);

            /* Truncate path at component boundary if too long */
            if (strlen(pathbuf) > max_path) {
                const char *p = pathbuf + strlen(pathbuf) - max_path + 4;
                const char *slash = strchr(p, '/');
                if (slash != NULL)
                    snprintf(path_display, sizeof(path_display), "...%s", slash);
                else
                    snprintf(path_display, sizeof(path_display), "...%s", p);
            } else {
                snprintf(path_display, sizeof(path_display), "%s", pathbuf);
            }

            if (bctx->nfs->net.spoof_str != NULL)
                snprintf(prompt, sizeof(prompt), "nfsh [SPOOFING %s] %s:%s> ",
                    bctx->nfs->net.spoof_str, bctx->nfs->server.name, path_display);
            else
                snprintf(prompt, sizeof(prompt), "nfsh %s:%s> ",
                    bctx->nfs->server.name, path_display);
        }

        if (nfsh_readln(prompt, buf, sizeof(buf)) == NULL)
            break; /* Ctrl-D exits browse mode */

        /* Clear any interrupt from Ctrl-C during line editing */
        browse_interrupted = 0;

        /* Skip empty lines and comments */
        if (buf[0] == '\0' || buf[0] == '#')
            continue;

#ifndef NO_READLINE
        add_history(buf);
#endif

        /* shell escape for convenience */
        if (nfsh_shell_escape(buf))
            continue;

        /* Parse redirections (<, >, >>, 2>/dev/null, 2>&1) */
        struct redir_state redir;
        int sink_type;
        struct nfs_io nfs_io;

        parse_redirections(buf, &redir);

        /* Setup NFS I/O and check access permissions */
        if (browse_setup_nfs_io(bctx, &redir, &nfs_io, &sink_type) < 0)
            continue;

        /* Apply simple redirections (2>/dev/null, 2>&1) */
        redir_apply(&redir);

        /* Execute command or pipeline */
        linecopy = strdup(buf);
        if (linecopy != NULL) {
            struct nfs_io *nfs_ptr = browse_has_nfs_io(&redir) ? &nfs_io : NULL;
            browse_execute_pipeline(bctx, linecopy, browse_execute,
                sink_type, nfs_ptr);
            free(linecopy);
        }

        /* Restore redirections */
        redir_restore(&redir);
    }

    /* Restore original SIGINT handler */
    sigaction(SIGINT, &old_sa, NULL);

    bctx->nfs->quiet = saved_quiet;
    return 0;
}

#ifndef NO_READLINE
struct readline_backup {
    char **history_lines;
    int history_count;
    rl_completion_func_t *completion_func;
};

static void
browse_completion_init(struct pathctx *pctx, struct idmap *map)
{
    size_t i, count;

    /* Count commands */
    for (count = 0; browse_cmds[count].name != NULL; count++)
        ;

    browse_completion_cmds = malloc((count + 1) * sizeof(struct completion_cmd));
    if (browse_completion_cmds == NULL)
        return;

    for (i = 0; i < count; i++) {
        browse_completion_cmds[i].name = browse_cmds[i].name;
        browse_completion_cmds[i].syntax = browse_cmds[i].syntax;
    }
    browse_completion_cmds[count].name = NULL;
    browse_completion_cmds[count].syntax = NULL;

    completion_init(browse_completion_cmds, count);
    completion_set_pathctx(pctx);
    completion_set_idmap(map);
}

static void
browse_completion_cleanup(void)
{
    completion_set_pathctx(NULL);
    completion_set_idmap(NULL);
    completion_cleanup();
    free(browse_completion_cmds);
    browse_completion_cmds = NULL;
}

static struct readline_backup *
readline_save(void)
{
    struct readline_backup *backup;
    HIST_ENTRY **list;
    int i;
    char *line_copy;

    backup = malloc(sizeof(*backup));
    if (backup == NULL)
        return NULL;

    backup->history_lines = NULL;
    backup->history_count = 0;
    backup->completion_func = rl_attempted_completion_function;

    list = history_list();
    if (list == NULL)
        return backup;

    /* Count entries */
    for (i = 0; list[i] != NULL; i++)
        backup->history_count++;

    if (backup->history_count == 0)
        return backup;

    backup->history_lines = malloc(sizeof(char *) * backup->history_count);
    if (backup->history_lines == NULL) {
        free(backup);
        return NULL;
    }

    /* Copy entries */
    for (i = 0; i < backup->history_count; i++) {
        line_copy = strdup(list[i]->line);
        if (line_copy == NULL) {
            while (--i >= 0)
                free(backup->history_lines[i]);
            free(backup->history_lines);
            free(backup);
            return NULL;
        }
        backup->history_lines[i] = line_copy;
    }

    clear_history();
    rl_attempted_completion_function = NULL;
    return backup;
}

static void
readline_restore(struct readline_backup *backup)
{
    int i;

    if (backup == NULL)
        return;

    clear_history();

    for (i = 0; i < backup->history_count; i++) {
        add_history(backup->history_lines[i]);
        free(backup->history_lines[i]);
    }

    free(backup->history_lines);
    rl_attempted_completion_function = backup->completion_func;
    free(backup);
}
#endif /* NO_READLINE */

/*
 * Initialize mount and NFS services if not already done.
 * Returns 0 on success, -1 on error.
 */
static int
browse_init_services(struct nfsctx *ctx)
{
    if (ctx->ports.mountd == 0 || ctx->proto.mount_version_mask == 0) {
        init_mount_version(ctx);
        if (ctx->ports.mountd == 0) {
            fprintf(stderr, "*** mount service unavailable\n");
            return -1;
        }
    }

    if (ctx->ports.nfsd == 0 || ctx->proto.nfs_version_mask == 0) {
        init_nfs_version(ctx);
        if (ctx->ports.nfsd == 0) {
            fprintf(stderr, "*** NFS service unavailable\n");
            return -1;
        }
    }

    return 0;
}

/*
 * Try to find a matching export and create pathctx for path.
 * Sets bctx->pctx on success.
 * Returns 0 on success, -1 on error.
 */
static int
browse_find_and_mount(struct nfsctx *ctx, const char *path,
    struct browse_ctx *bctx)
{
    uint8_t root_fh[NFS_FHSIZE_MAX];
    int root_fhlen;
    const char *mount_path;
    const char *nav_path = NULL;
    int saved_quiet;

    /* Early check: is NFS service available? */
    if (!nfs_service_available(ctx)) {
        fprintf(stderr, "*** NFS service unavailable on %s\n",
            ctx->server.name ? ctx->server.name : "server");
        return -1;
    }

    /* Strategy 1: Path matches an export - mount that, navigate to remainder */
    mount_path = mount_exports_find_best(ctx, path);
    if (mount_path != NULL) {
        size_t mount_len = strlen(mount_path);

        if (path[mount_len] == '/') {
            nav_path = path + mount_len;
        } else if (path[mount_len] == '\0') {
            nav_path = NULL;
        } else {
            fprintf(stderr, "*** No export matches path %s\n", path);
            return -1;
        }

        root_fhlen = mount_mnt_cached(ctx, mount_path, root_fh,
            sizeof(root_fh), MNT_CACHE_UMNT);
        if (root_fhlen < 0) {
            if (errno != 0)
                fprintf(stderr, "*** Cannot mount %s: %s\n",
                    mount_path, strerror(errno));
            else
                fprintf(stderr, "*** Cannot mount %s (RPC error)\n", mount_path);
            return -1;
        }

        saved_quiet = ctx->quiet;
        ctx->quiet = 1;
        bctx->pctx = try_pathctx_for_path(ctx, root_fh, root_fhlen,
            mount_path, nav_path, &bctx->initial_file);
        ctx->quiet = saved_quiet;

        if (bctx->pctx == NULL) {
            if (errno != 0)
                fprintf(stderr, "*** Cannot access %s: %s\n",
                    path, strerror(errno));
            else
                fprintf(stderr, "*** Cannot access %s (NFS error)\n", path);
            return -1;
        }
        return 0;
    }

    /* Strategy 2: Try each export in priority order */
    if (mount_exports_cache_count(ctx) > 0) {
        struct mount_export_iter iter;

        saved_quiet = ctx->quiet;
        ctx->quiet = 1;
        mount_export_iter_init(&iter, path);

        while ((mount_path = mount_export_iter_next(ctx, &iter)) != NULL) {
            root_fhlen = mount_mnt_cached(ctx, mount_path, root_fh,
                sizeof(root_fh), MNT_CACHE_UMNT);
            if (root_fhlen < 0)
                continue;

            bctx->pctx = try_pathctx_for_path(ctx, root_fh, root_fhlen,
                mount_path, path, &bctx->initial_file);
            if (bctx->pctx != NULL)
                break;
        }
        ctx->quiet = saved_quiet;

        if (bctx->pctx != NULL)
            return 0;
    }

    /* Strategy 3: Auto-enumerate exports and retry */
    if (mount_exports_cache_count(ctx) == 0) {
        struct mount_export *xpl = NULL;

        if (mount_get_exports(ctx, &xpl) < 0) {
            if (errno != 0)
                fprintf(stderr, "*** Failed to get exports: %s\n",
                    strerror(errno));
            else
                fprintf(stderr, "*** Failed to get exports (RPC error)\n");
            return -1;
        }

        if (xpl == NULL) {
            fprintf(stderr, "*** Server has no exports\n");
            return -1;
        }
        mount_export_free(xpl);

        if (mount_exports_cache_count(ctx) == 0) {
            if (!ctx->cache.enabled)
                fprintf(stderr, "*** Caching is disabled\n");
            else
                fprintf(stderr, "*** No exports available\n");
            return -1;
        }

        /* Retry with freshly cached exports */
        return browse_find_and_mount(ctx, path, bctx);
    }

    fprintf(stderr, "*** Cannot access %s from any export\n", path);
    return -1;
}

/*
 * Initialize ID mappings from server's /etc/passwd and /etc/group.
 */
static void
browse_init_idmap(struct nfsctx *ctx, struct idmap *idmap, struct pathctx *pctx)
{
    int saved_quiet = ctx->quiet;
    ctx->quiet = 1;
    idmap_init(idmap, pctx);
    ctx->quiet = saved_quiet;
}

/*
 * Mount all known exports for cross-mount navigation.
 */
static void
browse_mount_all_exports(struct nfsctx *ctx, struct pathctx *pctx)
{
    size_t ei;
    const char *exp;
    uint8_t fh[NFS_FHSIZE_MAX];
    int fhlen;
    int saved_quiet = ctx->quiet;

    ctx->quiet = 1;

    /* Mount "/" first if available - marks root as ceiling */
    exp = mount_exports_find_best(ctx, "/");
    if (exp != NULL && strcmp(exp, "/") == 0) {
        fhlen = mount_mnt_cached(ctx, "/", fh, sizeof(fh), MNT_CACHE_UMNT);
        if (fhlen >= 0) {
            struct nfs_fh nfs_fh;
            nfs_fh.len = fhlen;
            memcpy(nfs_fh.data, fh, fhlen);
            pathctx_mount(pctx, "/", &nfs_fh);
        }
    }

    /* Mount remaining exports */
    for (ei = 0; (exp = mount_exports_cache_get(ctx, ei)) != NULL; ei++) {
        struct nfs_fh nfs_fh;

        if (strcmp(exp, "/") == 0)
            continue;

        fhlen = mount_mnt_cached(ctx, exp, fh, sizeof(fh), MNT_CACHE_UMNT);
        if (fhlen < 0)
            continue;

        nfs_fh.len = fhlen;
        memcpy(nfs_fh.data, fh, fhlen);
        pathctx_mount(pctx, exp, &nfs_fh);
    }

    ctx->quiet = saved_quiet;
}

int
cmd_browse(struct nfsctx *ctx, int argc, char **argv)
{
    struct browse_ctx bctx = {0};
    const char *path;
    char pathbuf[NFS_MAXPATHLEN];
#ifndef NO_READLINE
    struct readline_backup *rl_backup;
#else
    struct norl_history_backup *norl_backup;
#endif

    /* Sort commands once on first invocation */
    if (!browse_cmds_sorted) {
        size_t ncmds;
        for (ncmds = 0; browse_cmds[ncmds].name != NULL; ncmds++)
            ;
        qsort(browse_cmds, ncmds, sizeof(browse_cmds[0]), name_cmp);
        browse_cmds_sorted = 1;
    }

    if (argc > 2) {
        errno = EINVAL;
        return -1;
    }

    /* Default to "/" if no path specified */
    path = (argc == 2) ? argv[1] : "/";

    /* Normalize path (rejects relative paths) */
    if (path[0] != '/' || path_normalize(path, pathbuf, sizeof(pathbuf)) < 0) {
        fprintf(stderr, "*** Must be an absolute path\n");
        errno = EINVAL;
        return -1;
    }
    path = pathbuf;

    /* Initialize services */
    if (browse_init_services(ctx) < 0)
        return 0;

    /* Initialize browse context */
    bctx.nfs = ctx;
    bctx.pctx = NULL;
    bctx.running = 0;
    bctx.autouid = 1;

    /* Find export and create pathctx */
    if (browse_find_and_mount(ctx, path, &bctx) < 0)
        return 0;

    /* Set home directory for cd with no args */
    pathctx_set_home(bctx.pctx);

    /* Mount all exports for cross-mount navigation */
    browse_mount_all_exports(ctx, bctx.pctx);

    /* Load uid/gid mappings */
    browse_init_idmap(ctx, &bctx.idmap, bctx.pctx);

#ifndef NO_READLINE
    rl_backup = readline_save();
    browse_completion_init(bctx.pctx, &bctx.idmap);
#else
    norl_backup = norl_history_save();
#endif

    browse_shell(&bctx);

#ifndef NO_READLINE
    browse_completion_cleanup();
    readline_restore(rl_backup);
    nfsh_completion_init();
    completion_set_nfsctx(bctx.nfs);
#else
    norl_history_restore(norl_backup);
#endif

    /* Clean up */
    idmap_free(&bctx.idmap);
    if (bctx.pctx) {
        pathctx_destroy(bctx.pctx);
        free(bctx.pctx);
    }

    return 0;
}
