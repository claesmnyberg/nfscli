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
 * nfsh_cmds.c - Shell command implementations
 *
 * Command table and implementations for the interactive shell.
 * Separated from nfsh.c for better organization.
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "browse.h"
#include "cmdparse.h"
#include "display.h"
#include "explore.h"
#include "mount.h"
#include "nfs.h"
#include "nfs_cache.h"
#include "nfs_escape.h"
#include "nfs_ops.h"
#include "nfs_util.h"
#include "nfscli.h"
#include "nfsh_cmds.h"
#include "pathctx.h"
#include "portmap.h"
#include "portmap_ops.h"
#include "print.h"
#include "rpc.h"
#include "str.h"
#include "transfer.h"

/* Validate name length - use in commands that take a filename argument */
#define CHECK_NAME_LEN(ctx, name)                            \
    do {                                                     \
        if (strlen(name) > NAMEMAXLEN) {                     \
            print(V_INFO, ctx, "** Error: Name too long\n"); \
            errno = EINVAL;                                  \
            return -1;                                       \
        }                                                    \
    } while (0)

/* Check that mount port and version have been resolved */
#define CHECK_MOUNTD_PORT(ctx)                                             \
    do {                                                                   \
        if ((ctx)->ports.mountd == 0 || (ctx)->proto.mount_version == 0) { \
            fprintf(stderr, "** Error: mount service not configured, "     \
                            "perhaps run 'getport mount'?\n");             \
            return 0;                                                      \
        }                                                                  \
    } while (0)

/* Validate argument count with specific error messages */
#define CHECK_ARGC_MIN(n)                                 \
    do {                                                  \
        if (argc < (n)) {                                 \
            fprintf(stderr, "*** Missing argument(s)\n"); \
            errno = EINVAL;                               \
            return -1;                                    \
        }                                                 \
    } while (0)

#define CHECK_ARGC_MAX(n)                                \
    do {                                                 \
        if (argc > (n)) {                                \
            fprintf(stderr, "*** Too many arguments\n"); \
            errno = EINVAL;                              \
            return -1;                                   \
        }                                                \
    } while (0)

#define CHECK_ARGC(min, max) \
    do {                     \
        CHECK_ARGC_MIN(min); \
        CHECK_ARGC_MAX(max); \
    } while (0)

#define CHECK_ARGC_EXACT(n) CHECK_ARGC(n, n)

/* Parse and set a uint32 context field from argv[1]
 * Accepts signed values (e.g., -2 for nobody/anonymous) which are
 * converted to their unsigned 32-bit equivalent (e.g., 4294967294)
 */
#define CMD_SET_UINT32(field)                                        \
    do {                                                             \
        long _val;                                                   \
        char *_ep;                                                   \
        CHECK_ARGC_EXACT(2);                                         \
        errno = 0;                                                   \
        _val = strtol(argv[1], &_ep, 0);                             \
        if (_ep == argv[1] || *_ep != '\0' || errno != 0) {          \
            errno = EINVAL;                                          \
            return -1;                                               \
        }                                                            \
        /* On 64-bit systems, check value fits in 32 bits */         \
        if (sizeof(long) > 4) {                                      \
            if (_val < (long)INT32_MIN || _val > (long)UINT32_MAX) { \
                errno = ERANGE;                                      \
                return -1;                                           \
            }                                                        \
        }                                                            \
        ctx->field = (uint32_t)_val;                                 \
        return 0;                                                    \
    } while (0)

/*
 * Print "version not available" error with supported versions.
 */
static void
print_version_unavailable(const char *name, int requested, uint8_t mask,
    int min_ver, int max_ver)
{
    int v;
    int has_any = 0;

    /* Check if any versions are available */
    for (v = min_ver; v <= max_ver; v++)
        if (mask & VERSION_AVAIL(v))
            has_any = 1;

    if (!has_any) {
        fprintf(stderr, "*** %s service unavailable\n", name);
        return;
    }

    fprintf(stderr, "*** %s v%d unavailable (server supports:", name, requested);
    for (v = min_ver; v <= max_ver; v++)
        if (mask & VERSION_AVAIL(v))
            fprintf(stderr, " v%d", v);
    fprintf(stderr, ")\n");
}

/* Local routines */
static int cmd_access(struct nfsctx *, int, char **);
static int cmd_cache(struct nfsctx *, int, char **);
static int cmd_commit(struct nfsctx *, int, char **);
static int cmd_cat(struct nfsctx *, int, char **);
static int cmd_create(struct nfsctx *, int, char **);
static int cmd_df(struct nfsctx *, int, char **);
static int cmd_dump(struct nfsctx *, int, char **);
static int cmd_exports(struct nfsctx *, int, char **);
static int cmd_fsinfo(struct nfsctx *, int, char **);
static int cmd_getattr(struct nfsctx *, int, char **);
static int cmd_getfh(struct nfsctx *, int, char **);
static int cmd_getoff(struct nfsctx *, int, char **);
static int cmd_getport(struct nfsctx *, int, char **);
static int cmd_get(struct nfsctx *, int, char **);
static int cmd_help(struct nfsctx *, int, char **);
static int cmd_link(struct nfsctx *, int, char **);
static int cmd_lookup(struct nfsctx *, int, char **);
static int cmd_mkdir(struct nfsctx *, int, char **);
static int cmd_mknod(struct nfsctx *, int, char **);
static int cmd_mnt(struct nfsctx *, int, char **);
static int cmd_pathconf(struct nfsctx *, int, char **);
static int cmd_ping(struct nfsctx *, int, char **);
static int cmd_putoff(struct nfsctx *, int, char **);
static int cmd_put(struct nfsctx *, int, char **);
static int cmd_readdirplus(struct nfsctx *, int, char **);
static int cmd_readdir(struct nfsctx *, int, char **);
static int cmd_readlink(struct nfsctx *, int, char **);
static int cmd_read(struct nfsctx *, int, char **);
static int cmd_remove(struct nfsctx *, int, char **);
static int cmd_rename(struct nfsctx *, int, char **);
static int cmd_rmdir(struct nfsctx *, int, char **);
static int cmd_rpcinfo(struct nfsctx *, int, char **);
static int cmd_setattr(struct nfsctx *, int, char **);
static int cmd_set_gid(struct nfsctx *, int, char **);
static int cmd_settings(struct nfsctx *, int, char **);
static int cmd_set_uid(struct nfsctx *, int, char **);
static int cmd_set_verbose(struct nfsctx *, int, char **);
static int cmd_symlink(struct nfsctx *, int, char **);
static int cmd_umnt(struct nfsctx *, int, char **);
static int cmd_umntall(struct nfsctx *, int, char **);
static int cmd_protocol(struct nfsctx *, int, char **);
static int cmd_write(struct nfsctx *, int, char **);

/* All interactive commands */
struct cmd cmds[] =
    {
        {"!<command>", "", "Execute (local) shell command", "", NULL},
        {"access", "<fh> [rwxdel]",
            "(NFS v3 ACCESS) Check access permissions",
            "    fh     -  File or directory handle\n"
            "    mask   -  Permission mask to check (default: all)\n"
            "              r=read, w=modify, x=execute/lookup\n"
            "              e=extend, d=delete, l=lookup (dirs)\n\n"
            "NFSv3 only. Result shows which permissions are actually granted.\n",
            cmd_access},

        {"browse", "[<export>]",
            "Browse remote filesystem",
            "    export  -  Export path or other absolute path (default: /)\n",
            cmd_browse},

        {"cache", "[on|off|clear|detailed]",
            "Control directory cache",
            "    (none)    -  Show cache status\n"
            "    on        -  Enable directory caching (default)\n"
            "    off       -  Disable directory caching\n"
            "    clear     -  Clear all cached data\n"
            "    detailed  -  Show detailed cache statistics\n",
            cmd_cache},

        {"cat", "<filefh>",
            "(NFS READ) Read file and write to terminal",
            "    filefh  -  File handle (regular file only)\n",
            cmd_cat},

        {"commit", "<filefh> [offset] [count]",
            "(NFS v3 COMMIT) Commit cached writes to stable storage",
            "    filefh  -  File handle (regular file only)\n"
            "    offset  -  Start offset (default: 0)\n"
            "    count   -  Byte count (default: 0 = entire file)\n\n"
            "Forces data previously written with UNSTABLE to stable storage.\n"
            "Returns a write verifier for detecting server reboots.\n"
            "NFSv3 only.\n",
            cmd_commit},

        {"create", "<dirfh> <name> <mode> [guarded|exclusive|unchecked]",
            "(NFS CREATE) Create regular file in directory",
            "    dirfh  -  Directory file handle\n"
            "    name   -  Filename to create\n"
            "    mode   -  Permissions (octal)\n"
            "    cmode  -  Create mode (NFSv3 only, default: guarded)\n\n"
            "NFSv3 create modes:\n"
            "    guarded    -  Fail with EEXIST if file exists (default)\n"
            "    exclusive  -  Atomic create with 8-byte verifier\n"
            "    unchecked  -  Create file, truncate if exists\n\n"
            "NFSv2 ignores create mode (behavior is server-dependent).\n\n"
            "    create FH newfile.txt 0644\n"
            "    create FH config.tmp 0600 guarded\n"
            "    create FH .lockfile 0600 exclusive\n",
            cmd_create},

        {"df", "<fh>",
            "(NFS STATFS/FSSTAT) Get filesystem statistics",
            "    fh  -  File handle on the filesystem\n\n"
            "Shows filesystem usage: total/used/available space and inodes.\n"
            "NFSv2: Uses STATFS (block-based values).\n"
            "NFSv3: Uses FSSTAT (byte-based values).\n",
            cmd_df},

        {"dump", "",
            "(Mount DUMP) List file systems mounted by all clients",
            "",
            cmd_dump},

        {"explore", "[-a]",
            "Explore remote NFS server",
            "    1) Resolve FH for all shares exported to everyone\n"
            "    2) Climb to the top directory of each share, to try to find root fs\n"
            "    3) Attempt to list and display interesting files and directories\n\n"
            "    -a  -  Attempt to resolve all shares, regardless of client IP\n",
            cmd_explore},

        {"exports", "",
            "(Mount EXPORT) Show the NFS server's export list",
            "Shows export paths and access groups (host restrictions).\n"
            "Exports available to everyone are shown as <everyone>.\n",
            cmd_exports},

        {"fsinfo", "<fh>",
            "(NFS v3 FSINFO) Get filesystem information",
            "    fh  -  File handle on the filesystem\n\n"
            "Returns static filesystem properties:\n"
            "  - Maximum and preferred read/write sizes\n"
            "  - Maximum file size\n"
            "  - Time resolution\n"
            "  - Capability flags (symlinks, hard links, etc.)\n\n"
            "NFSv3 only.\n",
            cmd_fsinfo},

        {"get", "<filefh> <local-file>",
            "(NFS READ) Download file",
            "    filefh      -  File handle (regular file only)\n"
            "    local-file  -  Local filename\n",
            cmd_get},

        {"getattr", "<fh> [-l]",
            "(NFS GETATTR) Get attributes for file or directory",
            "    fh  -  File or directory handle\n\n"
            "    -l  -  Long format (show ATIME/CTIME/FSID/FID)\n",
            cmd_getattr},

        {"getfh", "<export>",
            "(Mount v3 MNT + UMNTALL) Get fh for exported directory and unregister this client",
            "    export  -  Export path\n",
            cmd_getfh},

        {"getoff", "<filefh> <offset> <local-file>",
            "(NFS READ) Download file from offset to local file",
            "    filefh      -  File handle (regular file only)\n"
            "    offset      -  Offset into file\n"
            "    local-file  -  Local filename\n",
            cmd_getoff},

        {"getport", "nfs|mount [<version>]",
            "(Portmap v2 GETPORT/v3 GETADDR) Query portmap service for port number",
            "    nfs      -  NFS service (probes v2-3)\n"
            "    mount    -  Mount service (probes v1-3)\n"
            "    version  -  Optional: query single version only\n\n"
            "Uses portmap v2 GETPORT or v3 GETADDR based on 'protocol portmap' setting.\n",
            cmd_getport},

        {"gid", "[<gid>]",
            "Show or set GID to use in calls",
            "    (none)  -  Show current GID\n"
            "    gid     -  Numeric GID (-2 for anonymous/nobody)\n",
            cmd_set_gid},

        {"help", "[<command>]",
            "Show command help",
            "    command  -  Command name\n",
            cmd_help},

        {"link", "<fh> <dirfh> <name>",
            "(NFS LINK) Create hard link to file",
            "    fh     -  File handle\n"
            "    dirfh  -  Directory file handle\n"
            "    name   -  Filename\n\n"
            "Hard links must be on the same filesystem.\n"
            "Use 'symlink' for cross-filesystem or dangling links.\n",
            cmd_link},

        {"lookup", "<dirfh> <name> [-l]",
            "(NFS LOOKUP) Lookup name in directory",
            "    dirfh  -  Directory file handle\n"
            "    name   -  File or directory name\n\n"
            "    -l     -  Long format (show ATIME/CTIME/FSID/FID)\n",
            cmd_lookup},

        {"ls", "<dirfh> [-c] [-l]",
            "List directory contents (alias for readdirplus)",
            "    dirfh  -  Directory file handle\n\n"
            "    -c     -  Color highlighting of file names\n"
            "    -l     -  Output a long list of information\n",
            cmd_readdirplus},

        {"mkdir", "<dirfh> <name> <mode>",
            "(NFS MKDIR) Create directory",
            "    dirfh  -  Directory file handle\n"
            "    name   -  Directory name\n"
            "    mode   -  Directory permissions (octal)\n",
            cmd_mkdir},

        {"mknod", "<dirfh> <name> chr|blk|fifo|sock <mode> [<major> <minor>]",
            "(NFS v3 MKNOD) Create device or special file",
            "    dirfh  -  Directory file handle\n"
            "    name   -  Filename to create\n"
            "    type   -  chr, blk, fifo, sock\n"
            "    mode   -  Permissions (octal)\n"
            "    major  -  Major device number (chr/blk only)\n"
            "    minor  -  Minor device number (chr/blk only)\n\n"
            "NFSv3 only.\n\n"
            "    chr    -  Character device (requires major/minor)\n"
            "    blk    -  Block device (requires major/minor)\n"
            "    fifo   -  Named pipe\n"
            "    sock   -  Unix domain socket\n\n"
            "    mknod FH null chr 0666 1 3\n"
            "    mknod FH mypipe fifo 0644\n",
            cmd_mknod},

        {"mnt", "<export>",
            "(Mount MNT) Get file handle for mount of exported path",
            "    export  -  Export path\n",
            cmd_mnt},

        {"pathconf", "<fh>",
            "(NFS v3 PATHCONF) Get POSIX path configuration",
            "    fh  -  File or directory handle\n\n"
            "Returns POSIX pathconf(2) information:\n"
            "  - Maximum filename length\n"
            "  - Maximum link count\n"
            "  - Case sensitivity/preservation\n"
            "  - chown restrictions\n\n"
            "NFSv3 only.\n",
            cmd_pathconf},

        {"ping", "[portmap|mount|nfs]",
            "(RPC NULL) Test connectivity to RPC service",
            "    (none)    -  Test NFS server (default)\n"
            "    portmap   -  Test portmapper (port 111)\n"
            "    mount     -  Test mount daemon\n"
            "    nfs       -  Test NFS server\n\n"
            "Sends RPC NULL procedure and measures round-trip time.\n",
            cmd_ping},

        {"put", "<local-file> <dirfh> <remote-name> <mode>",
            "(NFS CREATE + WRITE) Upload file to directory represented by file handle",
            "    local-file   -  Local filename\n"
            "    dirfh        -  Directory file handle\n"
            "    remote-name  -  Remote filename\n"
            "    mode         -  File permissions (octal)\n",
            cmd_put},

        {"putoff", "<local-file> <offset> <filefh>",
            "(NFS WRITE) Resume file upload from offset",
            "    local-file  -  Local filename\n"
            "    offset      -  Offset into file\n"
            "    filefh      -  File handle (regular file only)\n",
            cmd_putoff},

        {"read", "<filefh> <offset> <count> [-r]",
            "(NFS READ) Read from file",
            "    filefh  -  File handle (regular file only)\n"
            "    offset  -  Offset into file\n"
            "    count   -  Number of bytes\n\n"
            "    -r      -  Print raw data to stdout\n",
            cmd_read},

        {"readdir", "<dirfh>",
            "(NFS READDIR) Read directory contents",
            "    dirfh  -  Directory file handle\n",
            cmd_readdir},

        {"readdirplus", "<dirfh> [-c] [-l]",
            "(NFS v3 READDIRPLUS) Read directory contents",
            "    dirfh  -  Directory file handle\n\n"
            "    -c     -  Color highlighting of file names\n"
            "    -l     -  Output a long list of information\n",
            cmd_readdirplus},

        {"readlink", "<fh>",
            "(NFS READLINK) Read target of symbolic link",
            "    fh  -  Symlink handle\n",
            cmd_readlink},

        {"remove", "<dirfh> <name>",
            "(NFS REMOVE) Remove file from directory",
            "    dirfh  -  Directory file handle\n"
            "    name   -  Filename\n",
            cmd_remove},

        {"rename", "<src-dirfh> <src-name> <dst-dirfh> <dst-name>",
            "(NFS RENAME) Rename file or directory from src-dirfh/src-name to dst-dirfh/dst-name",
            "    src-dirfh  -  Source directory handle\n"
            "    src-name   -  Source name\n"
            "    dst-dirfh  -  Destination directory handle\n"
            "    dst-name   -  Destination name\n\n"
            "Cross-filesystem renames are not supported.\n"
            "If destination exists, it will be removed.\n",
            cmd_rename},

        {"rmdir", "<dirfh> <name>",
            "(NFS RMDIR) Remove directory",
            "    dirfh  -  Directory file handle\n"
            "    name   -  Directory name\n\n"
            "Directory must be empty.\n",
            cmd_rmdir},

        {"rpcinfo", "[-p|-s]",
            "(Portmap DUMP) List registered RPC services",
            "    (none)  -  Use best available (v3 if available, else v2)\n"
            "    -p      -  Force portmapper v2 (port numbers)\n"
            "    -s      -  Force rpcbind v3 (netid, owner)\n",
            cmd_rpcinfo},

        {"setattr", "<fh> <options>",
            "(NFS SETATTR) Set attributes for file or directory",
            "    fh  -  File or directory handle\n\n"
            "Options:\n"
            "    -m <mode>  -  Set file mode (octal)\n"
            "    -u <uid>   -  Set owner user ID\n"
            "    -g <gid>   -  Set owner group ID\n"
            "    -s <size>  -  Set file size (truncate)\n"
            "    -a         -  Set atime to server time\n"
            "    -A <sec>   -  Set atime to specific Unix time\n"
            "    -M         -  Set mtime to server time\n"
            "    -T <sec>   -  Set mtime to specific Unix time\n\n"
            "Examples:\n"
            "    setattr FH -m 0644           - chmod\n"
            "    setattr FH -u 1000 -g 100    - chown\n"
            "    setattr FH -s 0              - truncate to zero\n"
            "    setattr FH -a -M             - touch (update times)\n",
            cmd_setattr},

        {"settings", "",
            "Display current settings",
            "",
            cmd_settings},

        {"symlink", "<dirfh> <name> <mode> <target>",
            "(NFS SYMLINK) Create symbolic link",
            "    dirfh   -  Directory file handle\n"
            "    name    -  Symlink name\n"
            "    mode    -  Permissions (octal)\n"
            "    target  -  Target path\n\n"
            "Target path can be absolute or relative, and need not exist.\n"
            "Unlike 'link', symlinks can span filesystems.\n",
            cmd_symlink},

        {"quit", "",
            "Quit",
            "",
            NULL},

        {"uid", "[<uid>]",
            "Show or set UID to use in calls",
            "    (none)  -  Show current UID\n"
            "    uid     -  Numeric UID (-2 for anonymous/nobody)\n",
            cmd_set_uid},

        {"umnt", "<path>",
            "(Mount UMNT) Unmount a specific export path",
            "    path  -  Export path to unmount (e.g., /data)\n",
            cmd_umnt},

        {"umntall", "",
            "(Mount UMNTALL) Removes all of the mount entries for this client at server",
            "",
            cmd_umntall},

        {"verbose", "[<verbose>]",
            "Show or set verbosity level",
            "    (none)  -  Show current level\n"
            "    level   -  0/info, 1/detail, 2/debug, 3/trace\n",
            cmd_set_verbose},

        {"protocol", "[portmap|mount|nfs <n>]",
            "Display or set protocol version",
            "    (none)       -  Show all protocol versions\n"
            "    portmap <n>  -  Set portmap protocol to version n\n"
            "    mount <n>    -  Set mount protocol to version n\n"
            "    nfs <n>      -  Set NFS protocol to version n\n",
            cmd_protocol},

        {"write", "<filefh> <offset> <hexdata> [sync|datasync|unstable]",
            "(NFS WRITE) Write to file",
            "    filefh    -  File handle (regular file only)\n"
            "    offset    -  Offset into file\n"
            "    hexdata   -  Hex data to write\n"
            "    stability -  Write stability mode (NFSv3 only):\n"
            "                 sync     - FILE_SYNC (default) - data+metadata stable\n"
            "                 datasync - DATA_SYNC - data stable, metadata may buffer\n"
            "                 unstable - UNSTABLE - server may buffer, use commit after\n\n"
            "NFSv2 always uses synchronous writes; stability is ignored.\n",
            cmd_write},

        {NULL, NULL, NULL, NULL, NULL}};

static int
cmd_help(struct nfsctx *ctx, int argc, char **argv)
{
    uint32_t i;
    uint32_t w;

    (void)ctx;
    CHECK_ARGC(1, 2);

    printf("\n");

    /* Print help for specific command */
    if (argc == 2) {
        for (i = 0; cmds[i].name != NULL; i++) {

            if (!strcmp(cmds[i].name, argv[1])) {
                printf("%s\n", cmds[i].help_short);
                printf("Usage: %s %s\n", cmds[i].name, cmds[i].syntax);
                printf("%s\n", cmds[i].help_long);
                return (0);
            }
        }

        fprintf(stderr, "*** Command '%s' not found\n", argv[1]);
        /* Fall through to show available commands */
    }

    printf("NFS v3 CLI v%s, by Claes M Nyberg <cmn@signedness.org>, Aug 2023\n",
        NFSCLI_VERSION);
    printf("Available commands:\n");
    for (i = 0; cmds[i].name != NULL; i++) {
        w = printf("%s ", cmds[i].name);
        while (w++ < 30)
            printf(".");
        printf(" %s\n", cmds[i].help_short);
    }
    printf("\n");
    return 0;
}

static int
cmd_mknod(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_create_res res;
    struct nfs_fh dirfh;
    uint32_t mode, major, minor;
    int type;
    int needs_devnums;

    /* Parse type first to determine argc requirements */
    if (argc < 4) {
        print(V_INFO, ctx, "** Error: mknod requires at least: dirfh name type mode\n");
        errno = EINVAL;
        return -1;
    }

    /* Determine type and whether major/minor are needed */
    if (strcmp(argv[3], "chr") == 0) {
        type = NFS_FTYPE_CHR;
        needs_devnums = 1;
    } else if (strcmp(argv[3], "blk") == 0) {
        type = NFS_FTYPE_BLK;
        needs_devnums = 1;
    } else if (strcmp(argv[3], "fifo") == 0) {
        type = NFS_FTYPE_FIFO;
        needs_devnums = 0;
    } else if (strcmp(argv[3], "sock") == 0) {
        type = NFS_FTYPE_SOCK;
        needs_devnums = 0;
    } else {
        print(V_INFO, ctx, "** Error: Unknown type '%s' (use chr, blk, fifo, sock)\n",
            argv[3]);
        errno = EINVAL;
        return -1;
    }

    /* Check argument count based on type */
    if (needs_devnums) {
        if (argc != 7) {
            print(V_INFO, ctx, "** Error: %s requires major and minor: "
                               "mknod dirfh name %s mode major minor\n",
                argv[3], argv[3]);
            errno = EINVAL;
            return -1;
        }
    } else {
        if (argc != 5) {
            print(V_INFO, ctx, "** Error: %s does not use major/minor: "
                               "mknod dirfh name %s mode\n",
                argv[3], argv[3]);
            errno = EINVAL;
            return -1;
        }
    }

    /* Parse file handle */
    if (nfs_parse_fh_arg(argv[1], &dirfh) < 0)
        return -1;

    /* Check name length */
    CHECK_NAME_LEN(ctx, argv[2]);

    /* Mode */
    if (parse_mode(argv[4], &mode) < 0)
        return -1;

    /* Major/minor for device types */
    if (needs_devnums) {
        if (parse_u32(argv[5], &major) < 0) {
            print(V_INFO, ctx, "** Error: Bad major number\n");
            errno = EINVAL;
            return -1;
        }
        if (parse_u32(argv[6], &minor) < 0) {
            print(V_INFO, ctx, "** Error: Bad minor number\n");
            errno = EINVAL;
            return -1;
        }
    } else {
        major = 0;
        minor = 0;
    }

    memset(&res, 0, sizeof(res));
    if (nfs_mknod(ctx, &dirfh, argv[2], type, mode, major, minor, &res) < 0)
        return 0; /* NFS operation failure */

    printf("Created FH:");
    HEXDUMP(res.fh.data, res.fh.len);

    return 0;
}

static int
cmd_symlink(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_fh dirfh;
    uint32_t mode;

    CHECK_ARGC_EXACT(5);

    /* Parse file handle */
    if (nfs_parse_fh_arg(argv[1], &dirfh) < 0)
        return -1;

    /* Mode */
    if (parse_mode(argv[3], &mode) < 0)
        return -1;

    if (nfs_symlink(ctx, &dirfh, argv[2], argv[4], mode) < 0)
        return 0; /* NFS operation failure */
    return 0;
}

static int
cmd_link(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_fh nfh, ndirfh;

    CHECK_ARGC_EXACT(4);

    /* Parse file handle */
    if (nfs_parse_fh_arg(argv[1], &nfh) < 0)
        return -1;

    /* Parse directory file handle */
    if (nfs_parse_fh_arg(argv[2], &ndirfh) < 0)
        return -1;

    if (nfs_link(ctx, &nfh, &ndirfh, argv[3]) < 0)
        return 0; /* NFS operation failure */
    return 0;
}

static int
cmd_lookup(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_lookup_res res;
    struct nfs_fh dirfh;
    struct parsed_args pa;
    char attrbuf[ATTRBUFLEN];
    uint32_t opts = 0;

    if (parse_cmdline(argc, argv, "l", 2, 2, &pa) < 0)
        return -1;

    if (strchr(pa.opts, 'l'))
        opts |= ATTRSTR_LONG;

    /* Directory FH */
    if (nfs_parse_fh_arg(pa.args[0], &dirfh) < 0)
        return -1;

    memset(&res, 0, sizeof(res));
    if (nfs_lookup(ctx, &dirfh, pa.args[1], &res) < 0)
        return 0; /* NFS operation failure */

    fmt_attr(ctx, &res.obj_attr, opts, NULL, attrbuf, sizeof(attrbuf));

    printf("%s FH:", attrbuf);
    HEXDUMP(res.fh.data, res.fh.len);

    return 0;
}

static int
cmd_settings(struct nfsctx *ctx, int argc, char **argv)
{
    (void)argv;
    CHECK_ARGC_EXACT(1);
    printf("\n");

    printf("Server ..................................... %s\n", ctx->server.name);
    printf("Spoofed IPv4 ............................... %s\n", ctx->net.spoof_ip ? ctx->net.spoof_str : "Disabled");
    printf("Port local ................................. %u/udp\n", ntohs(ctx->ports.local));
    printf("Port RPC ................................... %u/udp\n", ntohs(ctx->ports.rpc));
    printf("Port NFSd .................................. %u/udp\n", ntohs(ctx->ports.nfsd));
    printf("Port mountd ................................ %u/udp\n", ntohs(ctx->ports.mountd));
    printf("UID ........................................ %u\n", ctx->uid);
    printf("GID ........................................ %u\n", ctx->gid);
    printf("Timeout .................................... %ld sec\n", ctx->net.timeout.tv_sec);
    printf("Verbose .................................... %u (%s)\n", ctx->verbose,
        verbose_name(ctx->verbose));
    printf("Directory cache ............................ %s\n", ctx->cache.enabled ? "On" : "Off");

    printf("\n");
    return 0;
}

static int
cmd_putoff(struct nfsctx *ctx, int argc, char **argv)
{
    uint8_t fh[NFS_FHSIZE_MAX];
    FILE *inf;
    int fhlen;
    uint64_t offset;
    int64_t tot;

    CHECK_ARGC_EXACT(4);

    if (parse_u64(argv[2], &offset) < 0) {
        print(V_INFO, ctx, "** Error: Bad offset\n");
        errno = EINVAL;
        return -1;
    }

    if ((fhlen = nfs_parse_fh(argv[3], fh, sizeof(fh))) < 0)
        return -1;

    if ((inf = fopen(argv[1], "rb")) == NULL) {
        print(V_INFO, ctx, "** Error: Failed to open %s: %s\n", argv[1], strerror(errno));
        return 0; /* Local file operation failure */
    }

    if (fseek(inf, offset, SEEK_SET) != 0) {
        print(V_INFO, ctx, "** Error: Failed to seek: %s\n", strerror(errno));
        fclose(inf);
        return 0; /* Local file operation failure */
    }

    print(V_INFO, ctx, "Uploading from offset %lu\n", offset);
    tot = transfer_upload(ctx, fh, fhlen, offset, inf);
    fclose(inf);

    if (tot < 0)
        return 0; /* NFS operation failure */

    printf("\n");
    print(V_INFO, ctx, "Transferred %ld bytes\n", tot);
    return 0;
}

static int
cmd_put(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_create_res res;
    struct nfs_fh ndirfh;
    FILE *inf;
    uint32_t mode;
    int64_t tot;

    CHECK_ARGC_EXACT(5);

    /* Directory FH */
    if (nfs_parse_fh_arg(argv[2], &ndirfh) < 0)
        return -1;

    if (parse_mode(argv[4], &mode) < 0)
        return -1;

    if ((inf = fopen(argv[1], "rb")) == NULL) {
        print(V_INFO, ctx, "** Error: Failed to open %s: %s\n", argv[1], strerror(errno));
        return 0; /* Local file operation failure */
    }

    memset(&res, 0, sizeof(res));
    if (nfs_create(ctx, &ndirfh, argv[3], mode, NFS_CREATE_GUARDED, &res) < 0) {
        fclose(inf);
        return 0; /* NFS operation failure */
    }

    /*
     * NFSv3 CREATE may not return file handle (RFC 1813).
     * If not returned, do a LOOKUP to get it.
     */
    if (!res.has_fh) {
        struct nfs_lookup_res lu;
        memset(&lu, 0, sizeof(lu));
        if (nfs_lookup(ctx, &ndirfh, argv[3], &lu) < 0) {
            fclose(inf);
            return 0;
        }
        nfs_fh_copy(&res.fh, &lu.fh);
    }

    print(V_INFO, ctx, "Uploading %s to %s\n", argv[1], argv[3]);
    tot = transfer_upload(ctx, res.fh.data, res.fh.len, 0, inf);
    fclose(inf);

    if (tot < 0)
        return 0; /* NFS operation failure */

    printf("\n");
    print(V_INFO, ctx, "Transferred %ld bytes\n", tot);
    return 0;
}

static int
cmd_getoff(struct nfsctx *ctx, int argc, char **argv)
{
    uint8_t fh[NFS_FHSIZE_MAX];
    FILE *fp;
    uint64_t off;
    int fhlen;
    int64_t tot;

    CHECK_ARGC_EXACT(4);

    if ((fhlen = nfs_parse_fh(argv[1], fh, sizeof(fh))) < 0)
        return -1;

    if (parse_u64(argv[2], &off) < 0) {
        print(V_INFO, ctx, "** Error: Bad offset: %s\n", argv[2]);
        errno = EINVAL;
        return -1;
    }

    if ((fp = fopen(argv[3], "r+")) == NULL) {
        print(V_INFO, ctx, "** Error: Failed to open %s\n", argv[3]);
        return 0; /* Local file operation failure */
    }

    if (fseek(fp, off, SEEK_SET) != 0) {
        print(V_INFO, ctx, "** Error: Failed to seek: %s\n", strerror(errno));
        fclose(fp);
        return 0; /* Local file operation failure */
    }

    print(V_INFO, ctx, "Downloading to %s from offset %lu\n", argv[3], off);
    tot = transfer_download(ctx, fh, fhlen, off, fp, DL_PROGRESS);
    fclose(fp);

    if (tot < 0)
        return 0; /* NFS operation failure */

    printf("\n");
    print(V_INFO, ctx, "Wrote %ld bytes to %s\n", tot, argv[3]);
    return 0;
}

static int
cmd_get(struct nfsctx *ctx, int argc, char **argv)
{
    uint8_t fh[NFS_FHSIZE_MAX];
    FILE *fp;
    int fhlen;
    int64_t tot;

    CHECK_ARGC_EXACT(3);

    if ((fhlen = nfs_parse_fh(argv[1], fh, sizeof(fh))) < 0)
        return -1;

    if ((fp = fopen(argv[2], "w")) == NULL) {
        print(V_INFO, ctx, "** Error: Failed to open %s\n", argv[2]);
        return 0; /* Local file operation failure */
    }

    print(V_INFO, ctx, "Downloading to %s\n", argv[2]);
    tot = transfer_download(ctx, fh, fhlen, 0, fp, DL_PROGRESS);
    if (fclose(fp) != 0) {
        print(V_INFO, ctx, "** Warning: fclose failed: %s\n", strerror(errno));
        /* Data may not have been fully flushed to disk */
    }

    if (tot < 0)
        return 0; /* NFS operation failure */

    printf("\n");
    print(V_INFO, ctx, "Wrote %ld bytes to %s\n", tot, argv[2]);
    return 0;
}

#define CACHE_STATUS_BRIEF 0
#define CACHE_STATUS_FULL  1

static void
print_cache_status(struct nfsctx *ctx, int mode)
{
    struct nfs_cache_stats stats;
    uint64_t lookup_total, readdir_total;
    int have_stats;
    time_t now;

    printf("Directory cache: %s\n", ctx->cache.enabled ? "Enabled" : "Disabled");

    /* Directory cache stats (only when enabled) */
    have_stats = 0;
    if (ctx->cache.enabled)
        have_stats = (nfs_cache_get_stats(ctx, &stats) == 0);
    if (have_stats) {
        now = time(NULL);
        lookup_total = stats.lookup_hits + stats.lookup_misses;
        readdir_total = stats.readdir_hits + stats.readdir_misses;

        if (mode == CACHE_STATUS_FULL) {
            printf("\nDirectory Cache:\n");
            printf("  Directories ........ %zu / %zu max\n",
                stats.dir_count, stats.dir_max);
            printf("  Entries ............ %zu total\n", stats.entry_count);
            if (stats.entry_count > 0) {
                printf("    With file handles  %zu (%d%%)\n",
                    stats.entries_with_fh,
                    (int)(100 * stats.entries_with_fh / stats.entry_count));
                printf("    With attributes .. %zu (%d%%)\n",
                    stats.entries_with_attr,
                    (int)(100 * stats.entries_with_attr / stats.entry_count));
                printf("    Stale ............ %zu\n", stats.stale_entries);
            }
            printf("  Complete listings .. %zu", stats.complete_dirs);
            if (stats.dir_count > 0)
                printf(" (%d%%)", (int)(100 * stats.complete_dirs / stats.dir_count));
            printf("\n");
            if (stats.oldest_dir > 0) {
                char newest[16], oldest[16];
                str_duration(now - stats.newest_dir, newest, sizeof(newest));
                str_duration(now - stats.oldest_dir, oldest, sizeof(oldest));
                if (strcmp(newest, oldest) == 0)
                    printf("  Age ................ %s\n", newest);
                else
                    printf("  Age ................ %s - %s\n", newest, oldest);
            }
            printf("  Hit rate:\n");
            printf("    Lookup ........... ");
            if (lookup_total > 0)
                printf("%d%% (%lu/%lu)\n",
                    (int)(100 * stats.lookup_hits / lookup_total),
                    (unsigned long)stats.lookup_hits,
                    (unsigned long)lookup_total);
            else
                printf("n/a\n");
            printf("    Readdir .......... ");
            if (readdir_total > 0)
                printf("%d%% (%lu/%lu)\n",
                    (int)(100 * stats.readdir_hits / readdir_total),
                    (unsigned long)stats.readdir_hits,
                    (unsigned long)readdir_total);
            else
                printf("n/a\n");
        } else {
            printf("  Directories ...... %zu cached, %zu entries\n",
                stats.dir_count, stats.entry_count);
            printf("  Hit rate ......... ");
            if (lookup_total > 0 || readdir_total > 0) {
                if (lookup_total > 0)
                    printf("lookup %d%% (%lu)",
                        (int)(100 * stats.lookup_hits / lookup_total),
                        (unsigned long)stats.lookup_hits);
                if (lookup_total > 0 && readdir_total > 0)
                    printf(", ");
                if (readdir_total > 0)
                    printf("readdir %d%% (%lu)",
                        (int)(100 * stats.readdir_hits / readdir_total),
                        (unsigned long)stats.readdir_hits);
                printf("\n");
            } else {
                printf("n/a\n");
            }
        }
    }

    /*
     * Other caches - grouped by category:
     * - Protocol: Export, Mount FH
     * - File metadata: Attribute, Symlink, Parent FH (directory already shown above)
     */
    if (mode == CACHE_STATUS_FULL) {
        uint64_t mnt_total = ctx->cache.mount_fh.hits + ctx->cache.mount_fh.misses;
        uint64_t attr_total = ctx->cache.attr_hits + ctx->cache.attr_misses;
        uint64_t sym_total = ctx->cache.symlink_hits + ctx->cache.symlink_misses;

        /* Protocol caches */
        printf("\nExport Cache:\n");
        printf("  Entries ............ %zu\n", mount_exports_cache_count(ctx));

        printf("\nMount FH Cache:\n");
        printf("  Entries ............ %zu\n", mount_fh_cache_count(ctx));
        printf("  Hit rate ........... ");
        if (mnt_total > 0)
            printf("%d%% (%lu/%lu)\n",
                (int)(100 * ctx->cache.mount_fh.hits / mnt_total),
                (unsigned long)ctx->cache.mount_fh.hits,
                (unsigned long)mnt_total);
        else
            printf("n/a\n");

        /* File metadata caches (directory already shown above) */
        printf("\nAttribute Cache:\n");
        printf("  Entries ............ %zu\n", ctx->cache.attr_count);
        printf("  Hit rate ........... ");
        if (attr_total > 0)
            printf("%d%% (%lu/%lu)\n",
                (int)(100 * ctx->cache.attr_hits / attr_total),
                (unsigned long)ctx->cache.attr_hits,
                (unsigned long)attr_total);
        else
            printf("n/a\n");

        printf("\nSymlink Cache:\n");
        printf("  Entries ............ %zu\n", ctx->cache.symlink_count);
        printf("  Hit rate ........... ");
        if (sym_total > 0)
            printf("%d%% (%lu/%lu)\n",
                (int)(100 * ctx->cache.symlink_hits / sym_total),
                (unsigned long)ctx->cache.symlink_hits,
                (unsigned long)sym_total);
        else
            printf("n/a\n");

        printf("\nParent FH Cache:\n");
        printf("  Entries ............ %zu\n", nfs_parent_cache_count());
    } else {
        /* Protocol caches */
        printf("\nProtocol caches:\n");
        printf("  Exports .......... %zu cached\n", mount_exports_cache_count(ctx));
        printf("  Mount FH ......... %zu cached", mount_fh_cache_count(ctx));
        if (ctx->cache.mount_fh.hits > 0)
            printf(", %lu hits", (unsigned long)ctx->cache.mount_fh.hits);
        printf("\n");

        /* File metadata caches */
        printf("\nMetadata caches:\n");
        printf("  Attributes ....... %zu cached", ctx->cache.attr_count);
        if (ctx->cache.attr_hits > 0)
            printf(", %lu hits", (unsigned long)ctx->cache.attr_hits);
        printf("\n");
        printf("  Symlinks ......... %zu cached", ctx->cache.symlink_count);
        if (ctx->cache.symlink_hits > 0)
            printf(", %lu hits", (unsigned long)ctx->cache.symlink_hits);
        printf("\n");
        printf("  Parent FH ........ %zu cached\n", nfs_parent_cache_count());
    }
}

static int
cmd_cache(struct nfsctx *ctx, int argc, char **argv)
{
    const char *arg;

    if (argc < 2) {
        /* Default: show status */
        arg = "status";
    } else {
        arg = argv[1];
    }

    if (strcmp(arg, "on") == 0) {
        ctx->cache.enabled = 1;
        print_cache_status(ctx, CACHE_STATUS_BRIEF);
    } else if (strcmp(arg, "off") == 0) {
        ctx->cache.enabled = 0;
        print_cache_status(ctx, CACHE_STATUS_BRIEF);
    } else if (strcmp(arg, "clear") == 0) {
        /* Clear directory cache */
        nfs_cache_invalidate_all(ctx);
        /* Clear exports cache */
        mount_exports_cache_clear(ctx);
        /* Clear mount file handle cache */
        mount_fh_cache_clear(ctx);
        /* Clear symlink cache */
        nfs_symlink_cache_clear(ctx);
        /* Clear attribute cache */
        nfs_attr_cache_clear(ctx);
        /* Clear parent FH cache (escape probing) */
        nfs_parent_cache_clear();
        print_cache_status(ctx, CACHE_STATUS_BRIEF);
    } else if (strcmp(arg, "status") == 0) {
        print_cache_status(ctx, CACHE_STATUS_BRIEF);
    } else if (strcmp(arg, "detailed") == 0) {
        print_cache_status(ctx, CACHE_STATUS_FULL);
    } else {
        fprintf(stderr, "*** Unknown argument: %s\n", arg);
        printf("Usage: cache [on|off|clear|detailed]\n");
        return -1;
    }

    return 0;
}

static int
cmd_cat(struct nfsctx *ctx, int argc, char **argv)
{
    uint8_t fh[NFS_FHSIZE_MAX];
    int fhlen;
    int64_t tot;

    CHECK_ARGC_EXACT(2);

    if ((fhlen = nfs_parse_fh(argv[1], fh, sizeof(fh))) < 0)
        return -1;

    tot = transfer_download(ctx, fh, fhlen, 0, stdout, DL_CHECK_BINARY);
    if (tot == DL_BINARY) {
        fprintf(stderr, "*** Binary file (not shown)\n");
        return 0;
    }
    if (tot < 0)
        return 0; /* NFS operation failure */

    printf("\n-- EOF (%ld bytes)\n", tot);
    return 0;
}

static int
cmd_commit(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_fh fh;
    struct nfs_commit_res res;
    uint64_t offset = 0;
    uint32_t count = 0;

    if (argc < 2 || argc > 4) {
        fprintf(stderr, "Usage: commit <filefh> [offset] [count]\n");
        return -1;
    }

    /* FH */
    if (nfs_parse_fh_arg(argv[1], &fh) < 0)
        return -1;

    if (argc >= 3) {
        if (parse_u64(argv[2], &offset) < 0) {
            fprintf(stderr, "*** Invalid offset: %s\n", argv[2]);
            return -1;
        }
    }

    if (argc >= 4) {
        if (parse_u32(argv[3], &count) < 0) {
            fprintf(stderr, "*** Invalid count: %s\n", argv[3]);
            return -1;
        }
    }

    if (nfs_commit(ctx, &fh, offset, count, &res) < 0) {
        if (errno == ENOTSUP)
            fprintf(stderr, "** Error: COMMIT not supported in NFSv2\n");
        return 0; /* NFS operation failure */
    }

    printf("Committed ");
    if (offset == 0 && count == 0)
        printf("entire file");
    else if (count == 0)
        printf("from offset %llu to end", (unsigned long long)offset);
    else
        printf("%u bytes from offset %llu", count, (unsigned long long)offset);
    printf(" (verf=0x%016llx)\n", (unsigned long long)res.verifier);

    return 0;
}

static int
cmd_rename(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_fh nsrcfh, ndstfh;

    CHECK_ARGC_EXACT(5);

    /* Src FH */
    if (nfs_parse_fh_arg(argv[1], &nsrcfh) < 0)
        return -1;

    /* Src Name */
    CHECK_NAME_LEN(ctx, argv[2]);

    /* Dest FH */
    if (nfs_parse_fh_arg(argv[3], &ndstfh) < 0)
        return -1;

    /* Dest Name */
    CHECK_NAME_LEN(ctx, argv[4]);

    if (nfs_rename(ctx, &nsrcfh, argv[2], &ndstfh, argv[4]) < 0)
        return 0; /* NFS operation failure */
    return 0;
}

static int
cmd_mkdir(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_create_res res;
    struct nfs_fh dirfh;
    uint32_t mode;

    CHECK_ARGC_EXACT(4);

    /* FH */
    if (nfs_parse_fh_arg(argv[1], &dirfh) < 0)
        return -1;

    /* Name */
    CHECK_NAME_LEN(ctx, argv[2]);

    /* Mode */
    if (parse_mode(argv[3], &mode) < 0)
        return -1;

    memset(&res, 0, sizeof(res));
    if (nfs_mkdir(ctx, &dirfh, argv[2], mode, &res) < 0)
        return 0; /* NFS operation failure */

    printf("Created FH:");
    HEXDUMP(res.fh.data, res.fh.len);

    return 0;
}

static int
cmd_rmdir(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_fh dirfh;

    CHECK_ARGC_EXACT(3);

    /* FH */
    if (nfs_parse_fh_arg(argv[1], &dirfh) < 0)
        return -1;

    /* Name */
    CHECK_NAME_LEN(ctx, argv[2]);

    if (nfs_rmdir(ctx, &dirfh, argv[2]) < 0)
        return 0; /* NFS operation failure */
    return 0;
}

static int
cmd_create(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_create_res res;
    struct nfs_fh dirfh;
    uint32_t mode;
    int create_mode;

    if (argc < 4 || argc > 5) {
        print(V_INFO, ctx, "** Error: create requires 3-4 arguments\n");
        errno = EINVAL;
        return -1;
    }

    /* FH */
    if (nfs_parse_fh_arg(argv[1], &dirfh) < 0)
        return -1;

    /* Name */
    CHECK_NAME_LEN(ctx, argv[2]);

    /* Mode */
    if (parse_mode(argv[3], &mode) < 0)
        return -1;

    /* Create mode (optional, default: guarded) */
    create_mode = NFS_CREATE_GUARDED;
    if (argc == 5) {
        if (strcmp(argv[4], "guarded") == 0) {
            create_mode = NFS_CREATE_GUARDED;
        } else if (strcmp(argv[4], "exclusive") == 0) {
            create_mode = NFS_CREATE_EXCLUSIVE;
        } else if (strcmp(argv[4], "unchecked") == 0) {
            create_mode = NFS_CREATE_UNCHECKED;
        } else {
            print(V_INFO, ctx, "** Error: Unknown create mode '%s' "
                               "(use guarded, exclusive, unchecked)\n",
                argv[4]);
            errno = EINVAL;
            return -1;
        }

        /* Warn if using create mode with NFSv2 */
        if (ctx->proto.nfs_version < 3) {
            print(V_INFO, ctx, "Warning: NFSv2 ignores create mode\n");
        }
    }

    memset(&res, 0, sizeof(res));
    if (nfs_create(ctx, &dirfh, argv[2], mode, create_mode, &res) < 0)
        return 0; /* NFS operation failure */

    if (res.has_fh) {
        printf("Created FH:");
        HEXDUMP(res.fh.data, res.fh.len);
    } else {
        printf("Created (no file handle returned by server)\n");
    }

    return 0;
}

/*
 * Parse unsigned 32-bit value from string with error checking.
 * Returns 0 on success, -1 on error (with message printed).
 */
static int
parse_u32_opt(const char *arg, uint32_t *out, const char *opt_name)
{
    char *endp;
    unsigned long val;

    errno = 0;
    val = strtoul(arg, &endp, 10);
    if (endp == arg || *endp != '\0' || errno != 0 || val > UINT32_MAX) {
        fprintf(stderr, "Invalid %s: %s\n", opt_name, arg);
        return -1;
    }
    *out = (uint32_t)val;
    return 0;
}

/*
 * Parse unsigned 64-bit value from string with error checking.
 * Returns 0 on success, -1 on error (with message printed).
 */
static int
parse_u64_opt(const char *arg, uint64_t *out, const char *opt_name)
{
    char *endp;

    errno = 0;
    *out = strtoull(arg, &endp, 10);
    if (endp == arg || *endp != '\0' || errno != 0) {
        fprintf(stderr, "Invalid %s: %s\n", opt_name, arg);
        return -1;
    }
    return 0;
}

static int
cmd_setattr(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_fh nfh;
    struct nfs_sattr sattr;
    int i;

    if (argc < 3) {
        fprintf(stderr, "Usage: setattr <fh> <options>\n");
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  -m <mode>   Set file mode (octal)\n");
        fprintf(stderr, "  -u <uid>    Set owner user ID\n");
        fprintf(stderr, "  -g <gid>    Set owner group ID\n");
        fprintf(stderr, "  -s <size>   Set file size\n");
        fprintf(stderr, "  -a          Set atime to server time\n");
        fprintf(stderr, "  -A <sec>    Set atime to specific time\n");
        fprintf(stderr, "  -M          Set mtime to server time\n");
        fprintf(stderr, "  -T <sec>    Set mtime to specific time\n");
        return -1;
    }

    /* FH */
    if (nfs_parse_fh_arg(argv[1], &nfh) < 0)
        return -1;

    nfs_sattr_init(&sattr);

    /* Parse options */
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            uint32_t mode;
            if (parse_mode(argv[++i], &mode) < 0)
                return -1;
            sattr.set_mode = 1;
            sattr.mode = mode;
        } else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
            if (parse_u32_opt(argv[++i], &sattr.uid, "uid") < 0)
                return -1;
            sattr.set_uid = 1;
        } else if (strcmp(argv[i], "-g") == 0 && i + 1 < argc) {
            if (parse_u32_opt(argv[++i], &sattr.gid, "gid") < 0)
                return -1;
            sattr.set_gid = 1;
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            if (parse_u64_opt(argv[++i], &sattr.size, "size") < 0)
                return -1;
            sattr.set_size = 1;
        } else if (strcmp(argv[i], "-a") == 0) {
            /* Set atime to server time */
            sattr.set_atime = NFS_TIME_SET_TO_SERVER;
        } else if (strcmp(argv[i], "-A") == 0 && i + 1 < argc) {
            if (parse_u32_opt(argv[++i], &sattr.atime.sec, "atime") < 0)
                return -1;
            sattr.set_atime = NFS_TIME_SET_TO_CLIENT;
            sattr.atime.nsec = 0;
        } else if (strcmp(argv[i], "-M") == 0) {
            sattr.set_mtime = NFS_TIME_SET_TO_SERVER;
        } else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc) {
            if (parse_u32_opt(argv[++i], &sattr.mtime.sec, "mtime") < 0)
                return -1;
            sattr.set_mtime = NFS_TIME_SET_TO_CLIENT;
            sattr.mtime.nsec = 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return -1;
        }
    }

    if (nfs_setattr(ctx, &nfh, &sattr) < 0)
        return 0; /* NFS operation failure */
    return 0;
}

static int
cmd_remove(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_fh dirfh;

    CHECK_ARGC_EXACT(3);

    /* FH */
    if (nfs_parse_fh_arg(argv[1], &dirfh) < 0)
        return -1;

    /* Name */
    CHECK_NAME_LEN(ctx, argv[2]);

    if (nfs_remove(ctx, &dirfh, argv[2]) < 0)
        return 0; /* NFS operation failure */
    return 0;
}

static int
cmd_write(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_fh fh;
    struct nfs_write_res res;
    uint8_t *data = NULL;
    uint64_t offset;
    size_t len;
    int ret;
    int count;
    int stability;

    ret = 0;

    if (argc < 4 || argc > 5) {
        print(V_INFO, ctx, "** Error: Usage: write <filefh> <offset> <hexdata> "
                           "[sync|datasync|unstable]\n");
        errno = EINVAL;
        return -1;
    }

    /* FH */
    if (nfs_parse_fh_arg(argv[1], &fh) < 0)
        return -1;

    /* Offset */
    if (parse_u64(argv[2], &offset) < 0) {
        print(V_INFO, ctx, "** Error: Bad offset\n");
        errno = EINVAL;
        return -1;
    }

    len = strlen(argv[3]);
    if ((len % 2) != 0) {
        print(V_INFO, ctx, "** Error: Data string in hex must be even in length\n");
        errno = EINVAL;
        return -1;
    }

    if (len > 1024 * 2) {
        print(V_INFO, ctx, "** Error: Maximum length of data is limited to 1024 bytes\n");
        errno = EINVAL;
        return -1;
    }

    /* Parse stability mode (default: FILE_SYNC) */
    stability = NFS_FILE_SYNC;
    if (argc == 5) {
        if (strcmp(argv[4], "sync") == 0)
            stability = NFS_FILE_SYNC;
        else if (strcmp(argv[4], "datasync") == 0)
            stability = NFS_DATA_SYNC;
        else if (strcmp(argv[4], "unstable") == 0)
            stability = NFS_UNSTABLE;
        else {
            print(V_INFO, ctx, "** Error: Invalid stability mode '%s' "
                               "(use sync, datasync, or unstable)\n",
                argv[4]);
            errno = EINVAL;
            return -1;
        }
    }

    if ((data = malloc(len)) == NULL) {
        errno = ENOMEM;
        return -1; /* Memory allocation failure */
    }

    /* Data */
    if ((count = str_hex2bin(argv[3], data, len)) <= 0) {
        ret = -1; /* Invalid hex data format (message printed by str_hex2bin) */
        goto finished;
    }

    memset(&res, 0, sizeof(res));
    if (nfs_write_stable(ctx, &fh, offset, data, count, stability, &res) < 0) {
        ret = 0; /* NFS operation failure */
        goto finished;
    }

    /* Print result with verifier for unstable writes (NFSv3) */
    if (ctx->proto.nfs_version >= 3) {
        const char *mode_str = (res.committed == NFS_FILE_SYNC) ? "FILE_SYNC" : (res.committed == NFS_DATA_SYNC) ? "DATA_SYNC"
                                                                                                                 : "UNSTABLE";
        print(V_INFO, ctx, "Wrote %u bytes (%s, verf=0x%016llx)\n",
            res.count, mode_str, (unsigned long long)res.verifier);
    } else {
        print(V_INFO, ctx, "Wrote %u bytes\n", res.count);
    }

finished:
    free(data);
    return ret;
}

static int
cmd_read(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_read_res res;
    struct nfs_fh nfh;
    struct parsed_args pa;
    uint64_t offset;
    uint32_t count;
    size_t i;
    uint8_t print_raw = 0;

    memset(&res, 0, sizeof(res));

    if (parse_cmdline(argc, argv, "r", 3, 3, &pa) < 0)
        return -1;

    if (strchr(pa.opts, 'r'))
        print_raw = 1;

    /* FH */
    if (nfs_parse_fh_arg(pa.args[0], &nfh) < 0)
        return -1;

    /* Offset */
    if (parse_u64(pa.args[1], &offset) < 0) {
        print(V_INFO, ctx, "** Error: Bad offset\n");
        errno = EINVAL;
        return -1;
    }

    /* Count */
    if (parse_u32(pa.args[2], &count) < 0) {
        print(V_INFO, ctx, "** Error: Bad byte count\n");
        errno = EINVAL;
        return -1;
    }

    if (count > 32768) {
        print(V_INFO, ctx, "** Warning: Bytecount exceeds 32768, which seems to be a problem to decode for some servers\n");
    }

    if (nfs_read(ctx, &nfh, offset, count, &res) < 0)
        goto finished;

    if (print_raw) {
        if (fwrite(res.data, res.count, 1, stdout) != 1) {
            fprintf(stderr, "** Error: Failed to write data to stdout\n");
            goto finished;
        }
        printf("\n");
        goto finished;
    }

    /* Hexdump with ASCII in xxd style */
    i = 0;
    while (i < res.count) {
        char hbuf[128];
        char pbuf[128];
        int out;

        /* Dump 16 characters at a time */
        out = 16;
        if ((res.count - i) < 16)
            out = res.count - i;

        if (str_hex(&res.data[i], out, hbuf, sizeof(hbuf)) == NULL)
            goto finished;

        if (str_printable(&res.data[i], out, pbuf, sizeof(pbuf)) == NULL)
            goto finished;

        printf("%08lx: %-32s  %s\n", i, hbuf, pbuf);
        i += 16;
    }

finished:
    nfs_read_res_free(&res);
    return 0;
}

static int
cmd_readlink(struct nfsctx *ctx, int argc, char **argv)
{
    uint8_t fh[NFS_FHSIZE_MAX];
    int fhlen;

    CHECK_ARGC_EXACT(2);

    if ((fhlen = nfs_parse_fh(argv[1], fh, sizeof(fh))) < 0)
        return -1;

    if (transfer_readlink(ctx, fh, fhlen) < 0)
        return 0; /* NFS operation failure */

    return 0;
}

static int
cmd_getattr(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_fh nfh;
    struct nfs_attr attr;
    struct parsed_args pa;
    char attrbuf[ATTRBUFLEN];
    uint32_t opts = 0;

    if (parse_cmdline(argc, argv, "l", 1, 1, &pa) < 0)
        return -1;

    if (strchr(pa.opts, 'l'))
        opts |= ATTRSTR_LONG;

    /* FH */
    if (nfs_parse_fh_arg(pa.args[0], &nfh) < 0)
        return -1;

    memset(&attr, 0, sizeof(attr));
    if (nfs_getattr(ctx, &nfh, &attr) < 0)
        return 0; /* NFS operation failure */

    if (fmt_attr(ctx, &attr, opts, NULL, attrbuf, sizeof(attrbuf)) == NULL)
        return 0; /* Formatting failure */

    printf("%s\n", attrbuf);

    /* If symlink, show target */
    if (attr.type == NFS_FTYPE_LNK) {
        struct nfs_readlink_res linkres;
        memset(&linkres, 0, sizeof(linkres));

        if (nfs_readlink(ctx, &nfh, &linkres) == 0)
            printf("  -> %s\n", linkres.target);
    }

    return 0;
}

static int
cmd_readdir(struct nfsctx *ctx, int argc, char **argv)
{
    uint8_t fh[NFS_FHSIZE_MAX];
    int fhlen;

    CHECK_ARGC_EXACT(2);

    if ((fhlen = nfs_parse_fh(argv[1], fh, sizeof(fh))) < 0)
        return -1;

    if (list_dir(ctx, 0, fh, fhlen) < 0)
        return 0; /* NFS operation failure */

    return 0;
}

static int
cmd_readdirplus(struct nfsctx *ctx, int argc, char **argv)
{
    struct parsed_args pa;
    uint8_t fh[NFS_FHSIZE_MAX];
    uint32_t opts = 0;
    int fhlen;

    if (parse_cmdline(argc, argv, "lc", 1, 1, &pa) < 0)
        return -1;

    if (strchr(pa.opts, 'l'))
        opts |= READDIRPLUS_OPT_LONG;
    if (strchr(pa.opts, 'c'))
        opts |= READDIRPLUS_OPT_COLORS;

    if ((fhlen = nfs_parse_fh(pa.args[0], fh, sizeof(fh))) < 0)
        return -1;

    if (list_dir_plus(ctx, opts, fh, fhlen) < 0)
        return 0; /* NFS operation failure */

    return 0;
}

static int
cmd_exports(struct nfsctx *ctx, int argc, char **argv)
{
    struct mount_export *xpl;
    struct mount_export *head;

    (void)argv;
    CHECK_ARGC_EXACT(1);
    CHECK_MOUNTD_PORT(ctx);

    if (mount_get_exports(ctx, &xpl) < 0)
        return 0; /* Mount protocol operation failure */

    /* Print exports */
    head = xpl;
    while (xpl != NULL) {
        size_t tablen;

        printf("%s ", xpl->name);
        for (tablen = strlen(xpl->name); tablen < TABALIGN; tablen++)
            printf("_");
        printf(" %s\n", xpl->group);

        xpl = xpl->next;
    }

    /* Free exports list */
    mount_export_free(head);

    return 0;
}

static int
cmd_dump(struct nfsctx *ctx, int argc, char **argv)
{
    struct mount_entry *entries, *cur;

    (void)argv;
    CHECK_ARGC_EXACT(1);
    CHECK_MOUNTD_PORT(ctx);

    if (mount_dump_list(ctx, &entries) < 0)
        return 0; /* Mount protocol operation failure */

    for (cur = entries; cur != NULL; cur = cur->next)
        printf("%s:%s\n", cur->hostname, cur->directory);

    mount_entry_free(entries);
    return 0;
}

static int
cmd_umnt(struct nfsctx *ctx, int argc, char **argv)
{
    CHECK_ARGC_EXACT(2);
    CHECK_MOUNTD_PORT(ctx);
    if (mount_umnt(ctx, argv[1]) < 0)
        return 0; /* Mount protocol operation failure */
    printf("Unmounted %s\n", argv[1]);
    return 0;
}

static int
cmd_umntall(struct nfsctx *ctx, int argc, char **argv)
{
    (void)argv;
    CHECK_ARGC_EXACT(1);
    CHECK_MOUNTD_PORT(ctx);
    if (mount_umntall(ctx) < 0)
        return 0; /* Mount protocol operation failure */
    return 0;
}

static int
cmd_getfh(struct nfsctx *ctx, int argc, char **argv)
{
    CHECK_ARGC_EXACT(2);
    CHECK_MOUNTD_PORT(ctx);

    if (cmd_mnt(ctx, argc, argv) != 0)
        return 0; /* Mount operation failure (cmd_mnt handles errors) */

    /* Unregister this client after getting the file handle */
    /* Fallback to UMNT if UMNTALL not supported (HP-UX etc) */
    if (mount_umntall(ctx) < 0)
        mount_umnt(ctx, argv[1]);
    return 0;
}

static int
cmd_mnt(struct nfsctx *ctx, int argc, char **argv)
{
    char hex[1024];
    uint8_t fh[NFS_FHSIZE_MAX];
    int fhlen;

    CHECK_ARGC_EXACT(2);
    CHECK_MOUNTD_PORT(ctx);

    fhlen = mount_mnt_cached(ctx, argv[1], fh, sizeof(fh), 0);
    if (fhlen < 0)
        return 0; /* Mount protocol operation failure */

    str_hex(fh, fhlen, hex, sizeof(hex));
    print(V_INFO, ctx, "Received %u bytes fh for '%s': %s\n",
        fhlen, argv[1], hex);

    return 0;
}

static int
cmd_set_uid(struct nfsctx *ctx, int argc, char **argv)
{
    if (argc < 2) {
        printf("UID: %u\n", ctx->uid);
        return 0;
    }
    CMD_SET_UINT32(uid);
}

static int
cmd_set_verbose(struct nfsctx *ctx, int argc, char **argv)
{
    if (argc < 2) {
        printf("Verbosity: %u (%s)\n", ctx->verbose, verbose_name(ctx->verbose));
        return 0;
    }

    /* Accept named levels */
    if (strcmp(argv[1], "info") == 0) {
        ctx->verbose = V_INFO;
    } else if (strcmp(argv[1], "detail") == 0) {
        ctx->verbose = V_DETAIL;
    } else if (strcmp(argv[1], "debug") == 0) {
        ctx->verbose = V_DEBUG;
    } else if (strcmp(argv[1], "trace") == 0) {
        ctx->verbose = V_TRACE;
    } else {
        /* Numeric value */
        CMD_SET_UINT32(verbose);
    }
    return 0;
}

static int
cmd_set_gid(struct nfsctx *ctx, int argc, char **argv)
{
    if (argc < 2) {
        printf("GID: %u\n", ctx->gid);
        return 0;
    }
    CMD_SET_UINT32(gid);
}

/*
 * Format supported versions as slash-separated list (e.g., "1/2/3")
 * Returns pointer to static buffer.
 */
static const char *
format_supported_versions(uint8_t mask)
{
    static char buf[16];
    char *p = buf;
    uint8_t v;
    int first = 1;

    /* Mask out flags to get version bits only (bits 1-3) */
    uint8_t vers_mask = mask & 0x0F;

    if (vers_mask == 0) {
        if (mask & VERSION_MASK_FULL)
            return "(none)"; /* Fully enumerated, nothing found */
        return "-";          /* Not probed yet */
    }

    for (v = 1; v <= 3; v++) {
        if (vers_mask & (1U << v)) {
            if (!first)
                *p++ = '/';
            *p++ = '0' + v;
            first = 0;
        }
    }
    *p = '\0';
    return buf;
}

/*
 * Print discovery method with description.
 */
static void
print_discovery_method(struct nfsctx *ctx)
{
    if (ctx->portmap.discovery_method == 1) {
        /* Using DUMP */
        if (ctx->portmap.mount_perversion_ports)
            printf("\nDiscovery: DUMP (mount uses per-version ports)\n");
        else if (ctx->portmap.getport_status == PMAP_GETPORT_BUGGY)
            printf("\nDiscovery: DUMP (GETPORT returns stale registrations)\n");
        else
            printf("\nDiscovery: DUMP\n");
    } else if (ctx->portmap.discovery_method == 2) {
        /* Using GETPORT - note if buggy and using NULL verification */
        if (ctx->portmap.getport_status == PMAP_GETPORT_BUGGY)
            printf("\nDiscovery: GETPORT + NULL (compatibility mode)\n");
        else
            printf("\nDiscovery: GETPORT\n");
    }
    /* else: discovery hasn't happened yet, omit the line */
}

/*
 * Print a protocol row in version status table.
 */
static void
print_protocol_row(const char *name, uint16_t port_net,
    uint8_t version_mask, uint8_t active_version)
{
    char supported_buf[32];
    char port_buf[16];
    uint16_t port = ntohs(port_net);

    if (version_mask != 0)
        snprintf(supported_buf, sizeof(supported_buf), "%s",
            format_supported_versions(version_mask));
    else
        snprintf(supported_buf, sizeof(supported_buf), "(not probed)");

    /* Show "-" for unknown port instead of 0 */
    if (port != 0)
        snprintf(port_buf, sizeof(port_buf), "%u", port);
    else
        snprintf(port_buf, sizeof(port_buf), "-");

    if (active_version != 0)
        printf("%-10s %-10s %6s   %-13s %u\n",
            name, "UDP", port_buf, supported_buf, active_version);
    else
        printf("%-10s %-10s %6s   %-13s %s\n",
            name, "UDP", port_buf, supported_buf, "-");
}

/*
 * Print full version status in tabular format.
 */
static void
print_version_status(struct nfsctx *ctx)
{
    /* Check if we have any version info (either from full probe or specific version) */
    int have_portmap = (ctx->portmap.version_mask != 0);
    int have_mount = (ctx->proto.mount_version_mask != 0 || ctx->proto.mount_version != 0);
    int have_nfs = (ctx->proto.nfs_version_mask != 0 || ctx->proto.nfs_version != 0);
    char supported_buf[32];

    if (!have_portmap && !have_mount && !have_nfs) {
        printf("No protocol versions resolved yet\n");
        return;
    }

    /* Print header */
    printf("%-10s %-10s %6s   %-13s %s\n", "Protocol", "Transport", "Port", "Supported", "Active");

    /* Print portmap row if probed */
    if (have_portmap) {
        int active_ver;
        snprintf(supported_buf, sizeof(supported_buf), "%s",
            format_supported_versions(ctx->portmap.version_mask));
        /* Use forced version if set, otherwise highest available */
        if (ctx->portmap.version != 0)
            active_ver = ctx->portmap.version;
        else if (ctx->portmap.version_mask & VERSION_AVAIL_3)
            active_ver = 3;
        else if (ctx->portmap.version_mask & VERSION_AVAIL_2)
            active_ver = 2;
        else
            active_ver = 0;
        printf("%-10s %-10s %6u   %-13s %d\n",
            "portmap",
            "UDP",
            ntohs(ctx->ports.rpc),
            supported_buf,
            active_ver);
    }

    /* Print mount row if resolved */
    if (have_mount)
        print_protocol_row("mount", ctx->ports.mountd,
            ctx->proto.mount_version_mask, ctx->proto.mount_version);

    /* Print NFS row if resolved */
    if (have_nfs)
        print_protocol_row("NFS", ctx->ports.nfsd,
            ctx->proto.nfs_version_mask, ctx->proto.nfs_version);

    print_discovery_method(ctx);
}

/* Legacy functions for callers that set version and want confirmation */
static void
print_supported_versions(struct nfsctx *ctx, uint8_t mask, char *protname)
{
    uint8_t v;
    uint8_t vers_mask;

    if (ctx == NULL)
        return;

    /* Mask out flags to get version bits only (bits 1-3) */
    vers_mask = mask & 0x0F;

    print(V_INFO, ctx, "%s versions supported by remote host: ", protname);

    if (vers_mask == 0) {
        printf("none\n");
        return;
    }

    for (v = 1; v <= 3; v++) {
        if (vers_mask & (1U << v)) {
            printf("%d ", v);
        }
    }

    printf("\n");
}

static void
print_mount_version(struct nfsctx *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->proto.mount_version > 0) {
        print(V_INFO, ctx, "Using mount version %d\n", ctx->proto.mount_version);
    } else {
        print(V_INFO, ctx, "No supported mount version\n");
    }
}

static void
print_nfs_version(struct nfsctx *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->proto.nfs_version > 0) {
        print(V_INFO, ctx, "Using NFS version %d\n", ctx->proto.nfs_version);
    } else {
        print(V_INFO, ctx, "No supported NFS version\n");
    }
}

static int
cmd_protocol(struct nfsctx *ctx, int argc, char **argv)
{
    int prog = 0;
    int res;
    int ver_tmp;
    uint8_t new_ver = 0;

    CHECK_ARGC(1, 3);

    /* Parse protocol argument */
    if (argc >= 2) {
        if (strcmp(argv[1], "portmap") == 0) {
            prog = RPC_PROGRAM_PORTMAP;
        } else if (strcmp(argv[1], "mount") == 0) {
            prog = RPC_PROGRAM_MOUNT;
        } else if (strcmp(argv[1], "nfs") == 0) {
            prog = RPC_PROGRAM_NFS;
        } else {
            errno = EINVAL;
            return -1;
        }

        /* Version number is required when protocol is specified */
        if (argc != 3) {
            fprintf(stderr, "Usage: protocol %s <n>\n", argv[1]);
            errno = EINVAL;
            return -1;
        }

        if (str_to_int(argv[2], &ver_tmp, 1, 255) < 0) {
            fprintf(stderr, "*** Invalid version number: %s\n", argv[2]);
            errno = EINVAL;
            return -1;
        }
        new_ver = (uint8_t)ver_tmp;
    }

    /* Set version */
    if (new_ver) {
        switch (prog) {
        case RPC_PROGRAM_PORTMAP:
            if (new_ver != PMAP_VERSION_2 && new_ver != PMAP_VERSION_3) {
                fprintf(stderr, "*** Invalid portmap version: %d (use %d or %d)\n",
                    new_ver, PMAP_VERSION_2, PMAP_VERSION_3);
                return 0;
            }
            /* Probe if not yet known */
            if (ctx->portmap.version_mask == 0)
                ctx->portmap.version_mask = portmap_probe_versions(ctx);
            /* Check if requested version is available */
            if (!(ctx->portmap.version_mask & VERSION_AVAIL(new_ver))) {
                print_version_unavailable("portmap", new_ver,
                    ctx->portmap.version_mask, PMAP_VERSION_2, PMAP_VERSION_3);
                return 0;
            }
            ctx->portmap.version = new_ver;
            break;

        case RPC_PROGRAM_MOUNT:
            res = set_mount_version(ctx, new_ver);
            if (res < 0) {
                fprintf(stderr, "*** Invalid mount version: %d (use 1, 2, or 3)\n", new_ver);
                return 0;
            }
            if (res == 0) {
                print_version_unavailable("mount", new_ver,
                    ctx->proto.mount_version_mask, 1, 3);
                return 0;
            }
            break;

        case RPC_PROGRAM_NFS:
            res = set_nfs_version(ctx, new_ver);
            if (res < 0) {
                fprintf(stderr, "*** Invalid NFS version: %d (use %d or %d)\n",
                    new_ver, NFS_VERSION_2, NFS_VERSION_3);
                return 0;
            }
            if (res == 0) {
                print_version_unavailable("NFS", new_ver,
                    ctx->proto.nfs_version_mask, NFS_VERSION_2, NFS_VERSION_3);
                return 0;
            }
            break;
        }
    }

    /*
     * If no arguments (status display only), enumerate versions if not
     * already fully probed. This gives the user a complete picture.
     */
    if (argc == 1) {
        int need_portmap = (ctx->portmap.version_mask == 0);
        int need_mount = !(ctx->proto.mount_version_mask & VERSION_MASK_FULL);
        int need_nfs = !(ctx->proto.nfs_version_mask & VERSION_MASK_FULL);

        if (need_portmap || need_mount || need_nfs) {
            uint16_t port;
            uint8_t mask;

            /* Probe portmap/rpcbind versions first */
            if (need_portmap) {
                ctx->portmap.version_mask = portmap_probe_versions(ctx);
            }

            if (need_mount) {
                mask = portmap_probe(ctx, PMAP_PROG_MOUNTD, 1, 3, &port);
                ctx->proto.mount_version_mask = mask | VERSION_MASK_FULL;
                if (mask && ctx->ports.mountd == 0)
                    ctx->ports.mountd = port;
                if (ctx->proto.mount_version == 0)
                    set_highest_mount_version(ctx);
            }
            if (need_nfs) {
                mask = portmap_probe(ctx, PMAP_PROG_NFS, 2, 3, &port);
                ctx->proto.nfs_version_mask = mask | VERSION_MASK_FULL;
                if (mask && ctx->ports.nfsd == 0)
                    ctx->ports.nfsd = port;
                if (ctx->proto.nfs_version == 0)
                    set_highest_nfs_version(ctx);
            }
        }
    }

    /* Show full status - tabular format is compact enough for all cases */
    print_version_status(ctx);

    return 0;
}

static int
cmd_getport(struct nfsctx *ctx, int argc, char **argv)
{
    uint16_t port;
    uint8_t mask;
    int specific_version = 0;

    if (argc < 2 || argc > 3) {
        printf("Usage: getport <nfs|mount> [version]\n");
        return 0;
    }

    /* Parse version argument if provided */
    if (argc == 3) {
        char *endptr;
        long ver;
        errno = 0;
        ver = strtol(argv[2], &endptr, 10);
        if (endptr == argv[2] || *endptr != '\0' || errno != 0 || ver < 1 || ver > 255) {
            fprintf(stderr, "*** Invalid version: %s\n", argv[2]);
            return -1;
        }
        specific_version = (int)ver;
    }

    /* Invalidate cache when user explicitly requests fresh portmap data */
    if (!specific_version)
        portmap_cache_invalidate(ctx);

    /* Resolve port for NFS service */
    if (strcmp(argv[1], "nfs") == 0) {
        if (specific_version && (specific_version < 2 || specific_version > 3)) {
            fprintf(stderr, "*** Invalid NFS version: %d (use 2 or 3)\n", specific_version);
            return -1;
        }
        if (specific_version) {
            /* Query specific version - verify with NULL probe */
            port = portmap_verify(ctx, PMAP_PROG_NFS, specific_version);

            /* Mark version as tested (bit N+3 for version N) */
            ctx->proto.nfs_version_mask |= VERSION_TESTED(specific_version);

            if (port != 0) {
                ctx->ports.nfsd = port;
                /* Mark version as available */
                ctx->proto.nfs_version_mask |= VERSION_AVAIL(specific_version);
                ctx->proto.nfs_version = specific_version;
                update_nfs_ops(ctx);
                print(V_INFO, ctx, "NFS v%d on port %u/udp\n",
                    specific_version, ntohs(port));
            } else {
                print(V_INFO, ctx, "NFS v%d unavailable\n", specific_version);
            }

            /* If all NFS versions tested, we have full knowledge */
            if ((ctx->proto.nfs_version_mask & NFS_ALL_TESTED) == NFS_ALL_TESTED)
                ctx->proto.nfs_version_mask |= VERSION_MASK_FULL;
        } else {
            /* Probe all NFS versions (2, 3) - fresh query */
            mask = portmap_probe(ctx, PMAP_PROG_NFS, 2, 3, &port);
            if (mask != 0) {
                ctx->ports.nfsd = port;
                print(V_INFO, ctx, "Resolved NFS port to %u\n", ntohs(port));
                ctx->proto.nfs_version_mask = mask | VERSION_MASK_FULL;
                print_supported_versions(ctx, mask, "NFS");
                if (ctx->proto.nfs_version == 0)
                    set_highest_nfs_version(ctx);
                print_nfs_version(ctx);
            } else {
                /* Full probe done, nothing found */
                ctx->proto.nfs_version_mask = VERSION_MASK_FULL;
                print(V_INFO, ctx, "NFS service unavailable\n");
                ctx->ports.nfsd = 0;
            }
        }
    }

    /* Resolve port for mount service */
    else if (strcmp(argv[1], "mount") == 0) {
        if (specific_version && (specific_version < 1 || specific_version > 3)) {
            fprintf(stderr, "*** Invalid mount version: %d (use 1, 2, or 3)\n", specific_version);
            return -1;
        }
        if (specific_version) {
            /* Query specific version - verify with NULL probe */
            port = portmap_verify(ctx, PMAP_PROG_MOUNTD, specific_version);

            /* Mark version as tested (bit N+3 for version N) */
            ctx->proto.mount_version_mask |= VERSION_TESTED(specific_version);

            if (port != 0) {
                ctx->ports.mountd = port;
                /* Mark version as available */
                ctx->proto.mount_version_mask |= VERSION_AVAIL(specific_version);
                ctx->proto.mount_version = specific_version;
                print(V_INFO, ctx, "mount v%d on port %u/udp\n",
                    specific_version, ntohs(port));
            } else {
                print(V_INFO, ctx, "mount v%d unavailable\n", specific_version);
            }

            /* If all mount versions tested, we have full knowledge */
            if ((ctx->proto.mount_version_mask & MOUNT_ALL_TESTED) == MOUNT_ALL_TESTED)
                ctx->proto.mount_version_mask |= VERSION_MASK_FULL;
        } else {
            /* Probe all mount versions (1, 2, 3) */
            mask = portmap_probe(ctx, PMAP_PROG_MOUNTD, 1, 3, &port);
            if (mask != 0) {
                ctx->ports.mountd = port;
                print(V_INFO, ctx, "Resolved mount port to %u\n", ntohs(port));
                ctx->proto.mount_version_mask = mask | VERSION_MASK_FULL;
                print_supported_versions(ctx, mask, "mount");
                if (ctx->proto.mount_version == 0)
                    set_highest_mount_version(ctx);
                print_mount_version(ctx);
            } else {
                /* Full probe done, nothing found */
                ctx->proto.mount_version_mask = VERSION_MASK_FULL;
                print(V_INFO, ctx, "mount service unavailable\n");
                ctx->ports.mountd = 0;
            }
        }
    } else {
        fprintf(stderr, "*** Unknown service: %s\n", argv[1]);
        printf("Usage: getport <nfs|mount> [version]\n");
        return -1;
    }

    return 0;
}

static int
cmd_rpcinfo(struct nfsctx *ctx, int argc, char **argv)
{
    struct portmap_dump_entry *de, *cur;
    char namebuf[16], protbuf[16];
    int use_v3 = 0;
    int force_version = 0; /* 0=auto, 2=v2, 3=v3 */
    struct portmap_ops *ops;
    int ret;

    CHECK_ARGC(1, 2);

    /* Parse options */
    if (argc == 2) {
        if (strcmp(argv[1], "-p") == 0) {
            force_version = 2;
        } else if (strcmp(argv[1], "-s") == 0) {
            force_version = 3;
        } else {
            fprintf(stderr, "Usage: rpcinfo [-p|-s]\n");
            return -1;
        }
    }

    /* Determine which version to use */
    if (force_version == 2) {
        use_v3 = 0;
    } else if (force_version == 3) {
        use_v3 = 1;
    } else {
        /* Auto: use forced version if set via 'protocol portmap', otherwise probe */
        if (ctx->portmap.version != 0) {
            use_v3 = (ctx->portmap.version == 3) ? 1 : 0;
        } else {
            if (ctx->portmap.version_mask == 0)
                ctx->portmap.version_mask = portmap_probe_versions(ctx);
            /* Prefer v3 if available */
            use_v3 = (ctx->portmap.version_mask & VERSION_AVAIL_3) ? 1 : 0;
        }
    }

    /* Get the appropriate ops table */
    ops = portmap_get_ops(use_v3 ? 3 : 2);
    if (ops == NULL || ops->dump == NULL) {
        fprintf(stderr, "** Error: No dump function for portmap v%d\n",
            use_v3 ? 3 : 2);
        return -1;
    }

    ret = ops->dump(ctx, &de);
    if (ret < 0) {
        /* If forced v3 failed, don't fall back */
        if (force_version == 3) {
            fprintf(stderr, "** Error: rpcbind v3 DUMP failed\n");
            return 0;
        }
        /* If auto and v3 failed, try v2 */
        if (use_v3) {
            print(V_DETAIL, ctx, "rpcbind v3 failed, trying portmapper v2\n");
            ops = portmap_get_ops(2);
            if (ops != NULL && ops->dump != NULL) {
                ret = ops->dump(ctx, &de);
                if (ret >= 0)
                    use_v3 = 0;
            }
        }
        if (ret < 0)
            return 0; /* Portmap operation failure */
    }

    /* Display results - format depends on version */
    if (use_v3) {
        /* v3 format: show netid and owner */
        printf("   program vers netid       port service        owner\n");
        for (cur = de; cur != NULL; cur = cur->next) {
            rpc_program_name(cur->pm_prog, namebuf, sizeof(namebuf));
            printf("%10d %4d %-9s  %5d %-14s %s\n",
                cur->pm_prog, cur->pm_vers,
                cur->pm_netid[0] ? cur->pm_netid : "-",
                cur->pm_port, namebuf,
                cur->pm_owner[0] ? cur->pm_owner : "-");
        }
    } else {
        /* v2 format: classic port number display */
        printf("   program vers proto  port service\n");
        for (cur = de; cur != NULL; cur = cur->next) {
            rpc_program_name(cur->pm_prog, namebuf, sizeof(namebuf));
            rpc_protocol_name(cur->pm_prot, protbuf, sizeof(protbuf));
            printf("%10d %4d %5s %5d %s\n", cur->pm_prog, cur->pm_vers,
                protbuf, cur->pm_port, namebuf);
        }
    }

    /*
     * Cache fresh results and populate version masks.
     * Same side effects as getport - all use DUMP, all select highest.
     * Invalidate old cache first to avoid memory leak.
     */
    portmap_cache_invalidate(ctx);
    ctx->portmap.cache = de;
    ctx->portmap.cache_valid = 1;
    ctx->portmap.dump_status = PMAP_DUMP_OK;
    ctx->portmap.discovery_method = 1;

    /* Reset masks - rebuild from fresh data */
    ctx->proto.mount_version_mask = 0;
    ctx->proto.nfs_version_mask = 0;

    for (cur = de; cur != NULL; cur = cur->next) {
        if (cur->pm_prot != IPPROTO_UDP)
            continue;

        if (cur->pm_prog == PMAP_PROG_MOUNTD && cur->pm_vers >= 1 && cur->pm_vers <= 3) {
            ctx->proto.mount_version_mask |= VERSION_AVAIL(cur->pm_vers);
            if (ctx->ports.mountd == 0)
                ctx->ports.mountd = htons(cur->pm_port);
        } else if (cur->pm_prog == PMAP_PROG_NFS && cur->pm_vers >= 2 && cur->pm_vers <= 3) {
            ctx->proto.nfs_version_mask |= VERSION_AVAIL(cur->pm_vers);
            /* Don't override default nfsd port */
        }
    }

    /* DUMP gives complete picture - mark masks as fully enumerated */
    ctx->proto.mount_version_mask |= VERSION_MASK_FULL;
    ctx->proto.nfs_version_mask |= VERSION_MASK_FULL;

    /* Select highest available versions if not already set */
    if (ctx->proto.mount_version == 0)
        set_highest_mount_version(ctx);
    if (ctx->proto.nfs_version == 0)
        set_highest_nfs_version(ctx);

    return 0;
}

static int
cmd_ping(struct nfsctx *ctx, int argc, char **argv)
{
    struct timeval start, end;
    int ret;
    double elapsed_ms;
    const char *service = "nfs";

    if (argc > 2) {
        fprintf(stderr, "Usage: ping [portmap|mount|nfs]\n");
        return -1;
    }

    if (argc == 2)
        service = argv[1];

    if (strcmp(service, "portmap") == 0) {
        gettimeofday(&start, NULL);
        ret = portmap_null(ctx);
        gettimeofday(&end, NULL);
        if (ret < 0) {
            fprintf(stderr, "Portmap: FAILED\n");
            return 0;
        }
    } else if (strcmp(service, "mount") == 0) {
        CHECK_MOUNTD_PORT(ctx);
        gettimeofday(&start, NULL);
        ret = mount_null(ctx);
        gettimeofday(&end, NULL);
        if (ret < 0) {
            fprintf(stderr, "Mount: FAILED\n");
            return 0;
        }
    } else if (strcmp(service, "nfs") == 0) {
        /* nfs_null auto-discovers version via nfs_ensure_ops */
        gettimeofday(&start, NULL);
        ret = nfs_null(ctx);
        gettimeofday(&end, NULL);
        if (ret < 0) {
            fprintf(stderr, "NFS: FAILED\n");
            return 0;
        }
    } else {
        fprintf(stderr, "*** Unknown service: %s\n", service);
        fprintf(stderr, "Usage: ping [portmap|mount|nfs]\n");
        return -1;
    }

    elapsed_ms = (end.tv_sec - start.tv_sec) * 1000.0 +
        (end.tv_usec - start.tv_usec) / 1000.0;
    printf("%s: OK (%.1f ms)\n",
        strcmp(service, "portmap") == 0 ? "Portmap" : strcmp(service, "mount") == 0 ? "Mount"
                                                                                    : "NFS",
        elapsed_ms);

    return 0;
}

/*
 * Helper to format size in human-readable form.
 */
static void
format_size(uint64_t bytes, char *buf, size_t buflen)
{
    if (bytes >= (uint64_t)1024 * 1024 * 1024 * 1024)
        snprintf(buf, buflen, "%.1fT", (double)bytes / (1024.0 * 1024 * 1024 * 1024));
    else if (bytes >= 1024 * 1024 * 1024)
        snprintf(buf, buflen, "%.1fG", (double)bytes / (1024.0 * 1024 * 1024));
    else if (bytes >= 1024 * 1024)
        snprintf(buf, buflen, "%.1fM", (double)bytes / (1024.0 * 1024));
    else if (bytes >= 1024)
        snprintf(buf, buflen, "%.1fK", (double)bytes / 1024.0);
    else
        snprintf(buf, buflen, "%luB", (unsigned long)bytes);
}

static int
cmd_df(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_fh nfh;
    struct nfs_fsstat_res res;
    char total[32], used[32], avail[32];
    uint64_t used_bytes;
    int pct;

    CHECK_ARGC_EXACT(2);

    /* FH */
    if (nfs_parse_fh_arg(argv[1], &nfh) < 0)
        return -1;

    if (nfs_statfs(ctx, &nfh, &res) < 0) {
        print(V_INFO, ctx, "** Error: statfs failed: %s\n", strerror(errno));
        return 0;
    }

    /* Guard against underflow if server reports fbytes > tbytes */
    used_bytes = (res.fbytes <= res.tbytes) ? res.tbytes - res.fbytes : 0;
    pct = (res.tbytes > 0) ? (int)(100.0 * used_bytes / res.tbytes) : 0;

    format_size(res.tbytes, total, sizeof(total));
    format_size(used_bytes, used, sizeof(used));
    format_size(res.abytes, avail, sizeof(avail));

    printf("Filesystem statistics:\n");
    printf("  Total:     %s (%lu bytes)\n", total, (unsigned long)res.tbytes);
    printf("  Used:      %s (%lu bytes, %d%%)\n", used, (unsigned long)used_bytes, pct);
    printf("  Available: %s (%lu bytes)\n", avail, (unsigned long)res.abytes);

    if (res.tfiles > 0) {
        printf("  Files:     %lu total, %lu free\n",
            (unsigned long)res.tfiles, (unsigned long)res.ffiles);
    }

    if (ctx->proto.nfs_version == 2 && res.bsize > 0) {
        printf("  Block size: %u bytes\n", res.bsize);
        printf("  Blocks:    %u total, %u free, %u available\n",
            res.blocks, res.bfree, res.bavail);
    }

    return 0;
}

static int
cmd_fsinfo(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_fh nfh;
    struct nfs_fsinfo_res res;
    char maxfile[32];

    CHECK_ARGC_EXACT(2);

    /* FH */
    if (nfs_parse_fh_arg(argv[1], &nfh) < 0)
        return -1;

    if (nfs_fsinfo(ctx, &nfh, &res) < 0) {
        if (errno == ENOTSUP)
            print(V_INFO, ctx, "** Error: fsinfo is NFSv3 only\n");
        else
            print(V_INFO, ctx, "** Error: fsinfo failed: %s\n", strerror(errno));
        return 0;
    }

    format_size(res.maxfilesize, maxfile, sizeof(maxfile));

    printf("Filesystem info:\n");
    printf("  Read:      max=%u, preferred=%u, multiple=%u\n",
        res.rtmax, res.rtpref, res.rtmult);
    printf("  Write:     max=%u, preferred=%u, multiple=%u\n",
        res.wtmax, res.wtpref, res.wtmult);
    printf("  Readdir:   preferred=%u\n", res.dtpref);
    printf("  Max file:  %s (%lu bytes)\n", maxfile, (unsigned long)res.maxfilesize);
    printf("  Time res:  %u.%09u sec\n", res.time_delta.sec, res.time_delta.nsec);
    printf("  Features:  %s%s%s%s\n",
        (res.properties & NFS_FSF3_LINK) ? "hardlinks " : "",
        (res.properties & NFS_FSF3_SYMLINK) ? "symlinks " : "",
        (res.properties & NFS_FSF3_HOMOGENEOUS) ? "homogeneous " : "",
        (res.properties & NFS_FSF3_CANSETTIME) ? "settime" : "");

    return 0;
}

static int
cmd_access(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_fh nfh;
    struct nfs_access_res res;
    uint32_t mask = 0x3f; /* all bits by default */
    const char *p;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: access <fh> [rwxdel]\n");
        return -1;
    }

    /* FH */
    if (nfs_parse_fh_arg(argv[1], &nfh) < 0)
        return -1;

    /* Parse mask if provided */
    if (argc == 3) {
        mask = 0;
        for (p = argv[2]; *p; p++) {
            switch (*p) {
            case 'r':
                mask |= NFS_ACCESS3_READ;
                break;
            case 'w':
                mask |= NFS_ACCESS3_MODIFY;
                break;
            case 'x':
                mask |= NFS_ACCESS3_EXECUTE;
                break;
            case 'e':
                mask |= NFS_ACCESS3_EXTEND;
                break;
            case 'd':
                mask |= NFS_ACCESS3_DELETE;
                break;
            case 'l':
                mask |= NFS_ACCESS3_LOOKUP;
                break;
            default:
                fprintf(stderr, "Unknown permission: %c\n", *p);
                return -1;
            }
        }
    }

    if (nfs_access(ctx, &nfh, mask, &res) < 0) {
        if (errno == ENOTSUP)
            fprintf(stderr, "** Error: access is NFSv3 only\n");
        else
            fprintf(stderr, "** Error: access failed: %s\n", strerror(errno));
        return 0;
    }

    printf("Access permissions (requested 0x%02x, granted 0x%02x):\n", mask, res.access);
    printf("  %c READ      (list directory / read file)\n",
        (res.access & NFS_ACCESS3_READ) ? '+' : '-');
    printf("  %c LOOKUP    (search directory)\n",
        (res.access & NFS_ACCESS3_LOOKUP) ? '+' : '-');
    printf("  %c MODIFY    (write file / modify directory)\n",
        (res.access & NFS_ACCESS3_MODIFY) ? '+' : '-');
    printf("  %c EXTEND    (append file / add to directory)\n",
        (res.access & NFS_ACCESS3_EXTEND) ? '+' : '-');
    printf("  %c DELETE    (delete file / remove directory entry)\n",
        (res.access & NFS_ACCESS3_DELETE) ? '+' : '-');
    printf("  %c EXECUTE   (execute file)\n",
        (res.access & NFS_ACCESS3_EXECUTE) ? '+' : '-');

    return 0;
}

static int
cmd_pathconf(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfs_fh nfh;
    struct nfs_pathconf_res res;

    CHECK_ARGC_EXACT(2);

    /* FH */
    if (nfs_parse_fh_arg(argv[1], &nfh) < 0)
        return -1;

    if (nfs_pathconf(ctx, &nfh, &res) < 0) {
        if (errno == ENOTSUP)
            fprintf(stderr, "** Error: pathconf is NFSv3 only\n");
        else
            fprintf(stderr, "** Error: pathconf failed: %s\n", strerror(errno));
        return 0;
    }

    printf("Path configuration:\n");
    printf("  Max links:        %u\n", res.linkmax);
    printf("  Max name length:  %u\n", res.name_max);
    printf("  No truncate:      %s\n", res.no_trunc ? "yes" : "no");
    printf("  Chown restricted: %s\n", res.chown_restricted ? "yes" : "no");
    printf("  Case insensitive: %s\n", res.case_insensitive ? "yes" : "no");
    printf("  Case preserving:  %s\n", res.case_preserving ? "yes" : "no");

    return 0;
}

/*
 * Execute command.
 */
int
cmd_execute(struct nfsctx *ctx, int argc, char **argv)
{
    int i;

    /* Find command */
    for (i = 0; cmds[i].name != NULL; i++) {

        if (!strcmp(argv[0], cmds[i].name)) {
            /* Prepare for getopt(3) */
            optind = 0;

            if (cmds[i].func == NULL) {
                fprintf(stderr, "**** Error: No handler set for command '%s'\n", cmds[i].name);
                return -1;
            } else {
                if (cmds[i].func(ctx, argc, argv) < 0) {
                    /* Only show if errno set - commands handle their own error messages */
                    if (errno != 0)
                        fprintf(stderr, "**** Command '%s' failed, run 'help <cmd>' for help: %s\n", cmds[i].name, strerror(errno));
                    return -1;
                }

                break;
            }
        }
    }

    if (cmds[i].name == NULL) {
        fprintf(stderr, "**** Unknown command '%s', type 'help' for help\n", argv[0]);
        return -1;
    }

    return 0;
}

/*
 * Get sorted command count (for completion).
 */
size_t
cmd_count(void)
{
    size_t count = 0;
    while (cmds[count].name != NULL)
        count++;
    return count;
}
