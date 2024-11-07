/*
 * Copyright (C)  2023-2024 Claes M Nyberg <cmn@signedness.org>
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
 *      This product includes software developed by Claes M Nyberg.
 * 4. The name Claes M Nyberg may not be used to endorse or promote
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#ifndef NO_READLINE
#include <curses.h>
#include <term.h>
#include <readline/readline.h>
#include <readline/history.h>
#endif /* NO_READLINE */

#ifndef NFSH_MAXLINE
#define NFSH_MAXLINE	1024
#endif

#ifndef NFSH_MAXARGS
#define NFSH_MAXARGS	32
#endif

#include "nfscli.h"

/* Command function */
typedef int (*cmdfunc_t)(struct nfsctx *, int argc, char **argv);


/* Description of interactive command */
struct cmd {
    char *name;         /* Command name */
    char *syntax;       /* Commandline syntax */
    char *help_short;   /* Short helptext (one line) */
    char *help_long;    /* Long helptext (multiple lines) */
    cmdfunc_t func;     /* Command function */
};


/* Local routines */
static int cmdcmp(const void *, const void *);
static int cmd_help(struct nfsctx *, int, char **);
extern int cmd_explore(struct nfsctx *, int, char **);
static int cmd_read(struct nfsctx *, int, char **);
static int cmd_readlink(struct nfsctx *, int, char **);
static int cmd_write(struct nfsctx *, int, char **);
static int cmd_getattr(struct nfsctx *, int, char **);
static int cmd_mkdir(struct nfsctx *, int, char **);
static int cmd_rmdir(struct nfsctx *, int, char **);
static int cmd_create(struct nfsctx *, int, char **);
static int cmd_remove(struct nfsctx *, int, char **);
static int cmd_rename(struct nfsctx *, int, char **);
static int cmd_mknod_dev(struct nfsctx *, int, char **);
static int cmd_link(struct nfsctx *, int, char **);
static int cmd_symlink(struct nfsctx *, int, char **);
static int cmd_lookup(struct nfsctx *, int, char **);
static int cmd_setattr(struct nfsctx *, int, char **);
static int cmd_get(struct nfsctx *, int, char **);
static int cmd_getoff(struct nfsctx *, int, char **);
static int cmd_cat(struct nfsctx *, int, char **);
static int cmd_put(struct nfsctx *, int, char **);
static int cmd_putoff(struct nfsctx *, int, char **);
static int cmd_set_uid(struct nfsctx *, int, char **);
static int cmd_set_gid(struct nfsctx *, int, char **);
static int cmd_set_verbose(struct nfsctx *, int, char **);
static int cmd_settings(struct nfsctx *, int, char **);
static int cmd_getport(struct nfsctx *, int, char **);
static int cmd_mnt(struct nfsctx *, int, char **);
static int cmd_getfh(struct nfsctx *, int, char **);
static int cmd_dump(struct nfsctx *, int, char **);
static int cmd_umntall(struct nfsctx *, int, char **);
static int cmd_exports(struct nfsctx *, int, char **);
static int cmd_readdirplus(struct nfsctx *, int, char **);
static int cmd_readdir(struct nfsctx *, int, char **);


/* All interactive commands */
static struct cmd cmds[] =
{
    { "settings", "",
        "Display current settings",
        "",
        cmd_settings
    },

    { "help", "[command]",
        "Display help for all or specific command",
        "    command  -  The command to show help for\n",
        cmd_help
    },

    { "mnt", "<directory>",
        "(Mount v3 MNT) Get file handle for mount of exported path",
        "",
        cmd_mnt
    },

	{ "getfh", "<directory>",
		"(Mount v3 MNT + UMNTALL) Get fh for exported directory and unregister this client",
		"",
		cmd_getfh
	},


    { "umntall", "",
        "(Mount v3 UMNTALL) Removes all of the mount entries for this client at server",
        "",
        cmd_umntall
	},

    { "dump", "",
        "(Mount v3 DUMP) List file systems mounted by all clients",
        "",
        cmd_dump
    },

    { "uid", "<uid>",
        "Set UID to use in calls",
        "",
        cmd_set_uid
    },

    { "gid", "<gid>",
        "Set GID to use in calls",
        "",
        cmd_set_gid
    },

    { "verbose", "<level>",
        "Set level of verboseness",
        "",
        cmd_set_verbose
    },

    { "exports", "",
        "(Mount v3 EXPORT) Show the NFS server's export list",
        "",
        cmd_exports
    },

    { "setattr", "<fh> <mode>",
        "(NFS v3 SETATTR) Set mode on file represented by file handle",
        "",
        cmd_setattr
    },

    { "getport", "<service>",
        "(Portmap v2 GETPORT) Query portmap service for port number",
        "    getport nfs   - Get port for nfs service\n"
		"    getport mount - Get port for mount service\n",
        cmd_getport
    },

    { "readdirplus", "<fh> [-lc]",
        "(NFS v3 READDIRPLUS) Read directory contents",
        "    -l    - Output a long list of information\n"
        "    -c    - Color highlighting of file names\n",
        cmd_readdirplus
    },

    { "ls", "<fh> [-l]",
        "Alias for readdirplus",
        "",
        cmd_readdirplus
    },

    { "readdir", "<fh>",
        "(NFS v3 READDIR) Read directory contents",
        "",
        cmd_readdir
    },

    { "explore", "[-a]",
        "Explore remote NFS server",
		" -a: Attempt to resolve all shares, regardless of client IP\n"
		"  1) Resolve FH for all shares exported to everyone\n"
		"  2) Climb to the top directory of each share, to try to find root fs\n"
		"  3) Attempt to list and display interesting files and directories"
		"\n",
        cmd_explore
    },

    { "getattr", "<fh>",
        "(NFS v3 GETATTR) Get attributes for file handle",
        "",
        cmd_getattr
    },

    { "read", "<fh> <offset> <count> [-r]",
        "(NFS v3 READ) Read from file",
        "    -r    - Print raw data to stdout\n",
        cmd_read
    },

    { "readlink", "<fh>",
        "(NFS v3 READLINK) Read data from symbolic link represented by fh",
        "",
        cmd_readlink
    },

    { "write", "<fh> <offset> <hexdata>",
        "(NFS v3 WRITE) Write to file",
        "",
        cmd_write
    },

    { "mkdir", "<fh> <name> <mode>",
        "(NFS v3 MKDIR) Create a directory inside directory represented by file handle",
        "",
        cmd_mkdir
    },

    { "rmdir", "<fh> <name>",
        "(NFS v3 RMDIR) Remove directory inside directory represented by file handle",
        "",
        cmd_rmdir
    },

    { "mknod-chr", "<fh> <name> <mode> <major> <minor>",
        "(NFS v3 MKNOD) Create character device file in directory represented by fh",
        "",
        cmd_mknod_dev
	},

    { "mknod-blk", "<fh> <name> <mode> <major> <minor>",
        "(NFS v3 MKNOD) Create block device file in directory represented by fh",
        "",
        cmd_mknod_dev
	},

    { "create", "<fh> <name> <mode>",
        "(NFS v3 CREATE) Create a file inside directory represented by file handle",
        "",
        cmd_create
    },

    { "remove", "<fh> <name>",
        "(NFS v3 REMOVE) Remove a file inside directory represented by file handle",
        "",
        cmd_remove
    },

    { "rename", "<src-fh> <src-name> <dst-fh> <dst-name>",
        "(NFS v3 RENAME) Rename a file in directory represented by src-fh, to dst-name inside directory dst-fh",
        "",
        cmd_rename
    },

    { "link", "<fh> <dir-fh> <name>",
        "(NFS v3 LINK) Link the file represented by fh to a file inside the directory represented by dir-fh",
        "",
        cmd_link
    },

    { "symlink", "<fh> <name> <mode> <to>",
        "(NFS v3 SYMLINK) Create symbolic link in directory represented by fh",
        "",
        cmd_symlink
    },

    { "lookup", "<fh> <filename>",
        "(NFS v3 LOOKUP) Lookup file handle for filename in directory represented by file handle",
        "",
        cmd_lookup
    },

    { "get", "<fh> <local-file>",
        "(NFS v3 READ) Download file",
        "",
        cmd_get
    },

    { "getoff", "<fh> <offset> <local-file>",
        "(NFS v3 READ) Download file from offset to local file",
        "",
        cmd_getoff
	},

    { "cat", "<fh>",
        "(NFS v3 READ) Read file and write to terminal",
        "",
        cmd_cat
    },

    { "put", "<local-file> <fh> <remote-name> <mode>",
        "(NFS v3 CREATE + WRITE) Upload file to directory represented by file handle",
        "",
        cmd_put
    },

    { "putoff", "<local-file> <offset> <fh>",
        "(NFS v3 WRITE) Resume upload from offset in local file to remote file represented by fh",
        "",
        cmd_putoff
    },

    { "quit", "",
        "Quit",
        "",
        NULL
    },

	{NULL, NULL, NULL, NULL, NULL}
};

/*
 * Compare commands by name
 */
static int
cmdcmp(const void *a, const void *b)
{
    struct cmd *c1;
    struct cmd *c2;
    c1 = (struct cmd *)a;
    c2 = (struct cmd *)b;
    return(strcmp(c1->name, c2->name));
}



static int
cmd_help(struct nfsctx *ctx, int argc, char **argv)
{
    uint32_t i;
    uint32_t w;

	printf("\n");

    /* Print help for specific command */
    if (argv[1] != NULL) {
        for (i=0; cmds[i].name != NULL; i++) {

            if (!strcmp(cmds[i].name, argv[1])) {
        		printf("%s\n", cmds[i].help_short);
                printf("Usage: %s %s\n", cmds[i].name, cmds[i].syntax);
                printf("%s\n", cmds[i].help_long);
                return(0);
            }
        }

		printf("*** Command '%s' not found\n", argv[1]);
    }

    printf("\nNFS v3 CLI v%s, by Claes M Nyberg <cmn@signedness.org>, Aug 2023\n",
		NFSCLI_VERSION);
    printf("Available commands:\n");
    for (i=0; cmds[i].name != NULL; i++) {
        w = printf("%s ", cmds[i].name);
        while (w++ < 30)
            printf(".");
        printf(" %s\n", cmds[i].help_short);
    }
    printf("\n");
    return 0;
}

static int
cmd_mknod_dev(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfsv3_mknod_dev_args args;
    char *ep;

    if (argc != 6) {
        errno = EINVAL;
        return -1;
    }

    memset(&args, 0x00, sizeof(struct nfsv3_mknod_dev_args));

	if (strcmp(argv[0], "mknod-blk") == 0)
		args.type = NF3BLK;

	else if (strcmp(argv[0], "mknod-chr") == 0)
		args.type = NF3CHR;

    /* Parse file handle */
    if ( (args.fhlen = str_hex2bin(argv[1], args.fh, sizeof(args.fh))) <= 0) {
        errno = EINVAL;
        return -1;
    }

    snprintf(args.name, sizeof(args.name), "%s", argv[2]);

    /* Mode */
    args.mode = strtoul(argv[3], &ep, 0);
    if (*ep != '\0') {
        print(0, ctx, "** Error: Bad mode\n");
        errno = EINVAL;
        return -1;
    }

	/* Major */
	args.major = strtoul(argv[4], &ep, 0);
	if (*ep != '\0') {
		print(0, ctx, "** Error: Bad major\n");
		errno = EINVAL;
		return -1;
	}

	/* Minor */
	args.minor = strtoul(argv[5], &ep, 0);
	if (*ep != '\0') {
		print(0, ctx, "** Error: Bad minor\n");
		errno = EINVAL;
		return -1;
	}

    return nfsv3_mknod_dev(ctx, &args);
}


static int
cmd_symlink(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfsv3_symlink_args args;
	char *ep;

    if (argc != 5) {
        errno = EINVAL;
        return -1;
    }

    memset(&args, 0x00, sizeof(struct nfsv3_symlink_args));

    /* Parse file handle */
    if ( (args.fhlen = str_hex2bin(argv[1], args.fh, sizeof(args.fh))) <= 0) {
        errno = EINVAL;
        return -1;
    }

    snprintf(args.name, sizeof(args.name), "%s", argv[2]);

	/* Mode */
	args.mode = strtoul(argv[3], &ep, 0);
	if (*ep != '\0') {
		print(0, ctx, "** Error: Bad mode\n");
		errno = EINVAL;
		return -1;
	}
	
    snprintf(args.to, sizeof(args.to), "%s", argv[4]);
    return nfsv3_symlink(ctx, &args);
}


static int
cmd_link(struct nfsctx *ctx, int argc, char **argv)
{
	struct nfsv3_link_args args;

    if (argc != 4) {
        errno = EINVAL;
        return -1;
    }

    memset(&args, 0x00, sizeof(struct nfsv3_link_args));

    /* Parse file handle */
    if ( (args.fhlen = str_hex2bin(argv[1], args.fh, sizeof(args.fh))) <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* Parse file handle */
    if ( (args.dirfhlen = str_hex2bin(argv[2], args.dirfh, sizeof(args.dirfh))) <= 0) {
        errno = EINVAL;
        return -1;
    }

    snprintf(args.name, sizeof(args.name), "%s", argv[3]);
    return nfsv3_link(ctx, &args);
}


static int
cmd_lookup(struct nfsctx *ctx, int argc, char **argv)
{
	struct lookup_ret ret;
	uint8_t buf[4096];
	int fhlen;

	if (argc != 3) {
		errno = EINVAL;
		return -1;
	}

	/* FH */
	if ( (fhlen = str_hex2bin(argv[1], buf, sizeof(buf))) <= 0) {
		errno = EINVAL;
		return -1;
	}

	memset(&ret, 0x00, sizeof(struct lookup_ret));
	if (nfsv3_lookup(ctx, buf, fhlen, argv[2], &ret) < 0)
		return -1;

	nfsv3_attrstr(ctx, &ret.obj_attr, 0x00, NULL, (char *)buf, sizeof(buf));

	printf("%s FH:", buf);
	HEXDUMP(ret.fh, ret.fhlen);

	return 0;
}

static int
cmd_settings(struct nfsctx *ctx, int argc, char **argv)
{   
    printf("\n");

	printf("Server ..................................... %s\n", ctx->server);
	printf("Spoofed IPv4 ............................... %s\n", 
		ctx->spoof ? ctx->sip : "Disabled");
	printf("Port local ................................. %d\n", ntohs(ctx->port_local));
	printf("Port RPC ................................... %d\n", ntohs(ctx->port_rpc));
	printf("Port NFSd .................................. %d\n", ntohs(ctx->port_nfsd));
	printf("Port mountd ................................ %d\n", ntohs(ctx->port_mountd));

	printf("UID ........................................ %u\n", ctx->uid);
	printf("GID ........................................ %u\n", ctx->gid);
	printf("Verbose .................................... %u\n", ctx->verbose);

    printf("\n");
    return 0;
}

static int
cmd_putoff(struct nfsctx *ctx, int argc, char **argv)
{
	struct nfsv3_write_args wargs;
	uint8_t buf[IOBUFSIZE];
	FILE *inf;
	size_t n;
	int ret = 0;
	char *ep;
	size_t tot;

    if (argc != 4) {
        errno = EINVAL;
        return -1;
    }

    memset(&wargs, 0x00, sizeof(struct nfsv3_write_args));
	inf = NULL;

    /* Offset */
    wargs.offset = strtoul(argv[2], &ep, 0);
    if (*ep != '\0') {
        print(0, ctx, "** Error: Bad mode\n");
        errno = EINVAL;
        return -1;
    }

	/* Parse file handle */
    if ( (wargs.fhlen = str_hex2bin(argv[3], wargs.fh, sizeof(wargs.fh))) <= 0) {
        errno = EINVAL;
        return -1;
    }

	/* Open local file */
    if ( (inf = fopen(argv[1], "r")) == NULL) {
        print(0, ctx, "** Error: Failed to open %s: %s\n", argv[1], strerror(errno));
        ret = -1;
        goto finished;
    }

	/* Find offset */
	if (fseek(inf, wargs.offset, SEEK_SET) != 0) {
		print(0, ctx, "** Error: Failed to set offset in local file: %s\n", 
			strerror(errno));
		ret = -1;
		goto finished;
	}

    print(0, ctx, "Uploading (using buffer size %u) from offset %lu\n",
		IOBUFSIZE, wargs.offset);
	
	wargs.data = buf;
	tot = 0;

    /* Transfer file */
    while ( (n = fread(buf, 1, IOBUFSIZE, inf)) > 0) {
        wargs.count = n;
		tot += n;

        if (nfsv3_write(ctx, &wargs) < 0) {
            ret = -1;
            goto finished;
        }

        /* Print a '.' for every transfer */
        printf(".");
        fflush(stdout);

        wargs.offset += n;
    }

    printf("\n");
    print(0, ctx, "Transfered %lu bytes\n", tot);


finished:
	if (inf != NULL)
		fclose(inf);

	return ret;
}


static int
cmd_put(struct nfsctx *ctx, int argc, char **argv)
{
	struct nfsv3_create_args cargs;
	struct nfsv3_write_args wargs;
	FILE *inf;
	uint8_t buf[IOBUFSIZE];
	size_t n;
	int ret = 0;
	char *ep;

	if (argc != 5) {
		errno = EINVAL;
		return -1;
	}

	memset(&cargs, 0x00, sizeof(struct nfsv3_create_args));
	memset(&wargs, 0x00, sizeof(struct nfsv3_write_args));


	/* Parse file handle */
	if ( (cargs.fhlen = str_hex2bin(argv[2], cargs.fh, sizeof(cargs.fh))) <= 0) {
		errno = EINVAL;
		return -1;
	}

	/* Mode */
	cargs.mode = strtoul(argv[4], &ep, 0);
	if (*ep != '\0') {
		print(0, ctx, "** Error: Bad mode\n");
		errno = EINVAL;
		return -1;
	}

	/* Open local file */
	if ( (inf = fopen(argv[1], "r")) == NULL) {
		print(0, ctx, "** Error: Failed to open %s: %s\n", argv[1], strerror(errno));
		ret = -1;
		goto finished;
	}

	snprintf(cargs.name, sizeof(cargs.name), "%s", argv[3]);

	/* Create remote file */
	if (nfsv3_create(ctx, &cargs) < 0) {
		ret = -1;
		goto finished;
	}

	/* Should never happen */
	if (cargs.newfhlen > sizeof(wargs.fh)) {
		print(0, ctx, "** Error: File handle for created file exceeds buffer size\n");
		ret = -1;
		goto finished;
	}

	memcpy(wargs.fh, cargs.newfh, cargs.newfhlen);
	wargs.fhlen = cargs.newfhlen;
	wargs.offset = 0;
	wargs.data = buf;

	print(0, ctx, "Uploading %s to %s (using buffer size %u for each dot)\n", 
		argv[1], argv[3], IOBUFSIZE);

	/* Transfer file */
	while ( (n = fread(buf, 1, IOBUFSIZE, inf)) > 0) {
		wargs.count = n;

		if (nfsv3_write(ctx, &wargs) < 0) {
			ret = -1;
			goto finished;
		}

		/* Print a '.' for every transfer */
		printf(".");
		fflush(stdout);

		wargs.offset += n;
	}

	printf("\n");
	print(0, ctx, "Transfered %lu bytes\n", wargs.offset);
	
finished:

	if (inf != NULL)
		fclose(inf);

	return ret;
}

static int
cmd_getoff(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfsv3_read_args args;
    struct nfsv3_read_reply reply;
    FILE *fp;
    uint64_t off;
    uint64_t tot;
    int ret = 0;
	char *ep;

    off = 0;
    tot = 0;

    if (argc != 4) {
        errno = EINVAL;
        return -1;
    }
    memset(&args, 0x00, sizeof(struct nfsv3_read_args));

    /* FH */
    if ( (args.fhlen = str_hex2bin(argv[1], args.fh, sizeof(args.fh))) <= 0) {
        errno = EINVAL;
        return -1;
    }

	/* Offset */
    off = strtoul(argv[2], &ep, 0);
    if (*ep != '\0') {
        print(0, ctx, "** Error: Bad offset\n");
        errno = EINVAL;
        return -1;
    }

	/* Local file */
    if ( (fp = fopen(argv[3], "r+")) == NULL) {
        print(0, ctx, "** Error: Failed to open %s\n", argv[2]);
        return -1;
    }

	if (fseek(fp, off, SEEK_SET) != 0) {
		print(0, ctx, "** Error: Failed to seek offset in local file: %s\n", strerror(errno));
		return -1;
	}

    print(0, ctx, "Downloading to %s (using buffer size %u) from offset %lu\n", 
		argv[3], IOBUFSIZE, off);

    do {
        args.offset = off;
        args.count = IOBUFSIZE;

        memset(&reply, 0x00, sizeof(struct nfsv3_read_reply));
        print(1, ctx, "READ %s: %u bytes at offset 0x%lu (tot=%u)\n",
            argv[1], args.count, args.offset, tot);

        if (nfsv3_read(ctx, &args, &reply) < 0) {
            ret = -1;
            goto finished;
        }

        if (reply.buf != NULL) {
            free(reply.buf);
            reply.buf = NULL;
        }

        if (fwrite(reply.data, reply.len, 1, fp) != 1) {
            ret = -1;
            goto finished;
        }

        printf(".");
        fflush(stdout);

        off += args.count;
        tot += args.count;
    } while (reply.eof != 1);

    printf("\n");
    print(0, ctx, "Wrote %lu bytes to %s\n", tot, argv[3]);

finished:
    if (fp != NULL)
        fclose(fp);

    if (reply.buf != NULL)
        free(reply.buf);

    return ret;
}


static int
cmd_get(struct nfsctx *ctx, int argc, char **argv)
{
	struct nfsv3_read_args args;
	struct nfsv3_read_reply reply;
	FILE *fp;
	uint64_t off;
	uint64_t tot;
	int ret = 0;

	if (argc != 3) {
		errno = EINVAL;
		return -1;
	}
	memset(&args, 0x00, sizeof(struct nfsv3_read_args));

	/* FH */
	if ( (args.fhlen = str_hex2bin(argv[1], args.fh, sizeof(args.fh))) <= 0) {
		errno = EINVAL;
		return -1;
	}

	if ( (fp = fopen(argv[2], "w")) == NULL) {
		print(0, ctx, "** Error: Failed to open %s\n", argv[2]);
		return -1;
	}

	off = 0;
	tot = 0;
	print(0, ctx, "Downloading to %s (using buffer size %u)\n", argv[2], IOBUFSIZE);

	do {
		args.offset = off;
		args.count = IOBUFSIZE;
		
		memset(&reply, 0x00, sizeof(struct nfsv3_read_reply));
		print(1, ctx, "READ %s: %u bytes at offset 0x%lu (tot=%u)\n", 
			argv[1], args.count, args.offset, tot);

		if (nfsv3_read(ctx, &args, &reply) < 0) {
			ret = -1;
			goto finished;
		}

		if (reply.buf != NULL) {
			free(reply.buf);
			reply.buf = NULL;
		}

		if (fwrite(reply.data, reply.len, 1, fp) != 1) {
			ret = -1;
			goto finished;
		}

		printf(".");
		fflush(stdout);

		off += args.count;
		tot += args.count;
	} while (reply.eof != 1);	

	printf("\n");
	print(0, ctx, "Wrote %lu bytes to %s\n", tot, argv[2]);

finished:
	if (fp != NULL)
		fclose(fp);

	if (reply.buf != NULL)
		free(reply.buf);

	return ret;
}


static int
cmd_cat(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfsv3_read_args args;
    struct nfsv3_read_reply reply;
    uint64_t off;
    uint64_t tot;
    int ret = 0;

    if (argc != 2) {
        errno = EINVAL;
        return -1;
    }
    memset(&args, 0x00, sizeof(struct nfsv3_read_args));

    /* FH */
    if ( (args.fhlen = str_hex2bin(argv[1], args.fh, sizeof(args.fh))) <= 0) {
        errno = EINVAL;
        return -1;
    }

    off = 0;
    tot = 0;

    do {
        args.offset = off;
        args.count = IOBUFSIZE;

        memset(&reply, 0x00, sizeof(struct nfsv3_read_reply));
        print(1, ctx, "READ %s: %u bytes at offset 0x%lu (tot=%u)\n",
            argv[1], args.count, args.offset, tot);

        if (nfsv3_read(ctx, &args, &reply) < 0) {
            ret = -1;
            goto finished;
        }

        if (reply.buf != NULL) {
            free(reply.buf);
            reply.buf = NULL;
        }

        if (fwrite(reply.data, reply.len, 1, stdout) != 1) {
            ret = -1;
            goto finished;
        }

        off += args.count;
        tot += args.count;
    } while (reply.eof != 1);

    printf("\n-- EOF\n");
    print(0, ctx, "Wrote %lu bytes\n", tot);

finished:
    if (reply.buf != NULL)
        free(reply.buf);

    return ret;
}


static int
cmd_rename(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfsv3_rename_args args;

    memset(&args, 0x00, sizeof(struct nfsv3_rename_args));

    if (argc != 5) {
        errno = EINVAL;
        return -1;
    }

    /* Src FH */
    if ( (args.srcfhlen = str_hex2bin(argv[1], args.srcfh, sizeof(args.srcfh))) <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* Src Name */
    if (strlen(argv[2]) > (sizeof(args.srcname)-1)) {
        print(0, ctx, "** Error: Name of directory too long, exceeds %u bytes\n", NAMEMAXLEN);
        errno = EINVAL;
        return -1;
    }
    snprintf(args.srcname, sizeof(args.srcname), "%s", argv[2]);

    /* Dest FH */
    if ( (args.dstfhlen = str_hex2bin(argv[3], args.dstfh, sizeof(args.dstfh))) <= 0) {
        errno = EINVAL;
        return -1;
    }
    
    /* Dest Name */
    if (strlen(argv[4]) > (sizeof(args.dstname)-1)) {
        print(0, ctx, "** Error: Name of directory too long, exceeds %u bytes\n", NAMEMAXLEN);
        errno = EINVAL;
        return -1;
    }
    snprintf(args.dstname, sizeof(args.dstname), "%s", argv[4]);

    return nfsv3_rename(ctx, &args);
}


static int
cmd_mkdir(struct nfsctx *ctx, int argc, char **argv)
{
	struct nfsv3_mkdir_args args;
	char *ep;

	memset(&args, 0x00, sizeof(struct nfsv3_mkdir_args));

    if (argc != 4) {
        errno = EINVAL;
        return -1;
    }

    /* FH */
    if ( (args.fhlen = str_hex2bin(argv[1], args.fh, sizeof(args.fh))) <= 0) {
        errno = EINVAL;
        return -1;
    }

	/* Name */
	if (strlen(argv[2]) > (sizeof(args.name)-1)) {
		print(0, ctx, "** Error: Name of directory too long, exceeds %u bytes\n", NAMEMAXLEN);
		errno = EINVAL;
		return -1;
	}
	snprintf(args.name, sizeof(args.name), "%s", argv[2]);
	
	/* Mode */
    args.mode = strtoul(argv[3], &ep, 0);
    if (*ep != '\0') {
        print(0, ctx, "** Error: Bad mode\n");
        errno = EINVAL;
        return -1;
    }

	return nfsv3_mkdir(ctx, &args);
}

static int
cmd_rmdir(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfsv3_rmdir_args args;

    memset(&args, 0x00, sizeof(struct nfsv3_rmdir_args));

    if (argc != 3) {
        errno = EINVAL;
        return -1;
    }

    /* FH */
    if ( (args.fhlen = str_hex2bin(argv[1], args.fh, sizeof(args.fh))) <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* Name */
    if (strlen(argv[2]) > (sizeof(args.name)-1)) {
        print(0, ctx, "** Error: Name of directory too long, exceeds %u bytes\n", NAMEMAXLEN);
        errno = EINVAL;
        return -1;
    }
    snprintf(args.name, sizeof(args.name), "%s", argv[2]);

    return nfsv3_rmdir(ctx, &args);
}

static int
cmd_create(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfsv3_create_args args;
    char *ep;

    memset(&args, 0x00, sizeof(struct nfsv3_create_args));

    if (argc != 4) {
        errno = EINVAL;
        return -1;
    }

    /* FH */
    if ( (args.fhlen = str_hex2bin(argv[1], args.fh, sizeof(args.fh))) <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* Name */
    if (strlen(argv[2]) > (sizeof(args.name)-1)) {
        print(0, ctx, "** Error: Name of directory too long, exceeds %u bytes\n", NAMEMAXLEN);
        errno = EINVAL;
        return -1;
    }
    snprintf(args.name, sizeof(args.name), "%s", argv[2]);

    /* Mode */
    args.mode = strtoul(argv[3], &ep, 0);
    if (*ep != '\0') {
        print(0, ctx, "** Error: Bad mode\n");
        errno = EINVAL;
        return -1;
    }

    if (nfsv3_create(ctx, &args) < 0)
		return -1;

	return 0;
}

static int
cmd_setattr(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfsv3_setattr_args args;
    char *ep;

    memset(&args, 0x00, sizeof(struct nfsv3_setattr_args));

    if (argc != 3) {
        errno = EINVAL;
        return -1;
    }

    /* FH */
    if ( (args.fhlen = str_hex2bin(argv[1], args.fh, sizeof(args.fh))) <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* Mode */
    args.mode = strtoul(argv[2], &ep, 0);
    if (*ep != '\0') {
        print(0, ctx, "** Error: Bad mode\n");
        errno = EINVAL;
        return -1;
    }

    return nfsv3_setattr(ctx, &args);
}

static int
cmd_remove(struct nfsctx *ctx, int argc, char **argv)
{
    struct nfsv3_remove_args args;

    memset(&args, 0x00, sizeof(struct nfsv3_remove_args));

    if (argc != 3) {
        errno = EINVAL;
        return -1;
    }

    /* FH */
    if ( (args.fhlen = str_hex2bin(argv[1], args.fh, sizeof(args.fh))) <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* Name */
    if (strlen(argv[2]) > (sizeof(args.name)-1)) {
        print(0, ctx, "** Error: Name of directory too long, exceeds %u bytes\n", NAMEMAXLEN);
        errno = EINVAL;
        return -1;
    }
    snprintf(args.name, sizeof(args.name), "%s", argv[2]);

    return nfsv3_remove(ctx, &args);
}


static int
cmd_write(struct nfsctx *ctx, int argc, char **argv)
{
	struct nfsv3_write_args args;
	size_t len;
	char *pt;
	int ret;

	ret = 0;

	memset(&args, 0x00, sizeof(struct nfsv3_write_args));

	if (argc < 4) {
		errno = EINVAL;
		return -1;
	}

    /* FH */
    if ( (args.fhlen = str_hex2bin(argv[1], args.fh, sizeof(args.fh))) <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* Offset */
    args.offset = strtoull(argv[2], &pt, 0);
    if (*pt != '\0') {
        print(0, ctx, "** Error: Bad offset\n");
        errno = EINVAL;
        return -1;
    }

	len = strlen(argv[3]);
	if ((len % 2) != 0) {
		print(0, ctx, "** Error: Data string in hex must be even in length\n");
        errno = EINVAL;
        return -1;
	}

	if (len > 1024*2) {
		print(0, ctx, "** Error: Maximum length of data is limited to 1024 bytes\n");
		errno = EINVAL;
		return -1;
	}

	if ( (args.data = malloc(len)) == NULL) {
		errno = ENOMEM;
		return -1;
	}

    /* Data */
    if ( (args.count = str_hex2bin(argv[3], args.data, len)) <= 0) {
        errno = EINVAL;
        ret = -1;
		goto finished;
	}


	if (nfsv3_write(ctx, &args) < 0) 
		ret = -1;

finished:
	if (args.data != NULL) {
		free(args.data);
		args.data = NULL;
	}

	return ret;
}

static int
cmd_read(struct nfsctx *ctx, int argc, char **argv)
{
	struct nfsv3_read_args args;
	struct nfsv3_read_reply reply;
	char *pt;
	size_t i;
	uint8_t print_raw = 0;
	int opt;

	memset(&args, 0x00, sizeof(struct nfsv3_read_args));
	memset(&reply, 0x00, sizeof(struct nfsv3_read_reply));

	if (argc < 4) {
		errno = EINVAL;
		return -1;
	}

	/* FH */
	if ( (args.fhlen = str_hex2bin(argv[1], args.fh, sizeof(args.fh))) <= 0) {
		errno = EINVAL;
		return -1;
	}

	/* Offset */
    args.offset = strtoull(argv[2], &pt, 0);
    if (*pt != '\0') {
		print(0, ctx, "** Error: Bad offset\n");
        errno = EINVAL;
        return -1;
    }

	/* Count */
    args.count = strtoul(argv[3], &pt, 0);
    if (*pt != '\0') {
		print(0, ctx, "** Error: Bad byte count\n");
        errno = EINVAL;
        return -1;
    }

	if (args.count > 32768) {
		print(0, ctx, "** Warning: Bytecount exceeds 32768, which seems to be a problem to decode for some servers\n");
	}

	while ( (opt = getopt(argc-3, &argv[3], "r")) != -1) {
		switch (opt) {
			case 'r':
				print_raw = 1;
				break;

			default:
				print(0, ctx, "** Error: Unknown option %c\n", optopt);
				errno = EINVAL;
				//goto error;
				break;
		}
	}

	if (nfsv3_read(ctx, &args, &reply) < 0)
		goto error;

	if (print_raw) {
		fwrite(reply.data, reply.len, 1, stdout);
		printf("\n");
		goto finished;	
	}


	/* Hexdump with ASCII in xxd style */
	i = 0;
	while (i < reply.len) {
		char hbuf[128];
		char pbuf[128];
		int out;

		/* Dump 16 characters at a time */
		out = 16;
		if ((reply.len - i) < 16)
			out = reply.len - i;


		if (str_hex(&reply.data[i], out, hbuf, sizeof(hbuf)) == NULL)
			goto error;

		if (str_printable(&reply.data[i], out, pbuf, sizeof(pbuf)) == NULL)
			goto error;

		printf("%08lx: %-32s  %s\n", i, hbuf, pbuf);
		i += 16;
	}
	
finished:
	if (reply.buf != NULL)
		free(reply.buf);

	return 0;

	error:
		if (reply.buf != NULL)
			free(reply.buf);
		return -1;
}

static int
cmd_readlink(struct nfsctx *ctx, int argc, char **argv)
{
    uint8_t fh[4096];
    int fhlen;

    if (argc < 2) {
        errno = EINVAL;
        return -1;
    }

    if ( (fhlen = str_hex2bin(argv[1], fh, sizeof(fh))) <= 0) {
        errno = EINVAL;
        return -1;
    }

    if (nfsv3_readlink(ctx, fh, fhlen) < 0)
        return -1;

    return 0;
}

static int
cmd_getattr(struct nfsctx *ctx, int argc, char **argv)
{
	struct entattr attr;
    uint8_t buf[4096];
    int fhlen;

    if (argc < 2) {
        errno = EINVAL;
        return -1;
    }

    if ( (fhlen = str_hex2bin(argv[1], buf, sizeof(buf))) <= 0) {
        errno = EINVAL;
        return -1;
    }

	memset(&attr, 0x00, sizeof(struct entattr));
    if (nfsv3_getattr(ctx, buf, fhlen, &attr) < 0) {
        return -1;
	}

	if (nfsv3_attrstr(ctx, &attr, 0x00, NULL, 
			(char *)buf, sizeof(buf)) == NULL) {
		return -1;
	}

	printf("%s\n", buf);

    return 0;
}


static int
cmd_readdir(struct nfsctx *ctx, int argc, char **argv)
{
    uint8_t fh[4096];
    uint32_t opts;
    int fhlen;
    int opt;

    opts = 0;

    if (argc < 2) {
        errno = EINVAL;
        return -1;
    }

    if ( (fhlen = str_hex2bin(argv[1], fh, sizeof(fh))) <= 0) {
        errno = EINVAL;
        return -1;
    }

    while ( (opt = getopt(argc-1, &argv[1], "l")) != -1) {
        switch (opt) {
            case 'l':
                opts = opts | READDIR_OPT_LONG;
                break;

            default:
            printf("ERROR: %c\n", opt);
                errno = EINVAL;
                return -1;
        }
    }

    if (nfsv3_readdir(ctx, opts, fh, fhlen) < 0)
        return -1;

    return 0;
}


static int
cmd_readdirplus(struct nfsctx *ctx, int argc, char **argv)
{
	uint8_t fh[4096];
	uint32_t opts;
	int fhlen;
	int opt;

	opts = 0;

	if (argc < 2) {
		errno = EINVAL;
		return -1;
	}

	if ( (fhlen = str_hex2bin(argv[1], fh, sizeof(fh))) <= 0) {
		errno = EINVAL;
		return -1;
	}

	while ( (opt = getopt(argc-1, &argv[1], "lc")) != -1) {
		switch (opt) {
			case 'c':
				opts = opts | READDIRPLUS_OPT_COLORS;
				break;

			case 'l':
				opts = opts | READDIRPLUS_OPT_LONG;
				break;

			default:
			printf("ERROR: %c\n", opt);
				errno = EINVAL;
				return -1;
		}
	}

	if (nfsv3_readdirplus(ctx, opts, fh, fhlen) < 0)
		return -1;

	return 0;
}

static int
cmd_exports(struct nfsctx *ctx, int argc, char **argv)
{
	struct export_reply *xpl;

	if (ctx->port_mountd == 0) {
		fprintf(stderr, "** Error: No port for mount service set, perhaps run 'getport mount'?\n");
		errno = EINVAL;
		return -1;
	}

	if (mount_export(ctx, &xpl) < 0)
		return -1;

#define TABALIGN    48
	while (xpl != NULL) {
		size_t tablen;

		struct export_reply *tmp;
		
		printf("%s ", xpl->name);
		for (tablen=strlen(xpl->name); tablen < TABALIGN; tablen++)
			printf("_");
		printf(" %s\n", xpl->group);

		tmp = xpl->next;
		free(xpl);
		xpl = tmp;
	}

	return 0;
}

static int
cmd_dump(struct nfsctx *ctx, int argc, char **argv)
{
	return mount_dump(ctx);
}

static int
cmd_umntall(struct nfsctx *ctx, int argc, char **argv)
{
	return mount_umntall(ctx);
}

static int
cmd_getfh(struct nfsctx *ctx, int argc, char **argv)
{

	if (cmd_mnt(ctx, argc, argv) != 0)
		return -1;

	if (cmd_umntall(ctx, argc, argv) != 0)
		return -1;

	return 0;
}

static int
cmd_mnt(struct nfsctx *ctx, int argc, char **argv)
{
	char hex[1024];
	uint8_t *fh;
	int fhlen;

	if (ctx->port_mountd == 0) {
		fprintf(stderr, "** Error: No port for mount service set, perhaps run 'getport mount'?\n");
		errno = EINVAL;
		return -1;
	}

	/* list all mounts */
	if (argc == 1) {
		return 0;
	}

	if (argc != 2) {
		errno = EINVAL;
		return -1;
	}

	if ( (fhlen = mount_mount(ctx, argv[1], &fh)) < 0)
		return -1;

	str_hex(fh, fhlen, hex, sizeof(hex));
	print(0, ctx, "Received %u bytes fh for '%s': %s\n",
		fhlen, argv[1], hex);

	free(fh);
	return 0;
}

static int
cmd_set_uid(struct nfsctx *ctx, int argc, char **argv)
{
	uint32_t uid;
	char *ep;

    if (argc != 2) {
        errno = EINVAL;
        return -1;
    }

	uid = strtoul(argv[1], &ep, 0);
	if (*ep != '\0') {
		errno = EINVAL;
		return -1;
	}

	ctx->uid = uid;
    return 0;
}

static int
cmd_set_verbose(struct nfsctx *ctx, int argc, char **argv)
{
    uint32_t lvl;
    char *ep;

    if (argc != 2) {
        errno = EINVAL;
        return -1;
    }

    lvl = strtoul(argv[1], &ep, 0);
    if (*ep != '\0') {
        errno = EINVAL;
        return -1;
    }

    ctx->verbose = lvl;
    return 0;
}


static int
cmd_set_gid(struct nfsctx *ctx, int argc, char **argv)
{
    uint32_t gid;
    char *ep;

    if (argc != 2) {
        errno = EINVAL;
        return -1;
    }

    gid = strtoul(argv[1], &ep, 0);
    if (*ep != '\0') {
        errno = EINVAL;
        return -1;
    }

    ctx->gid = gid;
    return 0;
}


static int
cmd_getport(struct nfsctx *ctx, int argc, char **argv)
{
	if (argc != 2) {
		errno = EINVAL;
		goto error;
	}

	/* Resolve port for NFS service */
	if (strcmp(argv[1], "nfs") == 0) {
		int port;
		if ( (port = portmap_getport_nfsd(ctx)) > 0) {
			print(0, ctx, "Resolved NFS port to %d\n", ntohs(port));
			ctx->port_nfsd = port;
		}
	}

	/* Resolve port for mount service */
	else if (strcmp(argv[1], "mount") == 0) {
		int port;
		if ( (port = portmap_getport_mountd(ctx)) > 0) {
			print(0, ctx, "Resolved mount port to %d\n", ntohs(port));
			ctx->port_mountd = port;
		}
		else {
			goto error;
		}
	}
	else  {
		errno = EINVAL;
		goto error;
	}

	return 0;

error:
	return -1;
}

/*
 * Execute command.
 */
static int
cmd_execute(struct nfsctx *ctx, int argc, char **argv)
{
	int i;

	/* Find command */
	for (i=0; cmds[i].name != NULL; i++) {

		if (!strcmp(argv[0], cmds[i].name)) {
			/* Prepare for getopt(3) */
			optind = 1;

			if (cmds[i].func == NULL) {
				printf("**** Error: No handler set for command '%s'\n", cmds[i].name);
				return -1;
			}
			else {
				if (cmds[i].func(ctx, argc, argv) < 0) {
					printf("**** Command %s failed, run 'help <cmd>' for help: %s\n", cmds[i].name, strerror(errno));
					return -1;
				}

				break;
			}
		}
	}

	if (cmds[i].name == NULL) {
		printf("**** Unknown command '%s', type 'help' for help\n", argv[0]);
		return -1;
	}

	return 0;
}

/*
 * Read line into buffer which must have at least NFSH_MAXLINE bytes.
 */ 
char *
readln(char *prompt, char *buf, size_t buflen)
{
#ifndef NO_READLINE 
        char *input = NULL;
#endif

	memset(buf, 0x00, buflen);

#ifndef NO_READLINE 
        if ( (input = readline(prompt)) == NULL)
            return NULL;
        
        snprintf(buf, buflen-1, "%s", input);
		free(input);
#else   
        printf("%s", prompt);
        fflush(stdout);
        if (fgets(buf, buflen-1, stdin) == NULL)
            return NULL;
        
        if (buf[strlen(buf)-1] == '\n')
            buf[strlen(buf)-1] = '\0';
        if (buf[strlen(buf)-1] == '\r')
            buf[strlen(buf)-1] = '\0';
#endif
	
	return buf;
}


/*
 * NFS Client shell
 */
int
nfsh(struct nfsctx *ctx)
{
	char prompt[64];

    /* Sort commands */
    qsort(cmds, sizeof(cmds) / sizeof(struct cmd) -1,
        sizeof(struct cmd), cmdcmp);

    /* Init libreadline */
#ifndef NO_READLINE
    using_history();
    stifle_history(1024);
#endif

	if (ctx->sip != NULL) {
		snprintf(prompt, sizeof(prompt), "nfsh [SPOOFING %s] %s> ", ctx->sip, ctx->server);
	}
	else {
		snprintf(prompt, sizeof(prompt), "nfsh %s> ", ctx->server);
	}

	for (;;) {
		char buf[NFSH_MAXLINE];
		char *cmd;

		if (ctx->exec != NULL) {
			if (strlen(ctx->exec) > NFSH_MAXLINE) {
				fprintf(stderr, "String of commands exceeds maximum length\n");
				return -1;
			}
			snprintf(buf, sizeof(buf), "%s", ctx->exec);
			free(ctx->exec);
			ctx->exec = NULL;
		}

		/* Read a line */
		else if (readln(prompt, buf, sizeof(buf)) == NULL)
			continue;

	

#ifndef NO_READLINE
		if (buf[0] != '\0') {
			add_history(buf);
		}
#endif

		/* Run all commands separated by semicolon */
		cmd = strtok(buf, ";");
		while (cmd != NULL) {
			char *argv[NFSH_MAXARGS];
			int argc;

			memset(argv, 0x00, sizeof(argv));
        	argc = str_to_argv(cmd, argv, (sizeof(argv)/sizeof(char *))-1);

        	if (argc == 0)
				continue;

        	if (!strcmp(argv[0], "quit")) {
            	printf("Bye, bye\n");
           		return 0;
        	}

			cmd_execute(ctx, argc, argv);
			cmd = strtok(NULL, ";");
		}
	}


	return 0;
}
