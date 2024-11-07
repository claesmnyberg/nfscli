
/*
 * Copyright (C)  2023-2024 Claes M Nyberg <cmn@signedness.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *	must display the following acknowledgement:
 *	  This product includes software developed by Claes M Nyberg.
 * 4. The name Claes M Nyberg may not be used to endorse or promote
 *	products derived from this software without specific prior written
 *	permission.
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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "nfscli.h"

#define TABALIGN	32

/*
 * Convert RPC error to string
 */
char *
rpc_exec_errstr(int err)
{
	switch (err) {
		case RPC_EXEC_SUCCESS: return(""); break;
		case RPC_ERR_PROG_UNAVAIL: return("Program not available"); break;
		case RPC_ERR_PROG_MISMATCH: return("Unsupported version"); break;
		case RPC_ERR_PROG_NOTSUPP: return("Procedure not supported"); break;
		case RPC_ERR_PROG_DECODE: return("Can not decode params"); break;
		case RPC_ERR_PROG_MEM: return("Memory allocation failure"); break;
	}

	return "Unknown";
}


/*
 * Convert NFSV3 error to errno
 */
static int 
nfsv3_err2errno(int err)
{
	switch (err) {
		case NFSV3ERR_PERM:	return EPERM;
		case NFSV3ERR_NOENT: return ENOENT;
		case NFSV3ERR_IO: return EIO;
		case NFSV3ERR_NXIO: return ENXIO;
		case NFSV3ERR_ACCESS: return EACCES;
		case NFSV3ERR_EXIST: return EEXIST;
		case NFSV3ERR_XDEV: return EXDEV;
		case NFSV3ERR_NODEV: return ENODEV;
		case NFSV3ERR_NOTDIR: return ENOTDIR;
		case NFSV3ERR_ISDIR: return EISDIR;
		case NFSV3ERR_INVAL: return EINVAL;
		case NFSV3ERR_FBIG: return EFBIG;
		case NFSV3ERR_NOSPC: return ENOSPC;
		case NFSV3ERR_ROFS: return EROFS;
		case NFS3VERR_MLINK: return EMLINK;
		case NFS3VERR_NAMETOOLONG: return ENAMETOOLONG;
		case NFS3VERR_NOTEMPTY: return ENOTEMPTY;
		case NFS3VERR_DQUOT: return EDQUOT;
		case NFS3VERR_STALE: return ESTALE;
		case NFS3VERR_BADHANDLE: return EBADF;
#ifndef __FreeBSD__
		case NFS3VERR_NOT_SYNC: return EL2NSYNC;
#endif
		case NFS3VERR_BAD_COOKIE: return ESTALE;
		case NFS3VERR_NOTSUPP: return ENOTSUP;
		case NFS3VERR_TOOSMALL: return ENOBUFS;
		case NFS3VERR_SERVERFAULT: return ECANCELED;
#ifndef __FreeBSD__
		case NFS3VERR_BADTYPE: return EMEDIUMTYPE;
#endif
		case NFS3VERR_JUKEBOX: return ECANCELED;
	}
	return 0;
}

/*
 * Convert NFSV3 error to string
 */
const char *
nfsv3_errstr(int err)
{
	switch (err) {
		case NFSV3ERR_PERM: return "Not owner";
		case NFSV3ERR_NOENT: return "No such file or directory";
		case NFSV3ERR_IO: return "A hard error occurred when the operation was in progress";
		case NFSV3ERR_NXIO: return "No such device or address";
		case NFSV3ERR_ACCESS: return "Permission denied";
		case NFSV3ERR_EXIST: return "File exists";
		case NFSV3ERR_XDEV: return "Attempt to do an operation across the file system";
		case NFSV3ERR_NODEV: return "No such device";
		case NFSV3ERR_NOTDIR: return "Not a directory";
		case NFSV3ERR_ISDIR: return "Is a director";
		case NFSV3ERR_INVAL: return "Invalid argument";
		case NFSV3ERR_FBIG: return "File too large";
		case NFSV3ERR_NOSPC: return "No space left on device";
		case NFSV3ERR_ROFS: return "Read-only file system";
		case NFS3VERR_MLINK: return "Too many links";
		case NFS3VERR_NAMETOOLONG: return "File name too long";
		case NFS3VERR_NOTEMPTY: return "Directory not empty";
		case NFS3VERR_DQUOT: return "Disk quota exceeded";
		case NFS3VERR_STALE: return "The file handle given in the arguments is no longer valid";
		case NFS3VERR_BADHANDLE: return "File handle is not valid";
		case NFS3VERR_NOT_SYNC: return "Synchronization mismatch on SETATTR"; 
		case NFS3VERR_BAD_COOKIE: return "READDIR and READDIRPLUS cookie is stale"; 
		case NFS3VERR_NOTSUPP: return "Operation is not supported.";
		case NFS3VERR_TOOSMALL: return "Buffer or request is too small";
		case NFS3VERR_SERVERFAULT: return "Server abandons the request";
		case NFS3VERR_BADTYPE: return "Type of an object is not supported";
		case NFS3VERR_JUKEBOX: return "Request was initiated, but not completed";
	}
	return "Unknown";
}


/*
 * Rewrite filenames using ANSI escape sequences 
 * Returns the number of escape characters on success 
 */
#include "ansicolors.h"
int
ansi_highlight_filename(int colors, struct entattr *attr, char *name, char *buf, uint32_t buflen)
{
	char *clr = "";

	if (colors == 0) {
		snprintf(buf, buflen, "%s", name);
		return 0;
	}

	if (strcmp(name, "shadow") == 0) 
		clr = COLOR_BRED;
	else if (strcmp(name, "passwd") == 0) 
		clr = COLOR_BRED;
	else if (strcmp(name, "master.passwd") == 0) 
		clr = COLOR_BRED;
	else if (strcmp(name, "authorized_keys") == 0) 
		clr = COLOR_BRED;
	else if (strstr(name, "secret") != 0)
		clr = COLOR_BRED;
	else if (strstr(name, "password") != 0)
		clr = COLOR_BRED;
	else if (strstr(name, "id_rsa") != 0)
		clr = COLOR_BRED;
	else if (strstr(name, "id_ed") != 0)
		clr = COLOR_BRED;
	
	if (attr != NULL) {

		/* File type */
		switch (ntohl(attr->type)) {
			case 1: /* Regular File */
				
				/* Executable file */
				if (attr->mode & 64)
					clr = COLOR_BGREEN;
				if (attr->mode & 8)
					clr = COLOR_BGREEN;
				if (attr->mode & 1)
					clr = COLOR_BGREEN;
				
				/* Setuid */
				if (attr->mode & 2048)
					clr = COLOR_GREENB;
				if (attr->mode & 1024)
					clr = COLOR_GREENB;
				break; 

			case 2: clr = COLOR_BBLUE; break;  /* d */
			case 3: ; break;  /* b */
			case 4: ; break;  /* c */
			case 5: clr = COLOR_BMAGENTA; break;  /* l */
			case 6: ; break;  /* s */
		}
	}

	snprintf(buf, buflen, "%s%s%s", clr, name, clr[0] ? COLOR_RESET : "");
	return (strlen(buf) - strlen(name));
}

/*
 * Create attribute string
 * Returns a pointer to buffer on success, NULL on error.
 */
char *
nfsv3_attrstr(struct nfsctx *ctx, struct entattr *attr, 
	uint32_t opts, char *name, char *buf, size_t buflen)
{
	char tmp[512];
	char tmp2[64];
	size_t i;

	i = 0;
	memset(buf, 0x00, buflen);

	/* Type */
	switch (ntohl(attr->type)) {
		case 1: buf[i] = '-'; break;
		case 2: buf[i] = 'd'; break;
		case 3: buf[i] = 'b'; break;
		case 4: buf[i] = 'c'; break;
		case 5: buf[i] = 'l'; break;
		case 6: buf[i] = 's'; break;

		default:
			buf[i] = '?';
			break;
	}
	i++;

	if (i >= buflen)
		goto truncated;

	/* Permissions */
	if ( (i+12) > buflen)
		goto truncated;

	attr->mode = ntohl(attr->mode);

	/* Owner */
	buf[i++] = (attr->mode & 256) ? 'r' : '-';
	buf[i++] = (attr->mode & 128) ? 'w' : '-';
	if (attr->mode & 2048)
		buf[i++] = (attr->mode & 64) ? 's' : 'S';
	else 
		buf[i++] = (attr->mode & 64) ? 'x' : '-';

   /* Group */
   buf[i++] = (attr->mode & 32) ? 'r' : '-';
   buf[i++] = (attr->mode & 16) ? 'w' : '-';
   if (attr->mode & 1024)
		buf[i++] = (attr->mode & 8) ? 's' : 'S';
   else
	   buf[i++] = (attr->mode & 8) ? 'x' : '-';

	/* World */
	buf[i++] = (attr->mode & 4) ? 'r' : '-';
	buf[i++] = (attr->mode & 2) ? 'w' : '-';
	if (attr->mode & 512)
		buf[i++] = (attr->mode & 1) ? 't' : 'T';
	else
		buf[i++] = (attr->mode & 1) ? 'x' : '-';
	
	/* Number of links */
	attr->nlink = ntohl(attr->nlink);
	snprintf(tmp, sizeof(tmp), "%4u ",	attr->nlink);
	if ( (i + strlen(tmp)) >= buflen)
		goto truncated;

	memcpy(&buf[i], tmp, strlen(tmp));
	i += strlen(tmp);

	/* UID, GID */
	snprintf(tmp, sizeof(tmp), "  %-4u %-4u ", ntohl(attr->uid), ntohl(attr->gid));
	if ( (i + strlen(tmp)) >= buflen)
		goto truncated;
	
	memcpy(&buf[i], tmp, strlen(tmp));
	i += strlen(tmp);

	/* Size */
	snprintf(tmp, sizeof(tmp), "%6s  ",  str_hsize(be64toh(attr->size)));
	if ( (i + strlen(tmp)) >= buflen)
		goto truncated;

	memcpy(&buf[i], tmp, strlen(tmp));
	i += strlen(tmp);

	/* atime */
	if (opts & ATTRSTR_LONG) {
		str_time(tmp2, sizeof(tmp2), ntohl(attr->atime.secs));
		snprintf(tmp, sizeof(tmp), " ATIME:%s MTIME:", tmp2);

		if ( (i + strlen(tmp)) >= buflen)
			goto truncated;

		memcpy(&buf[i], tmp, strlen(tmp));
		i += strlen(tmp);
	}

	/* mtime */
	str_time(tmp2, sizeof(tmp2), ntohl(attr->mtime.secs));
	snprintf(tmp, sizeof(tmp), "%s ", tmp2);

	if ( (i + strlen(tmp)) >= buflen)
		goto truncated;

	memcpy(&buf[i], tmp, strlen(tmp));
	i += strlen(tmp);


	/* ctime */
	if (opts & ATTRSTR_LONG) {
		str_time(tmp2, sizeof(tmp2), ntohl(attr->ctime.secs));
		snprintf(tmp, sizeof(tmp), "CTIME:%s ", tmp2);

		if ( (i + strlen(tmp)) >= buflen)
			goto truncated;

		memcpy(&buf[i], tmp, strlen(tmp));
		i += strlen(tmp);
	}

	/* Name */
	if (name != NULL) {
		int len;
		char nametmp[256];
		int escapechars = 0;

#define NAMEALIGN 32

		escapechars = ansi_highlight_filename(opts & ATTRSTR_COLORS, 
			attr, name, nametmp, sizeof(nametmp));	

		memset(tmp, 0x00, sizeof(tmp));
		snprintf(tmp, sizeof(tmp)-NAMEALIGN, " %s ", nametmp);
		len = strlen(tmp);
		while (len < NAMEALIGN + escapechars) {
			tmp[len] = '_';
			len++;
		}

		tmp[len++] = ' ';
		tmp[len] = '\0';

		if ( (i + strlen(tmp)) >= buflen)
			goto truncated;

		memcpy(&buf[i], tmp, strlen(tmp));
		i += strlen(tmp);
	}

	if (opts & ATTRSTR_LONG) {
		snprintf(tmp, sizeof(tmp), " FSID:0x%lx FID:0x%-8lx", 
			be64toh(attr->fsid), be64toh(attr->fid));
	
		if ( (i + strlen(tmp)) >= buflen)
			goto truncated;

		memcpy(&buf[i], tmp, strlen(tmp));
		i += strlen(tmp);
	}

finished:
	return buf;

truncated:
	print(0, ctx, "** Warning, output truncated due to small buffer");
	goto finished;
}

/*
 * do GETATTR
 */
int
nfsv3_getattr(struct nfsctx *ctx, uint8_t *fhandle, uint32_t fhlen, struct entattr *save)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;
	uint8_t buf[8192];
	size_t totlen;
	uint8_t *pt;
	ssize_t n;
	uint32_t xid;

	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr);
	totlen += 4 + ALIGN(fhlen, 4);

	if (totlen > sizeof(buf)) {
		fprintf(stderr, "** Error: total length exceeds buffer\n");
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_GETATTR);
	pt = buf + sizeof(struct rpc_call_hdr);

	/* File handle */
	*(uint32_t *)pt = htonl(fhlen);
	pt += 4;
	memcpy(pt, fhandle, fhlen);
	pt += ALIGN(fhlen, 4);

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, buf, totlen) < 0) {
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}

	reply = (struct rpc_nfsreply_hdr *)buf;
	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));
	pt = buf + sizeof(struct rpc_nfsreply_hdr);

	if ((pt + sizeof(struct entattr)) > &buf[n]) {
		fprintf(stderr, "** Error: Response data exceeds length of read data\n");
		return -1;
	}

	memcpy(save, pt, sizeof(struct entattr));
	return 0;
}


/*
 * do LOOKUP
 * Returns the length of the looked up file handle on succes,
 * and -1 on error. 
 */
int
nfsv3_lookup(struct nfsctx *ctx, uint8_t *fhandle, 
	uint32_t fhlen, char *name, struct lookup_ret *save)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;
	uint32_t value_follows;
	uint8_t buf[8192];
	size_t totlen;
	uint8_t *pt;
	ssize_t n;
	uint32_t len;
	uint32_t xid;

	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr);
	totlen += 4 + ALIGN(fhlen, 4);
	totlen += 4 + ALIGN(strlen(name), 4);

	if (totlen > sizeof(buf)) {
		fprintf(stderr, "** Error: total length exceeds buffer\n");
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_LOOKUP);
	pt = buf + sizeof(struct rpc_call_hdr);

	/* File handle */
	*(uint32_t *)pt = htonl(fhlen);
	pt += 4;
	memcpy(pt, fhandle, fhlen);
	pt += ALIGN(fhlen, 4);

	if (strlen(name) > NAMEMAXLEN) {
		print(0, ctx, "** Error: name exceeds %u bytes\n", NAMEMAXLEN);
		errno = ENOBUFS;
		return -1;
	}

	/* Name */
	*(uint32_t *)pt = htonl(strlen(name));
	pt += 4;
	memcpy(pt, name, strlen(name));
	pt += ALIGN(strlen(name), 4);

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, buf, totlen) < 0) {
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}

	reply = (struct rpc_nfsreply_hdr *)buf;
	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));

	pt = buf + sizeof(struct rpc_nfsreply_hdr);
	len = ntohl(*(uint32_t *)pt);
	pt += 4;

	if ((pt + len) > &buf[n]) {
		fprintf(stderr, "** Error: Length exceeds reply buffer\n");
		return -1;
	}

	if (len > sizeof(save->fh)) {
		fprintf(stderr, "** Error: FH Length exceeds save buffer\n");
		return -1;
	}

	memcpy(save->fh, pt, len);
	save->fhlen = len;
	pt += ALIGN(len, 4);

	/* Object attributes */
	value_follows = ntohl(*(uint32_t *)pt);
	pt += 4;
	if (value_follows == 1) {
		if ((pt + sizeof(struct entattr)) > &buf[n]) {
			fprintf(stderr, "** Error: Response data exceeds length of read data\n");
			return -1;
		}
		memcpy(&save->obj_attr, pt, sizeof(struct entattr));
	}

	/* Directory attributes */
	value_follows = ntohl(*(uint32_t *)pt);
	pt += 4;
	if (value_follows == 1) {
		if ((pt + sizeof(struct entattr)) > &buf[n]) {
			fprintf(stderr, "** Error: Response data exceeds length of read data\n");
			return -1;
		}
		memcpy(&save->dir_attr, pt, sizeof(struct entattr));
	}

	return 0;
}


/*
 * Do RENAME
 */
int
nfsv3_rename(struct nfsctx *ctx, struct nfsv3_rename_args *args)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;
	uint8_t buf[8192];
	size_t totlen;
	uint32_t *len;
	uint8_t *pt;
	ssize_t n;
	uint32_t xid;

	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr);
	totlen += 4 + args->srcfhlen;
	totlen += 4 + ALIGN(strlen(args->srcname), 4);
	totlen += 4 + args->dstfhlen;
	totlen += 4 + ALIGN(strlen(args->dstname), 4);
	totlen = ALIGN(totlen, 4);

	if (totlen > sizeof(buf)) {
		fprintf(stderr, "** Error: total length exceeds buffer\n");
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_RENAME);
	pt = buf + sizeof(struct rpc_call_hdr);

	if (strlen(args->srcname) > NAMEMAXLEN) {
		print(0, ctx, "** Error: src name exceeds %s bytes\n", NAMEMAXLEN);
		errno = ENOBUFS;
		return -1;
	}

	if (strlen(args->dstname) > NAMEMAXLEN) {
		print(0, ctx, "** Error: dst name exceeds %s bytes\n", NAMEMAXLEN);
		errno = ENOBUFS;
		return -1;
	}

	/* Src dir fh */
	len = (uint32_t *)pt;
	*len = htonl(ALIGN(args->srcfhlen, 4));
	pt += 4;
	memcpy(pt, args->srcfh, args->srcfhlen);
	pt += ALIGN(args->srcfhlen, 4);

	/* Src dir file name */
	len = (uint32_t *)pt;
	*len = htonl(strlen(args->srcname));
	pt += 4;
	memcpy(pt, args->srcname, strlen(args->srcname));
	pt += ALIGN(strlen(args->srcname), 4);

	/* Dest dir fh */
	len = (uint32_t *)pt;
	*len = htonl(ALIGN(args->dstfhlen, 4));
	pt += 4;
	memcpy(pt, args->dstfh, args->dstfhlen);
	pt += ALIGN(args->dstfhlen, 4);

	/* Dest dir filename */
	len = (uint32_t *)pt;
	*len = htonl(strlen(args->dstname));
	pt += 4;
	memcpy(pt, args->dstname, strlen(args->dstname));
	pt += ALIGN(strlen(args->dstname), 4);

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, buf, totlen) < 0) {
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}

	reply = (struct rpc_nfsreply_hdr *)buf;
	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));

	return 0;
}


/*
 * Do RMDIR
 */
int
nfsv3_rmdir(struct nfsctx *ctx, struct nfsv3_rmdir_args *args)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;
	uint8_t buf[8192];
	size_t totlen;
	uint8_t *pt;	
	ssize_t n;
	uint32_t xid;

	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr);
	totlen += 4 + ALIGN(args->fhlen, 4);
	totlen += 4 + ALIGN(strlen(args->name), 4);

	if (totlen > sizeof(buf)) {
		fprintf(stderr, "** Error: total length exceeds buffer\n");
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_RMDIR);
	pt = buf + sizeof(struct rpc_call_hdr);

	/* File handle */
	*(uint32_t *)pt = htonl(args->fhlen);
	pt += 4;
	memcpy(pt, args->fh, args->fhlen);
	pt += ALIGN(args->fhlen, 4);

	if (strlen(args->name) > NAMEMAXLEN) {
		print(0, ctx, "** Error: name exceeds %u bytes\n", NAMEMAXLEN);
		errno = ENOBUFS;
		return -1;
	}

	/* Name */
	*(uint32_t *)pt = htonl(strlen(args->name));
	pt += 4;
	memcpy(pt, args->name, strlen(args->name));
	pt += ALIGN(strlen(args->name), 4);

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, buf, totlen) < 0) {
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}

	reply = (struct rpc_nfsreply_hdr *)buf;
	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));

	return 0;
}

/*
 * Do CREATE
 */
int
nfsv3_create(struct nfsctx *ctx, struct nfsv3_create_args *args)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;
	struct setattr *attr;
	uint32_t value_follows;
	uint8_t buf[8192];
	size_t totlen;
	uint8_t *pt;	
	ssize_t n;
	uint32_t xid;

	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr);
	totlen += 4 + ALIGN(args->fhlen, 4);
	totlen += 4 + ALIGN(strlen(args->name), 4);
	totlen += 4;
	totlen += sizeof(struct setattr);

	if (totlen > sizeof(buf)) {
		fprintf(stderr, "** Error: total length exceeds buffer\n");
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_CREATE);
	pt = buf + sizeof(struct rpc_call_hdr);

	/* File handle */
	*(uint32_t *)pt = htonl(args->fhlen);
	pt += 4;
	memcpy(pt, args->fh, args->fhlen);
	pt += ALIGN(args->fhlen, 4);

	if (strlen(args->name) > NAMEMAXLEN) {
		print(0, ctx, "** Error: name exceeds %u bytes\n", NAMEMAXLEN);
		errno = ENOBUFS;
		return -1;
	}

	/* Name */
	*(uint32_t *)pt = htonl(strlen(args->name));
	pt += 4;
	memcpy(pt, args->name, strlen(args->name));
	pt += ALIGN(strlen(args->name), 4);

	/* Create mode 
	 *   0 == UNCHECKED
	 *   1 == GUARDED
	 *   2 == EXCLUSIVE
	 */
	*(uint32_t *)pt = htonl(1);
	pt += 4;

	/* Attributes, we just set mode for now */
	attr = (struct setattr *)pt;
	pt += sizeof(struct setattr);
	attr->mode_value_follows = htonl(1);
	attr->mode = htonl(args->mode);

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, buf, totlen) < 0) {
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}

	reply = (struct rpc_nfsreply_hdr *)buf;
	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));
	pt = buf + sizeof(struct rpc_nfsreply_hdr);
	value_follows = ntohl(*(uint32_t *)pt);
	pt += 4;

	/* File handle */
	if (value_follows == 1) {
		uint32_t len = ntohl(*(uint32_t *)pt);
		pt += 4;

		if (len > FHMAXLEN) {
			print(1, ctx, "** Error: Returned file handle length exceeds buffer size\n");
			return -1;
		}

		args->newfhlen = len;
		memcpy(args->newfh, pt, args->newfhlen);
		pt += ALIGN(args->newfhlen, 4);

		printf("Created FH: ");
		HEXDUMP(args->newfh, args->newfhlen);
	}

	/* Object attributes follow */
	/* dir_wcc follow */

	return 0;
}

/*
 * Do REMOVE
 */
int
nfsv3_remove(struct nfsctx *ctx, struct nfsv3_remove_args *args)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;
	uint8_t buf[8192];
	size_t totlen;
	uint8_t *pt;	
	ssize_t n;
	uint32_t xid;

	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr);
	totlen += 4 + ALIGN(args->fhlen, 4);
	totlen += 4 + ALIGN(strlen(args->name), 4);

	if (totlen > sizeof(buf)) {
		fprintf(stderr, "** Error: total length exceeds buffer\n");
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_REMOVE);
	pt = buf + sizeof(struct rpc_call_hdr);

	/* File handle */
	*(uint32_t *)pt = htonl(args->fhlen);
	pt += 4;
	memcpy(pt, args->fh, args->fhlen);
	pt += ALIGN(args->fhlen, 4);

	/* Name */
	if (strlen(args->name) > NAMEMAXLEN) {
		print(0, ctx, "** Error: name exceeds %s bytes\n", NAMEMAXLEN);
		errno = ENOBUFS;
		return -1;
	}
	*(uint32_t *)pt = htonl(strlen(args->name));
	pt += 4;
	memcpy(pt, args->name, strlen(args->name));
	pt += ALIGN(strlen(args->name), 4);

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, buf, totlen) < 0) {
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}

	reply = (struct rpc_nfsreply_hdr *)buf;
	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));

	return 0;
}

/*
 * Do SETATTR
 */
int
nfsv3_setattr(struct nfsctx *ctx, struct nfsv3_setattr_args *args)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;
	struct setattr *attr;
	uint8_t buf[8192];
	size_t totlen;
	uint8_t *pt;	
	ssize_t n;
	uint32_t xid;

	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr);
	totlen += 4 + ALIGN(args->fhlen, 4);
	totlen += sizeof(struct setattr);
	totlen += 4; /* Guard */

	if (totlen > sizeof(buf)) {
		fprintf(stderr, "** Error: total length exceeds buffer\n");
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_SETATTR);
	pt = buf + sizeof(struct rpc_call_hdr);

	/* File handle */
	*(uint32_t *)pt = htonl(args->fhlen);
	pt += 4;
	memcpy(pt, args->fh, args->fhlen);
	pt += ALIGN(args->fhlen, 4);
		
	/* Attributes, we just set mode for now */
	attr = (struct setattr *)pt;
	pt += sizeof(struct setattr);
	memset(attr, 0x00, sizeof(struct setattr));
	attr->mode_value_follows = htonl(1);
	attr->mode = htonl(args->mode);

	/* Guard */
	*(uint32_t *)pt = htonl(0);
	pt += 4;

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, buf, totlen) < 0) {
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}

	reply = (struct rpc_nfsreply_hdr *)buf;
	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));

	/* previous attributes follow */
	/* current attributes follow */

	return 0;
}

/*
 * Do MKDIR
 */
int
nfsv3_mkdir(struct nfsctx *ctx, struct nfsv3_mkdir_args *args)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;
	struct setattr *attr;
	uint8_t buf[8192];
	uint32_t value_follows;
	uint32_t len;
	size_t totlen;
	uint8_t *pt;	
	ssize_t n;
	uint32_t xid;

	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr);
	totlen += 4 + ALIGN(args->fhlen, 4);
	totlen += 4 + ALIGN(strlen(args->name), 4);
	totlen += sizeof(struct setattr);

	if (totlen > sizeof(buf)) {
		fprintf(stderr, "** Error: total length exceeds buffer\n");
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_MKDIR);
	pt = buf + sizeof(struct rpc_call_hdr);

	/* File handle */
	*(uint32_t *)pt = htonl(args->fhlen);
	pt += 4;
	memcpy(pt, args->fh, args->fhlen);
	pt += ALIGN(args->fhlen, 4);
	
	/* Name */
	if (strlen(args->name) > NAMEMAXLEN) {
		print(0, ctx, "** Error: name exceeds %s bytes\n", NAMEMAXLEN);
		errno = ENOBUFS;
		return -1;
	}
	*(uint32_t *)pt = htonl(strlen(args->name));
	pt += 4;
	memcpy(pt, args->name, strlen(args->name));
	pt += ALIGN(strlen(args->name), 4);

	/* Attributes, we just set mode for now */
	attr = (struct setattr *)pt;
	pt += sizeof(struct setattr);
	memset(attr, 0x00, sizeof(struct setattr));
	attr->mode_value_follows = htonl(1);
	attr->mode = htonl(args->mode);

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, buf, totlen) < 0) {
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}

	reply = (struct rpc_nfsreply_hdr *)buf;
	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));
	pt = buf + sizeof(struct rpc_nfsreply_hdr);
	value_follows = ntohl(*(uint32_t *)pt);
	pt += 4;

	/* File handle */
	if (value_follows == 1) {
		len = ntohl(*(uint32_t *)pt);
		pt += 4;
		printf("FH:");
		HEXDUMP(pt, len);
		pt += ALIGN(len, 4);
	}

	/* Object attributes follow */
	/* dir_wcc follow */

	return 0;
}

/*
 * Do WRITE
 */
int
nfsv3_write(struct nfsctx *ctx, struct nfsv3_write_args *args)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;
	uint8_t buf[4096];
	uint8_t *pt;
	size_t totlen;
	ssize_t n;

	struct write_call_footer {
		uint64_t offset;
		uint32_t count;
		uint32_t stable;

		uint32_t datalen; /* CHECK RFC, FUZZ: Must be same as count ? */
		/* Data goes here */
	} __attribute__((packed)) *footer;

	uint32_t xid;

	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr);
	totlen += 4 + ALIGN(args->fhlen, 4);
	totlen += sizeof(struct write_call_footer);
	totlen += ALIGN(args->count, 4);

	if (totlen > sizeof(buf)) {
		fprintf(stderr, "** Error: total length exceeds buffer\n");
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_WRITE);
	pt = buf + sizeof(struct rpc_call_hdr);

	/* File handle */
	*(uint32_t *)pt = htonl(args->fhlen);
	pt += 4;
	memcpy(pt, args->fh, args->fhlen);
	pt += ALIGN(args->fhlen, 4);
		
	footer = (struct write_call_footer *)pt;
	pt += sizeof(struct write_call_footer);

	footer->offset = htobe64(args->offset);
	footer->count = htonl(args->count);
	//footer->stable = htonl(0); /* 0 == UNSTABLE */
	//footer->stable = htonl(1); /* 1 == DATA_SYNC */
	footer->stable = htonl(2); /* 2 == FILE_SYNC, commit to storage before returning */
	footer->datalen = htonl(args->count);
	
	memcpy(pt, args->data, args->count);
	pt += ALIGN(args->count, 4);

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, (uint8_t *)buf, totlen) < 0) {
		return -1;
	}

	reply = (struct rpc_nfsreply_hdr *)buf;
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}

	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));
	pt = buf + sizeof(struct rpc_nfsreply_hdr);
	print(1, ctx, "Wrote %u bytes of data\n", args->count);

		/* Before and after attributes */
		/* Count */
		/* Comitted */
		/* Verifier */

	return 0;
}

/*
 * Do READ
 */
int
nfsv3_read(struct nfsctx *ctx, struct nfsv3_read_args *args, struct nfsv3_read_reply *ret)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;
	uint8_t buf[4096];
	uint32_t value_follows;
	uint8_t *pt;
	size_t totlen;
	ssize_t n;

	struct read_call_footer {
		uint64_t offset;
		uint32_t count;
	} __attribute__((packed)) *footer;


	uint32_t xid;
	uint32_t buflen;

	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr);
	totlen += 4 + ALIGN(args->fhlen, 4);
	totlen += sizeof(struct read_call_footer);

	if (totlen > sizeof(buf)) {
		printf("** Error: Fileheader exceeds buffer length\n");
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_READ);
	pt = buf + sizeof(struct rpc_call_hdr);

	/* File handle */
	*(uint32_t *)pt = htonl(args->fhlen);
	pt += 4;
	memcpy(pt, args->fh, args->fhlen);
	pt += ALIGN(args->fhlen, 4);

	footer = (struct read_call_footer *)pt;
	pt += sizeof(struct read_call_footer);
	footer->offset = htobe64(args->offset);
	footer->count = htonl(args->count);

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, (uint8_t *)buf, totlen) < 0) {
		return -1;
	}

	buflen = sizeof(struct rpc_nfsreply_hdr);
	buflen += ALIGN(args->count, 4) + sizeof(struct entattr);
	buflen += 1024;

	if ( (ret->buf = calloc(1, buflen)) == NULL) {
		errno = ENOMEM;
		return -1;
	}
	
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, ret->buf, buflen)) < 0) {
		return -1;
	}

	reply = (struct rpc_nfsreply_hdr *)ret->buf;
	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));
	pt = ret->buf + sizeof(struct rpc_nfsreply_hdr);

	value_follows = ntohl(*(uint32_t *)pt);
	pt += 4;

	/* Attributes */
	if (value_follows == 1) {
		pt += sizeof(struct entattr);
	}

	/* Count (same as len?) */
	pt += 4;

	/* eof */
	ret->eof = ntohl(*(uint32_t *)pt);
	pt += 4;

	/* len */
	ret->len = ntohl(*(uint32_t *)pt);
	pt += 4;

	/* data */
	ret->data = pt;
	pt += ALIGN(ret->len, 4);

	print(1, ctx, "Received %u bytes of data (EOF=%u)\n",
		ret->len, ret->eof);

	return 0;
}

/*
 * Do SYMLINK Call
 */
int
nfsv3_symlink(struct nfsctx *ctx, struct nfsv3_symlink_args *args)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;
	struct setattr *attr;
	uint8_t buf[IOBUFSIZE*2];
	uint8_t *pt;
	size_t totlen;
	uint32_t xid;
	ssize_t n;

	xid = rand(); 
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr); 
	totlen += 4 + ALIGN(args->fhlen, 4);
	totlen += 4 + ALIGN(strlen(args->name), 4);
	totlen += ALIGN(sizeof(struct entattr), 4);
	totlen += 4 + ALIGN(strlen(args->to), 4);

	if (totlen > sizeof(buf)) {
		fprintf(stderr, " ** Error: Total length exceeds buffer\n");
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_SYMLINK);
	pt = buf + sizeof(struct rpc_call_hdr);

	/* File handle for directory */
	*(uint32_t *)pt = htonl(args->fhlen);
	pt += 4;
	memcpy(pt, args->fh, args->fhlen);
	pt += ALIGN(args->fhlen, 4);

	/* Symbolic link name */ 
	*(uint32_t *)pt = htonl(strlen(args->name));
	pt += 4;
	memcpy(pt, args->name, strlen(args->name));
	pt += ALIGN(strlen(args->name), 4);

	/* Attributes */
	attr = (struct setattr *)pt;
	pt += sizeof(struct setattr);
	attr->mode_value_follows = htonl(1); 
	attr->mode = htonl(args->mode);

	/* To */ 
	*(uint32_t *)pt = htonl(strlen(args->to));
	pt += 4;
	memcpy(pt, args->to, strlen(args->to));
	pt += ALIGN(strlen(args->to), 4);

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, buf, totlen) < 0) {
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}
	reply = (struct rpc_nfsreply_hdr *)buf;
	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));
	pt = buf + sizeof(struct rpc_nfsreply_hdr);

	return 0;
}

/*
 * Do READLINK Call
 */
int
nfsv3_readlink(struct nfsctx *ctx, uint8_t *fh, uint32_t fhlen)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;
	//struct entattr *attr;
	uint32_t len;
	uint32_t data_follows;
	uint8_t buf[IOBUFSIZE*2];
	uint8_t *pt;
	size_t totlen;
	uint32_t xid;
	ssize_t n;

	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr);
	totlen += 4 + ALIGN(fhlen, 4);

	if (totlen > sizeof(buf)) {
		fprintf(stderr, " ** Error: Total length exceeds buffer\n");
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_READLINK);
	pt = buf + sizeof(struct rpc_call_hdr);

	/* File handle for symbolic link */
	*(uint32_t *)pt = htonl(fhlen);
	pt += 4;
	memcpy(pt, fh, fhlen);
	pt += ALIGN(fhlen, 4);

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, buf, totlen) < 0) {
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}
	reply = (struct rpc_nfsreply_hdr *)buf;
	RPC_CHECK_REPLY(reply, n);

	reply->status = ntohl(reply->status);
	if (reply->status != NFSV3_OK) {
		print(0, ctx, "** NFSV3 Error %d: %s\n", reply->status, nfsv3_errstr(reply->status));
		print(1, ctx, "** Error: %s\n", nfsv3_errstr(reply->status));
		errno = nfsv3_err2errno(reply->status);
		return -1;
	}

	/* Post operation attributes */
	pt = buf + sizeof(struct rpc_nfsreply_hdr);
	data_follows = ntohl(*(uint32_t *)pt);
	pt += 4;
	if (data_follows) {
		//attr = (struct entattr *)pt;
		pt += sizeof(struct entattr);
	}

	/* Link data */
	len = ntohl(*(uint32_t *)pt);
	pt += 4;

	if ( (pt + len) > &buf[n]) {
		print(0, ctx, "** Error: length (%x) exceeds reply size\n", len);
		return -1;
	}

	fwrite(pt, len, 1, stdout);
	printf("\n");
	return 0;
}


/*
 * Do LINK Call
 */
int
nfsv3_link(struct nfsctx *ctx, struct nfsv3_link_args *args)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;
	uint8_t buf[IOBUFSIZE*2];
	uint8_t *pt;
	size_t totlen;
	uint32_t xid;
	ssize_t n;

	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr); 
	totlen += 4 + ALIGN(args->fhlen, 4);
	totlen += 4 + ALIGN(args->dirfhlen, 4);
	totlen += 4 + ALIGN(strlen(args->name), 4);

	if (totlen > sizeof(buf)) {
		fprintf(stderr, " ** Error: Total length exceeds buffer\n");
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_LINK);
	pt = buf + sizeof(struct rpc_call_hdr);

	/* File handle for existing file */
	*(uint32_t *)pt = htonl(args->fhlen);
	pt += 4;
	memcpy(pt, args->fh, args->fhlen);
	pt += ALIGN(args->fhlen, 4);

	/* File handle for directory */
	*(uint32_t *)pt = htonl(args->dirfhlen);
	pt += 4;
	memcpy(pt, args->dirfh, args->dirfhlen);
	pt += ALIGN(args->dirfhlen, 4);

	/* File name */
	*(uint32_t *)pt = htonl(strlen(args->name));
	pt += 4;
	memcpy(pt, args->name, strlen(args->name));
	pt += ALIGN(strlen(args->name), 4);

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, buf, totlen) < 0) {
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}
	reply = (struct rpc_nfsreply_hdr *)buf;
	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));
	pt = buf + sizeof(struct rpc_nfsreply_hdr);

	return 0;
}



/*
 * Do READDIR Call
 */
int
nfsv3_readdir(struct nfsctx *ctx, uint32_t opts, uint8_t *fhandle, uint32_t fhlen)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;

	struct readdir_call_footer {
		uint64_t cookie;
		uint64_t cookieverf;
		uint32_t count;
	} __attribute__((packed)) *footer;

	uint8_t buf[IOBUFSIZE*2];
	size_t totlen;
	uint8_t *pt;
	uint32_t value_follows;
	uint64_t verifier;
	uint64_t cookie;
	uint32_t eof;
	uint32_t xid;
	uint64_t calls;
	uint64_t tot;
	ssize_t n;

	verifier = 0;
	cookie = 0;
	calls = 0;
	tot = 0;

call_again:
	calls++;
	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr);
	totlen += 4 + ALIGN(fhlen, 4);
	totlen += sizeof(struct readdir_call_footer);

	if (totlen > sizeof(buf)) {
		fprintf(stderr, " ** Error: Total length exceeds buffer\n");
		return -1;
	}
	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_READDIR);
	pt = buf + sizeof(struct rpc_call_hdr);


	/* File handle */
	*(uint32_t *)pt = htonl(fhlen);
	pt += 4;
	memcpy(pt, fhandle, fhlen);
	pt += ALIGN(fhlen, 4);

	print(1, ctx, "FH len: %u\n", fhlen);

	footer = (struct readdir_call_footer *)pt;
	pt += sizeof(struct readdir_call_footer);
	footer->cookie = cookie;
	footer->cookieverf = verifier;
	footer->count = htonl(IOBUFSIZE);

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, buf, totlen) < 0) {
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}
	reply = (struct rpc_nfsreply_hdr *)buf;
	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));
	pt = buf + sizeof(struct rpc_nfsreply_hdr);

	tot += n;
	print(1, ctx, "Read %lu bytes of data for READDIR reply\n", n);
	value_follows = ntohl(*(uint32_t *)pt);
	pt += 4;

	/* Dir attributes */
	if (value_follows) {
		//struct entattr *dirattr;	
		//dirattr = (struct entattr *)pt;
		pt += sizeof(struct entattr);
	}

	/* Prepare for next call */
	verifier = *(uint64_t *)pt;
	pt += 8;

	value_follows = ntohl(*(uint32_t *)pt);
	pt += 4;

	/* Traverse all entries */
	while (value_follows) {
		uint64_t fid;
		uint32_t len;
		char *name;

		fid = be64toh(*(uint64_t *)pt);
		pt += 8;

		len = ntohl(*(uint32_t *)pt);
		pt += 4;

		name = (char *)pt;
		pt += ALIGN(len, 4);

		printf("FID:%016lx ", fid);
		fwrite(name, len, 1, stdout);
		printf("\n");

		cookie = *(uint64_t *)pt;
		pt += 8;

		value_follows = ntohl(*(uint32_t *)pt);
		pt += 4;
	}

	eof = ntohl(*(uint32_t *)pt);
	pt += 4;

	/* Run another call to get the rest entries */
	if (eof != 1) {
		print(1, ctx, "EOF != 1, running call %lu\n", calls+1);
		goto call_again;
	}

	print(1, ctx, "Transfered %lu bytes in %lu calls\n", tot, calls);
	return 0;
}

/*
 * Do MKNOD Call for character och block device files
 */
int
nfsv3_mknod_dev(struct nfsctx *ctx, struct nfsv3_mknod_dev_args *args)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;
	struct setattr *attr;
	size_t totlen;
	uint8_t buf[IOBUFSIZE*2];
	uint32_t xid;
	uint8_t *pt;
	uint32_t *len;
	ssize_t n;

	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr);
	totlen += 4 + ALIGN(args->fhlen, 4);
	totlen += 4 + ALIGN(strlen(args->name), 4);
	totlen += 4;
	totlen += sizeof(struct setattr);
	totlen += 4 + 4; /* Major minor */

	if (totlen > sizeof(buf)) {
		fprintf(stderr, "** Error: total length exceeds buffer\n");
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_MKNOD);
	pt = buf + sizeof(struct rpc_call_hdr);

	if (strlen(args->name) > NAMEMAXLEN) {
		print(0, ctx, "** Error: src name exceeds %s bytes\n", NAMEMAXLEN);
		errno = ENOBUFS;
		return -1;
	}

	/* Directory fh */
	len = (uint32_t *)pt;
	*len = htonl(ALIGN(args->fhlen, 4));
	pt += 4;
	memcpy(pt, args->fh, args->fhlen);
	pt += ALIGN(args->fhlen, 4);

	/* Name */
	len = (uint32_t *)pt;
	*len = htonl(strlen(args->name));
	pt += 4;
	memcpy(pt, args->name, strlen(args->name));
	pt += ALIGN(strlen(args->name), 4);

	/* Type */
	*(uint32_t *)pt = htonl(args->type);
	pt += 4;

	/* Attributes, we just set mode for now */
	attr = (struct setattr *)pt;
	pt += sizeof(struct setattr);
	attr->mode_value_follows = htonl(1);
	attr->mode = htonl(args->mode);

	/* Major */
	*(uint32_t *)pt = htonl(args->major);
	pt += 4;

	/* Minor */
	*(uint32_t *)pt = htonl(args->minor);
	pt += 4;

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, buf, totlen) < 0) {
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}

	reply = (struct rpc_nfsreply_hdr *)buf;
	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));

	/* Attributes follow */

	return 0;
}

/*
 * Initialize a readdirplus call structure for subsequent queries that
 * will return next entry in directory.
 * Returns 0 on success, -1 on error.
 */
int
nfsv3_readdirplus_init(struct nfsctx *ctx, 
	uint8_t *fhandle, uint32_t fhlen, struct dirpluspt *dpt)
{
	memset(dpt, 0x00, sizeof(struct dirpluspt));
	dpt->cookie = 0;
	dpt->verifier = 0;

	if (fhlen > sizeof(dpt->fh)) {
		fprintf(stderr, "** Error: Target file handle buffer too small\n");
		errno = ENOMEM;
		return -1;
	}
	memcpy(dpt->fh, fhandle, fhlen);
	dpt->fhlen = fhlen;

	return 0;
}

/*
 * Read next directory plus entry.
 * Returns 0 and fills the ent structure on success, -1 on error.
 * Returns 1 on eof, if there are no more entries to read;
 */
int
nfsv3_readdirplus_next(struct nfsctx *ctx, struct dirpluspt *dpt, struct dirplusent *ent)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;
	uint8_t buf[IOBUFSIZE];

	uint32_t value_follows;
	size_t totlen;
	ssize_t n;
	uint8_t *pt;
	uint32_t xid;

	uint64_t cookie;
	uint64_t verifier;
	
	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr);
	totlen += 4 + ALIGN(dpt->fhlen, 4);
	totlen += 8; /* cookie */
	totlen += 8; /* verifier */
	totlen += 4; /* dircount */
	totlen += 4; /* maxcount */

	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_READDIRPLUS);
	pt = buf + sizeof(struct rpc_call_hdr);

	/* File handle */
	 *(uint32_t *)pt = htonl(dpt->fhlen);
	pt += 4;
	memcpy(pt, dpt->fh, dpt->fhlen);
	pt += ALIGN(dpt->fhlen, 4);

	/* cookie */
	*(uint64_t *)pt = dpt->cookie;
	pt += 8;

	/* verifier */
	*(uint64_t *)pt = dpt->verifier;
	pt += 8;

	/* dircount */
	*(uint32_t *)pt = htonl(sizeof(buf) - (sizeof(struct entattr)+FHMAXLEN));
	pt += 4;

	/* maxcount */
	*(uint32_t *)pt = htonl(sizeof(buf));
	pt += 4;

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, buf, totlen) < 0) {
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}

	reply = (struct rpc_nfsreply_hdr *)buf;
	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));
	pt = buf + sizeof(struct rpc_nfsreply_hdr);

	print(1, ctx, "Read %lu bytes of data for READDIRPLUS reply\n", n);
	value_follows = ntohl(*(uint32_t *)pt);
	pt += 4;

	memset(ent, 0x00, sizeof(struct dirplusent));

	/* Dir attributes */
	if (value_follows == 1) {
		pt += sizeof(struct entattr);
	}

	verifier = *(uint64_t *)pt;
	pt += 8;

	if (dpt->verifier != 0) {

		if (dpt->verifier != verifier) {
			fprintf(stderr, "** Error: Receieved invalid verifier\n");
			return -1;
		}
	}

	value_follows = ntohl(*(uint32_t *)pt);
	pt += 4;

	/* We just return information for the first entry received */
	if (value_follows == 1) {
		uint32_t len;

		/* File ID */
		pt += 8;

		/* Here comes the name */
		len = ntohl(*(uint32_t *)pt);
		pt += 4;

		if (len > (sizeof(ent->name)-1)) {
			fprintf(stderr, "** Error: Name (%u bytes) exceeds buffer size (%lu)\n", 
				len, sizeof(ent->name));
			return -1;
		}

		memcpy(ent->name, pt, len);
		pt += ALIGN(len, 4);

		cookie = *(uint64_t *)pt;
		pt += 8;

		value_follows = ntohl(*(uint32_t *)pt);
		pt += 4;
		
		/* Name attributes */
		if (value_follows == 1) {
			memcpy(&ent->attr, pt, sizeof(struct entattr));
			pt += sizeof(struct entattr);
		}

		value_follows = ntohl(*(uint32_t *)pt);
		pt += 4;

		/* File handle */
		value_follows = ntohl(*(uint32_t *)pt);
		pt += 4;
		if (value_follows == 1) {
			len = ntohl(*(uint32_t *)pt);
			pt += 4;
	
			if (len > (sizeof(ent->fh)-1)) {
				fprintf(stderr, "** Error: FH (%u bytes) exceeds buffer size (%lu)\n",
					len, sizeof(ent->fh));
				return -1;
			}

			memcpy(ent->fh, pt, len);
			pt += ALIGN(len, 4);
			ent->fhlen = len;
		}

		value_follows = ntohl(*(uint32_t *)pt);
		pt += 4;
		dpt->entcount++;
	}

	/* We do not buffer subsequent entries
	 * If the entry fetched above was the last one, no more
	 * value should follow and the EOF marker should be read */
	if (value_follows == 0) {
		uint32_t eof;

		eof = ntohl(*(uint32_t *)pt);
		pt += 4;

		/* We reached the last entry */
		if (eof == 1)
			dpt->eof = 1;
	}

	/* Save the cookie and verifier for the next call */
	dpt->verifier = verifier;
	dpt->cookie = cookie;
	return dpt->eof;
}


/*
 * Find ".." using READDIRPLUS by reading entries one by one
 * in directory represented by file handle.
 * Returns the length of the filehandle for .. on success (which might be zero!)
 * and -1 on error.
 * The fiel handle is saved to the memory pointed to by fhsave which must hold at 
 * least FHMAXLEN bytes.
 */
int
nfsv3_readdirplus_dotdot(struct nfsctx *ctx, uint8_t *fhandle, uint32_t fhlen, uint8_t *fhsave)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;
	uint8_t buf[IOBUFSIZE];

	uint32_t value_follows;
	size_t totlen;
	ssize_t n;
	uint8_t *pt;
	uint32_t xid;
	uint32_t eof;

	uint64_t cookie;
	uint64_t verifier;

	verifier = 0;
	cookie = 0;

call_again:
	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);

	totlen = sizeof(struct rpc_call_hdr);
	totlen += 4 + ALIGN(fhlen, 4);
	totlen += 8; /* cookie */
	totlen += 8; /* verifier */
	totlen += 4; /* dircount */
	totlen += 4; /* maxcount */

	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_READDIRPLUS);
	pt = buf + sizeof(struct rpc_call_hdr);

	/* File handle */
	 *(uint32_t *)pt = htonl(fhlen);
	pt += 4;
	memcpy(pt, fhandle, fhlen);
	pt += ALIGN(fhlen, 4);

	/* cookie */
	*(uint64_t *)pt = cookie;
	pt += 8;

	/* verifier */
	*(uint64_t *)pt = verifier;
	pt += 8;

	/* dircount */
	*(uint32_t *)pt = htonl(sizeof(buf) - (sizeof(struct entattr)+FHMAXLEN));
	pt += 4;

	/* maxcount */
	*(uint32_t *)pt = htonl(sizeof(buf));
	pt += 4;

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, buf, totlen) < 0) {
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}

	reply = (struct rpc_nfsreply_hdr *)buf;
	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));
	pt = buf + sizeof(struct rpc_nfsreply_hdr);

	value_follows = ntohl(*(uint32_t *)pt);
	pt += 4;

	/* Dir attributes */
	if (value_follows == 1) {
		pt += sizeof(struct entattr);
	}

	/* Verifier */
	if (verifier != 0) {
		if (verifier != *(uint64_t *)pt) {
			fprintf(stderr, "** Error: Receieved invalid verifier\n");
			return -1;
		}
	}
	else {
		verifier = *(uint64_t *)pt;
	}
	pt += 8;

	value_follows = ntohl(*(uint32_t *)pt);
	pt += 4;

	/* Loop through all entries received */
	while (value_follows == 1) {
		uint32_t dotdot;
		uint32_t len;
		uint32_t fhlen;

		/* File ID */
		pt += 8;

		/* Here comes the name */
		len = ntohl(*(uint32_t *)pt);
		pt += 4;

		/* Found .. */
		dotdot = 0;
		fhlen = 0;
		if (len == 2) {
			if (memcmp(pt, "..", 2) == 0)
				dotdot = 1;
		}
		pt += ALIGN(len, 4);

		cookie = *(uint64_t *)pt;
		pt += 8;

		value_follows = ntohl(*(uint32_t *)pt);
		pt += 4;
		
		/* Name attributes */
		if (value_follows == 1) {
			pt += sizeof(struct entattr);
		}

		/* File handle */
		value_follows = ntohl(*(uint32_t *)pt);
		pt += 4;
		if (value_follows == 1) {
			len = ntohl(*(uint32_t *)pt);
			fhlen = len;
			pt += 4;
	
			if (len > (FHMAXLEN)) {
				fprintf(stderr, "** Error: FH (%u bytes) exceeds buffer size (FHMAXLEN)\n",
					len);
				return -1;
			}

			if (fhsave != NULL)
				memcpy(fhsave, pt, len);

			pt += ALIGN(len, 4);
		}

		/* Found it, just return */
		if (dotdot != 0) {
			return fhlen;
		}

		value_follows = ntohl(*(uint32_t *)pt);
		pt += 4;
	}

	eof = htonl(*(uint32_t *)pt);
	if (eof == 0)
		goto call_again;

	/* ".." was not found */
	return -1;
}


/*
 * Do READDIRPLUS Call
 */
int
nfsv3_readdirplus(struct nfsctx *ctx, uint32_t opts, uint8_t *fhandle, uint32_t fhlen)
{
	struct rpc_call_hdr *call;
	struct rpc_nfsreply_hdr *reply;

	uint8_t buf[IOBUFSIZE*10];
	uint32_t value_follows;
	size_t totlen;
	ssize_t n;
	uint8_t *pt;
	uint32_t eof;
	uint64_t cookie;
	uint64_t verifier;
	uint64_t calls;
	uint64_t tot;
	uint64_t ents;
	uint32_t xid;

	struct readdirplus_call_footer {
		uint64_t cookie;
		uint64_t verifier;
		uint32_t dircount;
		uint32_t maxcount;
	} __attribute__((packed)) *footer;

	verifier = 0;
	cookie = 0;
	calls = 0;
	tot = 0;
	ents = 0;

call_again:
	xid = rand();
	print(1, ctx, "Generated XID 0x%08x\n", xid);
	calls++;

	totlen = sizeof(struct rpc_call_hdr);
	totlen += 4 + ALIGN(fhlen, 4);
	totlen += sizeof(struct readdirplus_call_footer);

	if (totlen > sizeof(buf)) {
		fprintf(stderr, " ** Error: Total length exceeds buffer\n");
		return -1;
	}
	memset(buf, 0x00, sizeof(buf));
	call = (struct rpc_call_hdr *)buf;
	RPC_INIT_REQ(call, RPC_PROGRAM_NFS, 3, RPC_NFSV3_PROCEDURE_READDIRPLUS);
	pt = buf + sizeof(struct rpc_call_hdr);

	/* File handle */
	*(uint32_t *)pt = htonl(fhlen);
	pt += 4;
	memcpy(pt, fhandle, fhlen);
	pt += ALIGN(fhlen, 4);

	print(1, ctx, "FH len: %u\n", fhlen);

	footer = (struct readdirplus_call_footer *)pt;
	pt += sizeof(struct readdirplus_call_footer);
	footer->cookie = cookie;
	footer->verifier = verifier;
	footer->dircount = htonl(IOBUFSIZE/2);
	footer->maxcount = htonl(IOBUFSIZE);

	if (udp_write(ctx, ctx->ip, ctx->port_nfsd, buf, totlen) < 0) {
		return -1;
	}

	memset(buf, 0x00, sizeof(buf));
	if ( (n = udp_read(ctx, ctx->ip, ctx->port_nfsd, buf, sizeof(buf))) < 0) {
		return -1;
	}
	tot += n;
	reply = (struct rpc_nfsreply_hdr *)buf;
	RPC_CHECK_REPLY(reply, n);
	NFS_CHECK_REPLY(ntohl(reply->status));
	pt = buf + sizeof(struct rpc_nfsreply_hdr);

	print(1, ctx, "Read %lu bytes of data for READDIRPLUS reply\n", n);
	value_follows = ntohl(*(uint32_t *)pt);
	pt += 4;

	/* Dir attributes */
	if (value_follows == 1) {
		pt += sizeof(struct entattr);
	}

	verifier = *(uint64_t *)pt;
	pt += 8;

	value_follows = ntohl(*(uint32_t *)pt);
	pt += 4;

	while (value_follows == 1) {
	//	uint64_t fid;
		uint32_t len;
		char name[1024];

		ents++;

	//	fid = be64toh(*(uint64_t *)pt);
		pt += 8;

		len = ntohl(*(uint32_t *)pt);
		pt += 4;
		
		memset(name, 0x00, sizeof(name));
		memcpy(name, pt, len > (sizeof(name)-1) ? (sizeof(name)-1) : len);
		pt += ALIGN(len, 4);
		
		cookie = *(uint64_t *)pt;
		pt += 8;

		value_follows = ntohl(*(uint32_t *)pt);
		pt += 4;

		/* Name attributes */
		if (value_follows == 1) {
			char str[4096];
			struct entattr *attr;

			attr = (struct entattr *)pt;
			if (nfsv3_attrstr(ctx, attr, opts, name, str, sizeof(str)) != NULL) {
				printf("%s ", str);
			}

			pt += sizeof(struct entattr);
		}

		/* Sometimes there are no attributes associated with names */
		else {
			struct entattr attr;
			char str[4096];

			memset(&attr, 0x00, sizeof(struct entattr ));
			if (nfsv3_attrstr(ctx, &attr, opts, name, str, sizeof(str)) != NULL) {
				printf("%s ", str);
			}
		}

		value_follows = ntohl(*(uint32_t *)pt);
		pt += 4;

		/* File handle */
		if (value_follows == 1) {
			len = ntohl(*(uint32_t *)pt);
			pt += 4;
			printf("FH:");
			HEXDUMP(pt, len);
			pt += ALIGN(len, 4);
		}
		else {
			printf("\n");
		}

		if (pt > (buf + sizeof(buf))) {
			fprintf(stderr, "** Error: Buffer size exceeded\n");
			return -1;
		}

		value_follows = ntohl(*(uint32_t *)pt);
		pt += 4;
	}

	/* EOF marker */
	eof = htonl(*(uint32_t *)pt);

	if (eof == 0) {
		print(1, ctx, "EOF != 1, running call %lu\n", calls+1);
		goto call_again;
	}

	print(0, ctx, "Read %lu entries, %lu bytes, in %lu calls\n", 
		ents, tot, calls);
	
	return 0;
}

