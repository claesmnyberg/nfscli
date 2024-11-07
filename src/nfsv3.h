
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
#ifndef NFSV3_H
#define NFSV3_H

#include <stdint.h>
#include <errno.h>

#include "nfsh.h"

/* Align to a value that is a power of 2 */
#define ALIGN(siz, val)   (((siz) + (val) - 1) & ~((val) - 1))

#define FHMAXLEN	128
#define NAMEMAXLEN	256
#define IOBUFSIZE	1300 /* We try to keep data in a single UDP packet */

/* Leave this alone */
#define MACHINE_NAME	"desktop"

struct rpc_call {
    uint32_t xid;
    uint32_t msgtype;
    #define RPC_MSG_TYPE_CALL   0
    #define RPC_MSG_TYPE_REPLY  1

    uint32_t version;
    uint32_t program;
    #define RPC_PROGRAM_PORTMAP 100000
    #define RPC_PROGRAM_NFS     100003
    #define RPC_PROGRAM_MOUNT   100005

    uint32_t program_version;
    uint32_t procedure;
    #define RPC_NFSV3_PROCEDURE_GETATTR        	1
    #define RPC_NFSV3_PROCEDURE_SETATTR        	2
    #define RPC_NFSV3_PROCEDURE_LOOKUP        	3
    #define RPC_NFSV3_PROCEDURE_READLINK        5
    #define RPC_NFSV3_PROCEDURE_READ          	6
    #define RPC_NFSV3_PROCEDURE_WRITE          	7
    #define RPC_NFSV3_PROCEDURE_CREATE         	8
    #define RPC_NFSV3_PROCEDURE_MKDIR         	9
    #define RPC_NFSV3_PROCEDURE_SYMLINK        	10
    #define RPC_NFSV3_PROCEDURE_MKNOD        	11
    #define RPC_NFSV3_PROCEDURE_REMOVE         	12
    #define RPC_NFSV3_PROCEDURE_RMDIR         	13
    #define RPC_NFSV3_PROCEDURE_RENAME         	14
    #define RPC_NFSV3_PROCEDURE_LINK          	15
    #define RPC_NFSV3_PROCEDURE_READDIR 	  	16
    #define RPC_NFSV3_PROCEDURE_READDIRPLUS   	17
    
	#define RPC_PORTMAP_PROCEDURE_GETPORT   	3

    #define RPC_MOUNT_PROCEDURE_MNT         	1
    #define RPC_MOUNT_PROCEDURE_DUMP         	2
    #define RPC_MOUNT_PROCEDURE_UMNTALL         4
    #define RPC_MOUNT_PROCEDURE_EXPORT      	5

} __attribute__((packed));

#define NFSV3_OK 0
#define NFSV3ERR_PERM			1	// Not owner. The caller does not have correct ownership to perform the requested operation.
#define NFSV3ERR_NOENT			2	// No such file or directory. The file or directory specified does not exist.
#define NFSV3ERR_IO				5	// A hard error occurred when the operation was in progress. For example, this could be a disk error.
#define NFSV3ERR_NXIO			6	// No such device or address.
#define NFSV3ERR_ACCESS			13	// Permission denied. The caller does not have the correct permission to perform the requested operation.
#define NFSV3ERR_EXIST			17	// File exists. The file specified already exists.
#define NFSV3ERR_XDEV			18	// Attempt to do an operation across the file system.
#define NFSV3ERR_NODEV			19	// No such device.
#define NFSV3ERR_NOTDIR			20	// Not a directory. The caller specified a non-directory in a directory operation.
#define NFSV3ERR_ISDIR			21	// Is a directory. The caller specified a directory in a non-directory operation.
#define NFSV3ERR_INVAL			22	//An argument was passed to the z/OS NFS server that was not valid.
#define NFSV3ERR_FBIG			27	//File too large. The operation caused a file to grow beyond the server’s limit.
#define NFSV3ERR_NOSPC			28	//No space left on device. The operation caused the server’s file system to reach its limit.
#define NFSV3ERR_ROFS			30	//Read-only file system. Write tried on a read-only file system.
#define NFS3VERR_MLINK			31	//Too many links.
#define NFS3VERR_NAMETOOLONG	63	//File name too long. The file name in an operation was too long.
#define NFS3VERR_NOTEMPTY		66	//Directory not empty. Tried to remove a directory that was not empty.
#define NFS3VERR_DQUOT			69	//Disk quota exceeded. The client’s disk quota on the server has been exceeded.
#define NFS3VERR_STALE			70	//The file handle given in the arguments was not valid. That is, the file referred to by that file handle no longer exists, or access to it has been revoked.
#define NFS3VERR_BADHANDLE		10001	//File handle is not valid.
#define NFS3VERR_NOT_SYNC		10002	//Synchronization mismatch on SETATTR.
#define NFS3VERR_BAD_COOKIE		10003	//READDIR and READDIRPLUS cookie is stale.
#define NFS3VERR_NOTSUPP		10004	//Operation is not supported.
#define NFS3VERR_TOOSMALL		10005	//Buffer or request is too small.
#define NFS3VERR_SERVERFAULT	10006	//Server abandons the request.
#define NFS3VERR_BADTYPE		10007	//Type of an object is not supported.
#define NFS3VERR_JUKEBOX		10008	//Request was initiated, but not completed.

#define RPC_EXEC_SUCCESS 0
#define RPC_ERR_PROG_UNAVAIL	1
#define RPC_ERR_PROG_MISMATCH	2
#define RPC_ERR_PROG_NOTSUPP	3
#define RPC_ERR_PROG_DECODE		4
#define RPC_ERR_PROG_MEM		5


struct rpc_creds {
    uint32_t flavor;
    #define FLAVOR_AUTH_UNIX    1
    uint32_t length;
	uint32_t stamp;
	uint32_t machine_name_len;
	uint8_t machine_name[8];
	uint32_t uid;
	uint32_t gid;
	uint32_t auxgids;
} __attribute__((packed));

struct rpc_verifier {
    uint32_t flavor;
    uint32_t length;
} __attribute__((packed));

struct rpc_call_hdr {
	struct rpc_call r;
	struct rpc_creds c;
	struct rpc_verifier v;
} __attribute__((packed));

struct rpc_reply {
    uint32_t xid;
    uint32_t msgtype;
    uint32_t reply_state;
        #define RPC_ACCEPTED 0
} __attribute__((packed));

struct rpc_reply_hdr {
        struct rpc_reply r;
        struct rpc_verifier v;
        uint32_t accept_state;
} __attribute__((packed));

struct rpc_nfsreply_hdr {
	struct rpc_reply r;
	struct rpc_verifier v;
	uint32_t accept_state;
	uint32_t status; /* NFSV3_OK ? */
} __attribute__((packed));


struct setattr {
	uint32_t mode_value_follows; /* 1 */
	uint32_t mode;  
	uint32_t uid;   /* zero: do not change */
	uint32_t gid;   /* zero: do not change */
	uint32_t size;	/* zero: do not change */
	uint32_t atime; /* zero: do not change */
	uint32_t mtime; /* zero: do not change */
} __attribute__((packed));

struct entattr {
	uint32_t type;
	uint32_t mode;
	uint32_t nlink;
	uint32_t uid;
	uint32_t gid;
	uint64_t size;
	uint64_t used;
	uint64_t rdev;
	uint64_t fsid;
	uint64_t fid;
	struct {
		uint32_t secs;
		uint32_t nano;
	} atime;
	struct {
		uint32_t secs;
		uint32_t nano;
	} mtime;
	struct {
		uint32_t secs;
		uint32_t nano;
	} ctime;
}  __attribute__((packed));

#define NF3BLK	3
#define NF3CHR	4

/* Set RPC Call values */
#define RPC_INIT_REQ(__call, __prog, __ver, __proc)         \
{                                                           \
    (__call)->r.xid = htonl(xid);                           \
    (__call)->r.msgtype = htonl(RPC_MSG_TYPE_CALL);         \
    (__call)->r.version = htonl(2);                         \
    (__call)->r.program = htonl(__prog);                    \
    (__call)->r.program_version = htonl(__ver);             \
    (__call)->r.procedure = htonl(__proc);                  \
                                                            \
	/* AUTH_UNIX */                                         \
    (__call)->c.flavor = htonl(FLAVOR_AUTH_UNIX);           \
    (__call)->c.length = htonl(28);                         \
    (__call)->c.stamp = htonl(rand());                      \
    (__call)->c.machine_name_len = htonl(7);                \
    memcpy((__call)->c.machine_name, MACHINE_NAME, 8);      \
    (__call)->c.uid = htonl(ctx->uid);                      \
    (__call)->c.gid = htonl(ctx->gid);                      \
    (__call)->c.auxgids = htonl(0);                         \
                                                            \
	/* AUTH_NULL */                                         \
    (__call)->v.flavor = 0;                                 \
    (__call)->v.length = 0;                                 \
}

extern char *rpc_exec_errstr(int);

#define RPC_CHECK_REPLY(_r, _len)                                                       \
{                                                                                       \
    if ((_len >= 4) && ntohl((_r)->r.xid) != xid) {                                    \
        fprintf(stderr, "** Warning: Recevied bad XID, got %08x, expected %08x\n",      \
            (_r)->r.xid, htonl(xid));                                                   \
        return -1;                                                                      \
    }                                                                                   \
                                                                                        \
    if ((_len >= 8) && ntohl((_r)->r.msgtype) != RPC_MSG_TYPE_REPLY) {                 \
        fprintf(stderr, "** Warning: Did not receive Reply response, ignoring\n");      \
        return -1;                                                                      \
    }                                                                                   \
                                                                                        \
    if ((_len >= 12) && ntohl((_r)->r.reply_state) != RPC_ACCEPTED) {                  \
        fprintf(stderr, "** Error: RPC state %d: Message Denied\n",				        \
			ntohl((_r)->r.reply_state));                    							\
        return -1;                                                                      \
    }                                                                                   \
                                                                                        \
    if ((_len >= 16) && ntohl((_r)->accept_state) != RPC_EXEC_SUCCESS) {               \
        fprintf(stderr, "** Error: RPC exec failed (%d): %s\n",                         \
			ntohl((_r)->accept_state), rpc_exec_errstr(ntohl((_r)->accept_state)));     \
        return -1;                                                                      \
    }                                                                                   \
                                                                                        \
	if ( (_len) < sizeof( *(_r)  )) {                                                  \
		fprintf(stderr, "** Error: Short reply, got %lu, expected at least %lu\n",        \
			(_len), sizeof( *(_r)));                                                    \
		return -1;                                                                      \
	}                                                                                   \
}

#define NFS_CHECK_REPLY(__status)                                                     \
{                                                                                     \
	if ((__status) != NFSV3_OK) {                                                     \
		print(0, ctx, "** NFSV3 Error %d: %s\n", (__status), nfsv3_errstr(__status)); \
		print(1, ctx, "** Error: %s\n", nfsv3_errstr(__status));                      \
		errno = nfsv3_err2errno(__status);                                            \
		return -1;                                                                    \
	}                                                                                 \
}                                                                                     \


/* portmap.c */
extern int portmap_getport(struct nfsctx *, uint32_t);
#define portmap_getport_nfsd(__ctx)	portmap_getport((__ctx), RPC_PROGRAM_NFS)
#define portmap_getport_mountd(__ctx)	portmap_getport((__ctx), RPC_PROGRAM_MOUNT)

/* mount.c */
struct export_reply {
	char name[NAMEMAXLEN];
	char group[4096];
	uint8_t everyone;

	/* The file handle has to be filled in
	 * manually since it is only returned when
	 * a share is mounted, but we keep the variable
	 * here for convenience */
	uint8_t *fh;
	int fhlen;

	struct export_reply *next;
};

extern int mount_export(struct nfsctx *, struct export_reply **);
extern int mount_mount(struct nfsctx *, char *, uint8_t **);
extern int mount_umntall(struct nfsctx *);
extern int mount_dump(struct nfsctx *);

/* nfsv3 */
extern char *nfsv3_attrstr(struct nfsctx *ctx, struct entattr *, uint32_t, char *, char *, size_t);
#define ATTRSTR_LONG	0x01
#define ATTRSTR_COLORS	0x02

extern int nfsv3_readdirplus(struct nfsctx *, uint32_t, uint8_t *, uint32_t);
#define READDIRPLUS_OPT_LONG	ATTRSTR_LONG
#define READDIRPLUS_OPT_COLORS	ATTRSTR_COLORS

extern int nfsv3_readdir(struct nfsctx *, uint32_t, uint8_t *, uint32_t);
#define READDIR_OPT_LONG	ATTRSTR_LONG

struct nfsv3_read_args {
	uint8_t fh[FHMAXLEN*2]; 
	int fhlen;

	uint64_t offset;
	uint32_t count;
};

struct nfsv3_read_reply {
	uint8_t *data;	/* Pointer to received data (points past header of reply below) */
	uint32_t len;	/* Length of data */

	uint8_t *buf;	/* Pointer to reply buffer, with header, must be free'd */
	uint8_t eof;	/* Was this the last of the file ? */
};

struct nfsv3_write_args {
    uint8_t fh[FHMAXLEN];
    int fhlen;

    uint64_t offset;

	uint32_t count;
    uint8_t *data;
};

struct nfsv3_mkdir_args {
    uint8_t fh[FHMAXLEN];
    int fhlen;

	char name[256];
	uint32_t mode;
};

struct nfsv3_rmdir_args {
    uint8_t fh[FHMAXLEN];
    int fhlen;

	char name[256];
};

struct nfsv3_create_args {
    uint8_t fh[FHMAXLEN];
    int fhlen;

    char name[256];
    uint32_t mode;

	/* The file handle for the created file
	 * returned on success */
    uint8_t newfh[FHMAXLEN];
    uint32_t newfhlen;
};

struct nfsv3_remove_args {
    uint8_t fh[FHMAXLEN];
    int fhlen;

    char name[256];
};

struct nfsv3_setattr_args {
    uint8_t fh[FHMAXLEN];
    int fhlen;

	uint32_t mode;
};

struct nfsv3_link_args {
    uint8_t fh[FHMAXLEN];
    int fhlen;

    uint8_t dirfh[FHMAXLEN];
    uint32_t dirfhlen;

	char name[1024];
};

struct nfsv3_symlink_args {
    uint8_t fh[FHMAXLEN];
    int fhlen;
    char name[1024];
	uint32_t mode;

    char to[1024];
};

struct nfsv3_rename_args {
    uint8_t srcfh[FHMAXLEN];
    uint32_t srcfhlen;
	char srcname[256];

    uint8_t dstfh[FHMAXLEN];
    uint32_t dstfhlen;
	char dstname[256];
};

struct nfsv3_mknod_dev_args {
    uint8_t fh[FHMAXLEN];
    int fhlen;
    char name[256];

	int type;
	uint32_t mode;

	uint32_t major;
	uint32_t minor;
};

struct lookup_ret {
	uint8_t fh[FHMAXLEN];
	int fhlen;

	struct entattr obj_attr;
	struct entattr dir_attr;
};

extern int nfsv3_read(struct nfsctx *, struct nfsv3_read_args *, struct nfsv3_read_reply *);
extern int nfsv3_write(struct nfsctx *, struct nfsv3_write_args *);
extern int nfsv3_lookup(struct nfsctx *, uint8_t *, uint32_t, char *, struct lookup_ret *);
extern int nfsv3_trigger_openbsd_lookup_namelen(struct nfsctx *, uint8_t *, uint32_t, char *, uint32_t);
extern int nfsv3_readlink(struct nfsctx *, uint8_t *, uint32_t);
extern int nfsv3_getattr(struct nfsctx *, uint8_t *, uint32_t, struct entattr *);
extern int nfsv3_mkdir(struct nfsctx *, struct nfsv3_mkdir_args *);
extern int nfsv3_rmdir(struct nfsctx *, struct nfsv3_rmdir_args *);
extern int nfsv3_rename(struct nfsctx *, struct nfsv3_rename_args *);
extern int nfsv3_create(struct nfsctx *, struct nfsv3_create_args *);
extern int nfsv3_remove(struct nfsctx *, struct nfsv3_remove_args *);
extern int nfsv3_setattr(struct nfsctx *, struct nfsv3_setattr_args *);
extern int nfsv3_link(struct nfsctx *, struct nfsv3_link_args *);
extern int nfsv3_symlink(struct nfsctx *, struct nfsv3_symlink_args *);
extern int nfsv3_mknod_dev(struct nfsctx *, struct nfsv3_mknod_dev_args *);


struct dirpluspt {
	/* The directory we are currently reading */
	uint8_t fh[FHMAXLEN];
	int fhlen;

	uint64_t cookie;
	uint64_t verifier;

	uint64_t entcount;
	int eof;
};

struct dirplusent {
	uint8_t fh[FHMAXLEN];
	int fhlen;

	char name[2048];
	struct entattr attr;
};

extern int nfsv3_readdirplus_init(struct nfsctx *, uint8_t *, uint32_t, struct dirpluspt *);
extern int nfsv3_readdirplus_next(struct nfsctx *, struct dirpluspt *, struct dirplusent *);
extern int nfsv3_readdirplus_dotdot(struct nfsctx *, uint8_t *, uint32_t, uint8_t *);

#endif /* NFSV3_H */
