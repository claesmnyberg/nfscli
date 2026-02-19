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
 * browse_cmd.h - Browse shell command declarations
 */

#ifndef BROWSE_CMD_H
#define BROWSE_CMD_H

#include <stdint.h>

/* Forward declarations */
struct browse_ctx;
struct nfs_attr;

/*
 * Shared helpers for commands that need to check/switch uid for read access.
 * Used by cat, get, ls.
 */
int can_read(struct browse_ctx *bctx, const struct nfs_attr *attr);
uint32_t autouid_switch(struct browse_ctx *bctx, const struct nfs_attr *attr);
void autouid_restore(struct browse_ctx *bctx, uint32_t orig_uid);

/*
 * Directory commands (browse_cmd_dir.c)
 */
int bcmd_pwd(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_ls(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_cd(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_mkdir(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_rmdir(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_df(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_mv(struct browse_ctx *bctx, int argc, char **argv);

/*
 * File commands (browse_cmd_file.c)
 */
int bcmd_cat(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_stat(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_readlink(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_get(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_put(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_rm(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_ln(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_touch(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_truncate(struct browse_ctx *bctx, int argc, char **argv);

/*
 * Miscellaneous commands (browse_cmd_misc.c)
 */
int bcmd_help(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_echo(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_set(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_id(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_chmod(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_chown(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_mknod(struct browse_ctx *bctx, int argc, char **argv);

/*
 * Text processing commands (browse_cmd_text.c)
 */
int bcmd_find(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_grep(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_head(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_tail(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_wc(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_strings(struct browse_ctx *bctx, int argc, char **argv);
int bcmd_xxd(struct browse_ctx *bctx, int argc, char **argv);

#endif /* BROWSE_CMD_H */
