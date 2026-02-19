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
 * browse.h - Interactive filesystem browser
 *
 * Provides the "browse" command for interactive navigation of NFS exports.
 * Uses readline for command editing and tab completion.
 */

#ifndef BROWSE_H
#define BROWSE_H

struct nfsctx;
struct browse_ctx;

/* Command flags */
#define BCMD_META 0x01 /* Meta command (help/exit) - no --help handling */

/* Command function type */
typedef int (*browse_cmdfunc_t)(struct browse_ctx *, int argc, char **argv);

/* Command descriptor */
struct browse_cmd {
    const char *name;
    const char *syntax;
    const char *help_short;
    const char *help_long;
    browse_cmdfunc_t func;
    unsigned int flags;
};

/* Get command table (for help command) */
const struct browse_cmd *browse_get_cmds(void);

/* Browse command - interactive filesystem navigation */
int cmd_browse(struct nfsctx *, int, char **);

#endif /* BROWSE_H */
