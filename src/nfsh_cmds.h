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
 * nfsh_cmds.h - Shell command implementations
 *
 * Command table and implementations for the interactive shell.
 * Separated from nfsh.c for better organization.
 */

#ifndef NFSH_CMDS_H
#define NFSH_CMDS_H

struct nfsctx;

/* Command function type */
typedef int (*cmdfunc_t)(struct nfsctx *, int argc, char **argv);

/* Command descriptor */
struct cmd {
    const char *name;       /* Command name */
    const char *syntax;     /* Commandline syntax */
    const char *help_short; /* Short helptext (one line) */
    const char *help_long;  /* Long helptext (multiple lines) */
    cmdfunc_t func;         /* Command function */
};

/* Command table (defined in nfsh_cmds.c) */
extern struct cmd cmds[];

/* Execute a command by name */
int cmd_execute(struct nfsctx *ctx, int argc, char **argv);

/* Get sorted command count (for completion) */
size_t cmd_count(void);

#endif /* NFSH_CMDS_H */
