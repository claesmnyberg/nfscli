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
 * completion.h - Readline tab completion support
 */

#ifndef COMPLETION_H
#define COMPLETION_H

#ifndef NO_READLINE

#include <stdint.h>

/* Forward declarations */
struct nfsctx;
struct pathctx;
struct idmap;

/*
 * Command descriptor for completion
 */
struct completion_cmd {
    const char *name;
    const char *syntax;
};

/*
 * Initialize completion system.
 * cmds: array of command descriptors, NULL-terminated
 * count: number of commands in array
 */
void completion_init(const struct completion_cmd *cmds, size_t count);

/*
 * Clean up completion system resources.
 */
void completion_cleanup(void);

/*
 * Set NFS context for export path completion.
 * When set, arguments matching <export> patterns
 * will be completed using cached export paths.
 * ctx: NFS context, or NULL to disable
 */
void completion_set_nfsctx(struct nfsctx *ctx);

/*
 * Set pathctx context for path completion.
 * pctx: pathctx context, or NULL to disable
 */
void completion_set_pathctx(struct pathctx *pctx);

/*
 * Set idmap context for tilde (~user) completion.
 * map: idmap context, or NULL to disable
 */
void completion_set_idmap(struct idmap *map);

#endif /* NO_READLINE */

#endif /* COMPLETION_H */
