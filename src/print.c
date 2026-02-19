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
 * print.c - Verbose output utilities
 *
 * Provides level-controlled output (info, detail, debug, trace).
 * Output is suppressed based on verbosity level in ctx->verbose.
 */

#include <stdarg.h>
#include <time.h>

#include "nfscli.h"
#include "print.h"
#include "str.h"

/*
 * Only print if verbose level is high enough
 */
void
print(unsigned int level, struct nfsctx *ctx, const char *fmt, ...)
{
    va_list ap;
    char ts[128];

    if (ctx->verbose < level)
        return;

    if (str_time(ts, sizeof(ts) - 1, time(NULL)) == NULL)
        snprintf(ts, sizeof(ts), "?");
    printf("[%s] %s: ", ts, ctx->server.name);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}
