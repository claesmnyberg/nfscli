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
 * nfsh.c - Interactive shell and command loop
 *
 * Implements the main command loop with readline support, history management,
 * and input handling. Command implementations are in nfsh_cmds.c.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#ifndef NO_READLINE
#include <curses.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <term.h>
/*
 * Note: rl_done is declared as 'extern int' in readline.h, not volatile.
 * While not technically async-signal-safe, using rl_done in signal handlers
 * is standard practice in readline-based applications and works reliably.
 */
#endif /* NO_READLINE */

#ifndef NFSH_MAXLINE
#define NFSH_MAXLINE 1024
#endif

#ifndef NFSH_MAXARGS
#define NFSH_MAXARGS 32
#endif

#include "completion.h"
#include "display.h"
#include "nfscli.h"
#include "nfsh.h"
#include "nfsh_cmds.h"
#include "str.h"

/* Global flag for interrupt handling */
volatile sig_atomic_t g_interrupted = 0;

/*
 * Pending input buffer for pasted multi-line input.
 * When user pastes multiple lines, readline returns them all at once
 * with embedded newlines. We split on newlines and queue the rest here.
 *
 * SIGNAL SAFETY: This pointer is NOT volatile because the signal handler
 * never accesses it directly. The handler only sets g_interrupted, and the
 * main loop checks g_interrupted before accessing pending_input. This
 * sequencing ensures no data race: the main loop reads pending_input only
 * when not interrupted, or frees it after seeing g_interrupted.
 */
static char *pending_input = NULL;

/*
 * SIGINT handler for main shell
 *
 * This handler is async-signal-safe: it only sets volatile sig_atomic_t flags.
 * We avoid using rl_done as it's not properly async-signal-safe per POSIX.
 * Instead, set g_interrupted and let the main loop check it.
 */
static void
sigint_handler(int sig)
{
    int saved_errno = errno;
    (void)sig;
    g_interrupted = 1;
    errno = saved_errno;
}

#ifndef NO_READLINE
/* Completion cmd array for readline */
static struct completion_cmd *completion_cmds = NULL;
#endif

/*
 * Handle shell escape command (lines starting with '!').
 * Returns 1 if handled, 0 if not a shell escape.
 */
int
nfsh_shell_escape(const char *buf)
{
    const char *cmd;

    if (buf[0] != '!')
        return 0;

    cmd = buf + 1;
    if (cmd[0] != '\0') {
        int ret = system(cmd);
        (void)ret;
    }

    return 1;
}

#ifdef NO_READLINE
/* Simple history for non-readline builds */
#define NORL_HISTORY_SIZE 100
static char *norl_history[NORL_HISTORY_SIZE];
static int norl_history_count = 0;
static int norl_history_pos = 0;

static void
norl_history_add(const char *line)
{
    char *copy;

    if (line == NULL || line[0] == '\0')
        return;

    /* Don't add duplicates of the last entry */
    if (norl_history_count > 0 &&
        strcmp(norl_history[norl_history_count - 1], line) == 0)
        return;

    /* If full, free oldest and shift */
    if (norl_history_count >= NORL_HISTORY_SIZE) {
        free(norl_history[0]);
        memmove(&norl_history[0], &norl_history[1],
            (NORL_HISTORY_SIZE - 1) * sizeof(char *));
        norl_history_count--;
    }

    copy = strdup(line);
    if (copy != NULL) {
        norl_history[norl_history_count] = copy;
        norl_history_count++;
    }
    norl_history_pos = norl_history_count;
}

/*
 * Save current history and clear it (for browse mode separation).
 * Returns backup that must be passed to norl_history_restore().
 */
struct norl_history_backup *
norl_history_save(void)
{
    struct norl_history_backup *backup;

    backup = malloc(sizeof(*backup));
    if (backup == NULL)
        return NULL;

    backup->count = norl_history_count;
    backup->lines = NULL;

    if (norl_history_count > 0) {
        backup->lines = malloc(sizeof(char *) * norl_history_count);
        if (backup->lines == NULL) {
            free(backup);
            return NULL;
        }
        memcpy(backup->lines, norl_history, sizeof(char *) * norl_history_count);
    }

    /* Clear current history (don't free - backup owns them now) */
    norl_history_count = 0;
    norl_history_pos = 0;
    memset(norl_history, 0, sizeof(norl_history));

    return backup;
}

/*
 * Restore previously saved history.
 */
void
norl_history_restore(struct norl_history_backup *backup)
{
    int i;

    if (backup == NULL)
        return;

    /* Free current history */
    for (i = 0; i < norl_history_count; i++)
        free(norl_history[i]);

    /* Restore saved history */
    norl_history_count = backup->count;
    norl_history_pos = backup->count;
    if (backup->lines != NULL) {
        memcpy(norl_history, backup->lines, sizeof(char *) * backup->count);
        free(backup->lines);
    }

    free(backup);
}
#endif /* NO_READLINE */

/*
 * Read a line of input with optional readline support.
 * Returns pointer to buf on success, NULL on EOF/error.
 *
 * Handles pasted multi-line input by splitting on newlines.
 * When user pastes multiple lines, readline returns them all
 * with embedded newlines. We return the first line and queue
 * the rest for subsequent calls.
 */
char *
nfsh_readln(const char *prompt, char *buf, size_t buflen)
{
    memset(buf, 0, buflen);

    /*
     * Check for pending input from previous paste.
     * Return queued lines before reading new input.
     * Echo prompt and command so user sees what's being executed.
     * Clear interrupt flag to handle any signal during paste processing.
     */
    if (pending_input != NULL) {
        char *current;
        char *nl;
        char *remaining;
        size_t len;

        /* Check for interrupt and clean up pending input if needed */
        if (g_interrupted) {
            free(pending_input);
            pending_input = NULL;
            g_interrupted = 0;
            buf[0] = '\0';
            return buf;
        }

        current = pending_input;
        nl = strchr(current, '\n');
        if (nl != NULL) {
            /* More than one line pending - return first, keep rest */
            len = (size_t)(nl - current);
            if (len >= buflen)
                len = buflen - 1;
            memcpy(buf, current, len);
            buf[len] = '\0';
            /* Remove returned line from pending buffer */
            remaining = strdup(nl + 1);
            free(pending_input);
            pending_input = (remaining && remaining[0]) ? remaining : NULL;
            if (remaining && !remaining[0])
                free(remaining);
        } else {
            /* Last pending line */
            snprintf(buf, buflen, "%s", current);
            free(pending_input);
            pending_input = NULL;
        }
        /* Echo prompt and command for visibility (skip comments) */
        if (prompt && prompt[0] && buf[0] != '#')
            printf("%s%s\n", prompt, buf);
        return buf;
    }

    /* Non-TTY input: use plain fgets (no echo, no readline overhead) */
    if (!isatty(STDIN_FILENO)) {
        size_t len;
        if (fgets(buf, buflen - 1, stdin) == NULL)
            return NULL;
        len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n')
            buf[--len] = '\0';
        if (len > 0 && buf[len - 1] == '\r')
            buf[--len] = '\0';
        return buf;
    }

#ifndef NO_READLINE
    {
        char *input;
        char *nl;
        char *p;
        int extra_lines;
        int i;

        input = readline(prompt);
        if (input == NULL)
            return NULL;

        /*
         * Handle interrupt: rl_done=1 causes readline to return early.
         * Print newline for clean display and return empty input.
         */
        if (g_interrupted) {
            printf("\n");
            free(input);
            buf[0] = '\0';
            return buf;
        }

        /*
         * Check for embedded newlines (pasted multi-line input).
         * Split on first newline and queue the rest.
         *
         * When text is pasted, readline echoes all of it to the terminal.
         * We use ANSI escape sequences to erase the extra lines so it
         * looks like only the first command was typed.
         */
        nl = strchr(input, '\n');
        if (nl != NULL) {
            /* Count how many extra lines were pasted and displayed */
            extra_lines = 0;
            for (p = nl; *p; p++) {
                if (*p == '\n')
                    extra_lines++;
            }

            /* Erase the extra lines from display using ANSI escapes */
            if (extra_lines > 0 && isatty(STDOUT_FILENO)) {
                /*
                 * Move cursor up 'extra_lines' times and clear each line.
                 * ESC[A = move up, ESC[2K = clear line, ESC[B = move down
                 * After clearing, move back down to original position.
                 */
                for (i = 0; i < extra_lines; i++) {
                    printf("\033[A");  /* Move up one line */
                    printf("\033[2K"); /* Clear entire line */
                }
                /* Move back down to where we should be (after first command) */
                /* Actually we're now at the right place - just need newline */
                fflush(stdout);
            }

            /* Split at first newline */
            *nl = '\0';
            snprintf(buf, buflen, "%s", input);
            /* Queue remaining lines if any */
            if (nl[1] != '\0') {
                pending_input = strdup(nl + 1);
                /* If strdup fails, pending_input stays NULL - we just
                 * lose the queued input, which is graceful degradation */
            }
        } else {
            snprintf(buf, buflen, "%s", input);
        }
        free(input);
    }
#else
    /* TTY input without readline: use raw mode for basic line editing */
    {
        size_t len;
        struct termios orig, raw;
        size_t pos, i;
        int c;

        pos = 0;

        tcgetattr(STDIN_FILENO, &orig);
        raw = orig;
        raw.c_lflag &= ~(ECHO | ICANON);
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);

        printf("%s", prompt);
        fflush(stdout);

        len = 0;
        while ((c = getchar()) != EOF) {
            if (c == '\r' || c == '\n') {
                printf("\n");
                buf[len] = '\0';
                norl_history_add(buf);
                break;
            } else if (c == 127 || c == 8) { /* Backspace/DEL */
                if (pos > 0 && pos <= len && len > 0 && len <= buflen) {
                    /* Move chars after pos back, update display */
                    memmove(&buf[pos - 1], &buf[pos], len - pos);
                    pos--;
                    len--;
                    buf[len] = '\0';
                    /* Redraw: move back, print rest, clear extra, reposition */
                    printf("\b%s \b", &buf[pos]);
                    for (i = pos; i < len; i++)
                        printf("\b");
                    fflush(stdout);
                }
            } else if (c == 27) { /* Escape sequence (arrows) */
                int seq1 = getchar();
                if (seq1 == '[') {
                    int seq2 = getchar();
                    switch (seq2) {
                    case 'C': /* Right arrow */
                        if (pos < len) {
                            printf("\033[C");
                            fflush(stdout);
                            pos++;
                        }
                        break;
                    case 'D': /* Left arrow */
                        if (pos > 0) {
                            printf("\033[D");
                            fflush(stdout);
                            pos--;
                        }
                        break;
                    case 'A': /* Up arrow - history prev */
                        if (norl_history_pos > 0) {
                            norl_history_pos--;
                            /* Clear current line */
                            while (pos > 0) {
                                printf("\b \b");
                                pos--;
                            }
                            for (i = 0; i < len; i++)
                                printf(" ");
                            for (i = 0; i < len; i++)
                                printf("\b");
                            /* Copy history entry */
                            strncpy(buf, norl_history[norl_history_pos],
                                buflen - 1);
                            buf[buflen - 1] = '\0';
                            len = strlen(buf);
                            pos = len;
                            printf("%s", buf);
                            fflush(stdout);
                        }
                        break;
                    case 'B': /* Down arrow - history next */
                        if (norl_history_pos < norl_history_count) {
                            norl_history_pos++;
                            /* Clear current line */
                            while (pos > 0) {
                                printf("\b \b");
                                pos--;
                            }
                            for (i = 0; i < len; i++)
                                printf(" ");
                            for (i = 0; i < len; i++)
                                printf("\b");
                            /* Copy history entry or empty */
                            if (norl_history_pos < norl_history_count) {
                                strncpy(buf, norl_history[norl_history_pos],
                                    buflen - 1);
                                buf[buflen - 1] = '\0';
                                len = strlen(buf);
                            } else {
                                buf[0] = '\0';
                                len = 0;
                            }
                            pos = len;
                            printf("%s", buf);
                            fflush(stdout);
                        }
                        break;
                    case 'H': /* Home */
                        while (pos > 0) {
                            printf("\033[D");
                            pos--;
                        }
                        fflush(stdout);
                        break;
                    case 'F': /* End */
                        while (pos < len) {
                            printf("\033[C");
                            pos++;
                        }
                        fflush(stdout);
                        break;
                    case '3': /* Delete key (sends ESC [ 3 ~) */
                        if (getchar() == '~' && pos < len && len > 0 && len <= buflen) {
                            memmove(&buf[pos], &buf[pos + 1], len - pos - 1);
                            len--;
                            buf[len] = '\0';
                            printf("%s \b", &buf[pos]);
                            for (i = pos; i < len; i++)
                                printf("\b");
                            fflush(stdout);
                        }
                        break;
                    }
                }
            } else if (c == 3) { /* Ctrl-C */
                tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig);
                printf("^C\n");
                buf[0] = '\0';
                return buf;
            } else if (c == 4) { /* Ctrl-D */
                if (len == 0) {
                    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig);
                    return NULL;
                }
            } else if (c == 21) { /* Ctrl-U: clear line */
                while (pos > 0) {
                    printf("\b \b");
                    pos--;
                }
                for (i = 0; i < len - pos; i++)
                    printf(" ");
                for (i = 0; i < len - pos; i++)
                    printf("\b");
                fflush(stdout);
                len = 0;
                pos = 0;
                buf[0] = '\0';
            } else if (c >= 32 && c < 127 && len < buflen - 2) { /* Printable */
                /* Insert char at pos */
                if (pos < len && pos < buflen - 1 && len < buflen - 1) {
                    memmove(&buf[pos + 1], &buf[pos], len - pos);
                }
                buf[pos] = c;
                len++;
                buf[len] = '\0';
                printf("%s", &buf[pos]);
                pos++;
                for (i = pos; i < len; i++)
                    printf("\b");
                fflush(stdout);
            }
        }

        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig);
        buf[len] = '\0';
    }
#endif

    return buf;
}

#ifndef NO_READLINE
/*
 * Build completion_cmd array from cmds[] for the completion module.
 */
void
nfsh_completion_init(void)
{
    size_t num_cmds = cmd_count() + 1; /* +1 for NULL terminator */
    size_t i;

    /* Free any existing array (allows re-initialization) */
    if (completion_cmds) {
        free(completion_cmds);
        completion_cmds = NULL;
    }

    completion_cmds = malloc(num_cmds * sizeof(struct completion_cmd));
    if (!completion_cmds)
        return;

    for (i = 0; i < num_cmds; i++) {
        completion_cmds[i].name = cmds[i].name;
        completion_cmds[i].syntax = cmds[i].syntax;
    }

    completion_init(completion_cmds, num_cmds - 1); /* -1 for NULL terminator */
}

static void
nfsh_completion_cleanup(void)
{
    completion_cleanup();
    if (completion_cmds) {
        free(completion_cmds);
        completion_cmds = NULL;
    }
}
#endif

/*
 * NFS Client shell
 */
int
nfsh(struct nfsctx *ctx)
{
    char prompt[128];
    char *saveptr;
    struct sigaction sa, old_sa;

    /* Sort commands */
    qsort(cmds, cmd_count(),
        sizeof(struct cmd), name_cmp);

    /* Install SIGINT handler for interrupt support */
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* No SA_RESTART - let SIGINT interrupt blocking calls */
    sigaction(SIGINT, &sa, &old_sa);
    /* Note: old_sa contains previous handler; could be restored on exit */

#ifndef NO_READLINE
    /* Init libreadline */
    using_history();
    stifle_history(1024);

    nfsh_completion_init();
    completion_set_nfsctx(ctx);
#endif

    if (!ctx->term.interactive) {
        prompt[0] = '\0';
    } else if (ctx->net.spoof_str != NULL) {
        char spoof_display[32];
        /* Truncate spoof string if too long */
        if (strlen(ctx->net.spoof_str) > 28)
            snprintf(spoof_display, sizeof(spoof_display), "%.25s...", ctx->net.spoof_str);
        else
            snprintf(spoof_display, sizeof(spoof_display), "%s", ctx->net.spoof_str);
        snprintf(prompt, sizeof(prompt), "nfsh [SPOOFING %s] %s> ", spoof_display, ctx->server.name);
    } else {
        snprintf(prompt, sizeof(prompt), "nfsh %s> ", ctx->server.name);
    }

    /* Set batch saveptr for subshells (e.g., browse) to consume */
    ctx->batch_saveptr = &saveptr;

    for (;;) {
        char buf[NFSH_MAXLINE];
        char *cmd;

        if (ctx->exec != NULL) {
            if (strlen(ctx->exec) >= NFSH_MAXLINE) {
                fprintf(stderr, "String of commands exceeds maximum length\n");
                ctx->batch_saveptr = NULL;
                return -1;
            }
            snprintf(buf, sizeof(buf), "%s", ctx->exec);
            free(ctx->exec);
            ctx->exec = NULL;
        }

        /* Read a line */
        else if (nfsh_readln(prompt, buf, sizeof(buf)) == NULL) {
#ifndef NO_READLINE
            nfsh_completion_cleanup();
#endif
            printf("Bye, bye\n");
            ctx->batch_saveptr = NULL;
            return 0; /* Ctrl-D exits */
        }

        /* Clear any interrupt from Ctrl-C during line editing */
        g_interrupted = 0;

#ifndef NO_READLINE
        if (buf[0] != '\0') {
            add_history(buf);
        }
#endif
        /* shell escape for convenience */
        if (nfsh_shell_escape(buf))
            continue;

        /* Run all commands separated by semicolon */
        cmd = strtok_r(buf, ";", &saveptr);
        while (cmd != NULL) {
            char *argv[NFSH_MAXARGS];
            int argc;

            /* Skip leading whitespace */
            while (*cmd == ' ' || *cmd == '\t')
                cmd++;
            /* Skip comments and empty commands */
            if (*cmd == '\0' || *cmd == '#') {
                cmd = strtok_r(NULL, ";", &saveptr);
                continue;
            }

            memset(argv, 0x00, sizeof(argv));
            argc = str_to_argv(cmd, argv, (sizeof(argv) / sizeof(char *)) - 1);

            if (argc == 0) {
                cmd = strtok_r(NULL, ";", &saveptr);
                continue;
            }

            if (!strcmp(argv[0], "quit")) {
#ifndef NO_READLINE
                nfsh_completion_cleanup();
#endif
                printf("Bye, bye\n");
                ctx->batch_saveptr = NULL;
                return 0;
            }

            /* Reset interrupt flag before each command */
            g_interrupted = 0;
            cmd_execute(ctx, argc, argv);
            cmd = strtok_r(NULL, ";", &saveptr);
        }
    }
}
