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
 * completion.c - Readline tab completion support
 */

#ifndef NO_READLINE

#include <limits.h>
#include <readline/readline.h>
#include <stdlib.h>
#include <string.h>

#include "completion.h"
#include "idmap.h"
#include "mount.h"
#include "nfs.h"
#include "nfs_types.h"
#include "nfscli.h"
#include "pathctx.h"
#include "str.h"

/* NFS argument types for completion */
#define NFS_ARG_NONE    0 /* Not an NFS-completable argument */
#define NFS_ARG_PATH    1 /* <path> - any NFS path */
#define NFS_ARG_NAME    2 /* <name> - filename in directory (needs dirfh) */
#define NFS_ARG_FH      3 /* <fh> - file handle (any type) */
#define NFS_ARG_DIR     4 /* <dir> - directory path only */
#define NFS_ARG_EXPORT  5 /* <export> - export path from cache */
#define NFS_ARG_DIRFH   6 /* <dirfh> - directory file handle only */
#define NFS_ARG_FILE    7 /* <file> - files only, no directories */
#define NFS_ARG_FILEFH  8 /* <filefh> - file handle (files only) */
#define NFS_ARG_VERBOSE 9 /* <verbose> - verbosity level */

/*
 * Module state - grouped into a single struct for clarity.
 */
static struct completion_state {
    /* Command table */
    const struct completion_cmd *cmds;
    size_t cmd_count;

    /* Context pointers */
    struct nfsctx *nfsctx;
    struct pathctx *pctx;
    struct idmap *idmap;

    /* Completion lists */
    char **current_args;
    char **syntax_args;
    char **help_topics;
    char **nfs_list;
    int nfs_index;

    /* Tilde expansion state */
    char *tilde_prefix;
    size_t tilde_home_len;

    /* Filter flags */
    int dirs_only;
    int files_only;
    int fh_exclude_dirs;
} g_state;

/* Static completion lists for 'set' command */
static char *set_names[] = {"autouid", "completion", "gid", "uid", NULL};
static char *set_completion_values[] = {"basic", "enhanced", NULL};
static char *set_onoff_values[] = {"on", "off", NULL};

/* Verbose level names */
static const char *verbose_names[] = {"info", "detail", "debug", "trace", NULL};

/*
 * Grow a string array, checking for overflow.
 * Returns 0 on success, -1 on failure.
 */
static int
str_array_grow(char ***arrayp, size_t *capacityp)
{
    size_t newcap;
    char **newarr;

    if (*capacityp == 0) {
        newcap = 16; /* Start with reasonable capacity to reduce reallocs */
    } else if (*capacityp > SIZE_MAX / 2 / sizeof(char *)) {
        return -1;
    } else {
        newcap = *capacityp * 2;
    }

    newarr = realloc(*arrayp, newcap * sizeof(char *));
    if (newarr == NULL)
        return -1;

    *arrayp = newarr;
    *capacityp = newcap;
    return 0;
}

/*
 * Free a NULL-terminated string array.
 */
static void
str_array_free(char **arr)
{
    size_t i;

    if (arr == NULL)
        return;

    for (i = 0; arr[i] != NULL; i++)
        free(arr[i]);
    free(arr);
}

/*
 * Parse a pipe-separated choice list (e.g., "nfs|mount|rpc") into an array.
 * start points to first char, end points past last char.
 * Returns NULL-terminated array or NULL on error.
 */
static char **
parse_choice_items(const char *start, const char *end)
{
    char **items = NULL;
    size_t count = 0;
    size_t capacity = 0;
    const char *p, *next;
    char *item;
    size_t len;

    p = start;
    while (p < end) {
        /* Find next | or end */
        next = p;
        while (next < end && *next != '|')
            next++;

        len = next - p;
        if (len > 0) {
            if (count >= capacity) {
                if (str_array_grow(&items, &capacity) < 0)
                    goto fail;
            }
            item = strndup(p, len);
            if (item == NULL)
                goto fail;
            items[count++] = item;
        }

        p = (next < end && *next == '|') ? next + 1 : next;
    }

    /* Add NULL terminator */
    if (count >= capacity) {
        if (str_array_grow(&items, &capacity) < 0)
            goto fail;
    }
    items[count] = NULL;
    return items;

fail:
    str_array_free(items);
    return NULL;
}

/*
 * Parse contents of a [...] bracket block.
 * Returns items array and sets *is_choice if it's a pick-one pattern.
 */
static char **
parse_bracket_contents(const char *start, const char *end, int *is_choice)
{
    const char *pipe, *gt, *space;

    *is_choice = 0;

    /* Skip [-X] option blocks */
    if (*start == '-')
        return NULL;

    /* Check for <x|y> pattern inside angle brackets */
    if (*start == '<') {
        gt = memchr(start, '>', end - start);
        pipe = memchr(start, '|', end - start);
        if (gt && pipe && pipe < gt) {
            *is_choice = 1;
            return parse_choice_items(start + 1, gt);
        }
        return NULL;
    }

    /* Check for x|y pattern */
    pipe = memchr(start, '|', end - start);
    if (pipe != NULL) {
        *is_choice = 1;
        /* Find end of choice group (stop at space if present) */
        space = memchr(start, ' ', end - start);
        if (space != NULL && space < end)
            end = space;
        return parse_choice_items(start, end);
    }

    /* Single word optional argument like [full] */
    space = memchr(start, ' ', end - start);
    if (space == NULL) {
        char **items;
        *is_choice = 1;
        items = malloc(2 * sizeof(char *));
        if (items == NULL)
            return NULL;
        items[0] = strndup(start, end - start);
        if (items[0] == NULL) {
            free(items);
            return NULL;
        }
        items[1] = NULL;
        return items;
    }

    return NULL;
}

/*
 * Parse syntax string to extract completable arguments.
 * Returns a NULL-terminated array of strings.
 * Sets *is_choice to 1 if it's a [x|y] pattern (pick one).
 */
static char **
parse_syntax_args(const char *syntax, int *is_choice)
{
    char **args = NULL;
    char **bracket_items;
    size_t count = 0;
    size_t capacity = 0;
    const char *p, *start, *end, *pipe;
    int bracket_is_choice;
    size_t i;

    *is_choice = 0;
    p = syntax;

    while (*p) {
        if (*p == '[') {
            /* Handle [...] block */
            start = p + 1;
            end = strchr(start, ']');
            if (end == NULL) {
                p++;
                continue;
            }

            bracket_items = parse_bracket_contents(start, end, &bracket_is_choice);
            if (bracket_items != NULL) {
                if (bracket_is_choice)
                    *is_choice = 1;
                /* Merge items into args */
                for (i = 0; bracket_items[i] != NULL; i++) {
                    if (count >= capacity) {
                        if (str_array_grow(&args, &capacity) < 0) {
                            str_array_free(bracket_items);
                            goto fail;
                        }
                    }
                    args[count++] = bracket_items[i];
                }
                free(bracket_items); /* Don't free strings, just the array */
            }
            p = end + 1;
        } else if (*p == '<') {
            /* Skip <...> positional argument markers */
            while (*p && *p != '>')
                p++;
            if (*p)
                p++;
        } else if (*p != ' ' && *p != '-') {
            /* Potential bare foo|bar pattern */
            start = p;
            end = start;
            while (*end && *end != ' ' && *end != '<' && *end != '[')
                end++;

            pipe = start;
            while (pipe < end && *pipe != '|')
                pipe++;

            if (pipe < end) {
                /* Found bare choice pattern */
                char **choice_items = parse_choice_items(start, end);
                if (choice_items != NULL) {
                    *is_choice = 1;
                    for (i = 0; choice_items[i] != NULL; i++) {
                        if (count >= capacity) {
                            if (str_array_grow(&args, &capacity) < 0) {
                                str_array_free(choice_items);
                                goto fail;
                            }
                        }
                        args[count++] = choice_items[i];
                    }
                    free(choice_items);
                }
            }
            p = end;
        } else {
            p++;
        }
    }

    /* Add NULL terminator */
    if (count >= capacity) {
        if (str_array_grow(&args, &capacity) < 0)
            goto fail;
    }
    args[count] = NULL;
    return args;

fail:
    str_array_free(args);
    return NULL;
}

/*
 * Find which argument position expects a local filename.
 * Returns the 1-based position, or 0 if none found.
 */
static int
find_local_file_arg(const char *syntax)
{
    const char *p = syntax;
    int pos = 0;

    while (*p) {
        if (*p == '<') {
            pos++;
            if (strncmp(p, "<local", 6) == 0)
                return pos;
            while (*p && *p != '>')
                p++;
        }
        if (*p)
            p++;
    }
    return 0;
}

/*
 * Count required arguments (patterns like <arg> outside [...]).
 */
static int
count_required_args(const char *syntax)
{
    int count = 0;
    int in_bracket = 0;
    const char *p = syntax;

    while (*p) {
        if (*p == '[') {
            in_bracket++;
        } else if (*p == ']') {
            if (in_bracket > 0)
                in_bracket--;
        } else if (*p == '<' && !in_bracket) {
            count++;
            while (*p && *p != '>')
                p++;
        }
        if (*p)
            p++;
    }
    return count;
}

/*
 * Count maximum positional arguments a command accepts.
 * Returns INT_MAX for patterns ending with "...".
 */
static int
count_max_args(const char *syntax)
{
    int count = 0;
    const char *p = syntax;
    size_t len;

    len = strlen(syntax);
    if (len >= 3 && strcmp(syntax + len - 3, "...") == 0)
        return INT_MAX;

    while (*p) {
        while (*p == ' ')
            p++;
        if (*p == '\0')
            break;

        if (*p == '<') {
            count++;
            while (*p && *p != '>')
                p++;
            if (*p == '>')
                p++;
        } else if (*p == '[') {
            p++;
            if (*p == '-') {
                /* Skip [-X] options */
                while (*p && *p != ']')
                    p++;
                if (*p == ']')
                    p++;
            } else {
                /* Optional positional or choice */
                count++;
                while (*p && *p != ']')
                    p++;
                if (*p == ']')
                    p++;
            }
        } else if (*p != '-' && *p != '|') {
            count++;
            while (*p && *p != ' ' && *p != '[' && *p != '<')
                p++;
        } else {
            p++;
        }
    }
    return count;
}

/*
 * Check if an option is already used in the line.
 */
static int
option_used_in_line(const char *opt, const char *line)
{
    char opt_char;
    const char *p;

    if (!opt || opt[0] != '-' || !opt[1])
        return 0;

    opt_char = opt[1];
    p = line;

    /* Skip command name */
    while (*p && *p != ' ')
        p++;

    while (*p) {
        while (*p == ' ')
            p++;
        if (*p == '\0')
            break;

        if (*p == '-') {
            p++;
            while (*p && *p != ' ') {
                if (*p == opt_char)
                    return 1;
                p++;
            }
        } else {
            while (*p && *p != ' ')
                p++;
        }
    }
    return 0;
}

/*
 * Filter syntax_args to remove already-used options.
 * Returns count of remaining args.
 */
static int
filter_used_options(char **args, const char *line)
{
    int i, j;

    if (!args)
        return 0;

    for (i = 0, j = 0; args[i] != NULL; i++) {
        if (args[i][0] == '-' && option_used_in_line(args[i], line)) {
            free(args[i]);
        } else {
            args[j++] = args[i];
        }
    }
    args[j] = NULL;
    return j;
}

static void
free_syntax_args(void)
{
    if (g_state.syntax_args) {
        str_array_free(g_state.syntax_args);
        g_state.syntax_args = NULL;
    }
}

static void
free_nfs_completion_list(void)
{
    if (g_state.nfs_list) {
        pathctx_complete_free(g_state.nfs_list);
        g_state.nfs_list = NULL;
    }
    g_state.nfs_index = 0;
}

/*
 * File handle completion generator.
 */
static char *
nfs_fh_generator(const char *text, int state)
{
    static size_t len;
    static char **mount_cache_list;
    static size_t mount_cache_index;
    static size_t lookup_cache_index;
    static int mount_phase_done;
    struct nfs_lookup_cache_entry *entry;
    char *match;
    size_t i;

    if (!state) {
        mount_cache_list = NULL;
        mount_cache_index = 0;
        lookup_cache_index = 0;
        mount_phase_done = 0;
        len = strlen(text);

        if (g_state.nfsctx != NULL && !g_state.fh_exclude_dirs)
            mount_cache_list = mount_fh_cache_query_handles(g_state.nfsctx, text);
    }

    /* Phase 1: Mount FH cache */
    while (!mount_phase_done && mount_cache_list &&
        mount_cache_list[mount_cache_index] != NULL) {
        match = mount_cache_list[mount_cache_index++];
        if (strncmp(match, text, len) == 0)
            return strdup(match);
    }

    if (!mount_phase_done) {
        mount_phase_done = 1;
        if (mount_cache_list != NULL) {
            for (i = 0; mount_cache_list[i] != NULL; i++)
                free(mount_cache_list[i]);
            free(mount_cache_list);
            mount_cache_list = NULL;
        }
    }

    /* Phase 2: Lookup FH cache */
    if (g_state.nfsctx != NULL) {
        while (lookup_cache_index < NFS_LOOKUP_CACHE_SIZE) {
            entry = &g_state.nfsctx->cache.lookup_cache[lookup_cache_index++];

            if (entry->fh_hex == NULL)
                continue;
            if (strncmp(entry->fh_hex, text, len) != 0)
                continue;
            if (g_state.fh_exclude_dirs && entry->ftype == NFS_FTYPE_DIR)
                continue;

            return strdup(entry->fh_hex);
        }
    }

    return NULL;
}

/*
 * Complete directory entries by READDIR on a file handle.
 */
static char **
complete_dir_entries(struct nfsctx *ctx, const uint8_t *fh_data, int fhlen,
    const char *text)
{
    struct nfs_fh fh;
    struct nfs_dir dir;
    struct nfs_dirent *ep;
    char **results = NULL;
    char **new_results, **final;
    char *name_copy, *text_copy;
    size_t i, count = 0;
    size_t capacity = 0;
    size_t textlen;
    int saved_quiet;

    textlen = strlen(text);
    fh.len = fhlen;
    memcpy(fh.data, fh_data, fhlen);
    nfs_dir_init(&dir);

    saved_quiet = ctx->quiet;
    ctx->quiet = 1;

    if (nfs_readdir(ctx, &fh, &dir) < 0) {
        ctx->quiet = saved_quiet;
        nfs_dir_free(&dir);
        return NULL;
    }
    ctx->quiet = saved_quiet;

    for (i = 0; i < dir.count; i++) {
        ep = &dir.entries[i];

        if (strcmp(ep->name, ".") == 0 || strcmp(ep->name, "..") == 0)
            continue;
        if (textlen > 0 && strncmp(ep->name, text, textlen) != 0)
            continue;

        if (count >= capacity) {
            if (capacity == 0)
                capacity = 16;
            else if (capacity > SIZE_MAX / 2 / sizeof(char *))
                break;
            else
                capacity *= 2;
            new_results = realloc(results, (capacity + 1) * sizeof(char *));
            if (new_results == NULL)
                break;
            results = new_results;
        }

        name_copy = strdup(ep->name);
        if (name_copy == NULL)
            break;
        results[count++] = name_copy;
    }

    nfs_dir_free(&dir);

    if (results != NULL) {
        results[count] = NULL;

        if (count > 1) {
            final = malloc((count + 2) * sizeof(char *));
            if (final != NULL) {
                text_copy = strdup(text);
                if (text_copy != NULL) {
                    final[0] = text_copy;
                    memcpy(&final[1], results, (count + 1) * sizeof(char *));
                    free(results);
                    results = final;
                } else {
                    free(final);
                }
            }
        }
    }

    return results;
}

/*
 * Generator for export paths.
 */
static char *
export_generator(const char *text, int state)
{
    static size_t index;
    static size_t len;
    const char *exp;

    if (!state) {
        index = 0;
        len = strlen(text);
    }

    if (g_state.nfsctx == NULL)
        return NULL;

    while ((exp = mount_exports_cache_get(g_state.nfsctx, index++)) != NULL) {
        if (strncmp(exp, text, len) == 0)
            return strdup(exp);
    }

    return NULL;
}

/*
 * Generator for verbose level names.
 */
static char *
verbose_generator(const char *text, int state)
{
    static int index;
    size_t len;

    if (!state)
        index = 0;

    len = strlen(text);

    while (verbose_names[index] != NULL) {
        const char *name = verbose_names[index++];
        if (strncmp(name, text, len) == 0)
            return strdup(name);
    }

    return NULL;
}

/*
 * Check if a pattern appears within a <...> block.
 */
static int
match_in_angle_brackets(const char *start, const char *pattern)
{
    const char *end, *p;
    size_t plen;

    end = strchr(start, '>');
    plen = strlen(pattern);

    if (end == NULL)
        return 0;

    for (p = start; p + plen <= end + 1; p++) {
        if (strncmp(p, pattern, plen) == 0)
            return 1;
    }
    return 0;
}

/*
 * Determine arg type from a <...> block.
 */
static int
get_arg_type_from_bracket(const char *p)
{
    if (match_in_angle_brackets(p, "path>"))
        return NFS_ARG_PATH;
    if (strncmp(p, "<name>", 6) == 0)
        return NFS_ARG_NAME;
    if (match_in_angle_brackets(p, "file>"))
        return NFS_ARG_FILE;
    if (match_in_angle_brackets(p, "dirfh>"))
        return NFS_ARG_DIRFH;
    if (match_in_angle_brackets(p, "filefh>"))
        return NFS_ARG_FILEFH;
    if (match_in_angle_brackets(p, "dir>"))
        return NFS_ARG_DIR;
    if (strncmp(p, "<fh>", 4) == 0)
        return NFS_ARG_FH;
    if (strncmp(p, "<export>", 8) == 0)
        return NFS_ARG_EXPORT;
    if (strncmp(p, "<verbose>", 9) == 0)
        return NFS_ARG_VERBOSE;
    return NFS_ARG_NONE;
}

/*
 * Get NFS arg type for a given argument position.
 */
static int
get_nfs_arg_type(const char *syntax, int arg_pos)
{
    const char *p, *last_bracket, *file_bracket;
    int pos, type, has_ellipsis;

    p = syntax;
    last_bracket = NULL;
    file_bracket = NULL;
    pos = 0;
    has_ellipsis = (strstr(syntax, "...") != NULL);

    while (*p) {
        /* Skip [-X ...] option blocks */
        if (*p == '[' && *(p + 1) == '-') {
            while (*p && *p != ']')
                p++;
            if (*p == ']')
                p++;
            continue;
        }
        if (*p == '<') {
            pos++;
            last_bracket = p;
            if (pos == arg_pos)
                return get_arg_type_from_bracket(p);
            type = get_arg_type_from_bracket(p);
            if (type == NFS_ARG_FILE || type == NFS_ARG_PATH)
                file_bracket = p;
            while (*p && *p != '>')
                p++;
        }
        if (*p)
            p++;
    }

    if (has_ellipsis && arg_pos > pos && last_bracket != NULL)
        return get_arg_type_from_bracket(last_bracket);

    if (has_ellipsis && file_bracket != NULL && arg_pos > 0)
        return get_arg_type_from_bracket(file_bracket);

    return NFS_ARG_NONE;
}

/*
 * Tilde username completion generator.
 */
static char *
tilde_user_generator(const char *text, int state)
{
    static size_t index;
    static size_t prefix_len;
    struct idmap_user *user;
    const char *name;
    size_t namelen;
    char *result;

    if (!state) {
        index = 0;
        prefix_len = strlen(text) - 1;
    }

    if (g_state.idmap == NULL || !g_state.idmap->loaded)
        return NULL;

    while (index < g_state.idmap->user_count) {
        user = &g_state.idmap->users[index++];
        name = user->name;

        if (prefix_len == 0 || strncmp(name, text + 1, prefix_len) == 0) {
            namelen = strlen(name);
            result = malloc(1 + namelen + 2);
            if (result == NULL)
                return NULL;
            result[0] = '~';
            memcpy(result + 1, name, namelen);
            result[1 + namelen] = '/';
            result[1 + namelen + 1] = '\0';
            return result;
        }
    }

    return NULL;
}

/*
 * Expand tilde path to absolute path.
 * Returns malloc'd expanded path or NULL if no expansion needed.
 * Sets tilde_prefix and tilde_home_len in g_state for later conversion.
 */
static char *
expand_tilde_to_path(const char *text)
{
    const char *slash, *home;
    char username[256];
    char *expanded;
    size_t ulen, hlen, rlen;

    if (text[0] != '~' || g_state.idmap == NULL)
        return NULL;

    slash = strchr(text, '/');
    if (slash == NULL)
        return NULL;

    ulen = (size_t)(slash - text - 1);
    if (ulen >= sizeof(username))
        return NULL;

    memcpy(username, text + 1, ulen);
    username[ulen] = '\0';

    home = idmap_name_to_home(g_state.idmap, username);
    if (home == NULL)
        return NULL;

    hlen = strlen(home);
    rlen = strlen(slash);

    expanded = malloc(hlen + rlen + 1);
    if (expanded == NULL)
        return NULL;

    memcpy(expanded, home, hlen);
    memcpy(expanded + hlen, slash, rlen + 1);

    /* Save state for converting results back */
    free(g_state.tilde_prefix);
    g_state.tilde_prefix = strndup(text, slash - text);
    if (g_state.tilde_prefix == NULL) {
        free(expanded);
        return NULL;
    }
    g_state.tilde_home_len = hlen;

    return expanded;
}

/*
 * Convert completion results back to tilde format.
 */
static void
convert_paths_to_tilde(char **results, const char *expanded_home)
{
    size_t i, plen, rlen;
    char *r, *newres;

    if (g_state.tilde_prefix == NULL || results == NULL)
        return;

    plen = strlen(g_state.tilde_prefix);

    for (i = 0; results[i] != NULL; i++) {
        r = results[i];
        if (g_state.tilde_home_len > 0 &&
            strncmp(r, expanded_home, g_state.tilde_home_len) == 0) {
            rlen = strlen(r);
            newres = malloc(plen + rlen - g_state.tilde_home_len + 1);
            if (newres != NULL) {
                memcpy(newres, g_state.tilde_prefix, plen);
                memcpy(newres + plen, r + g_state.tilde_home_len,
                    rlen - g_state.tilde_home_len + 1);
                free(r);
                results[i] = newres;
            }
        }
    }
}

/*
 * NFS path completion generator.
 */
static char *
nfs_path_generator(const char *text, int state)
{
    static size_t len;
    static size_t export_index;
    static int exports_done;
    static int tilde_done;
    static char *expanded_path;
    const char *exp, *lookup_path;
    size_t exp_len;
    char *result, *match;

    if (!state) {
        free_nfs_completion_list();
        g_state.nfs_index = 0;
        export_index = 0;
        exports_done = 0;
        tilde_done = 0;
        free(g_state.tilde_prefix);
        g_state.tilde_prefix = NULL;
        g_state.tilde_home_len = 0;
        free(expanded_path);
        expanded_path = NULL;
        len = strlen(text);

        if (g_state.pctx != NULL) {
            /* Try tilde expansion */
            expanded_path = expand_tilde_to_path(text);
            lookup_path = expanded_path ? expanded_path : text;

            g_state.nfs_list = pathctx_complete(g_state.pctx, lookup_path,
                g_state.dirs_only, g_state.files_only);

            if (expanded_path != NULL)
                convert_paths_to_tilde(g_state.nfs_list, expanded_path);
        }
    }

    /* Tilde username completion */
    if (!tilde_done && len > 0 && text[0] == '~' && strchr(text, '/') == NULL) {
        match = tilde_user_generator(text, state);
        if (match != NULL)
            return match;
        tilde_done = 1;
    }

    /* Export completion (main shell mode only) */
    if (g_state.pctx == NULL && !exports_done) {
        if (!g_state.files_only && g_state.nfsctx != NULL) {
            if (len > 0 && text[0] != '/') {
                exports_done = 1;
            } else {
                while ((exp = mount_exports_cache_get(g_state.nfsctx,
                            export_index++)) != NULL) {
                    if (strncmp(exp, text, len) == 0) {
                        exp_len = strlen(exp);
                        result = malloc(exp_len + 2);
                        if (result != NULL) {
                            memcpy(result, exp, exp_len);
                            result[exp_len] = '/';
                            result[exp_len + 1] = '\0';
                        }
                        return result;
                    }
                }
                exports_done = 1;
            }
        } else {
            exports_done = 1;
        }
    }

    /* Path completion list */
    if (g_state.nfs_list != NULL) {
        while (g_state.nfs_list[g_state.nfs_index] != NULL) {
            match = g_state.nfs_list[g_state.nfs_index++];
            return strdup(match);
        }
        free_nfs_completion_list();
    }

    return NULL;
}

static void
free_help_topic_list(void)
{
    if (g_state.help_topics != NULL) {
        str_array_free(g_state.help_topics);
        g_state.help_topics = NULL;
    }
}

static void
gen_help_topic_list(void)
{
    size_t i, count, oindex;
    const char *p;
    char *topic_copy;

    free_help_topic_list();

    for (count = 0; g_state.cmds[count].name != NULL; count++)
        ;

    g_state.help_topics = malloc((count + 1) * sizeof(char *));
    if (g_state.help_topics == NULL)
        return;

    oindex = 0;
    for (i = 0; g_state.cmds[i].name != NULL; i++) {
        p = g_state.cmds[i].name;
        if (p[0] != '\0' && p[0] != '!') {
            topic_copy = strdup(p);
            if (topic_copy == NULL) {
                while (oindex > 0)
                    free(g_state.help_topics[--oindex]);
                free(g_state.help_topics);
                g_state.help_topics = NULL;
                return;
            }
            g_state.help_topics[oindex++] = topic_copy;
        }
    }
    g_state.help_topics[oindex] = NULL;
}

static char *
argument_generator(const char *text, int state)
{
    static int index;
    static size_t len;
    const char *arg;

    if (!state) {
        index = 0;
        len = strlen(text);
    }

    if (!g_state.current_args)
        return NULL;

    while (g_state.current_args[index] != NULL) {
        arg = g_state.current_args[index++];
        if (strncmp(arg, text, len) == 0)
            return strdup(arg);
    }

    return NULL;
}

static char *
command_generator(const char *text, int state)
{
    static size_t index;
    static size_t len;
    const char *name;

    if (!state) {
        index = 0;
        len = strlen(text);
    }

    while (g_state.cmds[index].name != NULL) {
        name = g_state.cmds[index++].name;
        if (name[0] == '!')
            continue;
        if (strncmp(name, text, len) == 0)
            return strdup(name);
    }

    return NULL;
}

/*
 * Count positional arguments only (skip options starting with -).
 */
static int
count_positional_words(const char *line)
{
    int count = 0;
    const char *p = line;
    int first = 1;

    while (*p) {
        while (*p == ' ')
            p++;
        if (*p == '\0')
            break;

        if (first || *p != '-') {
            count++;
            first = 0;
        }

        while (*p && *p != ' ')
            p++;
    }
    return count;
}

/*
 * Find the last unquoted pipe character before cursor.
 */
static const char *
find_last_pipe_before_cursor(const char *line, int cursor_pos)
{
    const char *last_pipe = NULL;
    const char *p = line;
    const char *end = line + cursor_pos;
    int in_single = 0;
    int in_double = 0;

    while (p < end && *p) {
        if (*p == '\'' && !in_double)
            in_single = !in_single;
        else if (*p == '"' && !in_single)
            in_double = !in_double;
        else if (*p == '|' && !in_single && !in_double)
            last_pipe = p;
        p++;
    }

    if (last_pipe != NULL) {
        last_pipe++;
        while (*last_pipe == ' ')
            last_pipe++;
        return last_pipe;
    }
    return NULL;
}

/*
 * Find the last unquoted redirection operator before cursor.
 * Returns pointer to start of filename position, or NULL if not after redir.
 */
static const char *
find_redir_before_cursor(const char *line, int cursor_pos)
{
    const char *last_redir = NULL;
    const char *p = line;
    const char *end = line + cursor_pos;
    int in_single = 0;
    int in_double = 0;

    while (p < end && *p) {
        if (*p == '\'' && !in_double)
            in_single = !in_single;
        else if (*p == '"' && !in_single)
            in_double = !in_double;
        else if ((*p == '<' || *p == '>') && !in_single && !in_double) {
            last_redir = p;
            /* Skip >> */
            if (*p == '>' && p + 1 < end && *(p + 1) == '>')
                last_redir = p + 1;
        }
        p++;
    }

    if (last_redir != NULL) {
        last_redir++;
        while (*last_redir == ' ')
            last_redir++;
        /* Only return if cursor is in the redirection target area */
        if (last_redir <= end)
            return last_redir;
    }
    return NULL;
}

/*
 * Handle 'set' command completion.
 */
static char **
complete_set_args(const char *text, int word_pos, char *saveptr)
{
    char *first_arg;

    if (word_pos == 2) {
        g_state.current_args = set_names;
    } else if (word_pos == 3) {
        first_arg = strtok_r(NULL, " ", &saveptr);
        if (first_arg) {
            if (strcmp(first_arg, "completion") == 0)
                g_state.current_args = set_completion_values;
            else if (strcmp(first_arg, "autouid") == 0)
                g_state.current_args = set_onoff_values;
        }
    }

    if (g_state.current_args && g_state.current_args[0])
        return rl_completion_matches(text, argument_generator);
    return NULL;
}

/*
 * Handle NFS argument completion (path, fh, export, etc).
 */
static char **
complete_nfs_arg(const char *text, int nfs_type, char *saveptr)
{
    char *dirfh_str;
    uint8_t dirfh[NFS_FHSIZE_MAX];
    int dirfhlen;
    char **m;
    size_t mlen;

    if (nfs_type == NFS_ARG_VERBOSE) {
        return rl_completion_matches(text, verbose_generator);
    }

    if (nfs_type == NFS_ARG_EXPORT) {
        if (g_state.nfsctx != NULL &&
            mount_exports_cache_count(g_state.nfsctx) > 0)
            return rl_completion_matches(text, export_generator);
        return NULL;
    }

    if (nfs_type == NFS_ARG_FH || nfs_type == NFS_ARG_DIRFH ||
        nfs_type == NFS_ARG_FILEFH) {
        g_state.fh_exclude_dirs = (nfs_type == NFS_ARG_FILEFH);
        return rl_completion_matches(text, nfs_fh_generator);
    }

    if (nfs_type == NFS_ARG_NAME) {
        dirfh_str = strtok_r(NULL, " ", &saveptr);
        if (dirfh_str != NULL && g_state.nfsctx != NULL) {
            dirfhlen = str_hex2bin(dirfh_str, dirfh, sizeof(dirfh));
            if (dirfhlen > 0)
                return complete_dir_entries(g_state.nfsctx, dirfh, dirfhlen, text);
        }
        return NULL;
    }

    if (nfs_type == NFS_ARG_PATH || nfs_type == NFS_ARG_DIR ||
        nfs_type == NFS_ARG_FILE) {
        g_state.dirs_only = (nfs_type == NFS_ARG_DIR);
        g_state.files_only = (nfs_type == NFS_ARG_FILE);
        m = rl_completion_matches(text, nfs_path_generator);
        if (m && m[0] && !m[1]) {
            mlen = strlen(m[0]);
            if (mlen > 0 && m[0][mlen - 1] == '/')
                rl_completion_suppress_append = 1;
        }
        return m;
    }

    return NULL;
}

/*
 * Handle syntax-based completion (options and choices).
 */
static char **
complete_from_syntax(const char *text, const char *syntax, int word_pos,
    int required_args, const char *line)
{
    int is_choice;

    g_state.syntax_args = parse_syntax_args(syntax, &is_choice);

    /* Still in required args - no optional completions */
    if (word_pos <= required_args + 1 && !is_choice) {
        free_syntax_args();
        return NULL;
    }

    if (filter_used_options(g_state.syntax_args, line) == 0) {
        free_syntax_args();
        return NULL;
    }

    g_state.current_args = g_state.syntax_args;

    /* For choice patterns, only complete on first arg */
    if (is_choice && word_pos > 2) {
        free_syntax_args();
        g_state.current_args = NULL;
        return NULL;
    }

    if (g_state.current_args && g_state.current_args[0])
        return rl_completion_matches(text, argument_generator);
    return NULL;
}

static char **
command_completion(const char *text, int start, int end)
{
    char **matches = NULL;
    char *line = NULL;
    char *saveptr;
    char *cmd_name;
    const char *effective_line;
    const char *after_pipe;
    const struct completion_cmd *cmd;
    int positional_wc, effective_start;
    int max_args, required_args, farg, word_pos, arg_index, nfs_type;
    int is_typing_option;
    size_t i, mlen;
    const char *after_redir;

    (void)end;

    free_syntax_args();
    g_state.current_args = NULL;

    /* Handle pipe - treat post-pipe as new command line */
    effective_line = rl_line_buffer;
    effective_start = start;

    after_pipe = find_last_pipe_before_cursor(rl_line_buffer, start);
    if (after_pipe != NULL) {
        int pipe_offset = after_pipe - rl_line_buffer;
        effective_line = after_pipe;
        effective_start = start - pipe_offset;
        if (effective_start < 0)
            effective_start = 0;
    }

    /* Check for redirection - complete with NFS paths + /dev/null */
    after_redir = find_redir_before_cursor(effective_line, effective_start);
    if (after_redir != NULL) {
        rl_attempted_completion_over = 1;
        g_state.dirs_only = 0;
        g_state.files_only = 0;
        matches = rl_completion_matches(text, nfs_path_generator);
        if (matches && matches[0] && !matches[1]) {
            mlen = strlen(matches[0]);
            if (mlen > 0 && matches[0][mlen - 1] == '/')
                rl_completion_suppress_append = 1;
        }
        return matches;
    }

    line = strdup(effective_line);
    if (!line)
        return NULL;

    cmd_name = strtok_r(line, " ", &saveptr);
    positional_wc = count_positional_words(effective_line);

    if (effective_start == 0) {
        /* Completing command name */
        rl_attempted_completion_over = 1;
        matches = rl_completion_matches(text, command_generator);
        free(line);
        return matches;
    }

    if (cmd_name == NULL) {
        free(line);
        return NULL;
    }

    /* Find command in table */
    cmd = NULL;
    for (i = 0; g_state.cmds[i].name != NULL; i++) {
        if (strcmp(g_state.cmds[i].name, cmd_name) == 0) {
            cmd = &g_state.cmds[i];
            break;
        }
    }

    if (cmd == NULL) {
        rl_attempted_completion_over = 1;
        free(line);
        return NULL;
    }

    max_args = count_max_args(cmd->syntax);
    required_args = count_required_args(cmd->syntax);
    farg = find_local_file_arg(cmd->syntax);

    is_typing_option = (text[0] == '-');
    word_pos = positional_wc + (text[0] == '\0' && !is_typing_option ? 1 : 0);

    /* Check max args */
    if (max_args != INT_MAX && word_pos > max_args + 1) {
        rl_attempted_completion_over = 1;
        free(line);
        return NULL;
    }

    /* Local file arg - use filesystem completion */
    if (farg > 0 && word_pos == farg + 1) {
        free(line);
        return NULL;
    }

    /* Help command */
    if (strcmp(cmd_name, "help") == 0) {
        g_state.current_args = g_state.help_topics;
        if (g_state.current_args && g_state.current_args[0]) {
            matches = rl_completion_matches(text, argument_generator);
            if (matches == NULL)
                rl_attempted_completion_over = 1;
        } else {
            rl_attempted_completion_over = 1;
        }
        free(line);
        return matches;
    }

    /* Set command */
    if (strcmp(cmd_name, "set") == 0) {
        rl_attempted_completion_over = 1;
        matches = complete_set_args(text, word_pos, saveptr);
        free(line);
        return matches;
    }

    /* Check for NFS arg type */
    arg_index = (word_pos > 0) ? word_pos - 1 : 0;
    nfs_type = get_nfs_arg_type(cmd->syntax, arg_index);

    if (nfs_type != NFS_ARG_NONE) {
        rl_attempted_completion_over = 1;
        matches = complete_nfs_arg(text, nfs_type, saveptr);
        free(line);
        return matches;
    }

    /* Syntax-based completion */
    rl_attempted_completion_over = 1;
    matches = complete_from_syntax(text, cmd->syntax, word_pos,
        required_args, effective_line);
    free(line);
    return matches;
}

/*
 * Initialize completion system.
 */
void
completion_init(const struct completion_cmd *cmds, size_t count)
{
    memset(&g_state, 0, sizeof(g_state));
    g_state.cmds = cmds;
    g_state.cmd_count = count;

    gen_help_topic_list();

    rl_attempted_completion_function = command_completion;
}

/*
 * Clean up completion system resources.
 */
void
completion_cleanup(void)
{
    free_help_topic_list();
    free_syntax_args();
    free_nfs_completion_list();
    free(g_state.tilde_prefix);
    memset(&g_state, 0, sizeof(g_state));
}

/*
 * Set NFS context for export path completion.
 */
void
completion_set_nfsctx(struct nfsctx *ctx)
{
    g_state.nfsctx = ctx;
}

/*
 * Set pathctx context for path completion.
 */
void
completion_set_pathctx(struct pathctx *pctx)
{
    g_state.pctx = pctx;
}

/*
 * Set idmap context for tilde (~user) completion.
 */
void
completion_set_idmap(struct idmap *map)
{
    g_state.idmap = map;
}

#endif /* NO_READLINE */
