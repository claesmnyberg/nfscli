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
 * browse_expand.c - Glob and tilde expansion for browse shell
 */

#include <errno.h>
#include <fnmatch.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "browse_ctx.h"
#include "browse_expand.h"
#include "cmdparse.h"
#include "idmap.h"
#include "nfs.h"
#include "nfscli.h"
#include "pathctx.h"

/*
 * Check if string contains glob metacharacters
 */
static int
has_glob_chars(const char *s)
{
    for (; *s; s++) {
        if (*s == '*' || *s == '?' || *s == '[')
            return 1;
    }
    return 0;
}

/* Comparison function for qsort of string pointers */
static int
cmp_strptr(const void *a, const void *b)
{
    return strcmp(*(const char **)a, *(const char **)b);
}

/*
 * Dynamic string array for building expanded argv.
 */
struct str_array {
    char **items;
    int count;
    size_t capacity;
};

/*
 * Initialize a string array.
 */
static void
str_array_init(struct str_array *arr)
{
    arr->items = NULL;
    arr->count = 0;
    arr->capacity = 0;
}

/*
 * Free all strings and the array itself.
 */
static void
str_array_free(struct str_array *arr)
{
    int i;

    for (i = 0; i < arr->count; i++)
        free(arr->items[i]);
    free(arr->items);
    str_array_init(arr);
}

/*
 * Grow array capacity if needed.
 * Returns 0 on success, -1 on failure.
 */
static int
str_array_grow(struct str_array *arr)
{
    size_t new_cap;
    char **new_items;

    if ((size_t)arr->count < arr->capacity)
        return 0;

    if (arr->capacity == 0) {
        new_cap = 16;
    } else {
        if (arr->capacity > SIZE_MAX / 2 / sizeof(char *))
            return -1;
        new_cap = arr->capacity * 2;
    }

    new_items = realloc(arr->items, new_cap * sizeof(char *));
    if (new_items == NULL)
        return -1;

    arr->items = new_items;
    arr->capacity = new_cap;
    return 0;
}

/*
 * Add a string to the array (takes ownership).
 * Returns 0 on success, -1 on failure.
 */
static int
str_array_add(struct str_array *arr, char *str)
{
    if (str_array_grow(arr) < 0)
        return -1;
    arr->items[arr->count++] = str;
    return 0;
}

/*
 * Add a copy of a string to the array.
 * Returns 0 on success, -1 on failure.
 */
static int
str_array_add_dup(struct str_array *arr, const char *str)
{
    char *copy = strdup(str);
    if (copy == NULL)
        return -1;
    if (str_array_add(arr, copy) < 0) {
        free(copy);
        return -1;
    }
    return 0;
}

/*
 * Split pattern into directory and glob parts.
 * Returns 0 on success, -1 if pattern is invalid.
 */
static int
split_glob_pattern(const char *pattern, char *dir_path, size_t dir_size,
    const char **glob_part)
{
    const char *slash;
    size_t dir_len;

    slash = strrchr(pattern, '/');
    if (slash != NULL) {
        dir_len = (size_t)(slash - pattern);
        if (dir_len == 0) {
            dir_path[0] = '/';
            dir_path[1] = '\0';
        } else {
            if (dir_len >= dir_size)
                return -1;
            memcpy(dir_path, pattern, dir_len);
            dir_path[dir_len] = '\0';
        }
        *glob_part = slash + 1;
    } else {
        dir_path[0] = '\0';
        *glob_part = pattern;
    }
    return 0;
}

/*
 * Get file handle for directory path.
 * Returns 0 on success, -1 on failure.
 */
static int
get_dir_fh(struct browse_ctx *bctx, const char *dir_path, struct nfs_fh *fh)
{
    struct path_result pres;
    const struct nfs_fh *cwd_fh;

    if (dir_path[0] != '\0') {
        if (path_resolve(bctx->pctx, dir_path, PATH_FOLLOW, &pres) < 0)
            return -1;
        *fh = pres.fh;
    } else {
        cwd_fh = pathctx_cwd_fh(bctx->pctx);
        if (cwd_fh == NULL)
            return -1;
        *fh = *cwd_fh;
    }
    return 0;
}

/*
 * Expand a single glob argument.
 * Returns array of matched names (caller must free), or NULL on error.
 * Sets *count to number of matches. If no matches, returns NULL with *count=0.
 */
static char **
expand_glob_arg(struct browse_ctx *bctx, const char *pattern, int *count)
{
    char dir_path[NFS_MAXPATHLEN];
    char full_path[NFS_MAXPATHLEN];
    const char *glob_part;
    const char *name;
    struct nfs_fh dir_fh;
    struct nfs_dir dir;
    struct str_array matches;
    size_t i;
    int n;

    *count = 0;
    str_array_init(&matches);

    /* Split pattern into directory and glob parts */
    if (split_glob_pattern(pattern, dir_path, sizeof(dir_path),
            &glob_part) < 0)
        return NULL;

    /* If glob part is empty (pattern ended with /), no expansion */
    if (*glob_part == '\0')
        return NULL;

    /* Get directory FH */
    if (get_dir_fh(bctx, dir_path, &dir_fh) < 0)
        return NULL;

    /* Read directory */
    nfs_dir_init(&dir);
    if (nfs_readdirplus(bctx->nfs, &dir_fh, &dir, NFS_READDIRPLUS_NAMES) < 0)
        return NULL;

    /* Match entries against pattern */
    for (i = 0; i < dir.count; i++) {
        name = dir.entries[i].name;

        /* Skip . and .. */
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;

        /* FNM_PERIOD: * and ? don't match leading dot (Unix convention) */
        if (fnmatch(glob_part, name, FNM_PERIOD) != 0)
            continue;

        /* Build full path if pattern had directory component */
        if (dir_path[0] != '\0')
            n = snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, name);
        else
            n = snprintf(full_path, sizeof(full_path), "%s", name);

        if (n < 0 || (size_t)n >= sizeof(full_path))
            continue;

        if (str_array_add_dup(&matches, full_path) < 0) {
            str_array_free(&matches);
            nfs_dir_free(&dir);
            return NULL;
        }
    }

    nfs_dir_free(&dir);

    /* No matches - return NULL (caller will use literal) */
    if (matches.count == 0) {
        str_array_free(&matches);
        return NULL;
    }

    /* Sort matches for consistent output */
    qsort(matches.items, matches.count, sizeof(char *), cmp_strptr);

    *count = matches.count;
    return matches.items;
}

/*
 * Expand a single tilde expression.
 * Returns malloc'd string with expansion, or NULL if no expansion.
 * ~ = home of current uid, ~user = home of specified user.
 */
static char *
expand_tilde_arg(struct browse_ctx *bctx, const char *arg)
{
    const char *home;
    const char *rest;
    size_t userlen;
    size_t homelen;
    size_t restlen;
    char username[IDMAP_NAME_MAX];
    char *result;

    if (arg[0] != '~')
        return NULL;

    /* Find end of username (up to / or end of string) */
    rest = strchr(arg + 1, '/');
    if (rest == NULL)
        rest = arg + strlen(arg);
    userlen = rest - (arg + 1);

    if (userlen == 0) {
        /* ~ alone = current user's home */
        home = idmap_uid_to_home(&bctx->idmap, bctx->nfs->uid);
    } else {
        /* ~username */
        if (userlen >= IDMAP_NAME_MAX)
            return NULL;
        memcpy(username, arg + 1, userlen);
        username[userlen] = '\0';
        home = idmap_name_to_home(&bctx->idmap, username);
    }

    if (home == NULL)
        return NULL;

    /* Build expanded path: home + rest */
    homelen = strlen(home);
    restlen = strlen(rest);
    if (homelen > SIZE_MAX - restlen - 1)
        return NULL;

    result = malloc(homelen + restlen + 1);
    if (result == NULL)
        return NULL;

    memcpy(result, home, homelen);
    memcpy(result + homelen, rest, restlen + 1);
    return result;
}

/*
 * Check if any argument needs tilde or glob expansion.
 */
static int
needs_expansion(int argc, char **argv)
{
    int i;
    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '~' || has_glob_chars(argv[i]))
            return 1;
    }
    return 0;
}

/*
 * Add glob matches to result array.
 * Returns 0 on success, -1 on failure (frees matches on failure).
 */
static int
add_glob_matches(struct str_array *result, char **matches, int match_count)
{
    int j, k;

    for (j = 0; j < match_count; j++) {
        if (result->count >= PARSED_ARGS_MAX) {
            fprintf(stderr, "*** glob: too many matches (max %d)\n",
                PARSED_ARGS_MAX - 1);
            for (k = j; k < match_count; k++)
                free(matches[k]);
            break;
        }
        if (str_array_add(result, matches[j]) < 0) {
            for (k = j; k < match_count; k++)
                free(matches[k]);
            free(matches);
            return -1;
        }
    }
    free(matches);
    return 0;
}

/*
 * Process a single argument for expansion.
 * Returns 0 on success, -1 on failure.
 */
static int
expand_single_arg(struct browse_ctx *bctx, const char *orig_arg,
    struct str_array *result)
{
    const char *arg = orig_arg;
    char *tilde_exp = NULL;
    char **matches;
    int match_count;

    /* First, expand tilde if present */
    if (arg[0] == '~') {
        tilde_exp = expand_tilde_arg(bctx, arg);
        if (tilde_exp != NULL)
            arg = tilde_exp;
    }

    if (has_glob_chars(arg)) {
        matches = expand_glob_arg(bctx, arg, &match_count);
        free(tilde_exp);

        if (matches != NULL && match_count > 0) {
            return add_glob_matches(result, matches, match_count);
        } else {
            /* No matches - pass through original literal */
            return str_array_add_dup(result, orig_arg);
        }
    }

    /* No glob chars - use tilde-expanded or original */
    if (tilde_exp != NULL) {
        if (str_array_add(result, tilde_exp) < 0) {
            free(tilde_exp);
            return -1;
        }
        return 0;
    } else {
        return str_array_add_dup(result, arg);
    }
}

/*
 * Expand tildes and globs in argv.
 * Returns new argv (caller must free with free_expanded_argv).
 * If no expansion needed, returns NULL and caller should use original argv.
 */
char **
expand_globs(struct browse_ctx *bctx, int argc, char **argv, int *new_argc)
{
    struct str_array result;
    int i;

    *new_argc = 0;

    /* Check if any expansion is needed */
    if (!needs_expansion(argc, argv))
        return NULL;

    str_array_init(&result);

    /* Copy command name */
    if (str_array_add_dup(&result, argv[0]) < 0)
        return NULL;

    /* Process each argument */
    for (i = 1; i < argc; i++) {
        if (expand_single_arg(bctx, argv[i], &result) < 0) {
            str_array_free(&result);
            return NULL;
        }
    }

    *new_argc = result.count;
    return result.items;
}

/*
 * Free expanded argv
 */
void
free_expanded_argv(char **argv, int argc)
{
    int i;
    for (i = 0; i < argc; i++)
        free(argv[i]);
    free(argv);
}
