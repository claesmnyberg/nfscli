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
 * idmap.c - UID/GID to name mapping from /etc/passwd and /etc/group
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "idmap.h"
#include "nfs.h"
#include "nfs_types.h"
#include "pathctx.h"

/* Maximum file size we'll read (passwd/group shouldn't be huge) */
#define IDMAP_MAX_FILE_SIZE (256 * 1024)

/* Initial capacity for arrays */
#define IDMAP_INITIAL_CAPACITY 64

/*
 * Read entire file contents into malloc'd buffer.
 * Returns buffer on success (caller frees), NULL on error.
 * Sets *size to bytes read.
 */
static char *
read_file_contents(struct pathctx *pctx, const char *path, size_t *size)
{
    struct path_result pres;
    struct nfs_read_res res;
    char *buf = NULL;
    char *newbuf;
    size_t total = 0;
    size_t capacity = 8192;
    uint64_t offset = 0;

    *size = 0;

    if (path_resolve(pctx, path, PATH_FOLLOW, &pres) < 0)
        return NULL;

    /* Get file size for sanity check */
    if (!pres.has_attr)
        nfs_getattr(pctx->nfs, &pres.fh, &pres.attr);
    if (pres.has_attr || nfs_getattr(pctx->nfs, &pres.fh, &pres.attr) == 0) {
        if (pres.attr.size > IDMAP_MAX_FILE_SIZE) {
            errno = EFBIG;
            return NULL;
        }
        if (pres.attr.size > 0)
            capacity = pres.attr.size + 1;
    }

    buf = malloc(capacity);
    if (buf == NULL)
        return NULL;

    /* Read file in chunks */
    while (1) {
        memset(&res, 0, sizeof(res));
        if (nfs_read(pctx->nfs, &pres.fh, offset, 8192, &res) < 0) {
            free(buf);
            return NULL;
        }

        if (res.count == 0) {
            if (res.buf)
                nfs_read_res_free(&res);
            break;
        }

        /* Grow buffer if needed */
        while (total + res.count + 1 > capacity) {
            if (capacity > SIZE_MAX / 2) {
                free(buf);
                if (res.buf)
                    nfs_read_res_free(&res);
                return NULL;
            }
            capacity *= 2;
            newbuf = realloc(buf, capacity);
            if (newbuf == NULL) {
                free(buf);
                if (res.buf)
                    nfs_read_res_free(&res);
                return NULL;
            }
            buf = newbuf;
        }

        /* Validate res.count before memcpy to prevent overflow */
        if (res.count > 0 && res.count <= capacity - 1 - total &&
            total <= SIZE_MAX - res.count) {
            memcpy(buf + total, res.data, res.count);
            total += res.count;
            offset += res.count;
        } else {
            /* Overflow or buffer full */
            if (res.buf)
                nfs_read_res_free(&res);
            break;
        }

        if (res.buf)
            nfs_read_res_free(&res);

        if (res.eof)
            break;

        if (total >= IDMAP_MAX_FILE_SIZE)
            break;
    }

    buf[total] = '\0';
    *size = total;
    return buf;
}

/*
 * Compare users by uid for qsort/bsearch
 */
static int
user_cmp(const void *a, const void *b)
{
    const struct idmap_user *ua = a;
    const struct idmap_user *ub = b;
    if (ua->uid < ub->uid)
        return -1;
    if (ua->uid > ub->uid)
        return 1;
    return 0;
}

/*
 * Compare groups by gid for qsort/bsearch
 */
static int
group_cmp(const void *a, const void *b)
{
    const struct idmap_group *ga = a;
    const struct idmap_group *gb = b;
    if (ga->gid < gb->gid)
        return -1;
    if (ga->gid > gb->gid)
        return 1;
    return 0;
}

/*
 * Parse /etc/passwd format: name:password:uid:gid:gecos:home:shell
 * Note: Uses strsep instead of strtok_r to handle empty fields (e.g., "::").
 */
static int
parse_passwd(struct idmap *map, const char *data, size_t size)
{
    char *buf, *line, *saveptr;
    char *endp;
    struct idmap_user *new_users;
    struct idmap_user *u;
    unsigned long uid_val;
    unsigned long gid_val;
    size_t capacity = IDMAP_INITIAL_CAPACITY;
    size_t namelen;
    size_t homelen;

    (void)size;

    map->users = malloc(capacity * sizeof(*map->users));
    if (map->users == NULL)
        return -1;
    map->user_count = 0;

    /* Make a mutable copy for parsing */
    buf = strdup(data);
    if (buf == NULL) {
        free(map->users);
        map->users = NULL;
        return -1;
    }

    for (line = strtok_r(buf, "\n", &saveptr); line != NULL;
        line = strtok_r(NULL, "\n", &saveptr)) {
        char *fields[7];
        char *field_ptr = line;
        int i;

        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\0')
            continue;

        /* Split into fields using strsep (handles empty fields) */
        for (i = 0; i < 7 && field_ptr != NULL; i++)
            fields[i] = strsep(&field_ptr, ":");

        /* Need at least name:pass:uid:gid (4 fields) with non-empty values */
        if (i < 4 || fields[0] == NULL || fields[0][0] == '\0' ||
            fields[2] == NULL || fields[2][0] == '\0' ||
            fields[3] == NULL || fields[3][0] == '\0')
            continue;

        /* Validate uid and gid are numeric and within uint32_t range */
        errno = 0;
        uid_val = strtoul(fields[2], &endp, 10);
        if (endp == fields[2] || *endp != '\0' || uid_val > UINT32_MAX || errno != 0)
            continue;

        errno = 0;
        gid_val = strtoul(fields[3], &endp, 10);
        if (endp == fields[3] || *endp != '\0' || gid_val > UINT32_MAX || errno != 0)
            continue;

        /* Grow array if needed */
        if (map->user_count >= capacity) {
            if (capacity > SIZE_MAX / 2 / sizeof(*map->users))
                break;
            capacity *= 2;
            new_users = realloc(map->users, capacity * sizeof(*map->users));
            if (new_users == NULL)
                break;
            map->users = new_users;
        }

        /* Add entry */
        u = &map->users[map->user_count];
        namelen = strlen(fields[0]);
        if (namelen >= IDMAP_NAME_MAX)
            namelen = IDMAP_NAME_MAX - 1;
        memcpy(u->name, fields[0], namelen);
        u->name[namelen] = '\0';
        u->uid = (uint32_t)uid_val;
        u->primary_gid = (uint32_t)gid_val;
        /* Home directory is field 5 (0-indexed), may be missing */
        if (i >= 6 && fields[5] != NULL && fields[5][0] != '\0') {
            homelen = strlen(fields[5]);
            if (homelen >= IDMAP_HOME_MAX)
                homelen = IDMAP_HOME_MAX - 1;
            memcpy(u->home, fields[5], homelen);
            u->home[homelen] = '\0';
        } else {
            u->home[0] = '\0';
        }
        map->user_count++;
    }

    free(buf);

    /* Sort by uid for binary search */
    if (map->user_count > 1)
        qsort(map->users, map->user_count, sizeof(*map->users), user_cmp);

    return 0;
}

/*
 * Parse comma-separated member list into group struct.
 * Returns 0 on success (even if no members), -1 on allocation failure.
 */
static int
parse_group_members(struct idmap_group *g, const char *member_str)
{
    char *buf, *member, *saveptr;
    char **new_members, *member_copy;
    size_t capacity = 8;
    size_t k;

    g->members = NULL;
    g->member_count = 0;

    if (member_str == NULL || member_str[0] == '\0')
        return 0;

    buf = strdup(member_str);
    if (buf == NULL)
        return -1;

    g->members = malloc(capacity * sizeof(char *));
    if (g->members == NULL) {
        free(buf);
        return -1;
    }

    for (member = strtok_r(buf, ",", &saveptr);
        member != NULL;
        member = strtok_r(NULL, ",", &saveptr)) {

        /* Grow array if needed */
        if (g->member_count >= capacity) {
            if (capacity > SIZE_MAX / 2 / sizeof(char *))
                goto fail;
            capacity *= 2;
            new_members = realloc(g->members, capacity * sizeof(char *));
            if (new_members == NULL)
                goto fail;
            g->members = new_members;
        }

        member_copy = strdup(member);
        if (member_copy == NULL)
            goto fail;
        g->members[g->member_count++] = member_copy;
    }

    free(buf);
    return 0;

fail:
    for (k = 0; k < g->member_count; k++)
        free(g->members[k]);
    free(g->members);
    g->members = NULL;
    g->member_count = 0;
    free(buf);
    return -1;
}

/*
 * Parse /etc/group format: name:password:gid:member1,member2,...
 * Note: Uses strsep instead of strtok_r to handle empty fields (e.g., "::").
 */
static int
parse_group(struct idmap *map, const char *data, size_t size)
{
    char *buf, *line, *saveptr;
    char *fields[4];
    char *field_ptr;
    char *endp;
    struct idmap_group *new_groups;
    struct idmap_group *g;
    unsigned long gid_val;
    size_t capacity = IDMAP_INITIAL_CAPACITY;
    size_t namelen;
    int i;

    (void)size;

    map->groups = malloc(capacity * sizeof(*map->groups));
    if (map->groups == NULL)
        return -1;
    map->group_count = 0;

    buf = strdup(data);
    if (buf == NULL) {
        free(map->groups);
        map->groups = NULL;
        return -1;
    }

    for (line = strtok_r(buf, "\n", &saveptr); line != NULL;
        line = strtok_r(NULL, "\n", &saveptr)) {

        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\0')
            continue;

        /* Split into fields using strsep (handles empty fields) */
        field_ptr = line;
        for (i = 0; i < 4 && field_ptr != NULL; i++)
            fields[i] = strsep(&field_ptr, ":");

        /* Need at least name:pass:gid (3 fields) with non-empty name and gid */
        if (i < 3 || fields[0] == NULL || fields[0][0] == '\0' ||
            fields[2] == NULL || fields[2][0] == '\0')
            continue;

        /* Validate gid is numeric and within uint32_t range */
        errno = 0;
        gid_val = strtoul(fields[2], &endp, 10);
        if (endp == fields[2] || *endp != '\0' || gid_val > UINT32_MAX || errno != 0)
            continue;

        /* Grow array if needed */
        if (map->group_count >= capacity) {
            if (capacity > SIZE_MAX / 2 / sizeof(*map->groups))
                break;
            capacity *= 2;
            new_groups = realloc(map->groups, capacity * sizeof(*map->groups));
            if (new_groups == NULL)
                break;
            map->groups = new_groups;
        }

        /* Add entry */
        g = &map->groups[map->group_count];
        namelen = strlen(fields[0]);
        if (namelen >= IDMAP_NAME_MAX)
            namelen = IDMAP_NAME_MAX - 1;
        memcpy(g->name, fields[0], namelen);
        g->name[namelen] = '\0';
        g->gid = (uint32_t)gid_val;

        /* Parse member list (ignore failures - just means no members) */
        (void)parse_group_members(g, i >= 4 ? fields[3] : NULL);

        map->group_count++;
    }

    free(buf);

    /* Sort by gid for binary search */
    if (map->group_count > 1)
        qsort(map->groups, map->group_count, sizeof(*map->groups), group_cmp);

    return 0;
}

/*
 * Initialize idmap by reading /etc/passwd and /etc/group
 */
int
idmap_init(struct idmap *map, struct pathctx *pctx)
{
    char *passwd_data = NULL;
    char *group_data = NULL;
    size_t passwd_size, group_size;

    memset(map, 0, sizeof(*map));

    /* Try to read and parse passwd */
    passwd_data = read_file_contents(pctx, "/etc/passwd", &passwd_size);
    if (passwd_data != NULL) {
        parse_passwd(map, passwd_data, passwd_size);
        free(passwd_data);
    }

    /* Try to read and parse group */
    group_data = read_file_contents(pctx, "/etc/group", &group_size);
    if (group_data != NULL) {
        parse_group(map, group_data, group_size);
        free(group_data);
    }

    map->loaded = (map->user_count > 0 || map->group_count > 0);
    return map->loaded ? 0 : -1;
}

/*
 * Free all idmap resources
 */
void
idmap_free(struct idmap *map)
{
    size_t i, j;

    if (map->users != NULL) {
        free(map->users);
        map->users = NULL;
    }

    if (map->groups != NULL) {
        for (i = 0; i < map->group_count; i++) {
            if (map->groups[i].members != NULL) {
                for (j = 0; j < map->groups[i].member_count; j++)
                    free(map->groups[i].members[j]);
                free(map->groups[i].members);
            }
        }
        free(map->groups);
        map->groups = NULL;
    }

    map->user_count = 0;
    map->group_count = 0;
    map->loaded = 0;
}

/*
 * Lookup username by uid (binary search)
 */
const char *
idmap_uid_to_name(struct idmap *map, uint32_t uid)
{
    struct idmap_user key;
    struct idmap_user *found;

    if (map == NULL || map->users == NULL || map->user_count == 0)
        return NULL;

    memset(&key, 0, sizeof(key));
    key.uid = uid;
    found = bsearch(&key, map->users, map->user_count,
        sizeof(*map->users), user_cmp);
    return found ? found->name : NULL;
}

/*
 * Lookup group name by gid (binary search)
 */
const char *
idmap_gid_to_name(struct idmap *map, uint32_t gid)
{
    struct idmap_group key;
    struct idmap_group *found;

    if (map == NULL || map->groups == NULL || map->group_count == 0)
        return NULL;

    memset(&key, 0, sizeof(key));
    key.gid = gid;
    found = bsearch(&key, map->groups, map->group_count,
        sizeof(*map->groups), group_cmp);
    return found ? found->name : NULL;
}

/*
 * Lookup uid by username (linear search)
 */
uint32_t
idmap_name_to_uid(struct idmap *map, const char *name)
{
    size_t i;

    if (map == NULL || map->users == NULL || name == NULL)
        return (uint32_t)-1;

    for (i = 0; i < map->user_count; i++) {
        if (strcmp(map->users[i].name, name) == 0)
            return map->users[i].uid;
    }
    return (uint32_t)-1;
}

/*
 * Lookup gid by group name (linear search)
 */
uint32_t
idmap_name_to_gid(struct idmap *map, const char *name)
{
    size_t i;

    if (map == NULL || map->groups == NULL || name == NULL)
        return (uint32_t)-1;

    for (i = 0; i < map->group_count; i++) {
        if (strcmp(map->groups[i].name, name) == 0)
            return map->groups[i].gid;
    }
    return (uint32_t)-1;
}

/*
 * Get user's primary gid
 */
static uint32_t
idmap_get_primary_gid(struct idmap *map, uint32_t uid)
{
    struct idmap_user key;
    struct idmap_user *found;

    if (map == NULL || map->users == NULL || map->user_count == 0)
        return (uint32_t)-1;

    memset(&key, 0, sizeof(key));
    key.uid = uid;
    found = bsearch(&key, map->users, map->user_count,
        sizeof(*map->users), user_cmp);
    return found ? found->primary_gid : (uint32_t)-1;
}

/*
 * Get all groups for a user (primary + supplementary)
 */
int
idmap_get_user_groups(struct idmap *map, uint32_t uid,
    uint32_t *gids, int max_gids)
{
    const char *username;
    uint32_t primary_gid;
    int count = 0;
    size_t i, j;

    if (map == NULL || gids == NULL || max_gids <= 0)
        return 0;

    /* Get username and primary gid */
    username = idmap_uid_to_name(map, uid);
    primary_gid = idmap_get_primary_gid(map, uid);

    /* Add primary group first */
    if (primary_gid != (uint32_t)-1 && count < max_gids)
        gids[count++] = primary_gid;

    /* Scan groups for supplementary membership */
    if (username != NULL && map->groups != NULL) {
        for (i = 0; i < map->group_count && count < max_gids; i++) {
            /* Skip if this is already the primary group */
            if (map->groups[i].gid == primary_gid)
                continue;

            /* Check if user is in member list */
            for (j = 0; j < map->groups[i].member_count; j++) {
                if (strcmp(map->groups[i].members[j], username) == 0) {
                    gids[count++] = map->groups[i].gid;
                    break;
                }
            }
        }
    }

    return count;
}

/*
 * Get home directory by uid (binary search)
 */
const char *
idmap_uid_to_home(struct idmap *map, uint32_t uid)
{
    struct idmap_user key;
    struct idmap_user *found;

    if (map == NULL || map->users == NULL || map->user_count == 0)
        return NULL;

    memset(&key, 0, sizeof(key));
    key.uid = uid;
    found = bsearch(&key, map->users, map->user_count,
        sizeof(*map->users), user_cmp);
    if (found && found->home[0] != '\0')
        return found->home;
    return NULL;
}

/*
 * Get home directory by username (linear search)
 */
const char *
idmap_name_to_home(struct idmap *map, const char *name)
{
    size_t i;

    if (map == NULL || map->users == NULL || name == NULL)
        return NULL;

    for (i = 0; i < map->user_count; i++) {
        if (strcmp(map->users[i].name, name) == 0) {
            if (map->users[i].home[0] != '\0')
                return map->users[i].home;
            return NULL;
        }
    }
    return NULL;
}
