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
 * idmap.h - UID/GID to name mapping from /etc/passwd and /etc/group
 *
 * Provides username/groupname resolution for browse mode by reading
 * passwd and group files from the NFS server's /etc directory.
 */

#ifndef IDMAP_H
#define IDMAP_H

#include <stddef.h>
#include <stdint.h>

#define IDMAP_NAME_MAX   32
#define IDMAP_HOME_MAX   256
#define IDMAP_MAX_GROUPS 64 /* Max supplementary groups to track per user */

struct pathctx;

/*
 * User entry from /etc/passwd
 */
struct idmap_user {
    uint32_t uid;
    uint32_t primary_gid;
    char name[IDMAP_NAME_MAX];
    char home[IDMAP_HOME_MAX];
};

/*
 * Group entry from /etc/group
 */
struct idmap_group {
    uint32_t gid;
    char name[IDMAP_NAME_MAX];
    char **members; /* NULL-terminated array of member names */
    size_t member_count;
};

/*
 * ID mapping context
 */
struct idmap {
    struct idmap_user *users;
    size_t user_count;
    struct idmap_group *groups;
    size_t group_count;
    int loaded; /* 1 if successfully loaded, 0 otherwise */
};

/*
 * Initialize idmap by reading /etc/passwd and /etc/group.
 * Returns 0 on success (or partial success), -1 if files not reachable.
 * On partial success (e.g., passwd exists but group doesn't), loads what's available.
 */
int idmap_init(struct idmap *map, struct pathctx *pctx);

/*
 * Free all resources associated with idmap.
 */
void idmap_free(struct idmap *map);

/*
 * Lookup functions - return pointer to static buffer or NULL if not found.
 * Returned strings are valid until next call to same function.
 */
const char *idmap_uid_to_name(struct idmap *map, uint32_t uid);
const char *idmap_gid_to_name(struct idmap *map, uint32_t gid);

/*
 * Reverse lookup - return id or (uint32_t)-1 if not found.
 */
uint32_t idmap_name_to_uid(struct idmap *map, const char *name);
uint32_t idmap_name_to_gid(struct idmap *map, const char *name);

/*
 * Get supplementary groups for a user.
 * Fills gids array with group IDs where user is a member (including primary).
 * Returns number of groups found, up to max_gids.
 */
int idmap_get_user_groups(struct idmap *map, uint32_t uid,
    uint32_t *gids, int max_gids);

/*
 * Get home directory for a user.
 * Returns pointer to home path or NULL if not found.
 */
const char *idmap_uid_to_home(struct idmap *map, uint32_t uid);
const char *idmap_name_to_home(struct idmap *map, const char *name);

#endif /* IDMAP_H */
