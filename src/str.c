
/*
 * Copyright (C)  2023-2024 Claes M Nyberg <cmn@signedness.org>
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
 *      This product includes software developed by Claes M Nyberg.
 * 4. The name Claes M Nyberg may not be used to endorse or promote
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>

/*
 * Create timestamp
 */
char *
str_timestamp(char *buf, size_t buflen)
{
    struct tm *tm;
    time_t caltime;

    time(&caltime);

    if ( (tm = localtime(&caltime)) == NULL)
        return(NULL);

    if (strftime(buf, buflen, "%Y-%m-%d %H:%M:%S", tm) == 0)
        return(NULL);

    return buf;
}


/*
 * Create time stamp from seconds counter
 */
char *
str_time(char *buf, size_t buflen, time_t secs)
{
	struct tm *tm;
	time_t caltime;

	caltime = secs;

	if ( (tm = localtime(&caltime)) == NULL)
		return(NULL);

	if (strftime(buf, buflen, "%Y-%m-%d %H:%M:%S", tm) == 0)
		return(NULL);

	return buf;
}


/*
 * Convert seconds into hh:mm:ss string
 */
char *
str_hhmmss(time_t sec, char *buf, size_t buflen)
{
    uint32_t h, m;

    h = sec / 3600;
    sec -= (h*3600);
    m = sec / 60;
    sec -= m * 60;
    snprintf(buf, buflen, "%02u:%02u:%02u", h, m, (uint32_t)sec);
    return(buf);
}

/*
 * Split string into tokens using space and non printable characters as 
 * deliminator.
 * Pointers to the strings are stored at strv, where max 
 * indicates the maximum number of pointers to store, including
 * the terminating NULL pointer.
 * Returns the number of valid string pointers set in strv.
 * Note that deliminating characters found in str is
 * replaced with the terminating '\0' character.
 */
unsigned int
str_to_argv(char *str, char **strv, unsigned int maxv)
{
    char *pt = str;
    unsigned int i;

    if ((str == NULL) || (strv == NULL) || (maxv == 0))
        return(0);

    i = 0;

    /* Skip leading spaces and non printable characters */
	while (isspace((int)*pt) || !isprint((int)*pt))
		pt++;

    while (*pt && (i < (maxv - 1)) ) {

        strv[i++] = pt;

        for (; !isspace((int)*pt) && *pt && isprint((int)*pt); pt++);

        if (*pt == '\0')
            break;

        *pt = '\0';
        pt++;

        for (; isspace((int)*pt); pt++);
    }

    strv[i] = (char *)NULL;
    return(i);

}


/*
 * Create hexadecimal representation of string and store in buf.
 * Returns a pointer to buf on success, NULL on error.
 */
char *
str_hex(uint8_t *str, size_t len, char *buf, size_t buflen)
{
	size_t i,j;

	if (buflen <= (len*2)) {
		fprintf(stderr, "** Error: buffer size to small\n");
		return NULL;
	}

	for (i=0,j=0; i<len; i++) {
		snprintf(&buf[j], buflen-j, "%02x", str[i]);
		j += 2;
	}

	return buf;
}

/*
 * Create a printable string from buffer and replace non
 * printable characters with a dot '.'.
 * Returns a pointer to buf on success, NULL on error.
 */
char *
str_printable(uint8_t *str, size_t len, char *buf, size_t buflen)
{
    size_t i;

#define BYTETABLE \
    "................................."\
    "!\"#$%&'()*+,-./0123456789:;<=>?@"\
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"\
    "abcdefghijklmnopqrstuvwxyz{|}~..."\
    "................................."\
    "................................."\
    "................................."\
    "..........................."

    if (buflen <= (len+1)) {
        fprintf(stderr, "** Error: buffer size to small\n");
        return NULL;
    }

    for (i=0; i<len; i++) 
		buf[i] = BYTETABLE[str[i]];

	buf[i] = '\0';
    return buf;
}


/*
 * Convert hexadecimal string to bytes.
 * Returns the number of bytes on success, 0 on error.
 */
int
str_hex2bin(const char *str, uint8_t *buf, size_t buflen)
{
    size_t i;
    size_t j;
    char *ep;
    size_t len;

    len = strlen(str);

    if (len % 2 != 0) {
        fprintf(stderr, "Hexadecimal string must be of even length\n");
        return -1;
    }

    if ( (len / 2) >= buflen) {
        fprintf(stderr, "Hexadecimal string exceeds buffer length\n");
        return -1;
    }

    for (i=0,j=0; i<len; i+=2,j++) {
        char val[3];

        val[0] = str[i];
        val[1] = str[i+1];
        val[2] = '\0';

        buf[j] = (uint8_t)strtoul(val, &ep, 16);
        if (errno == EINVAL || *ep != '\0') {
            fprintf(stderr, "Invalid hexadecimal value in byte array at index %lu: %c\n",
                i, str[i]);
            return 0;
        }
    }

    return j;
}

/*
 * Convert size to human readable string.
 */
const char *
str_hsize(size_t size)
{
    static char hstr[24];
    double num;
    char *pad = "";

    if (size / (1024*1024*1024) > 0) {
        num = size / (1024*1024*1024);
        pad = "G";
    }
    else if (size / (1024*1024) > 0) {
        num = size / (1024*1024);
        pad = "M";
    }
    else if (size / 1024 > 0) {
        num = size / (1024);
        pad = "K";
    }
    else
        num = size;

    if (num == size)
        snprintf(hstr, sizeof(hstr), "%lu", size);
    else
        snprintf(hstr, sizeof(hstr), "%.1f%s", num, pad);
    return(hstr);
}

