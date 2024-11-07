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

#ifndef _ANSI_COLORS_H
#define _ANSI_COLORS_H

#define ACOLOR_SET(__clr) \
	printf("%s", (__clr))

#define ACOLOR_RESET() \
    printf("%s", COLOR_RESET)

#define COLOR_BOLD	"\e[1m"

#define COLOR_BLACK "\e[0;30m"
#define COLOR_RED "\e[0;31m"
#define COLOR_GREEN "\e[0;32m"
#define COLOR_YELLOW "\e[0;33m"
#define COLOR_BLUEE "\e[0;34m"
#define COLOR_MAGENTA "\e[0;35m"
#define COLOR_CYANAN "\e[0;36m"
#define COLOR_WHITE "\e[0;37m"

/* Regular bold text */
#define COLOR_BBLACK "\e[1;30m"
#define COLOR_BRED "\e[1;31m"
#define COLOR_BGREEN "\e[1;32m"
#define COLOR_BYELLOW "\e[1;33m"
#define COLOR_BBLUE "\e[1;34m"
#define COLOR_BMAGENTA "\e[1;35m"
#define COLOR_BCYAN "\e[1;36m"
#define COLOR_BWHITE "\e[1;37m"

/* Regular underline text */
#define COLOR_UBLACK "\e[4;30m"
#define COLOR_URED "\e[4;31m"
#define COLOR_UGREEN "\e[4;32m"
#define COLOR_UYELLOW "\e[4;33m"
#define COLOR_UBLUE "\e[4;34m"
#define COLOR_UMAGENTA "\e[4;35m"
#define COLOR_UCYAN "\e[4;36m"
#define COLOR_UWHITE "\e[4;37m"

/* Regular background */
#define COLOR_BLACKB "\e[40m"
#define COLOR_REDB "\e[41m"
#define COLOR_GREENB "\e[42m"
#define COLOR_YELLOWB "\e[43m"
#define COLOR_BLUEB "\e[44m"
#define COLOR_MAGENTAB "\e[45m"
#define COLOR_CYANB "\e[46m"
#define COLOR_WHITEB "\e[47m"

/* High intensity background */
#define COLOR_BLACKHB "\e[0;100m"
#define COLOR_REDHB "\e[0;101m"
#define COLOR_GREENHB "\e[0;102m"
#define COLOR_YELLOWHB "\e[0;103m"
#define COLOR_BLUEHB "\e[0;104m"
#define COLOR_MAGENTAHB "\e[0;105m"
#define COLOR_CYANHB "\e[0;106m"
#define COLOR_WHITEHB "\e[0;107m"

/* High intensity text */
#define COLOR_HBLACK "\e[0;90m"
#define COLOR_HRED "\e[0;91m"
#define COLOR_HGREEN "\e[0;92m"
#define COLOR_HYELLOW "\e[0;93m"
#define COLOR_HBLUE "\e[0;94m"
#define COLOR_HMAGENTA "\e[0;95m"
#define COLOR_HCYAN "\e[0;96m"
#define COLOR_HWHITE "\e[0;97m"

/* Bold high intensity text */
#define COLOR_BHBLACK "\e[1;90m"
#define COLOR_BHRED "\e[1;91m"
#define COLOR_BHGREEN "\e[1;92m"
#define COLOR_BHYELLOW "\e[1;93m"
#define COLOR_BHBLUE "\e[1;94m"
#define COLOR_BHMAGENTA "\e[1;95m"
#define COLOR_BHCYAN "\e[1;96m"
#define COLOR_BHWHITE "\e[1;97m"

#define COLOR_RESET "\e[0m"

#endif /* _ANSI_COLORS_H */
