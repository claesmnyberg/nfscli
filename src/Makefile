#
# Build tested on Ubuntu 22.04.2 LTS
#

CC     = cc
LIBS   = -L/usr/local/lib -lreadline -ltinfo -lm -static
EXE    = 516-nfscli

# Compiler warning flags
WFLAGS = -Wall -Wextra -Wshadow -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes

# Detect stack protector support (prefer -strong, fall back to basic)
STACK_PROT := $(shell $(CC) -fstack-protector-strong -x c -c -o /dev/null /dev/null >/dev/null 2>&1 \
              && echo "-fstack-protector-strong" \
              || ($(CC) -fstack-protector -x c -c -o /dev/null /dev/null >/dev/null 2>&1 \
                  && echo "-fstack-protector" || echo ""))

# Hardening flags (FORTIFY_SOURCE requires -O1 or higher)
HARDEN = -D_FORTIFY_SOURCE=2 $(STACK_PROT)

CFLAGS = $(WFLAGS) $(HARDEN) -O2 -I/usr/local/include

OBJS = browse.o browse_cmd_dir.o browse_cmd_file.o browse_cmd_misc.o     \
       browse_cmd_text.o browse_expand.o browse_pipe.o browse_redir.o    \
       cmdparse.o completion.o display.o explore.o find.o grep.o idmap.o \
       mount.o net.o nfs.o nfs_cache.o nfs_escape.o nfs_util.o nfscli.o  \
       nfsh.o nfsh_cmds.o nfsv2.o nfsv3.o pathctx.o portmap.o portmapv2.o \
       portmapv3.o print.o rpc.o str.o transfer.o

.PHONY: all clean new tidy norl norl-static

all: ${OBJS}
	${CC} -o ${EXE} ${OBJS} ${LIBS}

clean:
	rm -f ${OBJS} ${EXE}

new: clean all

tidy:
	clang-format -i *.c *.h

# No-readline build (minimal dependencies)
norl: clean
	${MAKE} CFLAGS="${CFLAGS} -DNO_READLINE" LIBS="" all

norl-static: clean
	${MAKE} CFLAGS="${CFLAGS} -DNO_READLINE" LIBS="" _norl-static

_norl-static: ${OBJS}
	${CC} -s -o ${EXE} ${OBJS} -static
