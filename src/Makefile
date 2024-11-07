#
# Build tested on Ubuntu 22.04.2 LTS
#

CC		= cc
CFLAGS	= -Wall -I/usr/local/include 
OBJS	= nfscli.o net.o nfsh.o str.o portmap.o print.o mount.o nfsv3.o \
			explore.o ansicolors.o
LIBS	= -L/usr/local/lib -lreadline -ltinfo
EXE		= 516-nfscli

none: all

all: ${OBJS}
	${CC} -o ${EXE} ${OBJS} ${LIBS} 

clean:
	rm -f ${OBJS} ${EXE}

static: ${OBJS}
	${CC} -s -o ${EXE} ${OBJS} ${LIBS} -static

new: clean all
