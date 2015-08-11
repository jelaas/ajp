CC=musl-gcc-x86_32
CFLAGS=-Wall -std=c99 -D_POSIX_SOURCE

all:	ajp
ajp:	ajp.o jelopt.o skbuff.o jelist.o ttcp.o
clean:	
	rm -f *.o ajp
rpm:	ajp
	bar -c --license=GPLv2+ --name ajp ajp-1.2-1.rpm --prefix=/usr/bin --fuser=root --fgroup=root --version=1.2 --release=1 ajp
