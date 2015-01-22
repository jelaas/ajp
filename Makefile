CC=musl-gcc-x86_32
CFLAGS=-Wall -std=c99 -D_POSIX_SOURCE

all:	ajp
ajp:	ajp.o jelopt.o skbuff.o jelist.o ttcp.o
clean:	
	rm -f *.o ajp
