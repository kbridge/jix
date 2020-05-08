.PHONY: all clean

CFLAGS=-Wall -g
LDFLAGS=-lole32 -loleaut32 -luuid -lcabinet

all: jix.exe

jix.exe: jix.o miniz.o
	gcc -o jix.exe jix.o miniz.o $(LDFLAGS)

jix.o: jix.c
	gcc $(CFLAGS) -c jix.c

miniz.o: miniz.c miniz.h
	gcc $(CFLAGS) -c miniz.c

clean:
	del *.o
	del jix.exe
