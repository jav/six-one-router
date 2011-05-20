all: main

LIBS=-lpcap
GCC_OPTS=-ggdb
DEFS=-DDBG

main: list.o queue.o debug_pktheaders.o sixonetypes.o sixonelib.o main.o
	gcc ${GCC_OPTS} ${DEFS} ${LIBS} -pthread list.o queue.o debug_pktheaders.o sixonetypes.o sixonelib.o main.o -o sixone

main.o: main.c
	gcc ${GCC_OPTS} ${DEFS} -c main.c

sixonelib.o: sixonelib/sixonelib.c
	gcc ${GCC_OPTS} ${DEFS} -pthread -c sixonelib/sixonelib.c

sixonetypes.o: sixonelib/sixonetypes.c
	gcc ${GCC_OPTS} ${DEFS} -c sixonelib/sixonetypes.c

debug_pktheaders.o: sixonelib/debug_pktheaders.c
	gcc ${GCC_OPTS} ${DEFS} -c sixonelib/debug_pktheaders.c

queue.o: sixonelib/queue/queue.c
	gcc ${GCC_OPTS} ${DEFS} -c sixonelib/queue/queue.c

list.o: sixonelib/queue/list.c
	gcc ${GCC_OPTS} ${DEFS} -c sixonelib/queue/list.c

clean:
	rm -rf *.o sixone
