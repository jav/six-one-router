all: main

LIBS=-lpcap
GCC_OPTS=-ggdb
DEFS=-DDBG
INC=-Iinclude

main: debug_pktheaders.o sixonetypes.o sixonelib.o main.o
	gcc ${GCC_OPTS} ${DEFS} ${LIBS} ${INC} -pthread debug_pktheaders.o sixonetypes.o sixonelib.o main.o -o bin/sixone

main.o: src/main.c
	gcc ${GCC_OPTS} ${DEFS} ${INC} -c src/main.c

sixonelib.o: src/sixonelib.c
	gcc ${GCC_OPTS} ${DEFS} ${INC} -pthread -c src/sixonelib.c

sixonetypes.o: src/sixonetypes.c
	gcc ${GCC_OPTS} ${DEFS} ${INC} -c src/sixonetypes.c

debug_pktheaders.o: src/debug_pktheaders.c
	gcc ${GCC_OPTS} ${DEFS} ${INC} -c src/debug_pktheaders.c

clean:
	rm -rf bin/*.o bin/sixone
