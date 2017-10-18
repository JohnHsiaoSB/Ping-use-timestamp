CC=gcc

PROG=ping
all:
	${CC} -o ${PROG} ${PROG}.c

clean:
	rm -f ${PROG} ${PROG}.o

