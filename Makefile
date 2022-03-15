CC = gcc

LIB = -lcapstone

all : debug test testcap

debug : main.c debugger.c mysyscall.c mysiginfo.c
	$(CC) $^ -o $@ $(LIB)

test : test.c
	$(CC) $^ -o $@

testcap : testcap.c
	$(CC) $^ -o $@ $(LIB)

clean :
	rm test debug