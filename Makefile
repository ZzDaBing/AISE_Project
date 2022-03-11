CC?=gcc

all: program test

program: main.c
	$(CC) $< -o $@

test: test.c
	$(CC) $< -o $@

clean:
	rm -f program test

.PHONY: clean