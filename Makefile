CC?=gcc

all: program

program: main.c
	$(CC) $< -o $@

clean:
	rm -f program

.PHONY: clean