CC = gcc

all: debug test

debug: main.c
	$(CC) $< -o $@

test: test.c
	$(CC) $< -o $@

clean:
	rm -f debug test child_status.txt child_maps.txt

.PHONY: clean test debug