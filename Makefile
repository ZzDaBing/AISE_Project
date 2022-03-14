CC = gcc

all: debug test

debug: main.c
	$(CC) $< -o $@

test: test.c
	$(CC) $< -o $@

clean:
	rm -f debug test info_dir/child_status.txt info_dir/child_maps.txt

.PHONY: clean test debug