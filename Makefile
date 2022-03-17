CC = gcc

all: debug test

debug: main.c
	rm -rf info_dir
	mkdir info_dir
	$(CC) $< -o $@

test: test.c
	$(CC) $< -o $@

clean:
	rm -f debug test info_dir/child_status.txt info_dir/child_maps.txt
	rmdir info_dir

.PHONY: clean test debug