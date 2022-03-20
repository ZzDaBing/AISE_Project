CC = gcc

LIB = -lcapstone -lunwind

all : debug test testcap

debug: main.c debugger.c mysyscall.c mysiginfo.c
	rm -rf info_dir
	mkdir info_dir
	$(CC) $^ -o $@ $(LIB)

test : test.c
	$(CC) $^ -o $@

testcap : testcap.c
	$(CC) $^ -o $@ $(LIB)

clean:
	rm -f debug test testcap info_dir/child_status.txt info_dir/child_maps.txt
	rmdir info_dir

.PHONY: clean test testcap debug
