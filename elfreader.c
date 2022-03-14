#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>

int main(int argc, char **argv)
{
	void *start = NULL;
	int i, fd;
	struct stat stat;
	char *strtab;
	int nb_symbols;

	fd = open("./test", O_RDONLY, 660);
	if(fd < 0)
		perror("open");

	fstat(fd, &stat);

	start = mmap(0, stat.st_size, PROT_READ , MAP_FILE | MAP_SHARED, fd, 0);
	if(start == MAP_FAILED)
	{
		perror("mmap");
		abort();
	}

	Elf64_Ehdr* hdr = (Elf64_Ehdr *) start;
	Elf64_Sym* symtab;
	Elf64_Shdr* sections = (Elf64_Shdr *)((char *)start + hdr->e_shoff);

	printf("Check four first bytes: %x '%c' '%c' '%c'\n", *(char*)start,*((char*)start+1), *((char*)start+2), *((char*)start+3));

	for (i = 0; i < hdr->e_shnum; i++)
	{
		if (sections[i].sh_type == SHT_SYMTAB)
		{
			symtab = (Elf64_Sym *)((char *)start + sections[i].sh_offset);
			nb_symbols = sections[i].sh_size / sections[i].sh_entsize;
			strtab = (char*)((char*)start + sections[sections[i].sh_link].sh_offset);
		}
	}

	for (i = 0; i < nb_symbols; ++i) {
		printf("%d: %s\n", i, strtab + symtab[i].st_name);
	}



	return 0;
}