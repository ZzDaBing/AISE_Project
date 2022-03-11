#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/user.h>

int waitchild(pid_t pid) {
    int status;
    waitpid(pid, &status, 0);
    if(WIFSTOPPED(status)) {
        return 0;
    }
    else if (WIFEXITED(status)) {
        return 1;
    }
    else {
        printf("%d raised an unexpected status %d", pid, status);
        return 1;
    }
}

int main(int argc, char const *argv[])
{
	/*if(!argv[1]){
		printf("No executable passed in argument\n");
		return 1;
	}*/

	pid_t child = fork();

	if(child == 0){
		void* start = NULL;
		int i, fd;
		struct stat stat;
		char *strtab;
		int nb_symbols;

		fd = open(argv[1], O_RDONLY, 660);
		if(fd < 0)
			perror("open");

		// récupération de la taille du fichier
		fstat(fd, &stat);

		//projection du fichier (MAP_SHARED importe peu ici)
		start = mmap(0, stat.st_size, PROT_READ , MAP_FILE | MAP_SHARED, fd, 0);
		if(start == MAP_FAILED)
		{
			perror("mmap");
			abort();
		}

		// le premier octet mappé est le premier octet du fichier ELF
		// Via un cast, on va pouvoir manipuler le fichier ELF mappé en mémoire
		Elf64_Ehdr* hdr = (Elf64_Ehdr *) start;
		Elf64_Sym* symtab;

		// Affiche les 4 premiers octets
		printf("Check four first bytes: %x '%c' '%c' '%c'\n", *(char*)start,*((char*)start+1), *((char*)start+2), *((char*)start+3));


		// le header contient un champ donnant l'offset (en octet) où se trouve
		// les sections headers
		Elf64_Shdr* sections = (Elf64_Shdr *)((char *)start + hdr->e_shoff);

		// parcours des sections
		for (i = 0; i < hdr->e_shnum; i++)
		{
			// si la section courante est de type 'table de symbole'
			if (sections[i].sh_type == SHT_SYMTAB) {
				symtab = (Elf64_Sym *)((char *)start + sections[i].sh_offset);
				nb_symbols = sections[i].sh_size / sections[i].sh_entsize;

				//recup pointeur sur tableau 
				strtab = (char*)((char*)start + sections[sections[i].sh_link].sh_offset);

			}
		}

		// on parcourt alors la table des symboles
		// pour chaque entrée, le champ st_name est un offset en octet depuis 
		// le début du tableau où se trouve le nom.
		for (i = 0; i < nb_symbols; ++i) {
			//printf("%d: %s\n", i, strtab + symtab[i].st_name);
		}
		close(fd);

		char tmp[20] = "./";
		strcat(tmp, argv[1]);

		//Processus laisse le controle au processus pere
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		
		execvp(tmp, NULL);
		//execl("/bin/ls","ls", NULL);
	}
	else{
		printf("waiting for the child to stop\n");
		while(waitchild(child)){
			ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
		}

		ptrace(PTRACE_CONT, child, NULL, NULL);
		waitchild(child);
	}

	return 0;
}