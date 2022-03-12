#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bits/types/siginfo_t.h>
#include <bits/siginfo-consts.h>
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

// si_code values for SIGTRAP signal
#define TRAP_BRKPT  1	// Process breakpoint
#define TRAP_TRACE  2  	// Process trace trap
#define TRAP_BRANCH 3  	// Process taken branch trap
#define TRAP_HWBKPT 4  	// Hardware breakpoint/watchpoint			
#define TRAP_UNK	5	// Undiagnosed trap

void which_sigcode(siginfo_t *sig)
{
	printf("Error : ");
	if(sig->si_signo== 5)
		{
			switch(sig->si_code)
			{
				case TRAP_BRKPT :
					printf("Process breakpoint.\n");
					break;
				case TRAP_TRACE :
					printf("Process trace trap.\n");
					break;
				case TRAP_BRANCH :
					printf("Process taken branch trap.\n");
					break;
				case TRAP_HWBKPT :
					printf("Hardware breakpoint/watchpoint. \n");
					break;
				case TRAP_UNK :
					printf("Undiagnosed trap.\n");
					break;
				default:
					printf("Unknown SIGTRAP code.\n");
			}
		}
		else if(sig->si_signo == 11)
		{
			switch(sig->si_code)
			{
				case SEGV_MAPERR :
					printf("Address not mapped to object.\n");
					break;
				case SEGV_ACCERR :
					printf("Invalid permissions for mapped object.\n");
					break;
				case SEGV_BNDERR :
					printf("Bounds checking failure.\n");
					break;
				case SEGV_PKUERR :
					printf("Protection key checking failure.\n");
					break;
				case SEGV_ACCADI :
					printf("ADI not enabled for mapped object.\n");
					break;
				case SEGV_ADIDERR :
					printf("Disrupting MCD error.\n");
					break;
				case SEGV_ADIPERR :
					printf("Precise MCD exception.\n");
					break;
				case SEGV_MTEAERR :
					printf("Asynchronous ARM MTE error.\n");
					break;
				case SEGV_MTESERR :
					printf("Synchronous ARM MTE exception.\n");
					break;
				default:
					printf("Unknown SIGSEGV code.\n");
			}
		}
		putchar('\n');
}

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
	fprintf(stderr, "Parent PID = %d and PPID = %d\n", getpid(), getppid());
	if(argc != 2)
		return printf("Error arg : ./debug <executable>\n"), 1;

	// Argument is <executable> or ./<executable> at choice
	size_t len = strlen(argv[1]);
	int offset = 2;
	if(argv[1][0] == (char)'.' && argv[1][1] == (char)'/')
		offset = 0;
	char cmd[offset+len];
	if(offset == 2)
	{
		strncpy(cmd, "./", offset);
		strncat(cmd, argv[1], len);
	}
	else if(offset == 0)
		strncpy(cmd, argv[1], len);
	char * const eargv[] = {cmd, NULL};

	siginfo_t sig;
	int wait_status;

	pid_t child = fork();
	if(child == -1)
	{
		perror("fork");
		exit(EXIT_FAILURE);
	}

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
		munmap(start, stat.st_size);
		close(fd);

		// debugger
		printf("Child  PID = %d and PPID = %d\n", getpid(), getppid());

		printf("Debugger tracing %d\n", getpid());
		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
		{
			perror("ptrace_traceme");
			exit(EXIT_FAILURE);
		}

		printf("Running %s\n\n", cmd);
		if(execvp(eargv[0], eargv) == -1)
		{
			perror("execvp");
			exit(EXIT_FAILURE);
		}
	}
	else
	{
		if(waitpid(child, &wait_status, 0) == -1)
		{
			perror("waitpid");
			exit(EXIT_FAILURE);
		}

		if(WIFSTOPPED(wait_status))
        {
            printf("Waitpid : Received signal n°%d.\n" , (int) WSTOPSIG(wait_status));
        }

		ptrace(PTRACE_GETSIGINFO, child, NULL, &sig);
		printf("Ptrace --> ");
		printf("Signal number = %d\n", sig.si_signo);
		printf("\t   Signal code = %d\n", sig.si_code);
		
		which_sigcode(&sig);
		
		ptrace(PTRACE_CONT, child, NULL, NULL);

		wait_status = 0;
		if(waitpid(child, &wait_status, 0) == -1)
		{
			perror("waitpid");
			exit(EXIT_FAILURE);
		}

		if(WIFSTOPPED(wait_status))
        {
            printf("Waitpid : Received signal n°%d.\n" , (int) WSTOPSIG(wait_status));
        }

		ptrace(PTRACE_GETSIGINFO, child, NULL, &sig);
		printf("Ptrace --> ");
		printf("Signal number = %d\n", sig.si_signo);
		printf("\t   Signal code = %d\n", sig.si_code);
		printf("\t   Memory location (fault) = 0x%x\n", sig.si_addr);

		which_sigcode(&sig);
	}

	return 0;
}
