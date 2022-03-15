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
#include <errno.h>

// si_code values for SIGTRAP signal
#define TRAP_BRKPT  1	// Process breakpoint
#define TRAP_TRACE  2  	// Process trace trap
#define TRAP_BRANCH 3  	// Process taken branch trap
#define TRAP_HWBKPT 4  	// Hardware breakpoint/watchpoint			
#define TRAP_UNK	5	// Undiagnosed trap

//function to copy a src_file to dest_file
int cp(const char *to, const char *from)
{
    int fd_to, fd_from;
    char buf[4096];
    ssize_t nread;
    int saved_errno;

    fd_from = open(from, O_RDONLY);
    if (fd_from < 0)
        return -1;

    fd_to = open(to, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd_to < 0)
        goto out_error;

    while (nread = read(fd_from, buf, sizeof buf), nread > 0)
    {
        char *out_ptr = buf;
        ssize_t nwritten;

        do {
            nwritten = write(fd_to, out_ptr, nread);

            if (nwritten >= 0)
            {
                nread -= nwritten;
                out_ptr += nwritten;
            }
            else if (errno != EINTR)
            {
                goto out_error;
            }
        } while (nread > 0);
    }

    if (nread == 0)
    {
        if (close(fd_to) < 0)
        {
            fd_to = -1;
            goto out_error;
        }
        close(fd_from);

        /* Success! */
        return 0;
    }

  out_error:
    saved_errno = errno;

    close(fd_from);
    if (fd_to >= 0)
        close(fd_to);

    errno = saved_errno;
    return -1;
}

//print information for signal passed in argument
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
				/*case SEGV_MTEAERR :
					printf("Asynchronous ARM MTE error.\n");
					break;
				case SEGV_MTESERR :
					printf("Synchronous ARM MTE exception.\n");
					break;*/
				default:
					printf("Unknown SIGSEGV code.\n");
			}
		}
		putchar('\n');
}

int main(int argc, char const *argv[])
{
	//print the pid of current processus and his parent
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

	if(child == 0){	//child
		void* start = NULL;
		int i, fd;
		struct stat stat;
		char *strtab;
		int nb_symbols;

		fd = open(argv[1], O_RDONLY, 660);
		if(fd < 0)
			perror("open");

		// get file's size
		fstat(fd, &stat);

		//file mmap
		start = mmap(0, stat.st_size, PROT_READ , MAP_FILE | MAP_SHARED, fd, 0);
		if(start == MAP_FAILED)
		{
			perror("mmap");
			abort();
		}

		Elf64_Ehdr* hdr = (Elf64_Ehdr *) start;
		Elf64_Sym* symtab;

		//print 4 bytes
		printf("Check four first bytes: %x '%x' '%x' '%x'\n", *(char*)start,*((char*)start+1), *((char*)start+2), *((char*)start+3));


		//offset where are headers sections
		Elf64_Shdr* sections = (Elf64_Shdr *)((char *)start + hdr->e_shoff);

		//course of the sections
		for (i = 0; i < hdr->e_shnum; i++)
		{
			//if symbol table
			if (sections[i].sh_type == SHT_SYMTAB) {
				symtab = (Elf64_Sym *)((char *)start + sections[i].sh_offset);
				nb_symbols = sections[i].sh_size / sections[i].sh_entsize;

				//get pointer table
				strtab = (char*)((char*)start + sections[sections[i].sh_link].sh_offset);

			}
		}

		for (i = 0; i < nb_symbols; ++i) {
			printf("%d: %s\n", i, strtab + symtab[i].st_name);
			printf("info : %s\n", strtab + symtab[i].st_info);
			printf("value : 0x%llx\n", strtab + symtab[i].st_value);
		}

		//Offset where are program headers
		Elf64_Phdr* phdr = (Elf64_Phdr *)((char*)start + hdr->e_phoff);
		//course of the sections
		for (i = 0; i < hdr->e_phnum; i++)
		{
			//LOAD 
			/*if (phdr[i].p_type == PT_LOAD) {
				symtab = (Elf64_Sym *)((char *)start + sections[i].sh_offset);
				nb_symbols = sections[i].sh_size / sections[i].sh_entsize;

				//get pointer table
				strtab = (char*)((char*)start + sections[sections[i].sh_link].sh_offset);

			}*/
			//printf("phdr %d: %s\n", i, (char*)phdr[i].p_type);
		}

		munmap(start, stat.st_size);
		close(fd);

		//Debugger

		//print pid of current processu (child) and its parent
		printf("Child  PID = %d and PPID = %d\n", getpid(), getppid());

		printf("Debugger tracing %d\n", getpid());
		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
		{
			perror("ptrace_traceme");
			exit(EXIT_FAILURE);
		}

		//running program to debug
		printf("Running %s\n\n", cmd);
		if(execvp(eargv[0], eargv) == -1)
		{
			perror("execvp");
			exit(EXIT_FAILURE);
		}
	}
	else{	//father

		//Variable declarations
		struct user_regs_struct regs;
		unsigned int rip;

		//check if can trace child
		if(waitpid(child, &wait_status, 0) == -1)
		{
			perror("waitpid");
			exit(EXIT_FAILURE);
		}

		if(WIFSTOPPED(wait_status))
        {
            printf("Waitpid : Received signal n°%d.\n" , (int) WSTOPSIG(wait_status));
        }

        //get infos from the tracee
        ptrace(PTRACE_GETREGS, child, &regs.rip, rip);
		rip = ptrace(PTRACE_PEEKTEXT, child, regs.rip, NULL);
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

		//copy /proc//status file and /proc//maps file of child processus in new files in info_dir
		char str[30] = "";
		int pid_child = (int) child;
		sprintf(str, "/proc/%d/status", pid_child);
		cp("info_dir/child_status.txt", str);

		strcpy(str, "");
		sprintf(str, "/proc/%d/maps", pid_child);
		cp("info_dir/child_maps.txt", str);
	}

	return 0;
}
