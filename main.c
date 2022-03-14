#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bits/types/siginfo_t.h>
#include <bits/siginfo-consts.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <capstone/capstone.h>

#include "mysyscall.h"

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

void flush(FILE* in)
{
   int c;
   while ( (c = fgetc(in)) != EOF && c != '\n');
}

int main(int argc, char **argv)
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

	if(child == 0)
	{	
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
		// char tap = 'c';
		// int i = 0;
		long orig_eax;
		long ins;
		struct user_regs_struct regs;
		int i = 0;
		while(i < 100)
		{
			if(waitpid(child, &wait_status, 0) == -1)
			{
				perror("waitpid");
				exit(EXIT_FAILURE);
			}

			if(WIFSTOPPED(wait_status))
	        {
	            //printf("Waitpid : Received signal n°%d.\n" , (int) WSTOPSIG(wait_status));
	            // sleep(1);
	        }

			ptrace(PTRACE_GETREGS, child, NULL, &regs);
			ins = ptrace(PTRACE_PEEKTEXT, child, regs.rip, NULL);
			

			if(i%2 == 0)
				mysyscall(regs.orig_rax);
			// // printf("r15 = %.16llx\n", regs.r15);
			// // printf("r14 = %.16llx\n", regs.r14);
			// // printf("r13 = %.16llx\n", regs.r13);
			// // printf("r12 = %.16llx\n", regs.r12);
			printf("RBP = %.16llx RSP = %.16llx RIP = %.16llx\n", regs.rbp, regs.rsp, regs.rip);
			// printf("rax = %.16llx\n", regs.rax);
			// printf("rbx = %.16llx\n", regs.rbx);
			// printf("rcx = %.16llx\n", regs.rcx);
			// printf("rdx = %.16llx\n", regs.rdx);
			// printf("rsi = %.16llx\n", regs.rsi);
			// printf("rdi = %.16llx\n", regs.rdi);
			// // printf("r11 = %.16llx\n", regs.r11);
			// // printf("r10 = %.16llx\n", regs.r10);
			// // printf("r9 = %.16llx\n", regs.r9);
			// // printf("r8 = %.16llx\n", regs.r8);
			// printf("orig_rax = %.16llx\n", regs.orig_rax);
			// printf("cs = %.16llx\n", regs.cs);
			//printf("eflags = %.16llx\n\n", regs.eflags);
			// printf("ss = %.16llx\n", regs.ss);
			// // printf("fs_base = %.16llx\n", regs.fs_base);
			// // printf("gs_base = %.16llx\n", regs.gs_base);
			// // printf("ds = %.16llx\n", regs.ds);
			// // printf("es = %.16llx\n", regs.es);
			// // printf("fs = %.16llx\n", regs.fs);
			// // printf("gs = %.16llx\n", regs.gs);
			// printf("RIP: %.16llx Instruction executed: %.16lx\n\n", regs.rip, ins);


			// if(regs.orig_rax == SYS_execve)
			// {
			// 	printf("The child made a syscall %lld\n", regs.orig_rax);
			// 	ptrace(PTRACE_SINGLESTEP, child, 0, 0);
			// }
			// else
			ptrace(PTRACE_SYSCALL, child, NULL, NULL);

			// tap = getchar();
			// if(tap == (char)'q')
			// 	break;
			i++;
		}

		if(waitpid(child, &wait_status, 0) == -1)
		{
			perror("waitpid");
			exit(EXIT_FAILURE);
		}

		if(WIFSTOPPED(wait_status))
        {
            printf("Waitpid : Received signal n°%d.\n" , (int) WSTOPSIG(wait_status));
        }

		// ptrace(PTRACE_GETSIGINFO, child, NULL, &sig);
		// printf("Ptrace --> ");
		// printf("Signal number = %d\n", sig.si_signo);
		// printf("\t   Signal code = %d\n", sig.si_code);
		
		// which_sigcode(&sig);
		
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

		// ptrace(PTRACE_GETSIGINFO, child, NULL, &sig);
		// printf("Ptrace --> ");
		// printf("Signal number = %d\n", sig.si_signo);
		// printf("\t   Signal code = %d\n", sig.si_code);
		// printf("\t   Memory location (fault) = 0x%x\n", sig.si_addr);

		// which_sigcode(&sig);
		// char str[6];
		// snprintf(str, 6, "%d", child);
		// char * const eargv2[] = {"pmap","-X", str, NULL};
		// if(execvp(eargv2[0], eargv2) == -1)
		// {
		// 	perror("execvp");
		// 	exit(EXIT_FAILURE);
		// }
}

	return 0;
}
