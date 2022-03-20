#define _GNU_SOURCE

#include "debugger.h"

int main(int argc, char **argv)
{
	fprintf(stderr, "Parent PID = %d and PPID = %d\n", getpid(), getppid());
	if(argc != 2)
		return printf("Error arg : ./debug <executable>\n"), 1;

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

		run_exec(argv[1]);
	}
	else
	{
		struct user_regs_struct regs;
		uint64_t orig_opcode;

		while(1)
		{
			if(waitchild(child))
				break;

			getregs(child, &regs);
			//print_mainregs(&regs);

			orig_opcode = ptrace(PTRACE_PEEKTEXT, child, regs.rip, NULL);

		    // getchar();
			ptrace(PTRACE_SYSCALL, child, NULL, NULL);
		}

		putchar('\n');
		
		char str[30] = "";
		snprintf(str, 30, "/proc/%d/stat", child);
		// cp("info_dir/child_status.txt", str);
		readfile(str, PRINT);
		putchar('\n');
		strcpy(str, "");
		snprintf(str, 30, "/proc/%d/maps", child);
		// cp("info_dir/child_maps.txt", str);
		readfile(str, PRINT);
	}

	return 0;
}
