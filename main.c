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
		long orig_eax, prev_rip = 0;
		long ins;
		struct user_regs_struct regs;
		int i = 0;
		while(1)
		{
			if(waitchild(child))
				break;

			getregs(child, &regs);
			ins = ptrace(PTRACE_PEEKTEXT, child, regs.rip, NULL);

			print_mainregs(&regs);

			ptrace(PTRACE_SYSCALL, child, NULL, NULL);
		}
		
		// ptrace(PTRACE_CONT, child, NULL, NULL);

		putchar('\n');
		
		char str[30] = "";
		snprintf(str, 30, "/proc/%d/maps", child);
		// cp("info_dir/child_status.txt", str);

		// strcpy(str, "");
		// snprintf(str, 30, "/proc/%d/maps", child);
		// cp("info_dir/child_maps.txt", str);
		readfile(str, PRINT);
	}

	return 0;
}
