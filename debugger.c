#define _GNU_SOURCE
#include "debugger.h"

void run_exec(char *argv)
{
	// set executable command
	size_t len = strlen(argv);
	int offset = 2;

	if(argv[0] == (char)'.' && argv[1] == (char)'/')
		offset = 0;

	char cmd[offset+len];

	if(offset == 2)
	{
		strncpy(cmd, "./", offset);
		strncat(cmd, argv, len);
	}
	else if(offset == 0)
		strncpy(cmd, argv, len);

	char * const eargv[] = {cmd, NULL};

	printf("Running %s\n\n", cmd);
	if(execvp(eargv[0], eargv) == -1)
	{
		perror("execvp");
		exit(EXIT_FAILURE);
	}
}

void sig_detail(pid_t pid)
{
	siginfo_t sig;
	ptrace(PTRACE_GETSIGINFO, pid, NULL, &sig);

	char *p = strsignal(sig.si_signo);
	//printf("%s\n", sigabbrev_np(sig.si_signo));
	printf("= SIG%s --> %s\n", sigabbrev_np(sig.si_signo), p);
	printf("Signal code = %d --> ", sig.si_code);
	which_sigcode(&sig);
	printf("Memory location (fault) = 0x%x\n", sig.si_addr);
}

int waitchild(pid_t pid)
{
    int status;
    if(waitpid(pid, &status, 0) == -1)
    {
    	perror("waitpid");
    	exit(EXIT_FAILURE);
    }

    if(WIFSTOPPED(status) && WSTOPSIG(status) != 5)
    {
    	printf("Waitpid : Receiving signal n°%d " , (int) WSTOPSIG(status));
    	sig_detail(pid);
    	return 1;
    }
    else if(WSTOPSIG(status) == 5)
        return 0;
    else if(WIFEXITED(status))
    {
        printf("Terminated normally\n");
        return 1;
    }
    else
    {
        printf("%d raised an unexpected status %d", pid, status);
        return -1;
    }
}

void getregs(pid_t pid, struct user_regs_struct *regs)
{
	ptrace(PTRACE_GETREGS, pid, NULL, regs);
}

void print_allregs(struct user_regs_struct *regs)
{
	printf("orig_rax = 0x%.4llx", regs->orig_rax);
	if(regs->orig_rax != 0xffffffffffffffff)
	{
		printf(" --> corresponding syscall: ");
		mysyscall(regs->orig_rax);
	}
	printf("\nRIP = 0x%.16llx\n", regs->rip);
	printf("rax = 0x%.16llx\n", regs->rax);
	printf("rbx = 0x%.16llx\n", regs->rbx);
	printf("rcx = 0x%.16llx\n", regs->rcx);
	printf("rdx = 0x%.16llx\n", regs->rdx);
	printf("rsi = 0x%.16llx\n", regs->rsi);
	printf("rdi = 0x%.16llx\n", regs->rdi);
	printf("rbp = 0x%.16llx\n", regs->rbp);
	printf("rsp = 0x%.16llx\n", regs->rsp);
	printf("r8 = 0x%.16llx\n", regs->r8);
	printf("r9 = 0x%.16llx\n", regs->r9);
	printf("r10 = 0x%.16llx\n", regs->r10);
	printf("r11 = 0x%.16llx\n", regs->r11);
	printf("r12 = 0x%.16llx\n", regs->r12);
	printf("r13 = 0x%.16llx\n", regs->r13);
	printf("r14 = 0x%.16llx\n", regs->r14);
	printf("r15 = 0x%.16llx\n", regs->r15);
	printf("eflags = 0x%.16llx\n\n", regs->eflags);
	printf("cs = 0x%.16llx\n", regs->cs);
	printf("ss = 0x%.16llx\n", regs->ss);
	printf("fs_base = 0x%.16llx\n", regs->fs_base);
	printf("gs_base = 0x%.16llx\n", regs->gs_base);
	printf("ds = 0x%.16llx\n", regs->ds);
	printf("es = 0x%.16llx\n", regs->es);
	printf("fs = 0x%.16llx\n", regs->fs);
	printf("gs = 0x%.16llx\n", regs->gs);
}

void print_mainregs(struct user_regs_struct *regs)
{
	printf("orig_rax = 0x%.4llx", regs->orig_rax);
	if(regs->orig_rax != 0xffffffffffffffff)
	{
		printf(" --> corresponding syscall: ");
		mysyscall(regs->orig_rax);
	}
	printf("\nRIP = 0x%.16llx\n", regs->rip);
	// printf("rax = 0x%.16llx\n", regs->rax);
	// printf("rbx = 0x%.16llx\n", regs->rbx);
	// printf("rcx = 0x%.16llx\n", regs->rcx);
	// printf("rdx = 0x%.16llx\n", regs->rdx);
	// printf("rsi = 0x%.16llx\n", regs->rsi);
	// printf("rdi = 0x%.16llx\n", regs->rdi);
	// printf("rbp = 0x%.16llx\n", regs->rbp);
	// printf("rsp = 0x%.16llx\n", regs->rsp);
}

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

char **readfile(char *path, _Bool print)
{
	char s[100];
	char *rfile = NULL;
	FILE *fd = fopen(path, "r");
	if(!fd)
	{
		perror("fopen");
		exit(EXIT_FAILURE);
    }
    
    if(print)
	    while(fgets(s, 100, fd) != NULL)
    		printf("%s", s);
    else
    {
    	while(fgets(s, 100, fd) != NULL)
    	{
    		//coming soon
    	}
    }

	fclose(fd);
	return NULL;
}

void backtrace() {
	unw_cursor_t cursor;
	unw_context_t context;

	// Initialize cursor to current frame for local unwinding.
	unw_getcontext(&context);
	unw_init_local(&cursor, &context);

	// Unwind frames one by one, going up the frame stack.
	while (unw_step(&cursor) > 0) 
	{
		unw_word_t offset, pc;
		unw_get_reg(&cursor, UNW_REG_IP, &pc);
		if (pc == 0)
		{
			break;
		}
		printf("0x%lx:", pc);

		char sym[256];
		if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset) == 0)
		{
			printf(" (%s+0x%lx)\n", sym, offset);
		}
		else
		{
			printf(" -- error: unable to obtain symbol name for this frame\n");
		}
	}
}
