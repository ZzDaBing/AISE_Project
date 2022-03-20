#pragma once

#define UNW_LOCAL_ONLY

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bits/siginfo-consts.h>
#include <bits/types/siginfo_t.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <capstone/capstone.h>
#include <link.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/auxv.h>
#include <libunwind.h>
#include <sys/stat.h>
#include <sys/mman.h>

enum {READ=0, PRINT, REPR};

void which_sigcode(siginfo_t *sig);
void mysyscall(long orig);
void run_exec(char *argv);
void sig_detail(pid_t pid);
int waitchild(pid_t pid);
void getregs(pid_t pid, struct user_regs_struct *regs);
void print_allregs(struct user_regs_struct *regs);
void print_mainregs(struct user_regs_struct *regs);
int cp(const char *to, const char *from);
char **readfile(char *path, _Bool print);
void backtrace();
