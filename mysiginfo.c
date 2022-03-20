#define _GNU_SOURCE
#include "debugger.h"

//TODO: faire pour tous les signaux de bits/siginfo-consts.h
//		en pensant que les codes des signaux sont différents
//		suivant les ordis.

void which_sigcode(siginfo_t *sig)
{
	if(!strcmp(sigabbrev_np(sig->si_signo), "TRAP"))
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
	else if(!strcmp(sigabbrev_np(sig->si_signo), "SEGV"))
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
	else if(!strcmp(sigabbrev_np(sig->si_signo), "ILL"))
	{
		switch(sig->si_code)
		{
			case ILL_ILLOPC :
				printf("Illegal opcode.\n");
				break;
			case ILL_ILLOPN :
				printf("Illegal operand.\n");
				break;
			case ILL_ILLADR :
				printf("Illegal addressing mode.\n");
				break;
			case ILL_ILLTRP :
				printf("Illegal trap.\n");
				break;
			case ILL_PRVOPC :
				printf("Privileged opcode.\n");
				break;
			case ILL_PRVREG :
				printf("Privileged register.\n");
				break;
			case ILL_COPROC :
				printf("Coprocessor error.\n");
				break;
			case ILL_BADSTK :
				printf("Internal stack error.\n");
				break;
			case ILL_BADIADDR :
				printf("Unimplemented instruction address.\n");
				break;
			default:
				printf("Unknown SIGILL code.\n");
		}
	}
	else if(!strcmp(sigabbrev_np(sig->si_signo), "FPE"))
	{
		switch(sig->si_code)
		{
			case FPE_INTDIV :
				printf("Integer divide by zero.\n");
				break;
			case FPE_INTOVF :
				printf("Integer overflow.\n");
				break;
			case FPE_FLTDIV :
				printf("Floating point divide by zero.\n");
				break;
			case FPE_FLTOVF :
				printf("Floating point overflow.\n");
				break;
			case FPE_FLTUND :
				printf("Floating point underflow.\n");
				break;
			case FPE_FLTRES :
				printf("Floating point inexact result.\n");
				break;
			case FPE_FLTINV :
				printf("Floating point invalid operation.\n");
				break;
			case FPE_FLTSUB :
				printf("Subscript out of range.\n");
				break;
			case FPE_FLTUNK :
				printf("Undiagnosed floating point exception.\n");
				break;
			case FPE_CONDTRAP :
				printf("Trap on condition.\n");
				break;
			default:
				printf("Unknown SIGFPE code.\n");
		}
	}
	else if(!strcmp(sigabbrev_np(sig->si_signo), "BUS"))
	{
		switch(sig->si_code)
		{
			case BUS_ADRALN :
				printf("Invalid address alignment.\n");
				break;
			case BUS_ADRERR :
				printf("Non-existant physical address.\n");
				break;
			case BUS_OBJERR :
				printf("Object specific hardware error.\n");
				break;
			case BUS_MCEERR_AR :
				printf("Hardware memory error: action required.\n");
				break;
			case BUS_MCEERR_AO :
				printf("Hardware memory error: action optional.\n");
				break;
			default:
				printf("Unknown SIGBUS code.\n");
		}
	}
	else if(!strcmp(sigabbrev_np(sig->si_signo), "CHLD"))
	{
		switch(sig->si_code)
		{
			case CLD_EXITED :
				printf("Child has exited.\n");
				break;
			case CLD_KILLED :
				printf("Child was killed.\n");
				break;
			case CLD_DUMPED :
				printf("Child terminated abnormally.\n");
				break;
			case CLD_TRAPPED :
				printf("Traced child has trapped.\n");
				break;
			case CLD_STOPPED :
				printf("Child has stopped.\n");
				break;
			case CLD_CONTINUED :
				printf("Stopped child has continued.\n");
				break;
			default:
				printf("Unknown SIGCHLD code.\n");
		}
	}
	else if(!strcmp(sigabbrev_np(sig->si_signo), "POLL"))
	{
		switch(sig->si_code)
		{
			case POLL_IN :
				printf("Data input available.\n");
				break;
			case POLL_OUT :
				printf("Output buffers available.\n");
				break;
			case POLL_MSG :
				printf("Input message available.\n");
				break;
			case POLL_ERR :
				printf("I/O error.\n");
				break;
			case POLL_PRI :
				printf("High priority input available.\n");
				break;
			case POLL_HUP :
				printf("Device disconnected.\n");
				break;
			default:
				printf("Unknown SIGPOLL code.\n");
		}
	}
	else
		printf("No data about code of signal SIG%s\n", sigabbrev_np(sig->si_signo));
}