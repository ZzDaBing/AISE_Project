#define _GNU_SOURCE
#include "debugger.h"

//TODO: faire pour tous les signaux de bits/siginfo-consts.h
//		en pensant que les codes des signaux sont différents
//		suivant les ordis.

void which_sigcode(siginfo_t *sig)
{
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

}