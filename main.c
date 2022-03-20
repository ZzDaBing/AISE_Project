#define _GNU_SOURCE

#include "debugger.h"

int main(int argc, char **argv)
{
	//print the pid of current processus and his parent
	fprintf(stderr, "Parent PID = %d and PPID = %d\n", getpid(), getppid());
	if(argc != 2)
		return printf("Error arg : ./debug <executable>\n"), 1;

	pid_t child = fork();
	if(child == -1)
	{
		perror("fork");
		exit(EXIT_FAILURE);
	}

	if(child == 0) //child
	{	
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

		printf("\n========== Section Header ==========\n\n");
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

			printf("Section Header %d : \n", i);
			printf("\t.sh_name : %d,\n\t.sh_type : %x,\n\t.sh_flags : %x,\n\t.sh_addr : %x,\n\t.sh_offset : %x,\n\t.sh_size : %x,\n\t.sh_link : %x,\n\t.sh_info : %x,\n\t .sh_addralign : %x,\n\t .sh_entsize : %x\n\n",
		sections[i].sh_name, sections[i].sh_type, sections[i].sh_flags, sections[i].sh_addr, sections[i].sh_offset,
		sections[i].sh_size, sections[i].sh_link, sections[i].sh_info, sections[i].sh_addralign, sections[i].sh_entsize);

		}

		printf("\n========== Symbol Table ==========\n\n");
		char sym_info[20];
		char sym_other[10];
		//Symbol table info
		for (i = 0; i < nb_symbols; ++i) {

			//
			switch(symtab[i].st_info){
				case STT_NOTYPE:
					strcpy(sym_info, "NOT DEFINED");
					break;
				case STT_OBJECT:
					strcpy(sym_info, "OBJECT");
					break;
				case STT_FUNC:
					strcpy(sym_info, "FUNCTION/EXECUTABLE");
					break;
				case STT_SECTION:
					strcpy(sym_info, "SECTION");
					break;
				case STT_FILE:
					strcpy(sym_info, "FILE");
					break;
				case STT_LOPROC:
					strcpy(sym_info, "PROC-SPEC SEMANTICS");
					break;
				default :
				strcpy(sym_info, "UNKNOWN");
			}

			//
			switch(symtab[i].st_other){
				case STV_DEFAULT:
					strcpy(sym_other,"DEFAULT");
					break;
				case STV_INTERNAL:
					strcpy(sym_other,"INTERNAL");
					break;
				case STV_HIDDEN:
					strcpy(sym_other,"HIDDEN");
					break;
				case STV_PROTECTED:
					strcpy(sym_other,"PROTECTED");
					break;
				default :
				strcpy(sym_other,"UNKNOWN");
			}

			printf("Symbol Table %d : [%s]\n", i, strtab + symtab[i].st_name);
			printf("\tvalue : 0x%llx\n\tsize : 0x%llx\n\tinfo : %s\n\tother : %s\t(visibility)\n\tshndx : 0x%llx\n\n",
				strtab + symtab[i].st_value, strtab + symtab[i].st_size,
				sym_info, sym_other, strtab + symtab[i].st_shndx);
		}

		//Offset where are program headers
		Elf64_Phdr* phdr = (Elf64_Phdr *)((char*)start + hdr->e_phoff);
		
		printf("\n========== Program Header ==========\n\n");
		//course of the sections
		for (i = 0; i < hdr->e_phnum; i++)
		{
			//
			switch (phdr[i].p_type){
			    case PT_NULL:
			        printf("Program Header %d : [NULL]\n", i);
			        break;
			    case PT_LOAD:
			        printf("Program Header %d : [LOAD]\n", i);
			        break;
			    case PT_DYNAMIC:
			        printf("Program Header %d : [DYNAMIC]\n", i);
			        break;
			    case PT_INTERP:
			        printf("Program Header %d : [INTERP]\n", i);
			        break;
			    case PT_NOTE:
			        printf("Program Header %d : [NOTE]\n", i);
			        break;
			    case PT_SHLIB:
			        printf("Program Header %d : [SHLIB]\n", i);
			        break;
			    case PT_PHDR:
			        printf("Program Header %d : [PHDR]\n", i);
			        break;
			    case PT_LOPROC:
			        printf("Program Header %d : [LOPROC,HIPROC]\n", i);
			        break;
			    case PT_GNU_STACK:
			        printf("Program Header %d : [GNU_STACK]\n", i);
			        break;
			    default:
			        printf("Program Header %d : [UNKNOWN]\n", i);
			}
			printf("\t.p_type : %x,\n\t.p_offset : %x,\n\t.p_addr : %x,\n\t.p_vaddr : %x,\n\t.p_filesz : %x,\n\t .p_memsz : %x,\n\t .p_align : %x\n\n",phdr[i].p_type,
			  phdr[i].p_offset, phdr[i].p_paddr, phdr[i].p_vaddr, phdr[i].p_filesz,
			   phdr[i].p_memsz, phdr[i].p_align);
		}

		//close file
		munmap(start, stat.st_size);
		close(fd);

		//Debugger

		//print pid of current processus (child) and its parent
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
			// ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
		}

		putchar('\n');

		//copy /proc//status file and /proc//maps file of child processus in new files in info_dir
		char str[30] = "";
		snprintf(str, 30, "/proc/%d/stat", child);
		cp("info_dir/child_status.txt", str);
		readfile(str);
		
		putchar('\n');

		strcpy(str, "");
		snprintf(str, 30, "/proc/%d/maps", child);
		cp("info_dir/child_maps.txt", str);
		readfile(str);
		
		putchar('\n');

		//exec objdump
		strcpy(str, "objdump -d ");
		strcat(str, argv[1]);
		system(str);	
	}

	return 0;
}
