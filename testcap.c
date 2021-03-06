#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#include <inttypes.h>

#include <capstone/capstone.h>

//#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"
#define CODE "\x48\xbe\x00\x00\x00\x00\x00\x00\x00\x00"
//4800015496058948
//5177fffff0003d48

int main(void)
{
	csh handle;
	cs_insn *insn;
	size_t count;
	uint8_t code[5] = {0x51, 0x77, 0xff, 0xff, 0xf0};
	
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;
	cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	count = cs_disasm(handle, code, sizeof(CODE)-1, 0x1000, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("0x%"PRIx64":\t%s\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);

    return 0;
}