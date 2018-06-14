#include <stdio.h>
#include "scalehook.h"

scalehook_t *new_hook;
typedef void(*original)();

void kek()
{
	printf("[calling] kek called (Success.)\n");
	printf("Uninstalling hook...\n");
	if(!scalehook_uninstall(new_hook))
	{
		printf("[uninstalling] failed.\n");
		return;
	}
	printf("[uninstalling] success.\n");
	printf("Call the original function...\n");
	((original)new_hook->original_address)();
	printf("Destroying hook...\n");
	scalehook_destroy(new_hook);
	printf("[destroying] success.\n");
}

void lol()
{
	printf("[calling] lol called.\n");
}

int main(void)
{
	printf("============ scalehook test =============\n");
	printf("Installing hook....\n");
	new_hook = scalehook_create(lol, kek, 5, scalehook_opcode_jmp);
	// new_hook = scalehook_create_fast(lol, kek);
	if(!new_hook)
	{
		printf("[installing] failed.\n");
		return 1;
	}
	printf("[installing] success.\n");
	printf("Calling function...\n");
	lol();
	return 0;
}
