#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include "plthook.h"

void* my_malloc(size_t);

void install_library_hook (const char* library_name)
{
	plthook_t* pt_library;
	if (plthook_open(&pt_library, library_name) != 0) {
		printf ("disp_thread(): plthook_open error(%s): %s\n", library_name, plthook_error());
		return;
	}	

	if (plthook_replace (pt_library, "malloc", (void*)my_malloc, NULL) != 0) {
		printf ("disp_thread(): plthook_replace error: %s\n", plthook_error());
		plthook_close (pt_library);
		return;
	}

	plthook_close (pt_library);

}

void* my_malloc (size_t size)
{
	void* addr = malloc (size);
	printf ("my_malloc() : addr=%p, size=%d bytes\n", addr, size);

	return addr;
}
