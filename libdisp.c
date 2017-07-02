#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include "config.h"
#include "disp.h"

//#define FLUSH_MEM
#define USE_SPINLOCK
//#define DISP_RANGE		32
#define DISP_RANGE		2048
#define DISP_USLEEP		1000000


unsigned char* library_name="libcrypto.so.1.0.0";
//unsigned char* library_name="libgcrypt.so.20";

plt_info plts[1024]={0,};
void* (*plt_functions[1024])={0,};

int num_of_plts=0;
unsigned long long text_segment_addr=0;
unsigned int text_segment_size=0;
unsigned long long data_segment_addr=0;
unsigned int data_segment_size=0;

/* Forward declare these functions */
void* __libc_dlopen_mode(const char*, int);
void* __libc_dlsym(void*, const char*);
int   __libc_dlclose(void*);

void dump_plt_info();
int setup_plt_info(char*);

FILE* flog=NULL;

extern void* g_lib_base_addr;


void hexdump(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		fprintf(flog,"%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			fprintf(flog," ");
			if ((i+1) % 16 == 0) {
				fprintf(flog,"|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					fprintf(flog," ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					fprintf(flog,"   ");
				}
				fprintf(flog,"|  %s \n", ascii);
			}
		}
	}
}

void _memcpy(void *dest, void *src, size_t n)
{
   // Typecast src and dest addresses to (char *)
   char *csrc = (char *)src;
   char *cdest = (char *)dest;
 
   // Copy contents of src[] to dest[]
   for (int i=0; i<n; i++)
       cdest[i] = csrc[i];
}


#if defined(USE_SPINLOCK)
pthread_spinlock_t splock;

void INLINE disp_lock_init(){ pthread_spin_init(&splock, 0); }
void INLINE disp_lock(){ pthread_spin_lock (&splock); }
void INLINE disp_unlock(){ pthread_spin_unlock (&splock); }
void INLINE disp_lock_wait()
{
	disp_lock();
	disp_unlock();
}
#else

int disp_locked=0;

void INLINE disp_lock_init(){}
void INLINE disp_lock(){ disp_locked=1;}
void INLINE disp_unlock(){ disp_locked=0;}
void INLINE disp_lock_wait()
{
#if D_DEBUG==1
	#if 1
	if (disp_locked)
		fprintf (flog,"[+] disp_lock_wait(): locked\n");
	#endif
#endif

	while (disp_locked);
}
#endif

void mem_flush (void* addr, unsigned int size)
{
#if defined(FLUSH_MEM)
	/*fprintf (flog, "[+] mem_flush(): addr=%p, size=%d\n", addr, size);*/

	unsigned int blocks=size/64;
	for (int i=0;i<blocks;i++) {
		void** clflush_addr=(void**)addr+i*8;
		/*fprintf (flog, "[+] mem_flush(): clflush %p\n", clflush_addr);*/
		clflush ((void*)clflush_addr);
	}
#endif
}

void disp_hook (int offset) {
	int idx=offset/8;
#if 0
	disp_test();
#endif
	disp_lock_wait();
	fprintf (flog,"[+] hook():%s=%p\n",plts[idx].name, plt_functions[idx]);
	return;
}

int disp_mmap () {
	unsigned long long base_offset=(data_segment_addr-text_segment_addr)&0xfffff000;
	
	void* text_addr=(void*)0x8000000;
	void* data_addr=text_addr+base_offset;

	int text_map_size=text_segment_size+(text_segment_addr&0xfff)+64*2048;
	int data_map_size=data_segment_size+(data_segment_addr&0xfff)+64*2048;

	text_addr = mmap (text_addr, text_map_size, PROT_READ|PROT_EXEC|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	if (text_addr == MAP_FAILED)
	{	
		perror ("mmap(text_addr) failed:");
		return -1;
	}

	data_addr = mmap (data_addr, data_map_size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	if (data_addr == MAP_FAILED)
	{	
		perror ("mmap(data_addr) failed:");
		return -1;
	}


#if D_DEBUG==1
	fprintf (flog,"[+] disp_mmap(): mapped.. (text_addr=%p, size=0x%x)\n", text_addr, text_map_size);
	fprintf (flog,"[+] disp_mmap(): mapped.. (data_addr=%p, size=0x%x)\n", data_addr, data_map_size);
#endif

	return 0;
}


void displacement (int disp_offset) {

	unsigned long long base_offset=(data_segment_addr-text_segment_addr)&0xfffff000;
	
	void* text_addr=(void*)0x8000000;
	void* data_addr=text_addr+base_offset;

	void* text_addr_d=text_addr+disp_offset;
	void* data_addr_d=data_addr+disp_offset;
	unsigned int text_seg_size=text_segment_size+(text_segment_addr&0xfff);
	unsigned int data_seg_size=data_segment_size+(data_segment_addr&0xfff);

#if D_DEBUG==1
	#if 0
	//fprintf (flog,"[+] displacement(): process id=%d\n", getpid());
	fprintf (flog,"[+] displacement(): dli_fbase=%p, sym=%p\n", di.dli_fbase, sym);
	fprintf (flog,"[+] displacement(): disp_offset=%d\n", disp_offset);
	fprintf (flog,"[+] displacement(): text_addr=%p, text_addr_d=%p (%llx bytes)\n", text_addr, text_addr_d, text_segment_size+(text_segment_addr&0xfff));
	fprintf (flog,"[+] displacement(): data_addr=%p, data_addr_d=%p (%llx bytes)\n", data_addr, data_addr_d, data_segment_size+(data_segment_addr&0xfff));

	fprintf (flog,"[+] displacement(): adjusting PLT info\n");
	#endif
#endif

	disp_lock();

	memcpy (text_addr_d, g_lib_base_addr, text_seg_size);
	mem_flush (text_addr_d, text_seg_size);

	memcpy (data_addr_d, g_lib_base_addr+base_offset, data_seg_size);
	mem_flush (data_addr_d, data_seg_size);
	
	// set new symbol addresses to plt 
	for (int i=0;i<num_of_plts;i++) 
		plt_functions[i]=text_addr_d+plts[i].offset;

	disp_unlock();


#if D_DEBUG==1
	#if 0
	for (int i=0;i<num_of_plts;i++) {
		fprintf (flog,"[+] displacement(): PLT[%s](%p) <- %p\n", plts[i].name, (void*)plts[i].addr, plt_functions[i]);
		hexdump (plt_functions[i], 16);
	}
	#endif
#endif


	// we should fix it
	/*
	dlclose(lib);
	munmap (text_addr, 0x2000);
	munmap (data_addr, 0x2000);
	*/

}

void* disp_thread(void* a) {
#if 1
		flog = fopen("./inject.log", "w");
		if (NULL == flog)
		{
			perror ("fopen():");
			flog = stdout;
		}
		setbuf (flog, NULL);
#else
		flog=stdout;
#endif

		// setup plt info
		setup_plt_info (library_name);
		dump_plt_info();
		
		disp_mmap();

		printf ("libdisp has been successfully injected\n");

		disp_lock_init();
	
		int count=0, disp_offset=0;
	
		//displacement();
    while (1) {
				disp_offset=64 * ((count++)%DISP_RANGE);
				displacement (disp_offset);
        usleep(DISP_USLEEP);
    }

		fclose(flog);
}

void disp_init() {
	/* disp_ctor() will be called implicitly */
}


__attribute__((constructor))
void disp_ctor() {
    /* Note libpthread.so.0. For some reason,
       using the symbolic link (libpthread.so) will not work */
    void* pthread_lib = __libc_dlopen_mode("libpthread.so.0", RTLD_LAZY);
    int(*pthread_lib_create)(void*,void*,void*(*)(void*),void*);
    pthread_t t;

    *(void**)(&pthread_lib_create) = __libc_dlsym(pthread_lib, "pthread_create");
    pthread_lib_create(&t, NULL, disp_thread, NULL);

    __libc_dlclose(pthread_lib);
}

