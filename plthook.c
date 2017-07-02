#if defined(__sun) && defined(_XOPEN_SOURCE) && !defined(__EXTENSIONS__)
#define __EXTENSIONS__
#endif
#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#ifdef __sun
#include <procfs.h>
#define ELF_TARGET_ALL
#endif /* __sun */
#include <elf.h>
#include <link.h>
#include "plthook.h"
#include "config.h"

#ifndef __GNUC__
#define __attribute__(arg)
#endif

#if defined __linux__
#define ELF_OSABI     ELFOSABI_SYSV
#define ELF_OSABI_ALT ELFOSABI_LINUX
#elif defined __sun
#define ELF_OSABI     ELFOSABI_SOLARIS
#elif defined __FreeBSD__
#define ELF_OSABI     ELFOSABI_FREEBSD
#if defined __i386__ && __ELF_WORD_SIZE == 64
#error 32-bit application on 64-bit OS is not supported.
#endif
#elif defined _hpux || defined __hpux
#define ELF_OSABI     ELFOSABI_HPUX
#else
#error unsupported OS
#endif

#if defined __x86_64__ || defined __x86_64
#define ELF_DATA      ELFDATA2LSB
#define E_MACHINE     EM_X86_64
#ifdef R_X86_64_JUMP_SLOT
#define R_JUMP_SLOT   R_X86_64_JUMP_SLOT
#else
#define R_JUMP_SLOT   R_X86_64_JMP_SLOT
#endif
#define SHT_PLT_REL   SHT_RELA
#define Elf_Plt_Rel   Elf_Rela
#define PLT_SECTION_NAME ".rela.plt"
#define R_GLOBAL_DATA R_X86_64_GLOB_DAT
#define REL_DYN_SECTION_NAME ".rela.dyn"
#elif defined __i386__ || defined __i386
#define ELF_DATA      ELFDATA2LSB
#define E_MACHINE     EM_386
#define R_JUMP_SLOT   R_386_JMP_SLOT
#define SHT_PLT_REL   SHT_REL
#define Elf_Plt_Rel   Elf_Rel
#define PLT_SECTION_NAME ".rel.plt"
#define R_GLOBAL_DATA R_386_GLOB_DAT
#define REL_DYN_SECTION_NAME ".rel.dyn"
#elif 0 /* disabled because not tested */ && (defined __sparcv9 || defined __sparc_v9__)
#define ELF_DATA      ELFDATA2MSB
#define E_MACHINE     EM_SPARCV9
#define R_JUMP_SLOT   R_SPARC_JMP_SLOT
#define SHT_PLT_REL   SHT_RELA
#define Elf_Plt_Rel   Elf_Rela
#define PLT_SECTION_NAME ".rela.plt"
#elif 0 /* disabled because not tested */ && (defined __sparc || defined __sparc__)
#define ELF_DATA      ELFDATA2MSB
#define E_MACHINE     EM_SPARC
#define E_MACHINE_ALT EM_SPARC32PLUS
#define R_JUMP_SLOT   R_SPARC_JMP_SLOT
#define SHT_PLT_REL   SHT_RELA
#define Elf_Plt_Rel   Elf_Rela
#define PLT_SECTION_NAME ".rela.plt"
#elif 0 /* disabled because not tested */ && (defined __ia64 || defined __ia64__)
#define ELF_DATA      ELFDATA2MSB
#define E_MACHINE     EM_IA_64
#define R_JUMP_SLOT   R_IA64_IPLTMSB
#define SHT_PLT_REL   SHT_RELA
#define Elf_Plt_Rel   Elf_Rela
#define PLT_SECTION_NAME ".rela.plt"
*/
#else
#error E_MACHINE is not defined.
#endif

#if defined __LP64__
#ifndef ELF_CLASS
#define ELF_CLASS     ELFCLASS64
#endif
#define SIZE_T_FMT "lu"
#define ELF_WORD_FMT "u"
#define ELF_XWORD_FMT "lu"
#define Elf_Half Elf64_Half
#define Elf_Xword Elf64_Xword
#define Elf_Addr Elf64_Addr
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym  Elf64_Sym
#define Elf_Rel  Elf64_Rel
#define Elf_Rela Elf64_Rela
#ifndef ELF_R_SYM
#define ELF_R_SYM ELF64_R_SYM
#endif
#ifndef ELF_R_TYPE
#define ELF_R_TYPE ELF64_R_TYPE
#endif
#else /* __LP64__ */
#ifndef ELF_CLASS
#define ELF_CLASS     ELFCLASS32
#endif
#define SIZE_T_FMT "u"
#ifdef __sun
#define ELF_WORD_FMT "lu"
#define ELF_XWORD_FMT "lu"
#else
#define ELF_WORD_FMT "u"
#define ELF_XWORD_FMT "u"
#endif
#define Elf_Half Elf32_Half
#define Elf_Xword Elf32_Word
#define Elf_Addr Elf32_Addr
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym  Elf32_Sym
#define Elf_Rel  Elf32_Rel
#define Elf_Rela Elf32_Rela
#ifndef ELF_R_SYM
#define ELF_R_SYM ELF32_R_SYM
#endif
#ifndef ELF_R_TYPE
#define ELF_R_TYPE ELF32_R_TYPE
#endif
#endif /* __LP64__ */

#define PT_NULL    0
#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define PT_NOTE    4
#define PT_SHLIB   5
#define PT_PHDR    6
#define PT_TLS     7               /* Thread local storage segment */
#define PT_LOOS    0x60000000      /* OS-specific */
#define PT_HIOS    0x6fffffff      /* OS-specific */
#define PT_LOPROC  0x70000000
#define PT_HIPROC  0x7fffffff
#define PT_GNU_EH_FRAME		0x6474e550

//#define PT_GNU_STACK	(PT_LOOS + 0x474e551)

#define STB_LOCAL  0
#define STB_GLOBAL 1
#define STB_WEAK   2

#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_FUNC    2
#define STT_SECTION 3
#define STT_FILE    4
#define STT_COMMON  5
#define STT_TLS     6

#define SHN_UNDEF	0
#define SHN_LORESERVE	0xff00
#define SHN_LOPROC	0xff00
#define SHN_HIPROC	0xff1f
#define SHN_LIVEPATCH	0xff20
#define SHN_ABS		0xfff1
#define SHN_COMMON	0xfff2
#define SHN_HIRESERVE	0xffff

#define ELF_ST_BIND(x)		((x) >> 4)
#define ELF_ST_TYPE(x)		(((unsigned int) x) & 0xf)

/*
#define PF_R		0x4
#define PF_W		0x2
#define PF_X		0x1
*/


struct plthook {
    const char *base;
    const Elf_Phdr *phdr;
    size_t phnum;
    Elf_Shdr *shdr;
    size_t shnum;
    char *shstrtab;
    size_t shstrtab_size;
    const Elf_Sym *dynsym;
    size_t dynsym_cnt;
    const char *dynstr;
    size_t dynstr_size;
    const Elf_Plt_Rel *plt;
    size_t plt_cnt;
    Elf_Xword r_type;
#ifdef PT_GNU_RELRO
    const char *relro_start;
    const char *relro_end;
#endif
};

static char errmsg[512];

#ifdef PT_GNU_RELRO
static size_t page_size;
#endif

static int plthook_open_executable(plthook_t **plthook_out);
static int plthook_open_shared_library(plthook_t **plthook_out, const char *filename);
static int plthook_open_real(plthook_t **plthook_out, const char *base, const char *filename);
static int check_elf_header(const Elf_Ehdr *ehdr);
static int find_section(plthook_t *image, const char *name, const Elf_Shdr **out);
static void set_errmsg(const char *fmt, ...) __attribute__((__format__ (__printf__, 1, 2)));

extern FILE* flog;

int plthook_open(plthook_t **plthook_out, const char *filename)
{
    *plthook_out = NULL;
    if (filename == NULL) {
        return plthook_open_executable(plthook_out);
    } else {
        return plthook_open_shared_library(plthook_out, filename);
    }
}

int plthook_open_by_handle(plthook_t **plthook_out, void *hndl)
{
    struct link_map *lmap = NULL;

    if (hndl == NULL) {
        set_errmsg("NULL handle");
        return PLTHOOK_FILE_NOT_FOUND;
    }
    if (dlinfo(hndl, RTLD_DI_LINKMAP, &lmap) != 0) {
        set_errmsg("dlinfo error");
        return PLTHOOK_FILE_NOT_FOUND;
    }
    if (lmap->l_addr == 0 && *lmap->l_name == 0) {
        return plthook_open_executable(plthook_out);
    }
    return plthook_open_real(plthook_out, (const char*)lmap->l_addr, lmap->l_name);
}

int plthook_open_by_address(plthook_t **plthook_out, void *address)
{
    Dl_info info;

    *plthook_out = NULL;
    if (dladdr(address, &info) == 0) {
        set_errmsg("dladdr error");
        return PLTHOOK_FILE_NOT_FOUND;
    }
    return plthook_open_real(plthook_out, info.dli_fbase, info.dli_fname);
}

unsigned long long plthook_get_baseaddr ()
{
    char buf[128];
    FILE *fp = fopen("/proc/self/maps", "r");
    unsigned long base;

    if (fp == NULL) {
        set_errmsg("Could not open /proc/self/maps: %s",
                   strerror(errno));
        return PLTHOOK_INTERNAL_ERROR;
    }
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        set_errmsg("Could not read /proc/self/maps: %s",
                   strerror(errno));
        fclose(fp);
        return PLTHOOK_INTERNAL_ERROR;
    }
    fclose(fp);
    if (sscanf(buf, "%lx-%*x r-xp %*x %*x:%*x %*u ", &base) != 1) {
        set_errmsg("invalid /proc/self/maps format: %s", buf);
        return PLTHOOK_INTERNAL_ERROR;
    }

	return base;
}

static int plthook_open_executable(plthook_t **plthook_out)
{
#if defined __linux__
    /* Open the main program. */
    char buf[128];
    FILE *fp = fopen("/proc/self/maps", "r");
    unsigned long base;

    if (fp == NULL) {
        set_errmsg("Could not open /proc/self/maps: %s",
                   strerror(errno));
        return PLTHOOK_INTERNAL_ERROR;
    }
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        set_errmsg("Could not read /proc/self/maps: %s",
                   strerror(errno));
        fclose(fp);
        return PLTHOOK_INTERNAL_ERROR;
    }
    fclose(fp);
    if (sscanf(buf, "%lx-%*x r-xp %*x %*x:%*x %*u ", &base) != 1) {
        set_errmsg("invalid /proc/self/maps format: %s", buf);
        return PLTHOOK_INTERNAL_ERROR;
    }
#if 1
		//fprintf(stdout, /*flog,*/ "[+] plthook_open_executable(): buf=%s\n", buf);
		fprintf(flog,"[+] plthook_open_executable(): base=%p (pid=%d)\n", (const char*)base, getpid());
#endif
    return plthook_open_real(plthook_out, (const char*)base, "/proc/self/exe");
#elif defined __sun
    prmap_t prmap;
    pid_t pid = getpid();
    char fname[128];
    int fd;

    sprintf(fname, "/proc/%ld/map", (long)pid);
    fd = open(fname, O_RDONLY);
    if (fd == -1) {
        set_errmsg("Could not open %s: %s", fname,
                   strerror(errno));
        return PLTHOOK_INTERNAL_ERROR;
    }
    if (read(fd, &prmap, sizeof(prmap)) != sizeof(prmap)) {
        set_errmsg("Could not read %s: %s", fname,
                   strerror(errno));
        close(fd);
        return PLTHOOK_INTERNAL_ERROR;
    }
    close(fd);
    sprintf(fname, "/proc/%ld/object/a.out", (long)pid);
    return plthook_open_real(plthook_out, (const char*)prmap.pr_vaddr, fname);
#elif defined __FreeBSD__
    return plthook_open_shared_library(plthook_out, NULL);
#else
    set_errmsg("Opening the main program is not supported on this platform.");
    return PLTHOOK_NOT_IMPLEMENTED;
#endif
}

static int plthook_open_shared_library(plthook_t **plthook_out, const char *filename)
{
    void *hndl = dlopen(filename, RTLD_LAZY | RTLD_NOLOAD);
    struct link_map *lmap = NULL;

    if (hndl == NULL) {
        set_errmsg("dlopen error: %s", dlerror());
        return PLTHOOK_FILE_NOT_FOUND;
    }
    if (dlinfo(hndl, RTLD_DI_LINKMAP, &lmap) != 0) {
        set_errmsg("dlinfo error");
        dlclose(hndl);
        return PLTHOOK_FILE_NOT_FOUND;
    }
    dlclose(hndl);
		//printf ("lmap->l_name:%s\n", (const char*)lmap->l_name);
    return plthook_open_real(plthook_out, (const char*)lmap->l_addr, lmap->l_name);
}

static int plthook_open_real(plthook_t **plthook_out, const char *base, const char *filename)
{
    Elf_Ehdr ehdr;
    const Elf_Shdr *shdr;
    size_t shdr_size;
    int fd = -1;
    off_t offset;
    plthook_t *plthook;
    int rv;
#ifdef PT_GNU_RELRO
    size_t idx;
#endif

    if (base == NULL) {
        set_errmsg("The base address is zero.");
        return PLTHOOK_FILE_NOT_FOUND;
    }

#if 0
		fprintf (flog, "[+] plthook_open_real(): base=%p\n", base);
#endif

    if (filename == NULL) {
        set_errmsg("failed to get the file name on the disk.");
        return PLTHOOK_FILE_NOT_FOUND;
    }

    plthook = calloc(1, sizeof(plthook_t));
    if (plthook == NULL) {
        set_errmsg("failed to allocate memory: %" SIZE_T_FMT " bytes", sizeof(plthook_t));
        return PLTHOOK_OUT_OF_MEMORY;
    }

    fd = open(filename, O_RDONLY, 0);
    if (fd == -1) {
        set_errmsg("Could not open %s: %s", filename, strerror(errno));
        rv = PLTHOOK_FILE_NOT_FOUND;
        goto error_exit;
    }
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        set_errmsg("failed to read the ELF header.");
        rv = PLTHOOK_INVALID_FILE_FORMAT;
        goto error_exit;
    }

    /* sanity check */
    rv = check_elf_header(&ehdr);
    if (rv != 0) {
        goto error_exit;
    }
    if (ehdr.e_type == ET_DYN) {
        plthook->base = base;
    }
    plthook->phdr = (const Elf_Phdr *)(plthook->base + ehdr.e_phoff);
    plthook->phnum = ehdr.e_phnum;
    shdr_size = ehdr.e_shnum * ehdr.e_shentsize;
    plthook->shdr = calloc(1, shdr_size);
    if (plthook->shdr == NULL) {
        set_errmsg("failed to allocate memory: %" SIZE_T_FMT " bytes", shdr_size);
        rv = PLTHOOK_OUT_OF_MEMORY;
        goto error_exit;
    }
    offset = ehdr.e_shoff;
    if ((rv = lseek(fd, offset, SEEK_SET)) != offset) {
        set_errmsg("failed to seek to the section header table.");
        rv = PLTHOOK_INVALID_FILE_FORMAT;
        goto error_exit;
    }
    if (read(fd, plthook->shdr, shdr_size) != shdr_size) {
        set_errmsg("failed to read the section header table.");
        rv = PLTHOOK_INVALID_FILE_FORMAT;
        goto error_exit;
    }
    plthook->shnum = ehdr.e_shnum;
    plthook->shstrtab_size = plthook->shdr[ehdr.e_shstrndx].sh_size;
    plthook->shstrtab = malloc(plthook->shstrtab_size);
    if (plthook->shstrtab == NULL) {
        set_errmsg("failed to allocate memory: %" SIZE_T_FMT " bytes", plthook->shstrtab_size);
        rv = PLTHOOK_OUT_OF_MEMORY;
        goto error_exit;
    }
    offset = plthook->shdr[ehdr.e_shstrndx].sh_offset;
    if (lseek(fd, offset, SEEK_SET) != offset) {
        set_errmsg("failed to seek to the section header string table.");
        rv = PLTHOOK_INVALID_FILE_FORMAT;
        goto error_exit;
    }
    if (read(fd, plthook->shstrtab, plthook->shstrtab_size) != plthook->shstrtab_size) {
        set_errmsg("failed to read the section header string table.");
        rv = PLTHOOK_INVALID_FILE_FORMAT;
        goto error_exit;
    }
#ifdef PT_GNU_RELRO
    if (page_size == 0) {
        page_size = sysconf(_SC_PAGESIZE);
    }
    offset = ehdr.e_phoff;
    if ((rv = lseek(fd, offset, SEEK_SET)) != offset) {
        set_errmsg("failed to seek to the program header table.");
        rv = PLTHOOK_INVALID_FILE_FORMAT;
        goto error_exit;
    }
    for (idx = 0; idx < ehdr.e_phnum; idx++) {
        Elf_Phdr phdr;
        if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) {
            set_errmsg("failed to read the program header table.");
            rv = PLTHOOK_INVALID_FILE_FORMAT;
            goto error_exit;
        }
        if (phdr.p_type == PT_GNU_RELRO) {
            plthook->relro_start = plthook->base + phdr.p_vaddr;
            plthook->relro_end = plthook->relro_start + phdr.p_memsz;
        }
    }
#endif
    close(fd);
    fd = -1;

    rv = find_section(plthook, ".dynsym", &shdr);
    if (rv != 0) {
        goto error_exit;
    }
    if (shdr->sh_type != SHT_DYNSYM) {
        set_errmsg("The type of .dynsym section should be SHT_DYNSYM but %" ELF_WORD_FMT ".", shdr->sh_type);
        rv = PLTHOOK_INVALID_FILE_FORMAT;
        goto error_exit;
    }
    if (shdr->sh_entsize != sizeof(Elf_Sym)) {
        set_errmsg("The size of a section header entry should be sizeof(Elf_Sym)(%" SIZE_T_FMT ") but %" ELF_XWORD_FMT ".",
                   sizeof(Elf_Sym), shdr->sh_entsize);
        rv = PLTHOOK_INVALID_FILE_FORMAT;
        goto error_exit;
    }
    plthook->dynsym = (const Elf_Sym*)(plthook->base + shdr->sh_addr);
    plthook->dynsym_cnt = shdr->sh_size / shdr->sh_entsize;

    rv = find_section(plthook, ".dynstr", &shdr);
    if (rv != 0) {
        goto error_exit;
    }
    if (shdr->sh_type != SHT_STRTAB) {
        set_errmsg("The type of .dynstrx section should be SHT_STRTAB but %" ELF_WORD_FMT ".", shdr->sh_type);
        rv = PLTHOOK_INVALID_FILE_FORMAT;
        goto error_exit;
    }
    plthook->dynstr = (const char*)(plthook->base + shdr->sh_addr);
    plthook->dynstr_size = shdr->sh_size;

    rv = find_section(plthook, PLT_SECTION_NAME, &shdr);
    plthook->r_type = R_JUMP_SLOT;
#ifdef REL_DYN_SECTION_NAME
    if (rv != 0) {
        rv = find_section(plthook, REL_DYN_SECTION_NAME, &shdr);
        plthook->r_type = R_GLOBAL_DATA;
    }
#endif
    if (rv != 0) {
        goto error_exit;
    }
    if (shdr->sh_entsize != sizeof(Elf_Plt_Rel)) {
        set_errmsg("invalid " PLT_SECTION_NAME " table entry size: %" ELF_XWORD_FMT, shdr->sh_entsize);
        rv = PLTHOOK_INVALID_FILE_FORMAT;
        goto error_exit;
    }
    plthook->plt = (Elf_Plt_Rel *)(plthook->base + shdr->sh_addr);
    plthook->plt_cnt = shdr->sh_size / sizeof(Elf_Plt_Rel);

    *plthook_out = plthook;
    return 0;
 error_exit:
    if (fd != -1) {
        close(fd);
    }
    plthook_close(plthook);
    return rv;
}

void plthook_getseginfo(plthook_t* plthook)
{
	//printf ("[+] plthook_getseginfo(): phnum=%d, base=%p, phdr=%p\n", plthook->phnum, plthook->base, plthook->phdr);
	for (int i=0;i<plthook->phnum;i++)
	{
		const Elf_Phdr *phdr=plthook->phdr + i;
		if (phdr->p_type != PT_LOAD)
			continue;

		if (phdr->p_flags & PF_X) 
		{
#if D_DEBUG==1
			fprintf (flog,"[+] plthook_getseginfo(): [text segment] vaddr=%p, memsize=%x\n", (void*)phdr->p_vaddr, (unsigned int)phdr->p_memsz);	
#endif
			text_segment_addr = (unsigned long long)phdr->p_vaddr;
			text_segment_size=(unsigned int)phdr->p_memsz;
		} else {
#if D_DEBUG==1
			fprintf (flog,"[+] plthook_getseginfo(): [data segment] vaddr=%p, memsize=%x\n", (void*)phdr->p_vaddr, (unsigned int)phdr->p_memsz);	
			data_segment_addr = (unsigned long long)phdr->p_vaddr;
			data_segment_size=(unsigned int)phdr->p_memsz;
#endif
		}

	}

}

void dump_plt_info()
{
	fprintf (flog, "[+] dump_plt_info(): num_of_plts=%d\n", num_of_plts);
	for (int i=0;i<num_of_plts;i++)
	{
		fprintf (flog, "[+] dump_plt_info(): [%d] %p:%s\n",i, (char*)plts[i].addr, plts[i].name);
	}

}

void* g_lib_base_addr=NULL;

int setup_plt_info (char* shared_library_name)
{
    plthook_t *pt_self, *pt_library;
    unsigned int pos = 0; /* This must be initialized with zero. */
    char *name;
    void **addr;

		void* lib_hndl=NULL;
		void* sym;
		Dl_info di;

    if (plthook_open(&pt_self, NULL) != 0) {
        printf("plthook_open error: %s\n", plthook_error());
				return -1;
    }
    if (plthook_open(&pt_library, shared_library_name) != 0) {
        printf("plthook_open error(%s): %s\n", shared_library_name, plthook_error());
				return -1;
    }

		lib_hndl=dlopen(shared_library_name, RTLD_NOW);

		int idx=0;
    while (plthook_enum(pt_self, &pos, (const char**)&name, &addr) == 0) {
				if (plthook_is_library_symbol (pt_library, name))
				{
					// this plt is to be modified
#if D_DEBUG==1
        	fprintf(flog,"[+] setup_plt_info(): %p(%p) %s\n", addr, *addr, name);
#endif
					plts[idx].addr=(unsigned long long)addr;
					plts[idx].name=name;
					plts[idx]._hook=_plt_hook_func_array[idx];

					sym=dlsym(lib_hndl, name);
					if (!g_lib_base_addr) {
						dladdr (sym, &di);
						g_lib_base_addr=di.dli_fbase;
					}
					plts[idx].offset=sym-g_lib_base_addr;
						
					void** plt=(void*)plts[idx].addr;
					*plt = (void*)plts[idx]._hook;

					void* maddr=(void*)((size_t)addr & ~(page_size-1));
					if (mprotect (maddr, page_size, PROT_READ|PROT_WRITE)!=0) {							
						fprintf (flog, "[-] setup_plt_info(): mprotect error (page_size=%ld)\n", page_size);
					} else {
						//fprintf (flog, "[+] setup_plt_info(): mprotect success at %p (page_size=%ld)\n",addr, page_size);
					}
					idx++;	
				}
    }

		num_of_plts=idx;

		plthook_getseginfo(pt_library);

    plthook_close(pt_self);
    plthook_close(pt_library);

		return 0;
}

int plthook_is_library_symbol(plthook_t *plthook, const char* name)
{
	for (int i=0;i<plthook->dynsym_cnt;i++)
	{
		const Elf_Sym* dynsym=plthook->dynsym + i;
		size_t idx=dynsym->st_name;
		const char* symname = plthook->dynstr+idx;
		if (!strcmp(name, symname)) {	
			if (ELF_ST_BIND(dynsym->st_info) == STB_GLOBAL && ELF_ST_TYPE(dynsym->st_info)==STT_FUNC && dynsym->st_shndx!=SHN_UNDEF)
				return 1;
		} 
	}

	return 0;
}



int plthook_enum(plthook_t *plthook, unsigned int *pos, const char **name_out, void ***addr_out)
{
    while (*pos < plthook->plt_cnt) {
        const Elf_Plt_Rel *plt = plthook->plt + *pos;
        if (ELF_R_TYPE(plt->r_info) == plthook->r_type) {
            size_t idx = ELF_R_SYM(plt->r_info);

            if (idx >= plthook->dynsym_cnt) {
                set_errmsg(".dynsym index %" SIZE_T_FMT " should be less than %" SIZE_T_FMT ".", idx, plthook->dynsym_cnt);
                return PLTHOOK_INVALID_FILE_FORMAT;
            }
            idx = plthook->dynsym[idx].st_name;
            if (idx + 1 > plthook->dynstr_size) {
                set_errmsg("too big section header string table index: %" SIZE_T_FMT, idx);
                return PLTHOOK_INVALID_FILE_FORMAT;
            }
            *name_out = plthook->dynstr + idx;
            *addr_out = (void**)(plthook->base + plt->r_offset);
            (*pos)++;
            return 0;
        }
        (*pos)++;
    }
    *name_out = NULL;
    *addr_out = NULL;
    return EOF;
}

int plthook_replace(plthook_t *plthook, const char *funcname, void *funcaddr, void **oldfunc)
{
    size_t funcnamelen = strlen(funcname);
    unsigned int pos = 0;
    const char *name;
    void **addr;
    int rv;

    if (plthook == NULL) {
        set_errmsg("invalid argument: The first argument is null.");
        return PLTHOOK_INVALID_ARGUMENT;
    }
    while ((rv = plthook_enum(plthook, &pos, &name, &addr)) == 0) {
        if (strncmp(name, funcname, funcnamelen) == 0) {
            if (name[funcnamelen] == '\0' || name[funcnamelen] == '@') {
#ifdef PT_GNU_RELRO
                void *maddr = NULL;
                if (plthook->relro_start <= (char*)addr && (char*)addr < plthook->relro_end) {
                    maddr = (void*)((size_t)addr & ~(page_size - 1));
                    if (mprotect(maddr, page_size, PROT_READ | PROT_WRITE) != 0) {
                        set_errmsg("Could not change the process memory protection at %p: %s",
                                   maddr, strerror(errno));
                        return PLTHOOK_INTERNAL_ERROR;
                    }
                }
#endif
                if (oldfunc) {
                    *oldfunc = *addr;
                }
                *addr = funcaddr;
#ifdef PT_GNU_RELRO
                if (maddr != NULL) {
                    mprotect(maddr, page_size, PROT_READ);
                }
#endif
                return 0;
            }
        }
    }
    if (rv == EOF) {
        set_errmsg("no such function: %s", funcname);
        rv = PLTHOOK_FUNCTION_NOT_FOUND;
    }
    return rv;
}

void plthook_close(plthook_t *plthook)
{
    if (plthook != NULL) {
        free(plthook->shdr);
        free(plthook->shstrtab);
        free(plthook);
    }
}

const char *plthook_error(void)
{
    return errmsg;
}

static int check_elf_header(const Elf_Ehdr *ehdr)
{
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        set_errmsg("invalid file signature: 0x%02x,0x%02x,0x%02x,0x%02x",
                   ehdr->e_ident[0], ehdr->e_ident[1], ehdr->e_ident[2], ehdr->e_ident[3]);
        return PLTHOOK_INVALID_FILE_FORMAT;
    }
    if (ehdr->e_ident[EI_CLASS] != ELF_CLASS) {
        set_errmsg("invalid elf class: 0x%02x", ehdr->e_ident[EI_CLASS]);
        return PLTHOOK_INVALID_FILE_FORMAT;
    }
    if (ehdr->e_ident[EI_DATA] != ELF_DATA) {
        set_errmsg("invalid elf data: 0x%02x", ehdr->e_ident[EI_DATA]);
        return PLTHOOK_INVALID_FILE_FORMAT;
    }
    if (ehdr->e_ident[EI_VERSION] != EV_CURRENT) {
        set_errmsg("invalid elf version: 0x%02x", ehdr->e_ident[EI_VERSION]);
        return PLTHOOK_INVALID_FILE_FORMAT;
    }
    if (ehdr->e_ident[EI_OSABI] != ELF_OSABI
#ifdef ELF_OSABI_ALT
        && ehdr->e_ident[EI_OSABI] != ELF_OSABI_ALT
#endif
        ) {
        set_errmsg("invalid OS ABI: 0x%02x", ehdr->e_ident[EI_OSABI]);
        return PLTHOOK_INVALID_FILE_FORMAT;
    }
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        set_errmsg("invalid file type: 0x%04x", ehdr->e_type);
        return PLTHOOK_INVALID_FILE_FORMAT;
    }
    if (ehdr->e_machine != E_MACHINE
#ifdef E_MACHINE_ALT
        && ehdr->e_machine != E_MACHINE_ALT
#endif
        ) {
        set_errmsg("invalid machine type: %u", ehdr->e_machine);
        return PLTHOOK_INVALID_FILE_FORMAT;
    }
    if (ehdr->e_version != EV_CURRENT) {
        set_errmsg("invalid object file version: %" ELF_WORD_FMT, ehdr->e_version);
        return PLTHOOK_INVALID_FILE_FORMAT;
    }
    if (ehdr->e_ehsize != sizeof(Elf_Ehdr)) {
        set_errmsg("invalid elf header size: %u", ehdr->e_ehsize);
        return PLTHOOK_INVALID_FILE_FORMAT;
    }
    if (ehdr->e_phentsize != sizeof(Elf_Phdr)) {
        set_errmsg("invalid program header table entry size: %u", ehdr->e_phentsize);
        return PLTHOOK_INVALID_FILE_FORMAT;
    }
    if (ehdr->e_shentsize != sizeof(Elf_Shdr)) {
        set_errmsg("invalid section header table entry size: %u", ehdr->e_shentsize);
        return PLTHOOK_INVALID_FILE_FORMAT;
    }
    return 0;
}

static int find_section(plthook_t *image, const char *name, const Elf_Shdr **out)
{
    const Elf_Shdr *shdr = image->shdr;
    const Elf_Shdr *shdr_end = shdr + image->shnum;
    size_t namelen = strlen(name);

    while (shdr < shdr_end) {
        if (shdr->sh_name + namelen >= image->shstrtab_size) {
            set_errmsg("too big section header string table index: %" ELF_WORD_FMT, shdr->sh_name);
            return PLTHOOK_INVALID_FILE_FORMAT;
        }
        if (strcmp(image->shstrtab + shdr->sh_name, name) == 0) {
            *out = shdr;
            return 0;
        }
        shdr++;
    }
    set_errmsg("failed to find the section header: %s", name);
    return PLTHOOK_INVALID_FILE_FORMAT;
}

static void set_errmsg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(errmsg, sizeof(errmsg) - 1, fmt, ap);
    va_end(ap);
}
