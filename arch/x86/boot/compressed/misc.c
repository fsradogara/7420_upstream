// SPDX-License-Identifier: GPL-2.0
/*
 * misc.c
 *
 * This is a collection of several routines used to extract the kernel
 * which includes KASLR relocation, decompression, ELF parsing, and
 * relocation processing. Additionally included are the screen and serial
 * output functions and related debugging support functions.
 *
 * malloc by Hannu Savolainen 1993 and Matthias Urlichs 1994
 * puts by Nick Holloway 1993, better puts by Martin Mares 1995
 * High loaded stuff by Hans Lermen & Werner Almesberger, Feb. 1996
 */

/*
 * we have to be careful, because no indirections are allowed here, and
 * paravirt_ops is a kind of one. As it will only run in baremetal anyway,
 * we just keep it from happening
 */
#undef CONFIG_PARAVIRT
#ifdef CONFIG_X86_32
#define _ASM_DESC_H_ 1
#endif

#ifdef CONFIG_X86_64
#define _LINUX_STRING_H_ 1
#define __LINUX_BITMAP_H 1
#endif

#include <linux/linkage.h>
#include <linux/screen_info.h>
#include <linux/elf.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/boot.h>
#include <asm/bootparam.h>
#include "misc.h"
#include "error.h"
#include "../string.h"
#include "../voffset.h"

/*
 * WARNING!!
 * This code is compiled with -fPIC and it is relocated dynamically at
 * run time, but no relocation processing is performed. This means that
 * it is not safe to place pointers in static structures.
 */

/*
 * gzip declarations
 */

#define OF(args)	args
#define STATIC		static

#undef memset
#undef memcpy
#define memzero(s, n)	memset((s), 0, (n))

typedef unsigned char	uch;
typedef unsigned short	ush;
typedef unsigned long	ulg;

/*
 * Window size must be at least 32k, and a power of two.
 * We don't actually have a window just a huge output buffer,
 * so we report a 2G window size, as that should always be
 * larger than our output buffer:
 */
#define WSIZE		0x80000000

/* Input buffer: */
static unsigned char	*inbuf;

/* Sliding window buffer (and final output buffer): */
static unsigned char	*window;

/* Valid bytes in inbuf: */
static unsigned		insize;

/* Index of next byte to be processed in inbuf: */
static unsigned		inptr;

/* Bytes in output buffer: */
static unsigned		outcnt;

/* gzip flag byte */
#define ASCII_FLAG	0x01 /* bit 0 set: file probably ASCII text */
#define CONTINUATION	0x02 /* bit 1 set: continuation of multi-part gz file */
#define EXTRA_FIELD	0x04 /* bit 2 set: extra field present */
#define ORIG_NAM	0x08 /* bit 3 set: original file name present */
#define COMMENT		0x10 /* bit 4 set: file comment present */
#define ENCRYPTED	0x20 /* bit 5 set: file is encrypted */
#define RESERVED	0xC0 /* bit 6, 7:  reserved */

#define get_byte()	(inptr < insize ? inbuf[inptr++] : fill_inbuf())

/* Diagnostic functions */
#ifdef DEBUG
#  define Assert(cond, msg) do { if (!(cond)) error(msg); } while (0)
#  define Trace(x)	do { fprintf x; } while (0)
#  define Tracev(x)	do { if (verbose) fprintf x ; } while (0)
#  define Tracevv(x)	do { if (verbose > 1) fprintf x ; } while (0)
#  define Tracec(c, x)	do { if (verbose && (c)) fprintf x ; } while (0)
#  define Tracecv(c, x)	do { if (verbose > 1 && (c)) fprintf x ; } while (0)
#else
#  define Assert(cond, msg)
#  define Trace(x)
#  define Tracev(x)
#  define Tracevv(x)
#  define Tracec(c, x)
#  define Tracecv(c, x)
#endif

static int  fill_inbuf(void);
static void flush_window(void);
/* Macros used by the included decompressor code below. */
#define STATIC		static

/*
 * Use normal definitions of mem*() from string.c. There are already
 * included header files which expect a definition of memset() and by
 * the time we define memset macro, it is too late.
 */
#undef memcpy
#undef memset
#define memzero(s, n)	memset((s), 0, (n))
#define memmove		memmove

/* Functions used by the included decompressor code below. */
void *memmove(void *dest, const void *src, size_t n);

/*
 * This is set up by the setup-routine at boot-time
 */
static struct boot_params *real_mode;		/* Pointer to real-mode data */
static int quiet;

extern unsigned char input_data[];
extern int input_len;

static long bytes_out;

static void *memset(void *s, int c, unsigned n);
static void *memcpy(void *dest, const void *src, unsigned n);

static void __putstr(int, const char *);
#define putstr(__x)  __putstr(0, __x)

#ifdef CONFIG_X86_64
#define memptr long
#else
#define memptr unsigned
#endif

static memptr free_mem_ptr;
static memptr free_mem_end_ptr;
struct boot_params *real_mode;		/* Pointer to real-mode data */
struct boot_params *boot_params;

memptr free_mem_ptr;
memptr free_mem_end_ptr;

static char *vidmem;
static int vidport;
static int lines, cols;

#include "../../../../lib/inflate.c"
#ifdef CONFIG_KERNEL_GZIP
#include "../../../../lib/decompress_inflate.c"
#endif

#ifdef CONFIG_KERNEL_BZIP2
#include "../../../../lib/decompress_bunzip2.c"
#endif

#ifdef CONFIG_KERNEL_LZMA
#include "../../../../lib/decompress_unlzma.c"
#endif

#ifdef CONFIG_KERNEL_XZ
#include "../../../../lib/decompress_unxz.c"
#endif

#ifdef CONFIG_KERNEL_LZO
#include "../../../../lib/decompress_unlzo.c"
#endif

#ifdef CONFIG_KERNEL_LZ4
#include "../../../../lib/decompress_unlz4.c"
#endif
/*
 * NOTE: When adding a new decompressor, please update the analysis in
 * ../header.S.
 */

static void scroll(void)
{
	int i;

	memmove(vidmem, vidmem + cols * 2, (lines - 1) * cols * 2);
	for (i = (lines - 1) * cols * 2; i < lines * cols * 2; i += 2)
		vidmem[i] = ' ';
}

static void __putstr(int error, const char *s)
#define XMTRDY          0x20

#define TXR             0       /*  Transmit register (WRITE) */
#define LSR             5       /*  Line Status               */
static void serial_putchar(int ch)
{
	unsigned timeout = 0xffff;

	while ((inb(early_serial_base + LSR) & XMTRDY) == 0 && --timeout)
		cpu_relax();

	outb(ch, early_serial_base + TXR);
}

void __putstr(const char *s)
{
	int x, y, pos;
	char c;

#ifndef CONFIG_X86_VERBOSE_BOOTUP
	if (!error)
		return;
#endif

#ifdef CONFIG_X86_32
	if (real_mode->screen_info.orig_video_mode == 0 &&
	    lines == 0 && cols == 0)
		return;
#endif
	if (early_serial_base) {
		const char *str = s;
		while (*str) {
			if (*str == '\n')
				serial_putchar('\r');
			serial_putchar(*str++);
		}
	}

	if (lines == 0 || cols == 0)
		return;

	x = boot_params->screen_info.orig_x;
	y = boot_params->screen_info.orig_y;

	while ((c = *s++) != '\0') {
		if (c == '\n') {
			x = 0;
			if (++y >= lines) {
				scroll();
				y--;
			}
		} else {
			vidmem [(x + cols * y) * 2] = c;
			vidmem[(x + cols * y) * 2] = c;
			if (++x >= cols) {
				x = 0;
				if (++y >= lines) {
					scroll();
					y--;
				}
			}
		}
	}

	boot_params->screen_info.orig_x = x;
	boot_params->screen_info.orig_y = y;

	pos = (x + cols * y) * 2;	/* Update cursor position */
	outb(14, vidport);
	outb(0xff & (pos >> 9), vidport+1);
	outb(15, vidport);
	outb(0xff & (pos >> 1), vidport+1);
}

static void *memset(void *s, int c, unsigned n)
{
	int i;
	char *ss = s;

	for (i = 0; i < n; i++) ss[i] = c;
	return s;
}

static void *memcpy(void *dest, const void *src, unsigned n)
{
	int i;
	const char *s = src;
	char *d = dest;

	for (i = 0; i < n; i++) d[i] = s[i];
	return dest;
}

 * Fill the input buffer. This is called only when the buffer is empty
 * and at least one byte is really needed.
 */
static int fill_inbuf(void)
{
	error("ran out of input data");
	return 0;
}

 * Write the output window window[0..outcnt-1] and update crc and bytes_out.
 * (Used for the decompressed data only.)
 */
static void flush_window(void)
{
	/* With my window equal to my output buffer
	 * I only need to compute the crc here.
	 */
	unsigned long c = crc;         /* temporary variable */
	unsigned n;
	unsigned char *in, ch;

	in = window;
	for (n = 0; n < outcnt; n++) {
		ch = *in++;
		c = crc_32_tab[((int)c ^ ch) & 0xff] ^ (c >> 8);
	}
	crc = c;
	bytes_out += (unsigned long)outcnt;
	outcnt = 0;
void __puthex(unsigned long value)
{
	char alpha[2] = "0";
	int bits;

	for (bits = sizeof(value) * 8 - 4; bits >= 0; bits -= 4) {
		unsigned long digit = (value >> bits) & 0xf;

		if (digit < 0xA)
			alpha[0] = '0' + digit;
		else
			alpha[0] = 'a' + (digit - 0xA);

		__putstr(alpha);
	}
}

static void error(char *x)
{
	__putstr(1, "\n\n");
	__putstr(1, x);
	__putstr(1, "\n\n -- System halted");
	error_putstr("\n\n");
	error_putstr(x);
	error_putstr("\n\n -- System halted");

	while (1)
		asm("hlt");
}

#if CONFIG_X86_NEED_RELOCS
static void handle_relocations(void *output, unsigned long output_len,
			       unsigned long virt_addr)
{
	int *reloc;
	unsigned long delta, map, ptr;
	unsigned long min_addr = (unsigned long)output;
	unsigned long max_addr = min_addr + (VO___bss_start - VO__text);

	/*
	 * Calculate the delta between where vmlinux was linked to load
	 * and where it was actually loaded.
	 */
	delta = min_addr - LOAD_PHYSICAL_ADDR;

	/*
	 * The kernel contains a table of relocation addresses. Those
	 * addresses have the final load address of the kernel in virtual
	 * memory. We are currently working in the self map. So we need to
	 * create an adjustment for kernel memory addresses to the self map.
	 * This will involve subtracting out the base address of the kernel.
	 */
	map = delta - __START_KERNEL_map;

	/*
	 * 32-bit always performs relocations. 64-bit relocations are only
	 * needed if KASLR has chosen a different starting address offset
	 * from __START_KERNEL_map.
	 */
	if (IS_ENABLED(CONFIG_X86_64))
		delta = virt_addr - LOAD_PHYSICAL_ADDR;

	if (!delta) {
		debug_putstr("No relocation needed... ");
		return;
	}
	debug_putstr("Performing relocations... ");

	/*
	 * Process relocations: 32 bit relocations first then 64 bit after.
	 * Three sets of binary relocations are added to the end of the kernel
	 * before compression. Each relocation table entry is the kernel
	 * address of the location which needs to be updated stored as a
	 * 32-bit value which is sign extended to 64 bits.
	 *
	 * Format is:
	 *
	 * kernel bits...
	 * 0 - zero terminator for 64 bit relocations
	 * 64 bit relocation repeated
	 * 0 - zero terminator for inverse 32 bit relocations
	 * 32 bit inverse relocation repeated
	 * 0 - zero terminator for 32 bit relocations
	 * 32 bit relocation repeated
	 *
	 * So we work backwards from the end of the decompressed image.
	 */
	for (reloc = output + output_len - sizeof(*reloc); *reloc; reloc--) {
		long extended = *reloc;
		extended += map;

		ptr = (unsigned long)extended;
		if (ptr < min_addr || ptr > max_addr)
			error("32-bit relocation outside of kernel!\n");

		*(uint32_t *)ptr += delta;
	}
#ifdef CONFIG_X86_64
	while (*--reloc) {
		long extended = *reloc;
		extended += map;

		ptr = (unsigned long)extended;
		if (ptr < min_addr || ptr > max_addr)
			error("inverse 32-bit relocation outside of kernel!\n");

		*(int32_t *)ptr -= delta;
	}
	for (reloc--; *reloc; reloc--) {
		long extended = *reloc;
		extended += map;

		ptr = (unsigned long)extended;
		if (ptr < min_addr || ptr > max_addr)
			error("64-bit relocation outside of kernel!\n");

		*(uint64_t *)ptr += delta;
	}
#endif
}
#else
static inline void handle_relocations(void *output, unsigned long output_len,
				      unsigned long virt_addr)
{ }
#endif

static void parse_elf(void *output)
{
#ifdef CONFIG_X86_64
	Elf64_Ehdr ehdr;
	Elf64_Phdr *phdrs, *phdr;
#else
	Elf32_Ehdr ehdr;
	Elf32_Phdr *phdrs, *phdr;
#endif
	void *dest;
	int i;

	memcpy(&ehdr, output, sizeof(ehdr));
	if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
	   ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
	   ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
	   ehdr.e_ident[EI_MAG3] != ELFMAG3) {
		error("Kernel is not a valid ELF file");
		return;
	}

	if (!quiet)
		putstr("Parsing ELF... ");
	debug_putstr("Parsing ELF... ");

	phdrs = malloc(sizeof(*phdrs) * ehdr.e_phnum);
	if (!phdrs)
		error("Failed to allocate space for phdrs");

	memcpy(phdrs, output + ehdr.e_phoff, sizeof(*phdrs) * ehdr.e_phnum);

	for (i = 0; i < ehdr.e_phnum; i++) {
		phdr = &phdrs[i];

		switch (phdr->p_type) {
		case PT_LOAD:
#ifdef CONFIG_RELOCATABLE
			dest = output;
			dest += (phdr->p_paddr - LOAD_PHYSICAL_ADDR);
#else
			dest = (void *)(phdr->p_paddr);
#endif
			memmove(dest, output + phdr->p_offset, phdr->p_filesz);
			break;
		default: /* Ignore other PT_* */ break;
		}
	}
}

asmlinkage void decompress_kernel(void *rmode, memptr heap,
				  unsigned char *input_data,
				  unsigned long input_len,
				  unsigned char *output)
{
	real_mode = rmode;

	if (real_mode->hdr.loadflags & QUIET_FLAG)
		quiet = 1;

	free(phdrs);
}

/*
 * The compressed kernel image (ZO), has been moved so that its position
 * is against the end of the buffer used to hold the uncompressed kernel
 * image (VO) and the execution environment (.bss, .brk), which makes sure
 * there is room to do the in-place decompression. (See header.S for the
 * calculations.)
 *
 *                             |-----compressed kernel image------|
 *                             V                                  V
 * 0                       extract_offset                      +INIT_SIZE
 * |-----------|---------------|-------------------------|--------|
 *             |               |                         |        |
 *           VO__text      startup_32 of ZO          VO__end    ZO__end
 *             ^                                         ^
 *             |-------uncompressed kernel image---------|
 *
 */
asmlinkage __visible void *extract_kernel(void *rmode, memptr heap,
				  unsigned char *input_data,
				  unsigned long input_len,
				  unsigned char *output,
				  unsigned long output_len)
{
	const unsigned long kernel_total_size = VO__end - VO__text;
	unsigned long virt_addr = LOAD_PHYSICAL_ADDR;

	/* Retain x86 boot parameters pointer passed from startup_32/64. */
	boot_params = rmode;

	/* Clear flags intended for solely in-kernel use. */
	boot_params->hdr.loadflags &= ~KASLR_FLAG;

	sanitize_boot_params(boot_params);

	if (boot_params->screen_info.orig_video_mode == 7) {
		vidmem = (char *) 0xb0000;
		vidport = 0x3b4;
	} else {
		vidmem = (char *) 0xb8000;
		vidport = 0x3d4;
	}

	lines = boot_params->screen_info.orig_video_lines;
	cols = boot_params->screen_info.orig_video_cols;

	window = output;		/* Output buffer (Normally at 1M) */
	free_mem_ptr     = heap;	/* Heap */
	free_mem_end_ptr = heap + BOOT_HEAP_SIZE;
	inbuf  = input_data;		/* Input buffer */
	insize = input_len;
	inptr  = 0;

#ifdef CONFIG_X86_64
	if ((unsigned long)output & (__KERNEL_ALIGN - 1))
		error("Destination address not 2M aligned");
	if ((unsigned long)output >= 0xffffffffffUL)
		error("Destination address too large");
#else
	if ((u32)output & (CONFIG_PHYSICAL_ALIGN - 1))
		error("Destination address not CONFIG_PHYSICAL_ALIGN aligned");
	if (heap > ((-__PAGE_OFFSET-(512<<20)-1) & 0x7fffffff))
		error("Destination address too large");
#ifndef CONFIG_RELOCATABLE
	if ((u32)output != LOAD_PHYSICAL_ADDR)
		error("Wrong destination address");
#endif
#endif

	makecrc();
	if (!quiet)
		putstr("\nDecompressing Linux... ");
	gunzip();
	parse_elf(output);
	if (!quiet)
		putstr("done.\nBooting the kernel.\n");
	return;
	console_init();
	debug_putstr("early console in extract_kernel\n");

	free_mem_ptr     = heap;	/* Heap */
	free_mem_end_ptr = heap + BOOT_HEAP_SIZE;

	/* Report initial kernel position details. */
	debug_putaddr(input_data);
	debug_putaddr(input_len);
	debug_putaddr(output);
	debug_putaddr(output_len);
	debug_putaddr(kernel_total_size);

	/*
	 * The memory hole needed for the kernel is the larger of either
	 * the entire decompressed kernel plus relocation table, or the
	 * entire decompressed kernel plus .bss and .brk sections.
	 */
	choose_random_location((unsigned long)input_data, input_len,
				(unsigned long *)&output,
				max(output_len, kernel_total_size),
				&virt_addr);

	/* Validate memory location choices. */
	if ((unsigned long)output & (MIN_KERNEL_ALIGN - 1))
		error("Destination physical address inappropriately aligned");
	if (virt_addr & (MIN_KERNEL_ALIGN - 1))
		error("Destination virtual address inappropriately aligned");
#ifdef CONFIG_X86_64
	if (heap > 0x3fffffffffffUL)
		error("Destination address too large");
	if (virt_addr + max(output_len, kernel_total_size) > KERNEL_IMAGE_SIZE)
		error("Destination virtual address is beyond the kernel mapping area");
#else
	if (heap > ((-__PAGE_OFFSET-(128<<20)-1) & 0x7fffffff))
		error("Destination address too large");
#endif
#ifndef CONFIG_RELOCATABLE
	if ((unsigned long)output != LOAD_PHYSICAL_ADDR)
		error("Destination address does not match LOAD_PHYSICAL_ADDR");
	if (virt_addr != LOAD_PHYSICAL_ADDR)
		error("Destination virtual address changed when not relocatable");
#endif

	debug_putstr("\nDecompressing Linux... ");
	__decompress(input_data, input_len, NULL, NULL, output, output_len,
			NULL, error);
	parse_elf(output);
	handle_relocations(output, output_len, virt_addr);
	debug_putstr("done.\nBooting the kernel.\n");
	return output;
}

void fortify_panic(const char *name)
{
	error("detected buffer overflow");
}
