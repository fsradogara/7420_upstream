// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/minix_fs.h>
#include <linux/ext2_fs.h>
#include <linux/romfs_fs.h>
#include <linux/cramfs_fs.h>
#include <linux/initrd.h>
#include <linux/string.h>

#include "do_mounts.h"
#include <uapi/linux/cramfs_fs.h>
#include <linux/initrd.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "do_mounts.h"
#include "../fs/squashfs/squashfs_fs.h"

#include <linux/decompress/generic.h>


int __initdata rd_prompt = 1;/* 1 = prompt for RAM disk, 0 = don't prompt */

static int __init prompt_ramdisk(char *str)
{
	rd_prompt = simple_strtol(str,NULL,0) & 1;
	return 1;
}
__setup("prompt_ramdisk=", prompt_ramdisk);

int __initdata rd_image_start;		/* starting block # of image */

static int __init ramdisk_start_setup(char *str)
{
	rd_image_start = simple_strtol(str,NULL,0);
	return 1;
}
__setup("ramdisk_start=", ramdisk_start_setup);

static int __init crd_load(int in_fd, int out_fd);
static int __init crd_load(int in_fd, int out_fd, decompress_fn deco);

/*
 * This routine tries to find a RAM disk image to load, and returns the
 * number of blocks to read for a non-compressed image, 0 if the image
 * is a compressed image, and -1 if an image with the right magic
 * numbers could not be found.
 *
 * We currently check for the following magic numbers:
 * 	minix
 * 	ext2
 *	romfs
 *	cramfs
 * 	gzip
 */
static int __init 
identify_ramdisk_image(int fd, int start_block)
{
	const int size = 512;
	struct minix_super_block *minixsb;
	struct ext2_super_block *ext2sb;
	struct romfs_super_block *romfsb;
	struct cramfs_super *cramfsb;
	int nblocks = -1;
	unsigned char *buf;

	buf = kmalloc(size, GFP_KERNEL);
	if (!buf)
		return -1;

	minixsb = (struct minix_super_block *) buf;
	ext2sb = (struct ext2_super_block *) buf;
	romfsb = (struct romfs_super_block *) buf;
	cramfsb = (struct cramfs_super *) buf;
	memset(buf, 0xe5, size);

	/*
	 * Read block 0 to test for gzipped kernel
 *	minix
 *	ext2
 *	romfs
 *	cramfs
 *	squashfs
 *	gzip
 *	bzip2
 *	lzma
 *	xz
 *	lzo
 *	lz4
 */
static int __init
identify_ramdisk_image(int fd, int start_block, decompress_fn *decompressor)
{
	const int size = 512;
	struct minix_super_block *minixsb;
	struct romfs_super_block *romfsb;
	struct cramfs_super *cramfsb;
	struct squashfs_super_block *squashfsb;
	int nblocks = -1;
	unsigned char *buf;
	const char *compress_name;
	unsigned long n;

	buf = kmalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	minixsb = (struct minix_super_block *) buf;
	romfsb = (struct romfs_super_block *) buf;
	cramfsb = (struct cramfs_super *) buf;
	squashfsb = (struct squashfs_super_block *) buf;
	memset(buf, 0xe5, size);

	/*
	 * Read block 0 to test for compressed kernel
	 */
	ksys_lseek(fd, start_block * BLOCK_SIZE, 0);
	ksys_read(fd, buf, size);

	/*
	 * If it matches the gzip magic numbers, return -1
	 */
	if (buf[0] == 037 && ((buf[1] == 0213) || (buf[1] == 0236))) {
		printk(KERN_NOTICE
		       "RAMDISK: Compressed image found at block %d\n",
		       start_block);
	*decompressor = decompress_method(buf, size, &compress_name);
	if (compress_name) {
		printk(KERN_NOTICE "RAMDISK: %s image found at block %d\n",
		       compress_name, start_block);
		if (!*decompressor)
			printk(KERN_EMERG
			       "RAMDISK: %s decompressor not configured!\n",
			       compress_name);
		nblocks = 0;
		goto done;
	}

	/* romfs is at block zero too */
	if (romfsb->word0 == ROMSB_WORD0 &&
	    romfsb->word1 == ROMSB_WORD1) {
		printk(KERN_NOTICE
		       "RAMDISK: romfs filesystem found at block %d\n",
		       start_block);
		nblocks = (ntohl(romfsb->size)+BLOCK_SIZE-1)>>BLOCK_SIZE_BITS;
		goto done;
	}

	if (cramfsb->magic == CRAMFS_MAGIC) {
		printk(KERN_NOTICE
		       "RAMDISK: cramfs filesystem found at block %d\n",
		       start_block);
		nblocks = (cramfsb->size + BLOCK_SIZE - 1) >> BLOCK_SIZE_BITS;
		goto done;
	}

	/* squashfs is at block zero too */
	if (le32_to_cpu(squashfsb->s_magic) == SQUASHFS_MAGIC) {
		printk(KERN_NOTICE
		       "RAMDISK: squashfs filesystem found at block %d\n",
		       start_block);
		nblocks = (le64_to_cpu(squashfsb->bytes_used) + BLOCK_SIZE - 1)
			 >> BLOCK_SIZE_BITS;
		goto done;
	}

	/*
	 * Read 512 bytes further to check if cramfs is padded
	 */
	ksys_lseek(fd, start_block * BLOCK_SIZE + 0x200, 0);
	ksys_read(fd, buf, size);

	if (cramfsb->magic == CRAMFS_MAGIC) {
		printk(KERN_NOTICE
		       "RAMDISK: cramfs filesystem found at block %d\n",
		       start_block);
		nblocks = (cramfsb->size + BLOCK_SIZE - 1) >> BLOCK_SIZE_BITS;
		goto done;
	}

	/*
	 * Read block 1 to test for minix and ext2 superblock
	 */
	ksys_lseek(fd, (start_block+1) * BLOCK_SIZE, 0);
	ksys_read(fd, buf, size);

	/* Try minix */
	if (minixsb->s_magic == MINIX_SUPER_MAGIC ||
	    minixsb->s_magic == MINIX_SUPER_MAGIC2) {
		printk(KERN_NOTICE
		       "RAMDISK: Minix filesystem found at block %d\n",
		       start_block);
		nblocks = minixsb->s_nzones << minixsb->s_log_zone_size;
		goto done;
	}

	/* Try ext2 */
	if (ext2sb->s_magic == cpu_to_le16(EXT2_SUPER_MAGIC)) {
		printk(KERN_NOTICE
		       "RAMDISK: ext2 filesystem found at block %d\n",
		       start_block);
		nblocks = le32_to_cpu(ext2sb->s_blocks_count) <<
			le32_to_cpu(ext2sb->s_log_block_size);
	n = ext2_image_size(buf);
	if (n) {
		printk(KERN_NOTICE
		       "RAMDISK: ext2 filesystem found at block %d\n",
		       start_block);
		nblocks = n;
		goto done;
	}

	printk(KERN_NOTICE
	       "RAMDISK: Couldn't find valid RAM disk image starting at %d.\n",
	       start_block);
	

done:
	ksys_lseek(fd, start_block * BLOCK_SIZE, 0);
	kfree(buf);
	return nblocks;
}

int __init rd_load_image(char *from)
{
	int res = 0;
	int in_fd, out_fd;
	unsigned long rd_blocks, devblocks;
	int nblocks, i, disk;
	char *buf = NULL;
	unsigned short rotate = 0;
#if !defined(CONFIG_S390) && !defined(CONFIG_PPC_ISERIES)
	decompress_fn decompressor = NULL;
#if !defined(CONFIG_S390)
	char rotator[4] = { '|' , '/' , '-' , '\\' };
#endif

	out_fd = ksys_open("/dev/ram", O_RDWR, 0);
	if (out_fd < 0)
		goto out;

	in_fd = ksys_open(from, O_RDONLY, 0);
	if (in_fd < 0)
		goto noclose_input;

	nblocks = identify_ramdisk_image(in_fd, rd_image_start);
	nblocks = identify_ramdisk_image(in_fd, rd_image_start, &decompressor);
	if (nblocks < 0)
		goto done;

	if (nblocks == 0) {
		if (crd_load(in_fd, out_fd) == 0)
		if (crd_load(in_fd, out_fd, decompressor) == 0)
			goto successful_load;
		goto done;
	}

	/*
	 * NOTE NOTE: nblocks is not actually blocks but
	 * the number of kibibytes of data to load into a ramdisk.
	 */
	if (ksys_ioctl(out_fd, BLKGETSIZE, (unsigned long)&rd_blocks) < 0)
		rd_blocks = 0;
	else
		rd_blocks >>= 1;

	if (nblocks > rd_blocks) {
		printk("RAMDISK: image too big! (%dKiB/%ldKiB)\n",
		       nblocks, rd_blocks);
		goto done;
	}
		

	/*
	 * OK, time to copy in the data
	 */
	if (ksys_ioctl(in_fd, BLKGETSIZE, (unsigned long)&devblocks) < 0)
		devblocks = 0;
	else
		devblocks >>= 1;

	if (strcmp(from, "/initrd.image") == 0)
		devblocks = nblocks;

	if (devblocks == 0) {
		printk(KERN_ERR "RAMDISK: could not determine device size\n");
		goto done;
	}

	buf = kmalloc(BLOCK_SIZE, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "RAMDISK: could not allocate buffer\n");
		goto done;
	}

	printk(KERN_NOTICE "RAMDISK: Loading %dKiB [%ld disk%s] into ram disk... ",
		nblocks, ((nblocks-1)/devblocks)+1, nblocks>devblocks ? "s" : "");
	for (i = 0, disk = 1; i < nblocks; i++) {
		if (i && (i % devblocks == 0)) {
			pr_cont("done disk #%d.\n", disk++);
			rotate = 0;
			if (ksys_close(in_fd)) {
				printk("Error closing the disk.\n");
				goto noclose_input;
			}
			change_floppy("disk #%d", disk);
			in_fd = ksys_open(from, O_RDONLY, 0);
			if (in_fd < 0)  {
				printk("Error opening disk.\n");
				goto noclose_input;
			}
			printk("Loading disk #%d... ", disk);
		}
		sys_read(in_fd, buf, BLOCK_SIZE);
		sys_write(out_fd, buf, BLOCK_SIZE);
#if !defined(CONFIG_S390) && !defined(CONFIG_PPC_ISERIES)
		ksys_read(in_fd, buf, BLOCK_SIZE);
		ksys_write(out_fd, buf, BLOCK_SIZE);
#if !defined(CONFIG_S390)
		if (!(i % 16)) {
			pr_cont("%c\b", rotator[rotate & 0x3]);
			rotate++;
		}
#endif
	}
	pr_cont("done.\n");

successful_load:
	res = 1;
done:
	ksys_close(in_fd);
noclose_input:
	ksys_close(out_fd);
out:
	kfree(buf);
	ksys_unlink("/dev/ram");
	return res;
}

int __init rd_load_disk(int n)
{
	if (rd_prompt)
		change_floppy("root floppy disk to be loaded into RAM disk");
	create_dev("/dev/root", ROOT_DEV);
	create_dev("/dev/ram", MKDEV(RAMDISK_MAJOR, n));
	return rd_load_image("/dev/root");
}

/*
 * gzip declarations
 */

#define OF(args)  args

#ifndef memzero
#define memzero(s, n)     memset ((s), 0, (n))
#endif

typedef unsigned char  uch;
typedef unsigned short ush;
typedef unsigned long  ulg;

#define INBUFSIZ 4096
#define WSIZE 0x8000    /* window size--must be a power of two, and */
			/*  at least 32K for zip's deflate method */

static uch *inbuf;
static uch *window;

static unsigned insize;  /* valid bytes in inbuf */
static unsigned inptr;   /* index of next byte to be processed in inbuf */
static unsigned outcnt;  /* bytes in output buffer */
static int exit_code;
static int unzip_error;
static long bytes_out;
static int crd_infd, crd_outfd;

#define get_byte()  (inptr < insize ? inbuf[inptr++] : fill_inbuf())
		
/* Diagnostic functions (stubbed out) */
#define Assert(cond,msg)
#define Trace(x)
#define Tracev(x)
#define Tracevv(x)
#define Tracec(c,x)
#define Tracecv(c,x)

#define STATIC static
#define INIT __init

static int  __init fill_inbuf(void);
static void __init flush_window(void);
static void __init error(char *m);

#define NO_INFLATE_MALLOC

#include "../lib/inflate.c"

 * Fill the input buffer. This is called only when the buffer is empty
 * and at least one byte is really needed.
 * Returning -1 does not guarantee that gunzip() will ever return.
 */
static int __init fill_inbuf(void)
{
	if (exit_code) return -1;
	
	insize = sys_read(crd_infd, inbuf, INBUFSIZ);
	if (insize == 0) {
		error("RAMDISK: ran out of compressed data");
		return -1;
	}

	inptr = 1;

	return inbuf[0];
}

 * Write the output window window[0..outcnt-1] and update crc and bytes_out.
 * (Used for the decompressed data only.)
 */
static void __init flush_window(void)
{
    ulg c = crc;         /* temporary variable */
    unsigned n, written;
    uch *in, ch;
    
    written = sys_write(crd_outfd, window, outcnt);
    if (written != outcnt && unzip_error == 0) {
	printk(KERN_ERR "RAMDISK: incomplete write (%d != %d) %ld\n",
	       written, outcnt, bytes_out);
	unzip_error = 1;
    }
    in = window;
    for (n = 0; n < outcnt; n++) {
	    ch = *in++;
	    c = crc_32_tab[((int)c ^ ch) & 0xff] ^ (c >> 8);
    }
    crc = c;
    bytes_out += (ulg)outcnt;
    outcnt = 0;
static int exit_code;
static int decompress_error;
static int crd_infd, crd_outfd;

static long __init compr_fill(void *buf, unsigned long len)
{
	long r = ksys_read(crd_infd, buf, len);
	if (r < 0)
		printk(KERN_ERR "RAMDISK: error while reading compressed data");
	else if (r == 0)
		printk(KERN_ERR "RAMDISK: EOF while reading compressed data");
	return r;
}

static long __init compr_flush(void *window, unsigned long outcnt)
{
	long written = ksys_write(crd_outfd, window, outcnt);
	if (written != outcnt) {
		if (decompress_error == 0)
			printk(KERN_ERR
			       "RAMDISK: incomplete write (%ld != %ld)\n",
			       written, outcnt);
		decompress_error = 1;
		return -1;
	}
	return outcnt;
}

static void __init error(char *x)
{
	printk(KERN_ERR "%s\n", x);
	exit_code = 1;
	unzip_error = 1;
}

static int __init crd_load(int in_fd, int out_fd)
{
	int result;

	insize = 0;		/* valid bytes in inbuf */
	inptr = 0;		/* index of next byte to be processed in inbuf */
	outcnt = 0;		/* bytes in output buffer */
	exit_code = 0;
	bytes_out = 0;
	crc = (ulg)0xffffffffL; /* shift register contents */

	crd_infd = in_fd;
	crd_outfd = out_fd;
	inbuf = kmalloc(INBUFSIZ, GFP_KERNEL);
	if (!inbuf) {
		printk(KERN_ERR "RAMDISK: Couldn't allocate gzip buffer\n");
		return -1;
	}
	window = kmalloc(WSIZE, GFP_KERNEL);
	if (!window) {
		printk(KERN_ERR "RAMDISK: Couldn't allocate gzip window\n");
		kfree(inbuf);
		return -1;
	}
	makecrc();
	result = gunzip();
	if (unzip_error)
		result = 1;
	kfree(inbuf);
	kfree(window);
	decompress_error = 1;
}

static int __init crd_load(int in_fd, int out_fd, decompress_fn deco)
{
	int result;
	crd_infd = in_fd;
	crd_outfd = out_fd;

	if (!deco) {
		pr_emerg("Invalid ramdisk decompression routine.  "
			 "Select appropriate config option.\n");
		panic("Could not decompress initial ramdisk image.");
	}

	result = deco(NULL, 0, compr_fill, compr_flush, NULL, NULL, error);
	if (decompress_error)
		result = 1;
	return result;
}
