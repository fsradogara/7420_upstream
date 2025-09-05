/*
 * atari_scsi.c -- Device dependent functions for the Atari generic SCSI port
 *
 * Copyright 1994 Roman Hodek <Roman.Hodek@informatik.uni-erlangen.de>
 *
 *   Loosely based on the work of Robert De Vries' team and added:
 *    - working real DMA
 *    - Falcon support (untested yet!)   ++bjoern fixed and now it works
 *    - lots of extensions and bug fixes.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 *
 */

/*
 * Notes for Falcon SCSI DMA
 *
 * The 5380 device is one of several that all share the DMA chip. Hence
 * "locking" and "unlocking" access to this chip is required.
 *
 * Two possible schemes for ST DMA acquisition by atari_scsi are:
 * 1) The lock is taken for each command separately (i.e. can_queue == 1).
 * 2) The lock is taken when the first command arrives and released
 * when the last command is finished (i.e. can_queue > 1).
 *
 * The first alternative limits SCSI bus utilization, since interleaving
 * commands is not possible. The second gives better performance but is
 * unfair to other drivers needing to use the ST DMA chip. In order to
 * allow the IDE and floppy drivers equal access to the ST DMA chip
 * the default is can_queue == 1.
 */


#include <linux/module.h>

#define NDEBUG (0)

#define NDEBUG_ABORT		0x00100000
#define NDEBUG_TAGS		0x00200000
#define NDEBUG_MERGING		0x00400000

#define AUTOSENSE
/* For the Atari version, use only polled IO or REAL_DMA */
#define	REAL_DMA
/* Support tagged queuing? (on devices that are able to... :-) */
#define	SUPPORT_TAGS
#define	MAX_TAGS 32

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/nvram.h>
#include <linux/bitops.h>
#include <linux/wait.h>
#include <linux/platform_device.h>

#include <asm/setup.h>
#include <asm/atarihw.h>
#include <asm/atariints.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/irq.h>
#include <asm/traps.h>

#include "scsi.h"
#include <scsi/scsi_host.h>
#include "atari_scsi.h"
#include "NCR5380.h"
#include <asm/atari_stdma.h>
#include <asm/atari_stram.h>
#include <asm/io.h>

#include <linux/stat.h>
#include <scsi/scsi_host.h>

#define DMA_MIN_SIZE                    32

/* Definitions for the core NCR5380 driver. */

#define NCR5380_implementation_fields   /* none */

static u8 (*atari_scsi_reg_read)(unsigned int);
static void (*atari_scsi_reg_write)(unsigned int, u8);

#define NCR5380_read(reg)               atari_scsi_reg_read(reg)
#define NCR5380_write(reg, value)       atari_scsi_reg_write(reg, value)

#define NCR5380_queue_command           atari_scsi_queue_command
#define NCR5380_abort                   atari_scsi_abort
#define NCR5380_info                    atari_scsi_info

#define NCR5380_dma_xfer_len            atari_scsi_dma_xfer_len
#define NCR5380_dma_recv_setup          atari_scsi_dma_recv_setup
#define NCR5380_dma_send_setup          atari_scsi_dma_send_setup
#define NCR5380_dma_residual            atari_scsi_dma_residual

#define NCR5380_acquire_dma_irq(instance)      falcon_get_lock(instance)
#define NCR5380_release_dma_irq(instance)      falcon_release_lock()

#include "NCR5380.h"


#define	IS_A_TT()	ATARIHW_PRESENT(TT_SCSI)

#define	SCSI_DMA_WRITE_P(elt,val)				\
	do {							\
		unsigned long v = val;				\
		tt_scsi_dma.elt##_lo = v & 0xff;		\
		v >>= 8;					\
		tt_scsi_dma.elt##_lmd = v & 0xff;		\
		v >>= 8;					\
		tt_scsi_dma.elt##_hmd = v & 0xff;		\
		v >>= 8;					\
		tt_scsi_dma.elt##_hi = v & 0xff;		\
	} while(0)

#define	SCSI_DMA_READ_P(elt)					\
	(((((((unsigned long)tt_scsi_dma.elt##_hi << 8) |	\
	     (unsigned long)tt_scsi_dma.elt##_hmd) << 8) |	\
	   (unsigned long)tt_scsi_dma.elt##_lmd) << 8) |	\
	 (unsigned long)tt_scsi_dma.elt##_lo)


static inline void SCSI_DMA_SETADR(unsigned long adr)
{
	st_dma.dma_lo = (unsigned char)adr;
	MFPDELAY();
	adr >>= 8;
	st_dma.dma_md = (unsigned char)adr;
	MFPDELAY();
	adr >>= 8;
	st_dma.dma_hi = (unsigned char)adr;
	MFPDELAY();
}

static inline unsigned long SCSI_DMA_GETADR(void)
{
	unsigned long adr;
	adr = st_dma.dma_lo;
	MFPDELAY();
	adr |= (st_dma.dma_md & 0xff) << 8;
	MFPDELAY();
	adr |= (st_dma.dma_hi & 0xff) << 16;
	MFPDELAY();
	return adr;
}

static inline void ENABLE_IRQ(void)
{
	if (IS_A_TT())
		atari_enable_irq(IRQ_TT_MFP_SCSI);
	else
		atari_enable_irq(IRQ_MFP_FSCSI);
}

static inline void DISABLE_IRQ(void)
{
	if (IS_A_TT())
		atari_disable_irq(IRQ_TT_MFP_SCSI);
	else
		atari_disable_irq(IRQ_MFP_FSCSI);
}


#define HOSTDATA_DMALEN		(((struct NCR5380_hostdata *) \
				(atari_scsi_host->hostdata))->dma_len)

/* Time (in jiffies) to wait after a reset; the SCSI standard calls for 250ms,
 * we usually do 0.5s to be on the safe side. But Toshiba CD-ROMs once more
 * need ten times the standard value... */
#ifndef CONFIG_ATARI_SCSI_TOSHIBA_DELAY
#define	AFTER_RESET_DELAY	(HZ/2)
#else
#define	AFTER_RESET_DELAY	(5*HZ/2)
#endif

/***************************** Prototypes *****************************/

#ifdef REAL_DMA
static int scsi_dma_is_ignored_buserr(unsigned char dma_stat);
static void atari_scsi_fetch_restbytes(void);
static long atari_scsi_dma_residual(struct Scsi_Host *instance);
static int falcon_classify_cmd(Scsi_Cmnd *cmd);
static unsigned long atari_dma_xfer_len(unsigned long wanted_len,
					Scsi_Cmnd *cmd, int write_flag);
#endif
static irqreturn_t scsi_tt_intr(int irq, void *dummy);
static irqreturn_t scsi_falcon_intr(int irq, void *dummy);
static void falcon_release_lock_if_possible(struct NCR5380_hostdata *hostdata);
static void falcon_get_lock(void);
#ifdef CONFIG_ATARI_SCSI_RESET_BOOT
static void atari_scsi_reset_boot(void);
#endif
static unsigned char atari_scsi_tt_reg_read(unsigned char reg);
static void atari_scsi_tt_reg_write(unsigned char reg, unsigned char value);
static unsigned char atari_scsi_falcon_reg_read(unsigned char reg);
static void atari_scsi_falcon_reg_write(unsigned char reg, unsigned char value);

/************************* End of Prototypes **************************/

#ifdef REAL_DMA
static void atari_scsi_fetch_restbytes(void);

static unsigned long	atari_dma_residual, atari_dma_startaddr;
static short		atari_dma_active;
/* pointer to the dribble buffer */
static char		*atari_dma_buffer;
/* precalculated physical address of the dribble buffer */
static unsigned long	atari_dma_phys_buffer;
/* != 0 tells the Falcon int handler to copy data from the dribble buffer */
static char		*atari_dma_orig_addr;
/* size of the dribble buffer; 4k seems enough, since the Falcon cannot use
 * scatter-gather anyway, so most transfers are 1024 byte only. In the rare
 * cases where requests to physical contiguous buffers have been merged, this
 * request is <= 4k (one page). So I don't think we have to split transfers
 * just due to this buffer size...
 */
#define	STRAM_BUFFER_SIZE	(4096)
/* mask for address bits that can't be used with the ST-DMA */
static unsigned long	atari_dma_stram_mask;
#define STRAM_ADDR(a)	(((a) & atari_dma_stram_mask) == 0)
/* number of bytes to cut from a transfer to handle NCR overruns */
static int atari_read_overruns;
#endif

static int setup_can_queue = -1;
module_param(setup_can_queue, int, 0);
static int setup_cmd_per_lun = -1;
module_param(setup_cmd_per_lun, int, 0);
static int setup_sg_tablesize = -1;
module_param(setup_sg_tablesize, int, 0);
static int setup_hostid = -1;
module_param(setup_hostid, int, 0);
static int setup_toshiba_delay = -1;
module_param(setup_toshiba_delay, int, 0);


#if defined(CONFIG_TT_DMA_EMUL)
#include "atari_dma_emul.c"
#endif

#if defined(REAL_DMA)

static int scsi_dma_is_ignored_buserr(unsigned char dma_stat)
{
	int i;
	unsigned long addr = SCSI_DMA_READ_P(dma_addr), end_addr;

	if (dma_stat & 0x01) {

		/* A bus error happens when DMA-ing from the last page of a
		 * physical memory chunk (DMA prefetch!), but that doesn't hurt.
		 * Check for this case:
		 */

		for (i = 0; i < m68k_num_memory; ++i) {
			end_addr = m68k_memory[i].addr + m68k_memory[i].size;
			if (end_addr <= addr && addr <= end_addr + 4)
				return 1;
		}
	}
	return 0;
}


static irqreturn_t scsi_tt_intr(int irq, void *dev)
{
	struct Scsi_Host *instance = dev;
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	int dma_stat;

	dma_stat = tt_scsi_dma.dma_ctrl;

	INT_PRINTK("scsi%d: NCR5380 interrupt, DMA status = %02x\n",
	dprintk(NDEBUG_INTR, "scsi%d: NCR5380 interrupt, DMA status = %02x\n",
		   atari_scsi_host->host_no, dma_stat & 0xff);
	dsprintk(NDEBUG_INTR, instance, "NCR5380 interrupt, DMA status = %02x\n",
	         dma_stat & 0xff);

	/* Look if it was the DMA that has interrupted: First possibility
	 * is that a bus error occurred...
	 */
	if (dma_stat & 0x80) {
		if (!scsi_dma_is_ignored_buserr(dma_stat)) {
			printk(KERN_ERR "SCSI DMA caused bus error near 0x%08lx\n",
			       SCSI_DMA_READ_P(dma_addr));
			printk(KERN_CRIT "SCSI DMA bus error -- bad DMA programming!");
		}
	}

	/* If the DMA is active but not finished, we have the case
	 * that some other 5380 interrupt occurred within the DMA transfer.
	 * This means we have residual bytes, if the desired end address
	 * is not yet reached. Maybe we have to fetch some bytes from the
	 * rest data register, too. The residual must be calculated from
	 * the address pointer, not the counter register, because only the
	 * addr reg counts bytes not yet written and pending in the rest
	 * data reg!
	 */
	if ((dma_stat & 0x02) && !(dma_stat & 0x40)) {
		atari_dma_residual = hostdata->dma_len -
			(SCSI_DMA_READ_P(dma_addr) - atari_dma_startaddr);

		DMA_PRINTK("SCSI DMA: There are %ld residual bytes.\n",
		dprintk(NDEBUG_DMA, "SCSI DMA: There are %ld residual bytes.\n",
			   atari_dma_residual);

		if ((signed int)atari_dma_residual < 0)
			atari_dma_residual = 0;
		if ((dma_stat & 1) == 0) {
			/*
			 * After read operations, we maybe have to
			 * transport some rest bytes
			 */
			atari_scsi_fetch_restbytes();
		} else {
			/*
			 * There seems to be a nasty bug in some SCSI-DMA/NCR
			 * combinations: If a target disconnects while a write
			 * operation is going on, the address register of the
			 * DMA may be a few bytes farer than it actually read.
			 * This is probably due to DMA prefetching and a delay
			 * between DMA and NCR.  Experiments showed that the
			 * dma_addr is 9 bytes to high, but this could vary.
			 * The problem is, that the residual is thus calculated
			 * wrong and the next transfer will start behind where
			 * it should.  So we round up the residual to the next
			 * multiple of a sector size, if it isn't already a
			 * multiple and the originally expected transfer size
			 * was.  The latter condition is there to ensure that
			 * the correction is taken only for "real" data
			 * transfers and not for, e.g., the parameters of some
			 * other command.  These shouldn't disconnect anyway.
			 */
			if (atari_dma_residual & 0x1ff) {
				DMA_PRINTK("SCSI DMA: DMA bug corrected, "
				dprintk(NDEBUG_DMA, "SCSI DMA: DMA bug corrected, "
					   "difference %ld bytes\n",
					   512 - (atari_dma_residual & 0x1ff));
				atari_dma_residual = (atari_dma_residual + 511) & ~0x1ff;
			}
		}
		tt_scsi_dma.dma_ctrl = 0;
	}

	/* If the DMA is finished, fetch the rest bytes and turn it off */
	if (dma_stat & 0x40) {
		atari_dma_residual = 0;
		if ((dma_stat & 1) == 0)
			atari_scsi_fetch_restbytes();
		tt_scsi_dma.dma_ctrl = 0;
	}

	NCR5380_intr(irq, dev);

#if 0
	/* To be sure the int is not masked */
	atari_enable_irq(IRQ_TT_MFP_SCSI);
#endif
	return IRQ_HANDLED;
}


static irqreturn_t scsi_falcon_intr(int irq, void *dev)
{
	struct Scsi_Host *instance = dev;
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	int dma_stat;

	/* Turn off DMA and select sector counter register before
	 * accessing the status register (Atari recommendation!)
	 */
	st_dma.dma_mode_status = 0x90;
	dma_stat = st_dma.dma_mode_status;

	/* Bit 0 indicates some error in the DMA process... don't know
	 * what happened exactly (no further docu).
	 */
	if (!(dma_stat & 0x01)) {
		/* DMA error */
		printk(KERN_CRIT "SCSI DMA error near 0x%08lx!\n", SCSI_DMA_GETADR());
	}

	/* If the DMA was active, but now bit 1 is not clear, it is some
	 * other 5380 interrupt that finishes the DMA transfer. We have to
	 * calculate the number of residual bytes and give a warning if
	 * bytes are stuck in the ST-DMA fifo (there's no way to reach them!)
	 */
	if (atari_dma_active && (dma_stat & 0x02)) {
		unsigned long transferred;

		transferred = SCSI_DMA_GETADR() - atari_dma_startaddr;
		/* The ST-DMA address is incremented in 2-byte steps, but the
		 * data are written only in 16-byte chunks. If the number of
		 * transferred bytes is not divisible by 16, the remainder is
		 * lost somewhere in outer space.
		 */
		if (transferred & 15)
			printk(KERN_ERR "SCSI DMA error: %ld bytes lost in "
			       "ST-DMA fifo\n", transferred & 15);

		atari_dma_residual = HOSTDATA_DMALEN - transferred;
		DMA_PRINTK("SCSI DMA: There are %ld residual bytes.\n",
		atari_dma_residual = hostdata->dma_len - transferred;
		dprintk(NDEBUG_DMA, "SCSI DMA: There are %ld residual bytes.\n",
			   atari_dma_residual);
	} else
		atari_dma_residual = 0;
	atari_dma_active = 0;

	if (atari_dma_orig_addr) {
		/* If the dribble buffer was used on a read operation, copy the DMA-ed
		 * data to the original destination address.
		 */
		memcpy(atari_dma_orig_addr, phys_to_virt(atari_dma_startaddr),
		       hostdata->dma_len - atari_dma_residual);
		atari_dma_orig_addr = NULL;
	}

	NCR5380_intr(irq, dev);

	return IRQ_HANDLED;
}


static void atari_scsi_fetch_restbytes(void)
{
	int nr;
	char *src, *dst;
	unsigned long phys_dst;

	/* fetch rest bytes in the DMA register */
	phys_dst = SCSI_DMA_READ_P(dma_addr);
	nr = phys_dst & 3;
	if (nr) {
		/* there are 'nr' bytes left for the last long address
		   before the DMA pointer */
		phys_dst ^= nr;
		DMA_PRINTK("SCSI DMA: there are %d rest bytes for phys addr 0x%08lx",
			   nr, phys_dst);
		/* The content of the DMA pointer is a physical address!  */
		dst = phys_to_virt(phys_dst);
		DMA_PRINTK(" = virt addr %p\n", dst);
		dprintk(NDEBUG_DMA, "SCSI DMA: there are %d rest bytes for phys addr 0x%08lx",
			   nr, phys_dst);
		/* The content of the DMA pointer is a physical address!  */
		dst = phys_to_virt(phys_dst);
		dprintk(NDEBUG_DMA, " = virt addr %p\n", dst);
		for (src = (char *)&tt_scsi_dma.dma_restdata; nr != 0; --nr)
			*dst++ = *src++;
	}
}


static int falcon_got_lock = 0;
static DECLARE_WAIT_QUEUE_HEAD(falcon_fairness_wait);
static int falcon_trying_lock = 0;
static DECLARE_WAIT_QUEUE_HEAD(falcon_try_wait);
static int falcon_dont_release = 0;

/* This function releases the lock on the DMA chip if there is no
 * connected command and the disconnected queue is empty. On
 * releasing, instances of falcon_get_lock are awoken, that put
 * themselves to sleep for fairness. They can now try to get the lock
 * again (but others waiting longer more probably will win).
 */

static void falcon_release_lock_if_possible(struct NCR5380_hostdata *hostdata)
{
	unsigned long flags;

	if (IS_A_TT())
		return;

	local_irq_save(flags);

	if (falcon_got_lock && !hostdata->disconnected_queue &&
	    !hostdata->issue_queue && !hostdata->connected) {

		if (falcon_dont_release) {
#if 0
			printk("WARNING: Lock release not allowed. Ignored\n");
#endif
			local_irq_restore(flags);
			return;
		}
		falcon_got_lock = 0;
		stdma_release();
		wake_up(&falcon_fairness_wait);
	}

	local_irq_restore(flags);
/* This function releases the lock on the DMA chip if there is no
 * connected command and the disconnected queue is empty.
 */

static void falcon_release_lock(void)
{
	if (IS_A_TT())
		return;

	if (stdma_is_locked_by(scsi_falcon_intr))
		stdma_release();
}

/* This function manages the locking of the ST-DMA.
 * If the DMA isn't locked already for SCSI, it tries to lock it by
 * calling stdma_lock(). But if the DMA is locked by the SCSI code and
 * there are other drivers waiting for the chip, we do not issue the
 * command immediately but wait on 'falcon_fairness_queue'. We will be
 * waked up when the DMA is unlocked by some SCSI interrupt. After that
 * we try to get the lock again.
 * But we must be prepared that more than one instance of
 * falcon_get_lock() is waiting on the fairness queue. They should not
 * try all at once to call stdma_lock(), one is enough! For that, the
 * first one sets 'falcon_trying_lock', others that see that variable
 * set wait on the queue 'falcon_try_wait'.
 * Complicated, complicated.... Sigh...
 */

static void falcon_get_lock(void)
{
	unsigned long flags;

	if (IS_A_TT())
		return;

	local_irq_save(flags);

	while (!in_irq() && falcon_got_lock && stdma_others_waiting())
		sleep_on(&falcon_fairness_wait);

	while (!falcon_got_lock) {
		if (in_irq())
			panic("Falcon SCSI hasn't ST-DMA lock in interrupt");
		if (!falcon_trying_lock) {
			falcon_trying_lock = 1;
			stdma_lock(scsi_falcon_intr, NULL);
			falcon_got_lock = 1;
			falcon_trying_lock = 0;
			wake_up(&falcon_try_wait);
		} else {
			sleep_on(&falcon_try_wait);
		}
	}

	local_irq_restore(flags);
	if (!falcon_got_lock)
		panic("Falcon SCSI: someone stole the lock :-(\n");
}


/* This is the wrapper function for NCR5380_queue_command(). It just
 * tries to get the lock on the ST-DMA (see above) and then calls the
 * original function.
 */

#if 0
int atari_queue_command(Scsi_Cmnd *cmd, void (*done)(Scsi_Cmnd *))
{
	/* falcon_get_lock();
	 * ++guenther: moved to NCR5380_queue_command() to prevent
	 * race condition, see there for an explanation.
	 */
	return NCR5380_queue_command(cmd, done);
}
#endif


int atari_scsi_detect(struct scsi_host_template *host)
{
	static int called = 0;
	struct Scsi_Host *instance;

	if (!MACH_IS_ATARI ||
	    (!ATARIHW_PRESENT(ST_SCSI) && !ATARIHW_PRESENT(TT_SCSI)) ||
	    called)
		return 0;

	host->proc_name = "Atari";

	atari_scsi_reg_read  = IS_A_TT() ? atari_scsi_tt_reg_read :
					   atari_scsi_falcon_reg_read;
	atari_scsi_reg_write = IS_A_TT() ? atari_scsi_tt_reg_write :
					   atari_scsi_falcon_reg_write;

	/* setup variables */
	host->can_queue =
		(setup_can_queue > 0) ? setup_can_queue :
		IS_A_TT() ? ATARI_TT_CAN_QUEUE : ATARI_FALCON_CAN_QUEUE;
	host->cmd_per_lun =
		(setup_cmd_per_lun > 0) ? setup_cmd_per_lun :
		IS_A_TT() ? ATARI_TT_CMD_PER_LUN : ATARI_FALCON_CMD_PER_LUN;
	/* Force sg_tablesize to 0 on a Falcon! */
	host->sg_tablesize =
		!IS_A_TT() ? ATARI_FALCON_SG_TABLESIZE :
		(setup_sg_tablesize >= 0) ? setup_sg_tablesize : ATARI_TT_SG_TABLESIZE;

	if (setup_hostid >= 0)
		host->this_id = setup_hostid;
	else {
		/* use 7 as default */
		host->this_id = 7;
		/* Test if a host id is set in the NVRam */
		if (ATARIHW_PRESENT(TT_CLK) && nvram_check_checksum()) {
			unsigned char b = nvram_read_byte( 14 );
			/* Arbitration enabled? (for TOS) If yes, use configured host ID */
			if (b & 0x80)
				host->this_id = b & 7;
		}
	}

#ifdef SUPPORT_TAGS
	if (setup_use_tagged_queuing < 0)
		setup_use_tagged_queuing = DEFAULT_USE_TAGGED_QUEUING;
#endif
#ifdef REAL_DMA
	/* If running on a Falcon and if there's TT-Ram (i.e., more than one
	 * memory block, since there's always ST-Ram in a Falcon), then allocate a
	 * STRAM_BUFFER_SIZE byte dribble buffer for transfers from/to alternative
	 * Ram.
	 */
	if (MACH_IS_ATARI && ATARIHW_PRESENT(ST_SCSI) &&
	    !ATARIHW_PRESENT(EXTD_DMA) && m68k_num_memory > 1) {
		atari_dma_buffer = atari_stram_alloc(STRAM_BUFFER_SIZE, "SCSI");
		if (!atari_dma_buffer) {
			printk(KERN_ERR "atari_scsi_detect: can't allocate ST-RAM "
					"double buffer\n");
			return 0;
		}
		atari_dma_phys_buffer = virt_to_phys(atari_dma_buffer);
		atari_dma_orig_addr = 0;
	}
#endif
	instance = scsi_register(host, sizeof(struct NCR5380_hostdata));
	if (instance == NULL) {
		atari_stram_free(atari_dma_buffer);
		atari_dma_buffer = 0;
		return 0;
	}
	atari_scsi_host = instance;
	/*
	 * Set irq to 0, to avoid that the mid-level code disables our interrupt
	 * during queue_command calls. This is completely unnecessary, and even
	 * worse causes bad problems on the Falcon, where the int is shared with
	 * IDE and floppy!
	 */
       instance->irq = 0;

#ifdef CONFIG_ATARI_SCSI_RESET_BOOT
	atari_scsi_reset_boot();
#endif
	NCR5380_init(instance, 0);

	if (IS_A_TT()) {

		/* This int is actually "pseudo-slow", i.e. it acts like a slow
		 * interrupt after having cleared the pending flag for the DMA
		 * interrupt. */
		if (request_irq(IRQ_TT_MFP_SCSI, scsi_tt_intr, IRQ_TYPE_SLOW,
				 "SCSI NCR5380", instance)) {
			printk(KERN_ERR "atari_scsi_detect: cannot allocate irq %d, aborting",IRQ_TT_MFP_SCSI);
			scsi_unregister(atari_scsi_host);
			atari_stram_free(atari_dma_buffer);
			atari_dma_buffer = 0;
			return 0;
		}
		tt_mfp.active_edge |= 0x80;		/* SCSI int on L->H */
#ifdef REAL_DMA
		tt_scsi_dma.dma_ctrl = 0;
		atari_dma_residual = 0;
#ifdef CONFIG_TT_DMA_EMUL
		if (MACH_IS_HADES) {
			if (request_irq(IRQ_AUTO_2, hades_dma_emulator,
					 IRQ_TYPE_PRIO, "Hades DMA emulator",
					 hades_dma_emulator)) {
				printk(KERN_ERR "atari_scsi_detect: cannot allocate irq %d, aborting (MACH_IS_HADES)",IRQ_AUTO_2);
				free_irq(IRQ_TT_MFP_SCSI, instance);
				scsi_unregister(atari_scsi_host);
				atari_stram_free(atari_dma_buffer);
				atari_dma_buffer = 0;
				return 0;
			}
		}
#endif
		if (MACH_IS_MEDUSA || MACH_IS_HADES) {
			/* While the read overruns (described by Drew Eckhardt in
			 * NCR5380.c) never happened on TTs, they do in fact on the Medusa
			 * (This was the cause why SCSI didn't work right for so long
			 * there.) Since handling the overruns slows down a bit, I turned
			 * the #ifdef's into a runtime condition.
			 *
			 * In principle it should be sufficient to do max. 1 byte with
			 * PIO, but there is another problem on the Medusa with the DMA
			 * rest data register. So 'atari_read_overruns' is currently set
			 * to 4 to avoid having transfers that aren't a multiple of 4. If
			 * the rest data bug is fixed, this can be lowered to 1.
			 */
			atari_read_overruns = 4;
		}
#endif /*REAL_DMA*/
	} else { /* ! IS_A_TT */

		/* Nothing to do for the interrupt: the ST-DMA is initialized
		 * already by atari_init_INTS()
		 */

#ifdef REAL_DMA
		atari_dma_residual = 0;
		atari_dma_active = 0;
		atari_dma_stram_mask = (ATARIHW_PRESENT(EXTD_DMA) ? 0x00000000
					: 0xff000000);
#endif
	}

	printk(KERN_INFO "scsi%d: options CAN_QUEUE=%d CMD_PER_LUN=%d SCAT-GAT=%d "
#ifdef SUPPORT_TAGS
			"TAGGED-QUEUING=%s "
#endif
			"HOSTID=%d",
			instance->host_no, instance->hostt->can_queue,
			instance->hostt->cmd_per_lun,
			instance->hostt->sg_tablesize,
#ifdef SUPPORT_TAGS
			setup_use_tagged_queuing ? "yes" : "no",
#endif
			instance->hostt->this_id );
	NCR5380_print_options(instance);
	printk("\n");

	called = 1;
	return 1;
}

int atari_scsi_release(struct Scsi_Host *sh)
{
	if (IS_A_TT())
		free_irq(IRQ_TT_MFP_SCSI, sh);
	if (atari_dma_buffer)
		atari_stram_free(atari_dma_buffer);
	return 1;
}

void __init atari_scsi_setup(char *str, int *ints)
{
	/* Format of atascsi parameter is:
	 *   atascsi=<can_queue>,<cmd_per_lun>,<sg_tablesize>,<hostid>,<use_tags>
	 * Defaults depend on TT or Falcon, hostid determined at run time.
	 * Negative values mean don't change.
	 */

	if (ints[0] < 1) {
		printk("atari_scsi_setup: no arguments!\n");
		return;
	}

	if (ints[0] >= 1) {
		if (ints[1] > 0)
			/* no limits on this, just > 0 */
			setup_can_queue = ints[1];
	}
	if (ints[0] >= 2) {
		if (ints[2] > 0)
			setup_cmd_per_lun = ints[2];
	}
	if (ints[0] >= 3) {
		if (ints[3] >= 0) {
			setup_sg_tablesize = ints[3];
			/* Must be <= SG_ALL (255) */
			if (setup_sg_tablesize > SG_ALL)
				setup_sg_tablesize = SG_ALL;
		}
	}
	if (ints[0] >= 4) {
		/* Must be between 0 and 7 */
		if (ints[4] >= 0 && ints[4] <= 7)
			setup_hostid = ints[4];
		else if (ints[4] > 7)
			printk("atari_scsi_setup: invalid host ID %d !\n", ints[4]);
	}
#ifdef SUPPORT_TAGS
	if (ints[0] >= 5) {
		if (ints[5] >= 0)
			setup_use_tagged_queuing = !!ints[5];
	}
#endif
}

int atari_scsi_bus_reset(Scsi_Cmnd *cmd)
{
	int rv;
	struct NCR5380_hostdata *hostdata =
		(struct NCR5380_hostdata *)cmd->device->host->hostdata;

	/* For doing the reset, SCSI interrupts must be disabled first,
	 * since the 5380 raises its IRQ line while _RST is active and we
	 * can't disable interrupts completely, since we need the timer.
	 */
	/* And abort a maybe active DMA transfer */
	if (IS_A_TT()) {
		atari_turnoff_irq(IRQ_TT_MFP_SCSI);
#ifdef REAL_DMA
		tt_scsi_dma.dma_ctrl = 0;
#endif /* REAL_DMA */
	} else {
		atari_turnoff_irq(IRQ_MFP_FSCSI);
#ifdef REAL_DMA
		st_dma.dma_mode_status = 0x90;
		atari_dma_active = 0;
		atari_dma_orig_addr = NULL;
#endif /* REAL_DMA */
	}

	rv = NCR5380_bus_reset(cmd);

	/* Re-enable ints */
	if (IS_A_TT()) {
		atari_turnon_irq(IRQ_TT_MFP_SCSI);
	} else {
		atari_turnon_irq(IRQ_MFP_FSCSI);
	}
	if ((rv & SCSI_RESET_ACTION) == SCSI_RESET_SUCCESS)
		falcon_release_lock_if_possible(hostdata);

	return rv;
}
 * command immediately but tell the SCSI mid-layer to defer.
 */

static int falcon_get_lock(struct Scsi_Host *instance)
{
	if (IS_A_TT())
		return 1;

	if (stdma_is_locked_by(scsi_falcon_intr) &&
	    instance->hostt->can_queue > 1)
		return 1;

	if (in_interrupt())
		return stdma_try_lock(scsi_falcon_intr, instance);

	stdma_lock(scsi_falcon_intr, instance);
	return 1;
}

#ifndef MODULE
static int __init atari_scsi_setup(char *str)
{
	/* Format of atascsi parameter is:
	 *   atascsi=<can_queue>,<cmd_per_lun>,<sg_tablesize>,<hostid>,<use_tags>
	 * Defaults depend on TT or Falcon, determined at run time.
	 * Negative values mean don't change.
	 */
	int ints[8];

	get_options(str, ARRAY_SIZE(ints), ints);

	if (ints[0] < 1) {
		printk("atari_scsi_setup: no arguments!\n");
		return 0;
	}
	if (ints[0] >= 1)
		setup_can_queue = ints[1];
	if (ints[0] >= 2)
		setup_cmd_per_lun = ints[2];
	if (ints[0] >= 3)
		setup_sg_tablesize = ints[3];
	if (ints[0] >= 4)
		setup_hostid = ints[4];
	/* ints[5] (use_tagged_queuing) is ignored */
	/* ints[6] (use_pdma) is ignored */
	if (ints[0] >= 7)
		setup_toshiba_delay = ints[7];

	return 1;
}

__setup("atascsi=", atari_scsi_setup);
#endif /* !MODULE */


#ifdef CONFIG_ATARI_SCSI_RESET_BOOT
static void __init atari_scsi_reset_boot(void)
{
	unsigned long end;

	/*
	 * Do a SCSI reset to clean up the bus during initialization. No messing
	 * with the queues, interrupts, or locks necessary here.
	 */

	printk("Atari SCSI: resetting the SCSI bus...");

	/* get in phase */
	NCR5380_write(TARGET_COMMAND_REG,
		      PHASE_SR_TO_TCR(NCR5380_read(STATUS_REG)));

	/* assert RST */
	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_RST);
	/* The min. reset hold time is 25us, so 40us should be enough */
	udelay(50);
	/* reset RST and interrupt */
	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
	NCR5380_read(RESET_PARITY_INTERRUPT_REG);

	end = jiffies + AFTER_RESET_DELAY;
	while (time_before(jiffies, end))
		barrier();

	printk(" done\n");
}
#endif


const char *atari_scsi_info(struct Scsi_Host *host)
{
	/* atari_scsi_detect() is verbose enough... */
	static const char string[] = "Atari native SCSI";
	return string;
}


#if defined(REAL_DMA)

unsigned long atari_scsi_dma_setup(struct Scsi_Host *instance, void *data,
				   unsigned long count, int dir)
{
	unsigned long addr = virt_to_phys(data);

	DMA_PRINTK("scsi%d: setting up dma, data = %p, phys = %lx, count = %ld, "
#if defined(REAL_DMA)

static unsigned long atari_scsi_dma_setup(struct Scsi_Host *instance,
static unsigned long atari_scsi_dma_setup(struct NCR5380_hostdata *hostdata,
					  void *data, unsigned long count,
					  int dir)
{
	unsigned long addr = virt_to_phys(data);

	dprintk(NDEBUG_DMA, "scsi%d: setting up dma, data = %p, phys = %lx, count = %ld, dir = %d\n",
	        hostdata->host->host_no, data, addr, count, dir);

	if (!IS_A_TT() && !STRAM_ADDR(addr)) {
		/* If we have a non-DMAable address on a Falcon, use the dribble
		 * buffer; 'orig_addr' != 0 in the read case tells the interrupt
		 * handler to copy data from the dribble buffer to the originally
		 * wanted address.
		 */
		if (dir)
			memcpy(atari_dma_buffer, data, count);
		else
			atari_dma_orig_addr = data;
		addr = atari_dma_phys_buffer;
	}

	atari_dma_startaddr = addr;	/* Needed for calculating residual later. */

	/* Cache cleanup stuff: On writes, push any dirty cache out before sending
	 * it to the peripheral. (Must be done before DMA setup, since at least
	 * the ST-DMA begins to fill internal buffers right after setup. For
	 * reads, invalidate any cache, may be altered after DMA without CPU
	 * knowledge.
	 *
	 * ++roman: For the Medusa, there's no need at all for that cache stuff,
	 * because the hardware does bus snooping (fine!).
	 */
	dma_cache_maintenance(addr, count, dir);

	if (IS_A_TT()) {
		tt_scsi_dma.dma_ctrl = dir;
		SCSI_DMA_WRITE_P(dma_addr, addr);
		SCSI_DMA_WRITE_P(dma_cnt, count);
		tt_scsi_dma.dma_ctrl = dir | 2;
	} else { /* ! IS_A_TT */

		/* set address */
		SCSI_DMA_SETADR(addr);

		/* toggle direction bit to clear FIFO and set DMA direction */
		dir <<= 8;
		st_dma.dma_mode_status = 0x90 | dir;
		st_dma.dma_mode_status = 0x90 | (dir ^ 0x100);
		st_dma.dma_mode_status = 0x90 | dir;
		udelay(40);
		/* On writes, round up the transfer length to the next multiple of 512
		 * (see also comment at atari_dma_xfer_len()). */
		st_dma.fdc_acces_seccount = (count + (dir ? 511 : 0)) >> 9;
		udelay(40);
		st_dma.dma_mode_status = 0x10 | dir;
		udelay(40);
		/* need not restore value of dir, only boolean value is tested */
		atari_dma_active = 1;
	}

	return count;
}

static inline int atari_scsi_dma_recv_setup(struct NCR5380_hostdata *hostdata,
                                            unsigned char *data, int count)
{
	return atari_scsi_dma_setup(hostdata, data, count, 0);
}

static inline int atari_scsi_dma_send_setup(struct NCR5380_hostdata *hostdata,
                                            unsigned char *data, int count)
{
	return atari_scsi_dma_setup(hostdata, data, count, 1);
}

static int atari_scsi_dma_residual(struct NCR5380_hostdata *hostdata)
{
	return atari_dma_residual;
}


#define	CMD_SURELY_BLOCK_MODE	0
#define	CMD_SURELY_BYTE_MODE	1
#define	CMD_MODE_UNKNOWN		2

static int falcon_classify_cmd(Scsi_Cmnd *cmd)
static int falcon_classify_cmd(struct scsi_cmnd *cmd)
{
	unsigned char opcode = cmd->cmnd[0];

	if (opcode == READ_DEFECT_DATA || opcode == READ_LONG ||
	    opcode == READ_BUFFER)
		return CMD_SURELY_BYTE_MODE;
	else if (opcode == READ_6 || opcode == READ_10 ||
		 opcode == 0xa8 /* READ_12 */ || opcode == READ_REVERSE ||
		 opcode == RECOVER_BUFFERED_DATA) {
		/* In case of a sequential-access target (tape), special care is
		 * needed here: The transfer is block-mode only if the 'fixed' bit is
		 * set! */
		if (cmd->device->type == TYPE_TAPE && !(cmd->cmnd[1] & 1))
			return CMD_SURELY_BYTE_MODE;
		else
			return CMD_SURELY_BLOCK_MODE;
	} else
		return CMD_MODE_UNKNOWN;
}


/* This function calculates the number of bytes that can be transferred via
 * DMA. On the TT, this is arbitrary, but on the Falcon we have to use the
 * ST-DMA chip. There are only multiples of 512 bytes possible and max.
 * 255*512 bytes :-( This means also, that defining READ_OVERRUNS is not
 * possible on the Falcon, since that would require to program the DMA for
 * n*512 - atari_read_overrun bytes. But it seems that the Falcon doesn't have
 * the overrun problem, so this question is academic :-)
 */

static unsigned long atari_dma_xfer_len(unsigned long wanted_len,
					Scsi_Cmnd *cmd, int write_flag)
{
	unsigned long	possible_len, limit;
#ifndef CONFIG_TT_DMA_EMUL
	if (MACH_IS_HADES)
		/* Hades has no SCSI DMA at all :-( Always force use of PIO */
		return 0;
#endif
					struct scsi_cmnd *cmd, int write_flag)
static int atari_scsi_dma_xfer_len(struct NCR5380_hostdata *hostdata,
                                   struct scsi_cmnd *cmd)
{
	int wanted_len = cmd->SCp.this_residual;
	int possible_len, limit;

	if (wanted_len < DMA_MIN_SIZE)
		return 0;

	if (IS_A_TT())
		/* TT SCSI DMA can transfer arbitrary #bytes */
		return wanted_len;

	/* ST DMA chip is stupid -- only multiples of 512 bytes! (and max.
	 * 255*512 bytes, but this should be enough)
	 *
	 * ++roman: Aaargl! Another Falcon-SCSI problem... There are some commands
	 * that return a number of bytes which cannot be known beforehand. In this
	 * case, the given transfer length is an "allocation length". Now it
	 * can happen that this allocation length is a multiple of 512 bytes and
	 * the DMA is used. But if not n*512 bytes really arrive, some input data
	 * will be lost in the ST-DMA's FIFO :-( Thus, we have to distinguish
	 * between commands that do block transfers and those that do byte
	 * transfers. But this isn't easy... there are lots of vendor specific
	 * commands, and the user can issue any command via the
	 * SCSI_IOCTL_SEND_COMMAND.
	 *
	 * The solution: We classify SCSI commands in 1) surely block-mode cmd.s,
	 * 2) surely byte-mode cmd.s and 3) cmd.s with unknown mode. In case 1)
	 * and 3), the thing to do is obvious: allow any number of blocks via DMA
	 * or none. In case 2), we apply some heuristic: Byte mode is assumed if
	 * the transfer (allocation) length is < 1024, hoping that no cmd. not
	 * explicitly known as byte mode have such big allocation lengths...
	 * BTW, all the discussion above applies only to reads. DMA writes are
	 * unproblematic anyways, since the targets aborts the transfer after
	 * receiving a sufficient number of bytes.
	 *
	 * Another point: If the transfer is from/to an non-ST-RAM address, we
	 * use the dribble buffer and thus can do only STRAM_BUFFER_SIZE bytes.
	 */

	if (cmd->sc_data_direction == DMA_TO_DEVICE) {
		/* Write operation can always use the DMA, but the transfer size must
		 * be rounded up to the next multiple of 512 (atari_dma_setup() does
		 * this).
		 */
		possible_len = wanted_len;
	} else {
		/* Read operations: if the wanted transfer length is not a multiple of
		 * 512, we cannot use DMA, since the ST-DMA cannot split transfers
		 * (no interrupt on DMA finished!)
		 */
		if (wanted_len & 0x1ff)
			possible_len = 0;
		else {
			/* Now classify the command (see above) and decide whether it is
			 * allowed to do DMA at all */
			switch (falcon_classify_cmd(cmd)) {
			case CMD_SURELY_BLOCK_MODE:
				possible_len = wanted_len;
				break;
			case CMD_SURELY_BYTE_MODE:
				possible_len = 0; /* DMA prohibited */
				break;
			case CMD_MODE_UNKNOWN:
			default:
				/* For unknown commands assume block transfers if the transfer
				 * size/allocation length is >= 1024 */
				possible_len = (wanted_len < 1024) ? 0 : wanted_len;
				break;
			}
		}
	}

	/* Last step: apply the hard limit on DMA transfers */
	limit = (atari_dma_buffer && !STRAM_ADDR(virt_to_phys(cmd->SCp.ptr))) ?
		    STRAM_BUFFER_SIZE : 255*512;
	if (possible_len > limit)
		possible_len = limit;

	if (possible_len != wanted_len)
		DMA_PRINTK("Sorry, must cut DMA transfer size to %ld bytes "
		dprintk(NDEBUG_DMA, "Sorry, must cut DMA transfer size to %ld bytes "
			   "instead of %ld\n", possible_len, wanted_len);
		dprintk(NDEBUG_DMA, "DMA transfer now %d bytes instead of %d\n",
		        possible_len, wanted_len);

	return possible_len;
}


/* NCR5380 register access functions
 *
 * There are separate functions for TT and Falcon, because the access
 * methods are quite different. The calling macros NCR5380_read and
 * NCR5380_write call these functions via function pointers.
 */

static u8 atari_scsi_tt_reg_read(unsigned int reg)
{
	return tt_scsi_regp[reg * 2];
}

static void atari_scsi_tt_reg_write(unsigned int reg, u8 value)
{
	tt_scsi_regp[reg * 2] = value;
}

static u8 atari_scsi_falcon_reg_read(unsigned int reg)
{
	unsigned long flags;
	u8 result;

	reg += 0x88;
	local_irq_save(flags);
	dma_wd.dma_mode_status = (u_short)reg;
	result = (u8)dma_wd.fdc_acces_seccount;
	local_irq_restore(flags);
	return result;
}

static void atari_scsi_falcon_reg_write(unsigned int reg, u8 value)
{
	unsigned long flags;

	reg += 0x88;
	local_irq_save(flags);
	dma_wd.dma_mode_status = (u_short)reg;
	dma_wd.fdc_acces_seccount = (u_short)value;
	local_irq_restore(flags);
}


#include "NCR5380.c"

static struct scsi_host_template driver_template = {
	.proc_info		= atari_scsi_proc_info,
	.name			= "Atari native SCSI",
	.detect			= atari_scsi_detect,
	.release		= atari_scsi_release,
static int atari_scsi_bus_reset(struct scsi_cmnd *cmd)
static int atari_scsi_host_reset(struct scsi_cmnd *cmd)
{
	int rv;
	unsigned long flags;

	local_irq_save(flags);

	/* Abort a maybe active DMA transfer */
	if (IS_A_TT()) {
		tt_scsi_dma.dma_ctrl = 0;
	} else {
		if (stdma_is_locked_by(scsi_falcon_intr))
			st_dma.dma_mode_status = 0x90;
		atari_dma_active = 0;
		atari_dma_orig_addr = NULL;
	}

	rv = NCR5380_host_reset(cmd);

	/* The 5380 raises its IRQ line while _RST is active but the ST DMA
	 * "lock" has been released so this interrupt may end up handled by
	 * floppy or IDE driver (if one of them holds the lock). The NCR5380
	 * interrupt flag has been cleared already.
	 */

	local_irq_restore(flags);

	return rv;
}

#define DRV_MODULE_NAME         "atari_scsi"
#define PFX                     DRV_MODULE_NAME ": "

static struct scsi_host_template atari_scsi_template = {
	.module			= THIS_MODULE,
	.proc_name		= DRV_MODULE_NAME,
	.name			= "Atari native SCSI",
	.info			= atari_scsi_info,
	.queuecommand		= atari_scsi_queue_command,
	.eh_abort_handler	= atari_scsi_abort,
	.eh_bus_reset_handler	= atari_scsi_bus_reset,
	.can_queue		= 0, /* initialized at run-time */
	.this_id		= 0, /* initialized at run-time */
	.sg_tablesize		= 0, /* initialized at run-time */
	.cmd_per_lun		= 0, /* initialized at run-time */
	.use_clustering		= DISABLE_CLUSTERING
};


#include "scsi_module.c"

	.eh_host_reset_handler	= atari_scsi_host_reset,
	.this_id		= 7,
	.cmd_per_lun		= 2,
	.use_clustering		= DISABLE_CLUSTERING,
	.cmd_size		= NCR5380_CMD_SIZE,
};

static int __init atari_scsi_probe(struct platform_device *pdev)
{
	struct Scsi_Host *instance;
	int error;
	struct resource *irq;
	int host_flags = 0;

	irq = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (!irq)
		return -ENODEV;

	if (ATARIHW_PRESENT(TT_SCSI)) {
		atari_scsi_reg_read  = atari_scsi_tt_reg_read;
		atari_scsi_reg_write = atari_scsi_tt_reg_write;
	} else {
		atari_scsi_reg_read  = atari_scsi_falcon_reg_read;
		atari_scsi_reg_write = atari_scsi_falcon_reg_write;
	}

	if (ATARIHW_PRESENT(TT_SCSI)) {
		atari_scsi_template.can_queue    = 16;
		atari_scsi_template.sg_tablesize = SG_ALL;
	} else {
		atari_scsi_template.can_queue    = 1;
		atari_scsi_template.sg_tablesize = SG_NONE;
	}

	if (setup_can_queue > 0)
		atari_scsi_template.can_queue = setup_can_queue;

	if (setup_cmd_per_lun > 0)
		atari_scsi_template.cmd_per_lun = setup_cmd_per_lun;

	/* Leave sg_tablesize at 0 on a Falcon! */
	if (ATARIHW_PRESENT(TT_SCSI) && setup_sg_tablesize >= 0)
		atari_scsi_template.sg_tablesize = setup_sg_tablesize;

	if (setup_hostid >= 0) {
		atari_scsi_template.this_id = setup_hostid & 7;
	} else {
		/* Test if a host id is set in the NVRam */
		if (ATARIHW_PRESENT(TT_CLK) && nvram_check_checksum()) {
			unsigned char b = nvram_read_byte(16);

			/* Arbitration enabled? (for TOS)
			 * If yes, use configured host ID
			 */
			if (b & 0x80)
				atari_scsi_template.this_id = b & 7;
		}
	}

	/* If running on a Falcon and if there's TT-Ram (i.e., more than one
	 * memory block, since there's always ST-Ram in a Falcon), then
	 * allocate a STRAM_BUFFER_SIZE byte dribble buffer for transfers
	 * from/to alternative Ram.
	 */
	if (ATARIHW_PRESENT(ST_SCSI) && !ATARIHW_PRESENT(EXTD_DMA) &&
	    m68k_realnum_memory > 1) {
		atari_dma_buffer = atari_stram_alloc(STRAM_BUFFER_SIZE, "SCSI");
		if (!atari_dma_buffer) {
			pr_err(PFX "can't allocate ST-RAM double buffer\n");
			return -ENOMEM;
		}
		atari_dma_phys_buffer = atari_stram_to_phys(atari_dma_buffer);
		atari_dma_orig_addr = NULL;
	}

	instance = scsi_host_alloc(&atari_scsi_template,
	                           sizeof(struct NCR5380_hostdata));
	if (!instance) {
		error = -ENOMEM;
		goto fail_alloc;
	}

	instance->irq = irq->start;

	host_flags |= IS_A_TT() ? 0 : FLAG_LATE_DMA_SETUP;
	host_flags |= setup_toshiba_delay > 0 ? FLAG_TOSHIBA_DELAY : 0;

	error = NCR5380_init(instance, host_flags);
	if (error)
		goto fail_init;

	if (IS_A_TT()) {
		error = request_irq(instance->irq, scsi_tt_intr, 0,
		                    "NCR5380", instance);
		if (error) {
			pr_err(PFX "request irq %d failed, aborting\n",
			       instance->irq);
			goto fail_irq;
		}
		tt_mfp.active_edge |= 0x80;	/* SCSI int on L->H */

		tt_scsi_dma.dma_ctrl = 0;
		atari_dma_residual = 0;

		/* While the read overruns (described by Drew Eckhardt in
		 * NCR5380.c) never happened on TTs, they do in fact on the
		 * Medusa (This was the cause why SCSI didn't work right for
		 * so long there.) Since handling the overruns slows down
		 * a bit, I turned the #ifdef's into a runtime condition.
		 *
		 * In principle it should be sufficient to do max. 1 byte with
		 * PIO, but there is another problem on the Medusa with the DMA
		 * rest data register. So read_overruns is currently set
		 * to 4 to avoid having transfers that aren't a multiple of 4.
		 * If the rest data bug is fixed, this can be lowered to 1.
		 */
		if (MACH_IS_MEDUSA) {
			struct NCR5380_hostdata *hostdata =
				shost_priv(instance);

			hostdata->read_overruns = 4;
		}
	} else {
		/* Nothing to do for the interrupt: the ST-DMA is initialized
		 * already.
		 */
		atari_dma_residual = 0;
		atari_dma_active = 0;
		atari_dma_stram_mask = (ATARIHW_PRESENT(EXTD_DMA) ? 0x00000000
					: 0xff000000);
	}

	NCR5380_maybe_reset_bus(instance);

	error = scsi_add_host(instance, NULL);
	if (error)
		goto fail_host;

	platform_set_drvdata(pdev, instance);

	scsi_scan_host(instance);
	return 0;

fail_host:
	if (IS_A_TT())
		free_irq(instance->irq, instance);
fail_irq:
	NCR5380_exit(instance);
fail_init:
	scsi_host_put(instance);
fail_alloc:
	if (atari_dma_buffer)
		atari_stram_free(atari_dma_buffer);
	return error;
}

static int __exit atari_scsi_remove(struct platform_device *pdev)
{
	struct Scsi_Host *instance = platform_get_drvdata(pdev);

	scsi_remove_host(instance);
	if (IS_A_TT())
		free_irq(instance->irq, instance);
	NCR5380_exit(instance);
	scsi_host_put(instance);
	if (atari_dma_buffer)
		atari_stram_free(atari_dma_buffer);
	return 0;
}

static struct platform_driver atari_scsi_driver = {
	.remove = __exit_p(atari_scsi_remove),
	.driver = {
		.name	= DRV_MODULE_NAME,
	},
};

module_platform_driver_probe(atari_scsi_driver, atari_scsi_probe);

MODULE_ALIAS("platform:" DRV_MODULE_NAME);
MODULE_LICENSE("GPL");
