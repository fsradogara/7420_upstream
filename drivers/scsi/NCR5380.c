// SPDX-License-Identifier: GPL-2.0
/*
 * NCR 5380 generic driver routines.  These should make it *trivial*
 * to implement 5380 SCSI drivers under Linux with a non-trantor
 * architecture.
 *
 * Note that these routines also work with NR53c400 family chips.
 *
 * Copyright 1993, Drew Eckhardt
 * Visionary Computing
 * (Unix and Linux consulting and custom programming)
 * drew@colorado.edu
 * +1 (303) 666-5836
 *
 * DISTRIBUTION RELEASE 6. 
 *
 * For more information, please consult 
 * For more information, please consult
 *
 * NCR 5380 Family
 * SCSI Protocol Controller
 * Databook
 *
 * NCR Microelectronics
 * 1635 Aeroplaza Drive
 * Colorado Springs, CO 80916
 * 1+ (719) 578-3400
 * 1+ (800) 334-5454
 */

/*
 * $Log: NCR5380.c,v $

 * Revision 1.10 1998/9/2	Alan Cox
 *				(alan@redhat.com)
 * Revision 1.10 1998/9/2	Alan Cox
 *				(alan@lxorguk.ukuu.org.uk)
 * Fixed up the timer lockups reported so far. Things still suck. Looking 
 * forward to 2.3 and per device request queues. Then it'll be possible to
 * SMP thread this beast and improve life no end.
 
 * Revision 1.9  1997/7/27	Ronald van Cuijlenborg
 *				(ronald.van.cuijlenborg@tip.nl or nutty@dds.nl)
 * (hopefully) fixed and enhanced USLEEP
 * added support for DTC3181E card (for Mustek scanner)
 *

 * Revision 1.8			Ingmar Baumgart
 *				(ingmar@gonzo.schwaben.de)
 * added support for NCR53C400a card
 *

 * Revision 1.7  1996/3/2       Ray Van Tassle (rayvt@comm.mot.com)
 * added proc_info
 * added support needed for DTC 3180/3280
 * fixed a couple of bugs
 *

 * Revision 1.5  1994/01/19  09:14:57  drew
 * Fixed udelay() hack that was being used on DATAOUT phases
 * instead of a proper wait for the final handshake.
 *
 * Revision 1.4  1994/01/19  06:44:25  drew
 * *** empty log message ***
 *
 * Revision 1.3  1994/01/19  05:24:40  drew
 * Added support for TCR LAST_BYTE_SENT bit.
 *
 * Revision 1.2  1994/01/15  06:14:11  drew
 * REAL DMA support, bug fixes.
 *
 * Revision 1.1  1994/01/15  06:00:54  drew
 * Initial revision
 *
 * With contributions from Ray Van Tassle, Ingmar Baumgart,
 * Ronald van Cuijlenborg, Alan Cox and others.
 */

/* Ported to Atari by Roman Hodek and others. */

#ifndef NDEBUG
#define NDEBUG 0
#endif
#ifndef NDEBUG_ABORT
#define NDEBUG_ABORT 0
#endif

#if (NDEBUG & NDEBUG_LISTS)
#define LIST(x,y) {printk("LINE:%d   Adding %p to %p\n", __LINE__, (void*)(x), (void*)(y)); if ((x)==(y)) udelay(5); }
#define REMOVE(w,x,y,z) {printk("LINE:%d   Removing: %p->%p  %p->%p \n", __LINE__, (void*)(w), (void*)(x), (void*)(y), (void*)(z)); if ((x)==(y)) udelay(5); }
#else
#define LIST(x,y)
#define REMOVE(w,x,y,z)
#endif

#ifndef notyet
#undef LINKED
#undef REAL_DMA
#endif

#ifdef REAL_DMA_POLL
#undef READ_OVERRUNS
#define READ_OVERRUNS
#endif

#ifdef BOARD_REQUIRES_NO_DELAY
#define io_recovery_delay(x)
#else
#define io_recovery_delay(x)	udelay(x)
#endif
/* Adapted for the Sun 3 by Sam Creasey. */

/*
 * Design
 *
 * This is a generic 5380 driver.  To use it on a different platform,
 * one simply writes appropriate system specific macros (ie, data
 * transfer - some PC's will use the I/O bus, 68K's must use
 * memory mapped) and drops this file in their 'C' wrapper.
 *
 * As far as command queueing, two queues are maintained for
 * each 5380 in the system - commands that haven't been issued yet,
 * and commands that are currently executing.  This means that an
 * unlimited number of commands may be queued, letting
 * more commands propagate from the higher driver levels giving higher
 * throughput.  Note that both I_T_L and I_T_L_Q nexuses are supported,
 * allowing multiple commands to propagate all the way to a SCSI-II device
 * while a command is already executing.
 *
 *
 * Issues specific to the NCR5380 :
 *
 * When used in a PIO or pseudo-dma mode, the NCR5380 is a braindead
 * piece of hardware that requires you to sit in a loop polling for
 * the REQ signal as long as you are connected.  Some devices are
 * brain dead (ie, many TEXEL CD ROM drives) and won't disconnect
 * while doing long seek operations. [...] These
 * broken devices are the exception rather than the rule and I'd rather
 * spend my time optimizing for the normal case.
 *
 * Architecture :
 *
 * At the heart of the design is a coroutine, NCR5380_main,
 * which is started from a workqueue for each NCR5380 host in the
 * system.  It attempts to establish I_T_L or I_T_L_Q nexuses by
 * removing the commands from the issue queue and calling
 * NCR5380_select() if a nexus is not established.
 *
 * Once a nexus is established, the NCR5380_information_transfer()
 * phase goes through the various phases as instructed by the target.
 * if the target goes into MSG IN and sends a DISCONNECT message,
 * the command structure is placed into the per instance disconnected
 * queue, and NCR5380_main tries to find more work.  If the target is
 * idle for too long, the system will try to sleep.
 *
 * If a command has disconnected, eventually an interrupt will trigger,
 * calling NCR5380_intr()  which will in turn call NCR5380_reselect
 * to reestablish a nexus.  This will run main if necessary.
 *
 * On command termination, the done function will be called as
 * appropriate.
 *
 * SCSI pointers are maintained in the SCp field of SCSI command
 * structures, being initialized after the command is connected
 * in NCR5380_select, and set as appropriate in NCR5380_information_transfer.
 * Note that in violation of the standard, an implicit SAVE POINTERS operation
 * is done, since some BROKEN disks fail to issue an explicit SAVE POINTERS.
 */

/*
 * Using this file :
 * This file a skeleton Linux SCSI driver for the NCR 5380 series
 * of chips.  To use it, you write an architecture specific functions
 * and macros and include this file in your driver.
 *
 * These macros MUST be defined :
 *
 * NCR5380_read(register)  - read from the specified register
 *
 * NCR5380_write(register, value) - write to the specific register
 *
 * NCR5380_implementation_fields  - additional fields needed for this
 * specific implementation of the NCR5380
 *
 * Either real DMA *or* pseudo DMA may be implemented
 *
 * NCR5380_dma_xfer_len   - determine size of DMA/PDMA transfer
 * NCR5380_dma_send_setup - execute DMA/PDMA from memory to 5380
 * NCR5380_dma_recv_setup - execute DMA/PDMA from 5380 to memory
 * NCR5380_dma_residual   - residual byte count
 *
 * The generic driver is initialized by calling NCR5380_init(instance),
 * after setting the appropriate host specific fields and ID.
 */

#ifndef NCR5380_io_delay
#define NCR5380_io_delay(x)
#endif

#ifndef NCR5380_acquire_dma_irq
#define NCR5380_acquire_dma_irq(x)	(1)
#endif

#ifndef NCR5380_release_dma_irq
#define NCR5380_release_dma_irq(x)
#endif

static int do_abort(struct Scsi_Host *);
static void do_reset(struct Scsi_Host *);

/**
 * initialize_SCp - init the scsi pointer field
 * @cmd: command block to set up
 *
 * Set up the internal fields in the SCSI command.
 */

static __inline__ void initialize_SCp(Scsi_Cmnd * cmd)
static inline void initialize_SCp(struct scsi_cmnd *cmd)
{
	/*
	 * Initialize the Scsi Pointer field so that all of the commands in the
	 * various queues are valid.
	 */

	if (scsi_bufflen(cmd)) {
		cmd->SCp.buffer = scsi_sglist(cmd);
		cmd->SCp.buffers_residual = scsi_sg_count(cmd) - 1;
		cmd->SCp.ptr = sg_virt(cmd->SCp.buffer);
		cmd->SCp.this_residual = cmd->SCp.buffer->length;
	} else {
		cmd->SCp.buffer = NULL;
		cmd->SCp.buffers_residual = 0;
		cmd->SCp.ptr = NULL;
		cmd->SCp.this_residual = 0;
	}

	cmd->SCp.Status = 0;
	cmd->SCp.Message = 0;
}

/**
 * NCR5380_poll_politely2 - wait for two chip register values
 * @hostdata: host private data
 * @reg1: 5380 register to poll
 * @bit1: Bitmask to check
 * @val1: Expected value
 * @reg2: Second 5380 register to poll
 * @bit2: Second bitmask to check
 * @val2: Second expected value
 * @wait: Time-out in jiffies
 *
 * Polls the chip in a reasonably efficient manner waiting for an
 * event to occur. After a short quick poll we begin to yield the CPU
 * (if possible). In irq contexts the time-out is arbitrarily limited.
 * Callers may hold locks as long as they are held in irq mode.
 *
 * Returns 0 if either or both event(s) occurred otherwise -ETIMEDOUT.
 */

static int NCR5380_poll_politely2(struct NCR5380_hostdata *hostdata,
                                  unsigned int reg1, u8 bit1, u8 val1,
                                  unsigned int reg2, u8 bit2, u8 val2,
                                  unsigned long wait)
{
	unsigned long n = hostdata->poll_loops;
	unsigned long deadline = jiffies + wait;

	do {
		if ((NCR5380_read(reg1) & bit1) == val1)
			return 0;
		if ((NCR5380_read(reg2) & bit2) == val2)
			return 0;
		cpu_relax();
	} while (n--);

	if (irqs_disabled() || in_interrupt())
		return -ETIMEDOUT;

	/* Repeatedly sleep for 1 ms until deadline */
	while (time_is_after_jiffies(deadline)) {
		schedule_timeout_uninterruptible(1);
		if ((NCR5380_read(reg1) & bit1) == val1)
			return 0;
		if ((NCR5380_read(reg2) & bit2) == val2)
			return 0;
	}

	return -ETIMEDOUT;
}

#if NDEBUG
static struct {
	unsigned char mask;
	const char *name;
} signals[] = {
	{SR_DBP, "PARITY"},
	{SR_RST, "RST"},
	{SR_BSY, "BSY"},
	{SR_REQ, "REQ"},
	{SR_MSG, "MSG"},
	{SR_CD, "CD"},
	{SR_IO, "IO"},
	{SR_SEL, "SEL"},
	{0, NULL}
},
basrs[] = {
	{BASR_END_DMA_TRANSFER, "END OF DMA"},
	{BASR_DRQ, "DRQ"},
	{BASR_PARITY_ERROR, "PARITY ERROR"},
	{BASR_IRQ, "IRQ"},
	{BASR_PHASE_MATCH, "PHASE MATCH"},
	{BASR_BUSY_ERROR, "BUSY ERROR"},
	{BASR_ATN, "ATN"},
	{BASR_ACK, "ACK"},
	{0, NULL}
},
icrs[] = {
	{ICR_ASSERT_RST, "ASSERT RST"},
	{ICR_ARBITRATION_PROGRESS, "ARB. IN PROGRESS"},
	{ICR_ARBITRATION_LOST, "LOST ARB."},
	{ICR_ASSERT_ACK, "ASSERT ACK"},
	{ICR_ASSERT_BSY, "ASSERT BSY"},
	{ICR_ASSERT_SEL, "ASSERT SEL"},
	{ICR_ASSERT_ATN, "ASSERT ATN"},
	{ICR_ASSERT_DATA, "ASSERT DATA"},
	{0, NULL}
},
mrs[] = {
	{MR_BLOCK_DMA_MODE, "BLOCK DMA MODE"},
	{MR_TARGET, "TARGET"},
	{MR_ENABLE_PAR_CHECK, "PARITY CHECK"},
	{MR_ENABLE_PAR_INTR, "PARITY INTR"},
	{MR_ENABLE_EOP_INTR, "EOP INTR"},
	{MR_MONITOR_BSY, "MONITOR BSY"},
	{MR_DMA_MODE, "DMA MODE"},
	{MR_ARBITRATE, "ARBITRATE"},
	{0, NULL}
};

/**
 * NCR5380_print - print scsi bus signals
 * @instance: adapter state to dump
 *
 * Print the SCSI bus signals for debugging purposes
 */

static void NCR5380_print(struct Scsi_Host *instance)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	unsigned char status, data, basr, mr, icr, i;

	data = NCR5380_read(CURRENT_SCSI_DATA_REG);
	status = NCR5380_read(STATUS_REG);
	mr = NCR5380_read(MODE_REG);
	icr = NCR5380_read(INITIATOR_COMMAND_REG);
	basr = NCR5380_read(BUS_AND_STATUS_REG);

	printk(KERN_DEBUG "SR =   0x%02x : ", status);
	for (i = 0; signals[i].mask; ++i)
		if (status & signals[i].mask)
			printk(KERN_CONT "%s, ", signals[i].name);
	printk(KERN_CONT "\nBASR = 0x%02x : ", basr);
	for (i = 0; basrs[i].mask; ++i)
		if (basr & basrs[i].mask)
			printk(KERN_CONT "%s, ", basrs[i].name);
	printk(KERN_CONT "\nICR =  0x%02x : ", icr);
	for (i = 0; icrs[i].mask; ++i)
		if (icr & icrs[i].mask)
			printk(KERN_CONT "%s, ", icrs[i].name);
	printk(KERN_CONT "\nMR =   0x%02x : ", mr);
	for (i = 0; mrs[i].mask; ++i)
		if (mr & mrs[i].mask)
			printk(KERN_CONT "%s, ", mrs[i].name);
	printk(KERN_CONT "\n");
}

static struct {
	unsigned char value;
	const char *name;
} phases[] = {
	{PHASE_DATAOUT, "DATAOUT"},
	{PHASE_DATAIN, "DATAIN"},
	{PHASE_CMDOUT, "CMDOUT"},
	{PHASE_STATIN, "STATIN"},
	{PHASE_MSGOUT, "MSGOUT"},
	{PHASE_MSGIN, "MSGIN"},
	{PHASE_UNKNOWN, "UNKNOWN"}
};

/**
 * NCR5380_print_phase - show SCSI phase
 * @instance: adapter to dump
 *
 * Print the current SCSI phase for debugging purposes
 */

static void NCR5380_print_phase(struct Scsi_Host *instance)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	unsigned char status;
	int i;

	status = NCR5380_read(STATUS_REG);
	if (!(status & SR_REQ))
		shost_printk(KERN_DEBUG, instance, "REQ not asserted, phase unknown.\n");
	else {
		for (i = 0; (phases[i].value != PHASE_UNKNOWN) &&
		     (phases[i].value != (status & PHASE_MASK)); ++i)
			;
		shost_printk(KERN_DEBUG, instance, "phase %s\n", phases[i].name);
	}
}
#endif

/*
 * These need tweaking, and would probably work best as per-device 
 * flags initialized differently for disk, tape, cd, etc devices.
 * People with broken devices are free to experiment as to what gives
 * the best results for them.
 *
 * USLEEP_SLEEP should be a minimum seek time.
 *
 * USLEEP_POLL should be a maximum rotational latency.
 */
#ifndef USLEEP_SLEEP
/* 20 ms (reasonable hard disk speed) */
#define USLEEP_SLEEP (20*HZ/1000)
#endif
/* 300 RPM (floppy speed) */
#ifndef USLEEP_POLL
#define USLEEP_POLL (200*HZ/1000)
#define USLEEP_SLEEP msecs_to_jiffies(20)
#endif
/* 300 RPM (floppy speed) */
#ifndef USLEEP_POLL
#define USLEEP_POLL msecs_to_jiffies(200)
#endif
#ifndef USLEEP_WAITLONG
/* RvC: (reasonable time to wait on select error) */
#define USLEEP_WAITLONG USLEEP_SLEEP
#endif

/* 
 * Function : int should_disconnect (unsigned char cmd)
 *
 * Purpose : decide whether a command would normally disconnect or 
 *      not, since if it won't disconnect we should go to sleep.
 *
 * Input : cmd - opcode of SCSI command
 *
 * Returns : DISCONNECT_LONG if we should disconnect for a really long 
 *      time (ie always, sleep, look for REQ active, sleep), 
 *      DISCONNECT_TIME_TO_DATA if we would only disconnect for a normal
 *      time-to-data delay, DISCONNECT_NONE if this command would return
 *      immediately.
 *
 *      Future sleep algorithms based on time to data can exploit 
 *      something like this so they can differentiate between "normal" 
 *      (ie, read, write, seek) and unusual commands (ie, * format).
 *
 * Note : We don't deal with commands that handle an immediate disconnect,
 *        
 */

static int should_disconnect(unsigned char cmd)
{
	switch (cmd) {
	case READ_6:
	case WRITE_6:
	case SEEK_6:
	case READ_10:
	case WRITE_10:
	case SEEK_10:
		return DISCONNECT_TIME_TO_DATA;
	case FORMAT_UNIT:
	case SEARCH_HIGH:
	case SEARCH_LOW:
	case SEARCH_EQUAL:
		return DISCONNECT_LONG;
	default:
		return DISCONNECT_NONE;
	}
}

static void NCR5380_set_timer(struct NCR5380_hostdata *hostdata, unsigned long timeout)
{
	hostdata->time_expires = jiffies + timeout;
	schedule_delayed_work(&hostdata->coroutine, timeout);
}


static int probe_irq __initdata = 0;

/**
 * NCR5380_info - report driver and host information
 * @instance: relevant scsi host instance
 *
 *	Set a flag to indicate the IRQ in question was received. This is
 *	used by the IRQ probe code.
 */
 
static irqreturn_t __init probe_intr(int irq, void *dev_id)
{
	probe_irq = irq;
	return IRQ_HANDLED;
}

/**
 *	NCR5380_probe_irq	-	find the IRQ of an NCR5380
 *	@instance: NCR5380 controller
 *	@possible: bitmask of ISA IRQ lines
 *
 *	Autoprobe for the IRQ line used by the NCR5380 by triggering an IRQ
 *	and then looking to see what interrupt actually turned up.
 *
 *	Locks: none, irqs must be enabled on entry
 */

static int __init __maybe_unused NCR5380_probe_irq(struct Scsi_Host *instance,
						int possible)
{
	NCR5380_local_declare();
	struct NCR5380_hostdata *hostdata = (struct NCR5380_hostdata *) instance->hostdata;
	unsigned long timeout;
	int trying_irqs, i, mask;
	NCR5380_setup(instance);

	for (trying_irqs = i = 0, mask = 1; i < 16; ++i, mask <<= 1)
		if ((mask & possible) && (request_irq(i, &probe_intr, IRQF_DISABLED, "NCR-probe", NULL) == 0))
			trying_irqs |= mask;

	timeout = jiffies + (250 * HZ / 1000);
	probe_irq = SCSI_IRQ_NONE;
	for (trying_irqs = 0, i = 1, mask = 2; i < 16; ++i, mask <<= 1)
		if ((mask & possible) && (request_irq(i, &probe_intr, 0, "NCR-probe", NULL) == 0))
			trying_irqs |= mask;

	timeout = jiffies + msecs_to_jiffies(250);
	probe_irq = NO_IRQ;

	/*
	 * A interrupt is triggered whenever BSY = false, SEL = true
	 * and a bit set in the SELECT_ENABLE_REG is asserted on the 
	 * SCSI bus.
	 *
	 * Note that the bus is only driven when the phase control signals
	 * (I/O, C/D, and MSG) match those in the TCR, so we must reset that
	 * to zero.
	 */

	NCR5380_write(TARGET_COMMAND_REG, 0);
	NCR5380_write(SELECT_ENABLE_REG, hostdata->id_mask);
	NCR5380_write(OUTPUT_DATA_REG, hostdata->id_mask);
	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_DATA | ICR_ASSERT_SEL);

	while (probe_irq == SCSI_IRQ_NONE && time_before(jiffies, timeout))
	while (probe_irq == NO_IRQ && time_before(jiffies, timeout))
		schedule_timeout_uninterruptible(1);
	
	NCR5380_write(SELECT_ENABLE_REG, 0);
	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);

	for (i = 0, mask = 1; i < 16; ++i, mask <<= 1)
	for (i = 1, mask = 2; i < 16; ++i, mask <<= 1)
		if (trying_irqs & mask)
			free_irq(i, NULL);

	return probe_irq;
}

/**
 *	NCR58380_print_options	-	show options
 *	@instance: unused for now
 *
 *	Called by probe code indicating the NCR5380 driver options that 
 *	were selected. At some point this will switch to runtime options
 *	read from the adapter in question
 *	NCR58380_info - report driver and host information
 *	@instance: relevant scsi host instance
 *
 *	For use as the host template info() handler.
 *
 *	Locks: none
 * For use as the host template info() handler.
 */

static void __init __maybe_unused
NCR5380_print_options(struct Scsi_Host *instance)
{
	printk(" generic options"
#ifdef AUTOPROBE_IRQ
	       " AUTOPROBE_IRQ"
#endif
#ifdef AUTOSENSE
	       " AUTOSENSE"
#endif
#ifdef DIFFERENTIAL
	       " DIFFERENTIAL"
#endif
#ifdef REAL_DMA
	       " REAL DMA"
#endif
#ifdef REAL_DMA_POLL
	       " REAL DMA POLL"
#endif
#ifdef PARITY
	       " PARITY"
#endif
#ifdef PSEUDO_DMA
	       " PSEUDO DMA"
#endif
#ifdef UNSAFE
	       " UNSAFE "
#endif
	    );
	printk(" USLEEP, USLEEP_POLL=%d USLEEP_SLEEP=%d", USLEEP_POLL, USLEEP_SLEEP);
	printk(" generic release=%d", NCR5380_PUBLIC_RELEASE);
	if (((struct NCR5380_hostdata *) instance->hostdata)->flags & FLAG_NCR53C400) {
		printk(" ncr53c400 release=%d", NCR53C400_PUBLIC_RELEASE);
	}
static const char *NCR5380_info(struct Scsi_Host *instance)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);

	return hostdata->info;
}

/**
 * NCR5380_init - initialise an NCR5380
 * @instance: adapter to configure
 * @flags: control flags
 *
 * Initializes *instance and corresponding 5380 chip,
 * with flags OR'd into the initial flags value.
 *
 * Notes : I assume that the host, hostno, and id bits have been
 * set correctly. I don't care about the irq and other fields.
 *
 * *buffer: I/O buffer
 * **start: if inout == FALSE pointer into buffer where user read should start
 * offset: current offset
 * length: length of buffer
 * hostno: Scsi_Host host_no
 * inout: TRUE - user is writing; FALSE - user is reading
 *
 * Return the number of bytes read from or written
 */

#undef SPRINTF
#define SPRINTF(args...) do { if(pos < buffer + length-80) pos += sprintf(pos, ## args); } while(0)
static
char *lprint_Scsi_Cmnd(Scsi_Cmnd * cmd, char *pos, char *buffer, int length);
static
char *lprint_command(unsigned char *cmd, char *pos, char *buffer, int len);
static
char *lprint_opcode(int opcode, char *pos, char *buffer, int length);

static int __maybe_unused NCR5380_proc_info(struct Scsi_Host *instance,
	char *buffer, char **start, off_t offset, int length, int inout)
{
	char *pos = buffer;
	struct NCR5380_hostdata *hostdata;
	Scsi_Cmnd *ptr;

	hostdata = (struct NCR5380_hostdata *) instance->hostdata;

	if (inout) {		/* Has data been written to the file ? */
#ifdef DTC_PUBLIC_RELEASE
		dtc_wmaxi = dtc_maxi = 0;
#endif
#ifdef PAS16_PUBLIC_RELEASE
		pas_wmaxi = pas_maxi = 0;
#endif
		return (-ENOSYS);	/* Currently this is a no-op */
	}
	SPRINTF("NCR5380 core release=%d.   ", NCR5380_PUBLIC_RELEASE);
	if (((struct NCR5380_hostdata *) instance->hostdata)->flags & FLAG_NCR53C400)
		SPRINTF("ncr53c400 release=%d.  ", NCR53C400_PUBLIC_RELEASE);
#ifdef DTC_PUBLIC_RELEASE
	SPRINTF("DTC 3180/3280 release %d", DTC_PUBLIC_RELEASE);
#endif
#ifdef T128_PUBLIC_RELEASE
	SPRINTF("T128 release %d", T128_PUBLIC_RELEASE);
#endif
#ifdef GENERIC_NCR5380_PUBLIC_RELEASE
	SPRINTF("Generic5380 release %d", GENERIC_NCR5380_PUBLIC_RELEASE);
#endif
#ifdef PAS16_PUBLIC_RELEASE
	SPRINTF("PAS16 release=%d", PAS16_PUBLIC_RELEASE);
#endif

	SPRINTF("\nBase Addr: 0x%05lX    ", (long) instance->base);
	SPRINTF("io_port: %04x      ", (int) instance->io_port);
	if (instance->irq == SCSI_IRQ_NONE)
		SPRINTF("IRQ: None.\n");
	else
		SPRINTF("IRQ: %d.\n", instance->irq);

#ifdef DTC_PUBLIC_RELEASE
	SPRINTF("Highwater I/O busy_spin_counts -- write: %d  read: %d\n", dtc_wmaxi, dtc_maxi);
#endif
#ifdef PAS16_PUBLIC_RELEASE
	SPRINTF("Highwater I/O busy_spin_counts -- write: %d  read: %d\n", pas_wmaxi, pas_maxi);
#endif
	spin_lock_irq(instance->host_lock);
	if (!hostdata->connected)
		SPRINTF("scsi%d: no currently connected command\n", instance->host_no);
	else
		pos = lprint_Scsi_Cmnd((Scsi_Cmnd *) hostdata->connected, pos, buffer, length);
	SPRINTF("scsi%d: issue_queue\n", instance->host_no);
	for (ptr = (Scsi_Cmnd *) hostdata->issue_queue; ptr; ptr = (Scsi_Cmnd *) ptr->host_scribble)
		pos = lprint_Scsi_Cmnd(ptr, pos, buffer, length);

	SPRINTF("scsi%d: disconnected_queue\n", instance->host_no);
	for (ptr = (Scsi_Cmnd *) hostdata->disconnected_queue; ptr; ptr = (Scsi_Cmnd *) ptr->host_scribble)
		pos = lprint_Scsi_Cmnd(ptr, pos, buffer, length);
	spin_unlock_irq(instance->host_lock);
	
	*start = buffer;
	if (pos - buffer < offset)
		return 0;
	else if (pos - buffer - offset < length)
		return pos - buffer - offset;
	return length;
}

static char *lprint_Scsi_Cmnd(Scsi_Cmnd * cmd, char *pos, char *buffer, int length)
{
	SPRINTF("scsi%d : destination target %d, lun %d\n", cmd->device->host->host_no, cmd->device->id, cmd->device->lun);
	SPRINTF("        command = ");
	pos = lprint_command(cmd->cmnd, pos, buffer, length);
	return (pos);
}

static char *lprint_command(unsigned char *command, char *pos, char *buffer, int length)
{
	int i, s;
	pos = lprint_opcode(command[0], pos, buffer, length);
	for (i = 1, s = COMMAND_SIZE(command[0]); i < s; ++i)
		SPRINTF("%02x ", command[i]);
	SPRINTF("\n");
	return (pos);
}

static char *lprint_opcode(int opcode, char *pos, char *buffer, int length)
{
	SPRINTF("%2d (0x%02x)", opcode, opcode);
	return (pos);
static int __maybe_unused NCR5380_write_info(struct Scsi_Host *instance,
	char *buffer, int length)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);

	hostdata->spin_max_r = 0;
	hostdata->spin_max_w = 0;
	return 0;
}
#endif

static
void lprint_Scsi_Cmnd(struct scsi_cmnd *cmd, struct seq_file *m);
static
void lprint_command(unsigned char *cmd, struct seq_file *m);
static
void lprint_opcode(int opcode, struct seq_file *m);

static int __maybe_unused NCR5380_show_info(struct seq_file *m,
	struct Scsi_Host *instance)
{
	struct NCR5380_hostdata *hostdata;
	struct scsi_cmnd *ptr;

	hostdata = (struct NCR5380_hostdata *) instance->hostdata;

#ifdef PSEUDO_DMA
	seq_printf(m, "Highwater I/O busy spin counts: write %d, read %d\n",
	        hostdata->spin_max_w, hostdata->spin_max_r);
#endif
	spin_lock_irq(instance->host_lock);
	if (!hostdata->connected)
		seq_printf(m, "scsi%d: no currently connected command\n", instance->host_no);
	else
		lprint_Scsi_Cmnd((struct scsi_cmnd *) hostdata->connected, m);
	seq_printf(m, "scsi%d: issue_queue\n", instance->host_no);
	for (ptr = (struct scsi_cmnd *) hostdata->issue_queue; ptr; ptr = (struct scsi_cmnd *) ptr->host_scribble)
		lprint_Scsi_Cmnd(ptr, m);

	seq_printf(m, "scsi%d: disconnected_queue\n", instance->host_no);
	for (ptr = (struct scsi_cmnd *) hostdata->disconnected_queue; ptr; ptr = (struct scsi_cmnd *) ptr->host_scribble)
		lprint_Scsi_Cmnd(ptr, m);
	spin_unlock_irq(instance->host_lock);
	return 0;
}

static void lprint_Scsi_Cmnd(struct scsi_cmnd *cmd, struct seq_file *m)
{
	seq_printf(m, "scsi%d : destination target %d, lun %llu\n", cmd->device->host->host_no, cmd->device->id, cmd->device->lun);
	seq_puts(m, "        command = ");
	lprint_command(cmd->cmnd, m);
}

static void lprint_command(unsigned char *command, struct seq_file *m)
{
	int i, s;
	lprint_opcode(command[0], m);
	for (i = 1, s = COMMAND_SIZE(command[0]); i < s; ++i)
		seq_printf(m, "%02x ", command[i]);
	seq_putc(m, '\n');
}

static void lprint_opcode(int opcode, struct seq_file *m)
{
	seq_printf(m, "%2d (0x%02x)", opcode, opcode);
}


/**
 *	NCR5380_init	-	initialise an NCR5380
 *	@instance: adapter to configure
 *	@flags: control flags
 *
 *	Initializes *instance and corresponding 5380 chip,
 *      with flags OR'd into the initial flags value.
 *
 *	Notes : I assume that the host, hostno, and id bits have been
 *      set correctly.  I don't care about the irq and other fields. 
 *
 *	Returns 0 for success
 *
 *	Locks: interrupts must be enabled when we are called 
 * Returns 0 for success
 */

static int __devinit NCR5380_init(struct Scsi_Host *instance, int flags)
static int NCR5380_init(struct Scsi_Host *instance, int flags)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	int i;
	unsigned long deadline;
	unsigned long accesses_per_ms;

	instance->max_lun = 7;

	hostdata->host = instance;
	hostdata->id_mask = 1 << instance->this_id;
	hostdata->id_higher_mask = 0;
	for (i = hostdata->id_mask; i <= 0x80; i <<= 1)
		if (i > hostdata->id_mask)
			hostdata->id_higher_mask |= i;
	for (i = 0; i < 8; ++i)
		hostdata->busy[i] = 0;
	hostdata->dma_len = 0;

	spin_lock_init(&hostdata->lock);
	hostdata->connected = NULL;
	hostdata->issue_queue = NULL;
	hostdata->disconnected_queue = NULL;
	
	INIT_DELAYED_WORK(&hostdata->coroutine, NCR5380_main);
	
#ifdef NCR5380_STATS
	for (i = 0; i < 8; ++i) {
		hostdata->time_read[i] = 0;
		hostdata->time_write[i] = 0;
		hostdata->bytes_read[i] = 0;
		hostdata->bytes_write[i] = 0;
	}
	hostdata->timebase = 0;
	hostdata->pendingw = 0;
	hostdata->pendingr = 0;
#endif

	/* The CHECK code seems to break the 53C400. Will check it later maybe */
	if (flags & FLAG_NCR53C400)
		hostdata->flags = FLAG_HAS_LAST_BYTE_SENT | flags;
	else
		hostdata->flags = FLAG_CHECK_LAST_BYTE_SENT | flags;
	hostdata->sensing = NULL;
	INIT_LIST_HEAD(&hostdata->autosense);
	INIT_LIST_HEAD(&hostdata->unissued);
	INIT_LIST_HEAD(&hostdata->disconnected);

	hostdata->flags = flags;

#ifndef AUTOSENSE
	if ((instance->cmd_per_lun > 1) || instance->can_queue > 1)
		    printk(KERN_WARNING "scsi%d : WARNING : support for multiple outstanding commands enabled\n" "         without AUTOSENSE option, contingent allegiance conditions may\n"
		    	   "         be incorrectly cleared.\n", instance->host_no);
#endif				/* def AUTOSENSE */
	prepare_info(instance);
	INIT_WORK(&hostdata->main_task, NCR5380_main);
	hostdata->work_q = alloc_workqueue("ncr5380_%d",
	                        WQ_UNBOUND | WQ_MEM_RECLAIM,
	                        1, instance->host_no);
	if (!hostdata->work_q)
		return -ENOMEM;

	snprintf(hostdata->info, sizeof(hostdata->info),
		"%s, irq %d, io_port 0x%lx, base 0x%lx, can_queue %d, cmd_per_lun %d, sg_tablesize %d, this_id %d, flags { %s%s%s}",
		instance->hostt->name, instance->irq, hostdata->io_port,
		hostdata->base, instance->can_queue, instance->cmd_per_lun,
		instance->sg_tablesize, instance->this_id,
		hostdata->flags & FLAG_DMA_FIXUP     ? "DMA_FIXUP "     : "",
		hostdata->flags & FLAG_NO_PSEUDO_DMA ? "NO_PSEUDO_DMA " : "",
		hostdata->flags & FLAG_TOSHIBA_DELAY ? "TOSHIBA_DELAY " : "");

	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
	NCR5380_write(MODE_REG, MR_BASE);
	NCR5380_write(TARGET_COMMAND_REG, 0);
	NCR5380_write(SELECT_ENABLE_REG, 0);

	/* Calibrate register polling loop */
	i = 0;
	deadline = jiffies + 1;
	do {
		cpu_relax();
	} while (time_is_after_jiffies(deadline));
	deadline += msecs_to_jiffies(256);
	do {
		NCR5380_read(STATUS_REG);
		++i;
		cpu_relax();
	} while (time_is_after_jiffies(deadline));
	accesses_per_ms = i / 256;
	hostdata->poll_loops = NCR5380_REG_POLL_TIME * accesses_per_ms / 2;

	return 0;
}

/**
 * NCR5380_maybe_reset_bus - Detect and correct bus wedge problems.
 * @instance: adapter to check
 *
 * If the system crashed, it may have crashed with a connected target and
 * the SCSI bus busy. Check for BUS FREE phase. If not, try to abort the
 * currently established nexus, which we know nothing about. Failing that
 * do a bus reset.
 *
 * Note that a bus reset will cause the chip to assert IRQ.
 *
 * Returns 0 if successful, otherwise -ENXIO.
 */

static int NCR5380_maybe_reset_bus(struct Scsi_Host *instance)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	int pass;

	for (pass = 1; (NCR5380_read(STATUS_REG) & SR_BSY) && pass <= 6; ++pass) {
		switch (pass) {
		case 1:
		case 3:
		case 5:
			shost_printk(KERN_ERR, instance, "SCSI bus busy, waiting up to five seconds\n");
			NCR5380_poll_politely(hostdata,
			                      STATUS_REG, SR_BSY, 0, 5 * HZ);
			break;
		case 2:
			shost_printk(KERN_ERR, instance, "bus busy, attempting abort\n");
			do_abort(instance);
			break;
		case 4:
			shost_printk(KERN_ERR, instance, "bus busy, attempting reset\n");
			do_reset(instance);
			/* Wait after a reset; the SCSI standard calls for
			 * 250ms, we wait 500ms to be on the safe side.
			 * But some Toshiba CD-ROMs need ten times that.
			 */
			if (hostdata->flags & FLAG_TOSHIBA_DELAY)
				msleep(2500);
			else
				msleep(500);
			break;
		case 6:
			shost_printk(KERN_ERR, instance, "bus locked solid\n");
			return -ENXIO;
		}
	}
	return 0;
}

/**
 * NCR5380_exit - remove an NCR5380
 * @instance: adapter to remove
 *
 * Assumes that no more work can be queued (e.g. by NCR5380_intr).
 */

static void NCR5380_exit(struct Scsi_Host *instance)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);

	cancel_delayed_work(&hostdata->coroutine);
	flush_scheduled_work();
	cancel_delayed_work_sync(&hostdata->coroutine);
	cancel_work_sync(&hostdata->main_task);
	destroy_workqueue(hostdata->work_q);
}

/**
 * complete_cmd - finish processing a command and return it to the SCSI ML
 * @instance: the host instance
 * @cmd: command to complete
 */

static int NCR5380_queue_command(Scsi_Cmnd * cmd, void (*done) (Scsi_Cmnd *)) 
{
	struct Scsi_Host *instance = cmd->device->host;
	struct NCR5380_hostdata *hostdata = (struct NCR5380_hostdata *) instance->hostdata;
	Scsi_Cmnd *tmp;
static int NCR5380_queue_command_lck(struct scsi_cmnd *cmd, void (*done) (struct scsi_cmnd *))
static void complete_cmd(struct Scsi_Host *instance,
                         struct scsi_cmnd *cmd)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);

	dsprintk(NDEBUG_QUEUES, instance, "complete_cmd: cmd %p\n", cmd);

	if (hostdata->sensing == cmd) {
		/* Autosense processing ends here */
		if ((cmd->result & 0xff) != SAM_STAT_GOOD) {
			scsi_eh_restore_cmnd(cmd, &hostdata->ses);
			set_host_byte(cmd, DID_ERROR);
		} else
			scsi_eh_restore_cmnd(cmd, &hostdata->ses);
		hostdata->sensing = NULL;
	}

	hostdata->busy[scmd_id(cmd)] &= ~(1 << cmd->device->lun);

	cmd->scsi_done(cmd);
}

/**
 * NCR5380_queue_command - queue a command
 * @instance: the relevant SCSI adapter
 * @cmd: SCSI command
 *
 * cmd is added to the per-instance issue queue, with minor
 * twiddling done to the host specific fields of cmd.  If the
 * main coroutine is not running, it is restarted.
 */

static int NCR5380_queue_command(struct Scsi_Host *instance,
                                 struct scsi_cmnd *cmd)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	struct NCR5380_cmd *ncmd = scsi_cmd_priv(cmd);
	unsigned long flags;

#if (NDEBUG & NDEBUG_NO_WRITE)
	switch (cmd->cmnd[0]) {
	case WRITE_6:
	case WRITE_10:
		shost_printk(KERN_DEBUG, instance, "WRITE attempted with NDEBUG_NO_WRITE set\n");
		cmd->result = (DID_ERROR << 16);
		cmd->scsi_done(cmd);
		return 0;
	}
#endif /* (NDEBUG & NDEBUG_NO_WRITE) */

#ifdef NCR5380_STATS
	switch (cmd->cmnd[0]) {
		case WRITE:
		case WRITE_6:
		case WRITE_10:
			hostdata->time_write[cmd->device->id] -= (jiffies - hostdata->timebase);
			hostdata->bytes_write[cmd->device->id] += scsi_bufflen(cmd);
			hostdata->pendingw++;
			break;
		case READ:
		case READ_6:
		case READ_10:
			hostdata->time_read[cmd->device->id] -= (jiffies - hostdata->timebase);
			hostdata->bytes_read[cmd->device->id] += scsi_bufflen(cmd);
			hostdata->pendingr++;
			break;
	}
#endif

	/* 
	 * We use the host_scribble field as a pointer to the next command  
	 * in a queue 
	 */

	cmd->host_scribble = NULL;
	cmd->scsi_done = done;
	cmd->result = 0;

	if (!NCR5380_acquire_dma_irq(instance))
		return SCSI_MLQUEUE_HOST_BUSY;

	spin_lock_irqsave(&hostdata->lock, flags);

	/*
	 * Insert the cmd into the issue queue. Note that REQUEST SENSE
	 * commands are added to the head of the queue since any command will
	 * clear the contingent allegiance condition that exists and the
	 * sense data is only guaranteed to be valid while the condition exists.
	 */

	if (!(hostdata->issue_queue) || (cmd->cmnd[0] == REQUEST_SENSE)) {
		LIST(cmd, hostdata->issue_queue);
		cmd->host_scribble = (unsigned char *) hostdata->issue_queue;
		hostdata->issue_queue = cmd;
	} else {
		for (tmp = (Scsi_Cmnd *) hostdata->issue_queue; tmp->host_scribble; tmp = (Scsi_Cmnd *) tmp->host_scribble);
		LIST(cmd, tmp);
		tmp->host_scribble = (unsigned char *) cmd;
	}
	dprintk(NDEBUG_QUEUES, ("scsi%d : command added to %s of queue\n", instance->host_no, (cmd->cmnd[0] == REQUEST_SENSE) ? "head" : "tail"));
		for (tmp = (struct scsi_cmnd *) hostdata->issue_queue; tmp->host_scribble; tmp = (struct scsi_cmnd *) tmp->host_scribble);
		LIST(cmd, tmp);
		tmp->host_scribble = (unsigned char *) cmd;
	}
	dprintk(NDEBUG_QUEUES, "scsi%d : command added to %s of queue\n", instance->host_no, (cmd->cmnd[0] == REQUEST_SENSE) ? "head" : "tail");
	if (cmd->cmnd[0] == REQUEST_SENSE)
		list_add(&ncmd->list, &hostdata->unissued);
	else
		list_add_tail(&ncmd->list, &hostdata->unissued);

	spin_unlock_irqrestore(&hostdata->lock, flags);

	dsprintk(NDEBUG_QUEUES, instance, "command %p added to %s of queue\n",
	         cmd, (cmd->cmnd[0] == REQUEST_SENSE) ? "head" : "tail");

	/* Kick off command processing */
	queue_work(hostdata->work_q, &hostdata->main_task);
	return 0;
}

static inline void maybe_release_dma_irq(struct Scsi_Host *instance)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);

	/* Caller does the locking needed to set & test these data atomically */
	if (list_empty(&hostdata->disconnected) &&
	    list_empty(&hostdata->unissued) &&
	    list_empty(&hostdata->autosense) &&
	    !hostdata->connected &&
	    !hostdata->selecting) {
		NCR5380_release_dma_irq(instance);
	}
}

/**
 * dequeue_next_cmd - dequeue a command for processing
 * @instance: the scsi host instance
 *
 * Priority is given to commands on the autosense queue. These commands
 * need autosense because of a CHECK CONDITION result.
 *
 * Returns a command pointer if a command is found for a target that is
 * not already busy. Otherwise returns NULL.
 */

static struct scsi_cmnd *dequeue_next_cmd(struct Scsi_Host *instance)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	struct NCR5380_cmd *ncmd;
	struct scsi_cmnd *cmd;

	if (hostdata->sensing || list_empty(&hostdata->autosense)) {
		list_for_each_entry(ncmd, &hostdata->unissued, list) {
			cmd = NCR5380_to_scmd(ncmd);
			dsprintk(NDEBUG_QUEUES, instance, "dequeue: cmd=%p target=%d busy=0x%02x lun=%llu\n",
			         cmd, scmd_id(cmd), hostdata->busy[scmd_id(cmd)], cmd->device->lun);

			if (!(hostdata->busy[scmd_id(cmd)] & (1 << cmd->device->lun))) {
				list_del(&ncmd->list);
				dsprintk(NDEBUG_QUEUES, instance,
				         "dequeue: removed %p from issue queue\n", cmd);
				return cmd;
			}
		}
	} else {
		/* Autosense processing begins here */
		ncmd = list_first_entry(&hostdata->autosense,
		                        struct NCR5380_cmd, list);
		list_del(&ncmd->list);
		cmd = NCR5380_to_scmd(ncmd);
		dsprintk(NDEBUG_QUEUES, instance,
		         "dequeue: removed %p from autosense queue\n", cmd);
		scsi_eh_prep_cmnd(cmd, &hostdata->ses, NULL, 0, ~0);
		hostdata->sensing = cmd;
		return cmd;
	}
	return NULL;
}

static void requeue_cmd(struct Scsi_Host *instance, struct scsi_cmnd *cmd)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	struct NCR5380_cmd *ncmd = scsi_cmd_priv(cmd);

	if (hostdata->sensing == cmd) {
		scsi_eh_restore_cmnd(cmd, &hostdata->ses);
		list_add(&ncmd->list, &hostdata->autosense);
		hostdata->sensing = NULL;
	} else
		list_add(&ncmd->list, &hostdata->unissued);
}

/**
 * NCR5380_main - NCR state machines
 *
 * NCR5380_main is a coroutine that runs as long as more work can
 * be done on the NCR5380 host adapters in a system.  Both
 * NCR5380_queue_command() and NCR5380_intr() will try to start it
 * in case it is not running.
 */

static void NCR5380_main(struct work_struct *work)
{
	struct NCR5380_hostdata *hostdata =
		container_of(work, struct NCR5380_hostdata, main_task);
	struct Scsi_Host *instance = hostdata->host;
	Scsi_Cmnd *tmp, *prev;
	struct scsi_cmnd *tmp, *prev;
	int done;

	do {
		done = 1;
		if (!hostdata->connected && !hostdata->selecting) {
			dprintk(NDEBUG_MAIN, ("scsi%d : not connected\n", instance->host_no));
			dprintk(NDEBUG_MAIN, "scsi%d : not connected\n", instance->host_no);

		spin_lock_irq(&hostdata->lock);
		while (!hostdata->connected && !hostdata->selecting) {
			struct scsi_cmnd *cmd = dequeue_next_cmd(instance);

			if (!cmd)
				break;

			dsprintk(NDEBUG_MAIN, instance, "main: dequeued %p\n", cmd);

			/*
			 * Attempt to establish an I_T_L nexus here.
			 * On success, instance->hostdata->connected is set.
			 * On failure, we must add the command back to the
			 * issue queue so we can keep trying.
			 */
			/*
			 * REQUEST SENSE commands are issued without tagged
			 * queueing, even on SCSI-II devices because the
			 * contingent allegiance condition exists for the
			 * entire unit.
			 */
			for (tmp = (Scsi_Cmnd *) hostdata->issue_queue, prev = NULL; tmp; prev = tmp, tmp = (Scsi_Cmnd *) tmp->host_scribble) 
			{
				if (prev != tmp)
					dprintk(NDEBUG_LISTS, ("MAIN tmp=%p   target=%d   busy=%d lun=%d\n", tmp, tmp->target, hostdata->busy[tmp->target], tmp->lun));
				/*  When we find one, remove it from the issue queue. */
				if (!(hostdata->busy[tmp->device->id] & (1 << tmp->device->lun))) {
			for (tmp = (struct scsi_cmnd *) hostdata->issue_queue, prev = NULL; tmp; prev = tmp, tmp = (struct scsi_cmnd *) tmp->host_scribble)
			{
				if (prev != tmp)
				    dprintk(NDEBUG_LISTS, "MAIN tmp=%p   target=%d   busy=%d lun=%llu\n", tmp, tmp->device->id, hostdata->busy[tmp->device->id], tmp->device->lun);
				/*  When we find one, remove it from the issue queue. */
				if (!(hostdata->busy[tmp->device->id] &
				      (1 << (u8)(tmp->device->lun & 0xff)))) {
					if (prev) {
						REMOVE(prev, prev->host_scribble, tmp, tmp->host_scribble);
						prev->host_scribble = tmp->host_scribble;
					} else {
						REMOVE(-1, hostdata->issue_queue, tmp, tmp->host_scribble);
						hostdata->issue_queue = (Scsi_Cmnd *) tmp->host_scribble;
						hostdata->issue_queue = (struct scsi_cmnd *) tmp->host_scribble;
					}
					tmp->host_scribble = NULL;

					/* 
					 * Attempt to establish an I_T_L nexus here. 
					 * On success, instance->hostdata->connected is set.
					 * On failure, we must add the command back to the
					 *   issue queue so we can keep trying. 
					 */
					dprintk(NDEBUG_MAIN|NDEBUG_QUEUES, ("scsi%d : main() : command for target %d lun %d removed from issue_queue\n", instance->host_no, tmp->target, tmp->lun));
					dprintk(NDEBUG_MAIN|NDEBUG_QUEUES, "scsi%d : main() : command for target %d lun %llu removed from issue_queue\n", instance->host_no, tmp->device->id, tmp->device->lun);
	
					/*
					 * A successful selection is defined as one that 
					 * leaves us with the command connected and 
					 * in hostdata->connected, OR has terminated the
					 * command.
					 *
					 * With successful commands, we fall through
					 * and see if we can do an information transfer,
					 * with failures we will restart.
					 */
					hostdata->selecting = NULL;
					/* RvC: have to preset this to indicate a new command is being performed */

					if (!NCR5380_select(instance, tmp,
							    /* 
							     * REQUEST SENSE commands are issued without tagged
							     * queueing, even on SCSI-II devices because the 
							     * contingent allegiance condition exists for the 
							     * entire unit.
							     */
							    (tmp->cmnd[0] == REQUEST_SENSE) ? TAG_NONE : TAG_NEXT)) {
					/*
					 * REQUEST SENSE commands are issued without tagged
					 * queueing, even on SCSI-II devices because the
					 * contingent allegiance condition exists for the
					 * entire unit.
					 */

					if (!NCR5380_select(instance, tmp)) {
						break;
					} else {
						LIST(tmp, hostdata->issue_queue);
						tmp->host_scribble = (unsigned char *) hostdata->issue_queue;
						hostdata->issue_queue = tmp;
						done = 0;
						dprintk(NDEBUG_MAIN|NDEBUG_QUEUES, ("scsi%d : main(): select() failed, returned to issue_queue\n", instance->host_no));
						dprintk(NDEBUG_MAIN|NDEBUG_QUEUES, "scsi%d : main(): select() failed, returned to issue_queue\n", instance->host_no);
					}
					/* lock held here still */
				}	/* if target/lun is not busy */
			}	/* for */
			/* exited locked */
		}	/* if (!hostdata->connected) */
		if (hostdata->selecting) {
			tmp = (Scsi_Cmnd *) hostdata->selecting;
			/* Selection will drop and retake the lock */
			if (!NCR5380_select(instance, tmp, (tmp->cmnd[0] == REQUEST_SENSE) ? TAG_NONE : TAG_NEXT)) {
			tmp = (struct scsi_cmnd *) hostdata->selecting;
			/* Selection will drop and retake the lock */
			if (!NCR5380_select(instance, tmp)) {
				/* Ok ?? */

			if (!NCR5380_select(instance, cmd)) {
				dsprintk(NDEBUG_MAIN, instance, "main: select complete\n");
				maybe_release_dma_irq(instance);
			} else {
				dsprintk(NDEBUG_MAIN | NDEBUG_QUEUES, instance,
				         "main: select failed, returning %p to queue\n", cmd);
				requeue_cmd(instance, cmd);
			}
		}	/* if hostdata->selecting */
		if (hostdata->connected
#ifdef REAL_DMA
		    && !hostdata->dmalen
#endif
		    && (!hostdata->time_expires || time_before_eq(hostdata->time_expires, jiffies))
		    ) {
			dprintk(NDEBUG_MAIN, ("scsi%d : main() : performing information transfer\n", instance->host_no));
			NCR5380_information_transfer(instance);
			dprintk(NDEBUG_MAIN, ("scsi%d : main() : done set false\n", instance->host_no));
			dprintk(NDEBUG_MAIN, "scsi%d : main() : performing information transfer\n", instance->host_no);
		}
		if (hostdata->connected && !hostdata->dma_len) {
			dsprintk(NDEBUG_MAIN, instance, "main: performing information transfer\n");
			NCR5380_information_transfer(instance);
			done = 0;
		}
		spin_unlock_irq(&hostdata->lock);
		if (!done)
			cond_resched();
	} while (!done);
}

/*
 * NCR5380_dma_complete - finish DMA transfer
 * @instance: the scsi host instance
 *
 * Called by the interrupt handler when DMA finishes or a phase
 * mismatch occurs (which would end the DMA transfer).
 */

static void NCR5380_dma_complete(struct Scsi_Host *instance)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	int transferred;
	unsigned char **data;
	int *count;
	int saved_data = 0, overrun = 0;
	unsigned char p;

	if (hostdata->read_overruns) {
		p = hostdata->connected->SCp.phase;
		if (p & SR_IO) {
			udelay(10);
			if ((NCR5380_read(BUS_AND_STATUS_REG) &
			     (BASR_PHASE_MATCH | BASR_ACK)) ==
			    (BASR_PHASE_MATCH | BASR_ACK)) {
				saved_data = NCR5380_read(INPUT_DATA_REG);
				overrun = 1;
				dsprintk(NDEBUG_DMA, instance, "read overrun handled\n");
			}
		}
	}

#ifdef CONFIG_SUN3
	if ((sun3scsi_dma_finish(rq_data_dir(hostdata->connected->request)))) {
		pr_err("scsi%d: overrun in UDC counter -- not prepared to deal with this!\n",
		       instance->host_no);
		BUG();
	}

	if ((NCR5380_read(BUS_AND_STATUS_REG) & (BASR_PHASE_MATCH | BASR_ACK)) ==
	    (BASR_PHASE_MATCH | BASR_ACK)) {
		pr_err("scsi%d: BASR %02x\n", instance->host_no,
		       NCR5380_read(BUS_AND_STATUS_REG));
		pr_err("scsi%d: bus stuck in data phase -- probably a single byte overrun!\n",
		       instance->host_no);
		BUG();
	}
#endif

	NCR5380_write(MODE_REG, MR_BASE);
	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
	NCR5380_read(RESET_PARITY_INTERRUPT_REG);

	transferred = hostdata->dma_len - NCR5380_dma_residual(hostdata);
	hostdata->dma_len = 0;

	data = (unsigned char **)&hostdata->connected->SCp.ptr;
	count = &hostdata->connected->SCp.this_residual;
	*data += transferred;
	*count -= transferred;

	if (hostdata->read_overruns) {
		int cnt, toPIO;

		if ((NCR5380_read(STATUS_REG) & PHASE_MASK) == p && (p & SR_IO)) {
			cnt = toPIO = hostdata->read_overruns;
			if (overrun) {
				dsprintk(NDEBUG_DMA, instance,
				         "Got an input overrun, using saved byte\n");
				*(*data)++ = saved_data;
				(*count)--;
				cnt--;
				toPIO--;
			}
			if (toPIO > 0) {
				dsprintk(NDEBUG_DMA, instance,
				         "Doing %d byte PIO to 0x%p\n", cnt, *data);
				NCR5380_transfer_pio(instance, &p, &cnt, data);
				*count -= toPIO - cnt;
			}
		}
	}
}

/**
 * NCR5380_intr - generic NCR5380 irq handler
 * @irq: interrupt number
 * @dev_id: device info
 *
 * Handle interrupts, reestablishing I_T_L or I_T_L_Q nexuses
 * from the disconnected queue, and restarting NCR5380_main()
 * as required.
 *
 * The chip can assert IRQ in any of six different conditions. The IRQ flag
 * is then cleared by reading the Reset Parity/Interrupt Register (RPIR).
 * Three of these six conditions are latched in the Bus and Status Register:
 * - End of DMA (cleared by ending DMA Mode)
 * - Parity error (cleared by reading RPIR)
 * - Loss of BSY (cleared by reading RPIR)
 * Two conditions have flag bits that are not latched:
 * - Bus phase mismatch (non-maskable in DMA Mode, cleared by ending DMA Mode)
 * - Bus reset (non-maskable)
 * The remaining condition has no flag bit at all:
 * - Selection/reselection
 *
 * Hence, establishing the cause(s) of any interrupt is partly guesswork.
 * In "The DP8490 and DP5380 Comparison Guide", National Semiconductor
 * claimed that "the design of the [DP8490] interrupt logic ensures
 * interrupts will not be lost (they can be on the DP5380)."
 * The L5380/53C80 datasheet from LOGIC Devices has more details.
 *
 * Checking for bus reset by reading RST is futile because of interrupt
 * latency, but a bus reset will reset chip logic. Checking for parity error
 * is unnecessary because that interrupt is never enabled. A Loss of BSY
 * condition will clear DMA Mode. We can tell when this occurs because the
 * the Busy Monitor interrupt is enabled together with DMA Mode.
 */

static irqreturn_t __maybe_unused NCR5380_intr(int irq, void *dev_id)
{
	struct Scsi_Host *instance = dev_id;
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	int handled = 0;
	unsigned char basr;
	unsigned long flags;

	dprintk(NDEBUG_INTR, ("scsi : NCR5380 irq %d triggered\n",
		instance->irq));
	dprintk(NDEBUG_INTR, "scsi : NCR5380 irq %d triggered\n",
		instance->irq);

	do {
		done = 1;
		spin_lock_irqsave(instance->host_lock, flags);
		/* Look for pending interrupts */
		NCR5380_setup(instance);
		basr = NCR5380_read(BUS_AND_STATUS_REG);
		/* XXX dispatch to appropriate routine if found and done=0 */
		if (basr & BASR_IRQ) {
			NCR5380_dprint(NDEBUG_INTR, instance);
			if ((NCR5380_read(STATUS_REG) & (SR_SEL | SR_IO)) == (SR_SEL | SR_IO)) {
				done = 0;
				dprintk(NDEBUG_INTR, ("scsi%d : SEL interrupt\n", instance->host_no));
				NCR5380_reselect(instance);
				(void) NCR5380_read(RESET_PARITY_INTERRUPT_REG);
			} else if (basr & BASR_PARITY_ERROR) {
				dprintk(NDEBUG_INTR, ("scsi%d : PARITY interrupt\n", instance->host_no));
				(void) NCR5380_read(RESET_PARITY_INTERRUPT_REG);
			} else if ((NCR5380_read(STATUS_REG) & SR_RST) == SR_RST) {
				dprintk(NDEBUG_INTR, ("scsi%d : RESET interrupt\n", instance->host_no));
				dprintk(NDEBUG_INTR, "scsi%d : SEL interrupt\n", instance->host_no);
				NCR5380_reselect(instance);
				(void) NCR5380_read(RESET_PARITY_INTERRUPT_REG);
			} else if (basr & BASR_PARITY_ERROR) {
				dprintk(NDEBUG_INTR, "scsi%d : PARITY interrupt\n", instance->host_no);
				(void) NCR5380_read(RESET_PARITY_INTERRUPT_REG);
			} else if ((NCR5380_read(STATUS_REG) & SR_RST) == SR_RST) {
				dprintk(NDEBUG_INTR, "scsi%d : RESET interrupt\n", instance->host_no);
				(void) NCR5380_read(RESET_PARITY_INTERRUPT_REG);
			} else {
#if defined(REAL_DMA)
				/*
				 * We should only get PHASE MISMATCH and EOP interrupts
				 * if we have DMA enabled, so do a sanity check based on
				 * the current setting of the MODE register.
				 */

				if ((NCR5380_read(MODE_REG) & MR_DMA) && ((basr & BASR_END_DMA_TRANSFER) || !(basr & BASR_PHASE_MATCH))) {
					int transfered;
					int transferred;

					if (!hostdata->connected)
						panic("scsi%d : received end of DMA interrupt with no connected cmd\n", instance->hostno);

					transfered = (hostdata->dmalen - NCR5380_dma_residual(instance));
					transferred = (hostdata->dmalen - NCR5380_dma_residual(instance));
					hostdata->connected->SCp.this_residual -= transferred;
					hostdata->connected->SCp.ptr += transferred;
					hostdata->dmalen = 0;

					(void) NCR5380_read(RESET_PARITY_INTERRUPT_REG);
							
					/* FIXME: we need to poll briefly then defer a workqueue task ! */
					NCR5380_poll_politely(hostdata, BUS_AND_STATUS_REG, BASR_ACK, 0, 2*HZ);

					NCR5380_write(MODE_REG, MR_BASE);
					NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
				}
#else
				dprintk(NDEBUG_INTR, ("scsi : unknown interrupt, BASR 0x%X, MR 0x%X, SR 0x%x\n", basr, NCR5380_read(MODE_REG), NCR5380_read(STATUS_REG)));
				dprintk(NDEBUG_INTR, "scsi : unknown interrupt, BASR 0x%X, MR 0x%X, SR 0x%x\n", basr, NCR5380_read(MODE_REG), NCR5380_read(STATUS_REG));
				(void) NCR5380_read(RESET_PARITY_INTERRUPT_REG);
#endif
	spin_lock_irqsave(&hostdata->lock, flags);

	basr = NCR5380_read(BUS_AND_STATUS_REG);
	if (basr & BASR_IRQ) {
		unsigned char mr = NCR5380_read(MODE_REG);
		unsigned char sr = NCR5380_read(STATUS_REG);

		dsprintk(NDEBUG_INTR, instance, "IRQ %d, BASR 0x%02x, SR 0x%02x, MR 0x%02x\n",
		         irq, basr, sr, mr);

		if ((mr & MR_DMA_MODE) || (mr & MR_MONITOR_BSY)) {
			/* Probably End of DMA, Phase Mismatch or Loss of BSY.
			 * We ack IRQ after clearing Mode Register. Workarounds
			 * for End of DMA errata need to happen in DMA Mode.
			 */

			dsprintk(NDEBUG_INTR, instance, "interrupt in DMA mode\n");

			if (hostdata->connected) {
				NCR5380_dma_complete(instance);
				queue_work(hostdata->work_q, &hostdata->main_task);
			} else {
				NCR5380_write(MODE_REG, MR_BASE);
				NCR5380_read(RESET_PARITY_INTERRUPT_REG);
			}
		} else if ((NCR5380_read(CURRENT_SCSI_DATA_REG) & hostdata->id_mask) &&
		    (sr & (SR_SEL | SR_IO | SR_BSY | SR_RST)) == (SR_SEL | SR_IO)) {
			/* Probably reselected */
			NCR5380_write(SELECT_ENABLE_REG, 0);
			NCR5380_read(RESET_PARITY_INTERRUPT_REG);

			dsprintk(NDEBUG_INTR, instance, "interrupt with SEL and IO\n");

			if (!hostdata->connected) {
				NCR5380_reselect(instance);
				queue_work(hostdata->work_q, &hostdata->main_task);
			}
			if (!hostdata->connected)
				NCR5380_write(SELECT_ENABLE_REG, hostdata->id_mask);
		} else {
			/* Probably Bus Reset */
			NCR5380_read(RESET_PARITY_INTERRUPT_REG);

			dsprintk(NDEBUG_INTR, instance, "unknown interrupt\n");
#ifdef SUN3_SCSI_VME
			dregs->csr |= CSR_DMA_ENABLE;
#endif
		}
		handled = 1;
	} else {
		dsprintk(NDEBUG_INTR, instance, "interrupt without IRQ bit\n");
#ifdef SUN3_SCSI_VME
		dregs->csr |= CSR_DMA_ENABLE;
#endif
	}

	spin_unlock_irqrestore(&hostdata->lock, flags);

	return IRQ_RETVAL(handled);
}

#endif 

/**
 *	collect_stats		-	collect stats on a scsi command
 *	@hostdata: adapter 
 *	@cmd: command being issued
 *
 *	Update the statistical data by parsing the command in question
 */
 
static void collect_stats(struct NCR5380_hostdata *hostdata, Scsi_Cmnd * cmd) 
{
#ifdef NCR5380_STATS
	switch (cmd->cmnd[0]) {
	case WRITE:
	case WRITE_6:
	case WRITE_10:
		hostdata->time_write[scmd_id(cmd)] += (jiffies - hostdata->timebase);
		hostdata->pendingw--;
		break;
	case READ:
	case READ_6:
	case READ_10:
		hostdata->time_read[scmd_id(cmd)] += (jiffies - hostdata->timebase);
		hostdata->pendingr--;
		break;
	}
#endif
}


/* 
 * Function : int NCR5380_select (struct Scsi_Host *instance, Scsi_Cmnd *cmd, 
 *      int tag);
/* 
/*
 * Function : int NCR5380_select(struct Scsi_Host *instance,
 * struct scsi_cmnd *cmd)
 *
 * Purpose : establishes I_T_L or I_T_L_Q nexus for new or existing command,
 * including ARBITRATION, SELECTION, and initial message out for
 * IDENTIFY and queue messages.
 *
 * Inputs : instance - instantiation of the 5380 driver on which this 
 *      target lives, cmd - SCSI command to execute, tag - set to TAG_NEXT for 
 *      new tag, TAG_NONE for untagged queueing, otherwise set to the tag for 
 *      the command that is presently connected.
 *      target lives, cmd - SCSI command to execute.
 * 
 * Returns : -1 if selection could not execute for some reason,
 *      0 if selection succeeded or failed because the target 
 *      did not respond.
 * Inputs : instance - instantiation of the 5380 driver on which this
 * target lives, cmd - SCSI command to execute.
 *
 * Returns cmd if selection failed but should be retried,
 * NULL if selection failed and should not be retried, or
 * NULL if selection succeeded (hostdata->connected == cmd).
 *
 * Side effects :
 * If bus busy, arbitration failed, etc, NCR5380_select() will exit
 * with registers as they should have been on entry - ie
 * SELECT_ENABLE will be set appropriately, the NCR5380
 * will cease to drive any SCSI bus signals.
 *
 * If successful : I_T_L or I_T_L_Q nexus will be established,
 * instance->connected will be set to cmd.
 * SELECT interrupt will be disabled.
 *
 * If failed (no target) : cmd->scsi_done() will be called, and the
 * cmd->result host byte set to DID_BAD_TARGET.
 */
 
static int NCR5380_select(struct Scsi_Host *instance, Scsi_Cmnd * cmd, int tag) 
static int NCR5380_select(struct Scsi_Host *instance, struct scsi_cmnd *cmd)

static struct scsi_cmnd *NCR5380_select(struct Scsi_Host *instance,
                                        struct scsi_cmnd *cmd)
	__releases(&hostdata->lock) __acquires(&hostdata->lock)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	unsigned char tmp[3], phase;
	unsigned char *data;
	int len;
	int err;

	NCR5380_dprint(NDEBUG_ARBITRATION, instance);
	dprintk(NDEBUG_ARBITRATION, ("scsi%d : starting arbitration, id = %d\n", instance->host_no, instance->this_id));
	dprintk(NDEBUG_ARBITRATION, "scsi%d : starting arbitration, id = %d\n", instance->host_no, instance->this_id);
	dsprintk(NDEBUG_ARBITRATION, instance, "starting arbitration, id = %d\n",
	         instance->this_id);

	/*
	 * Arbitration and selection phases are slow and involve dropping the
	 * lock, so we have to watch out for EH. An exception handler may
	 * change 'selecting' to NULL. This function will then return NULL
	 * so that the caller will forget about 'cmd'. (During information
	 * transfer phases, EH may change 'connected' to NULL.)
	 */
	hostdata->selecting = cmd;

	/*
	 * Set the phase bits to 0, otherwise the NCR5380 won't drive the
	 * data bus during SELECTION.
	 */

	NCR5380_write(TARGET_COMMAND_REG, 0);

	/*
	 * Start arbitration.
	 */

	NCR5380_write(OUTPUT_DATA_REG, hostdata->id_mask);
	NCR5380_write(MODE_REG, MR_ARBITRATE);


	/* We can be relaxed here, interrupts are on, we are
	   in workqueue context, the birds are singing in the trees */
	spin_unlock_irq(instance->host_lock);
	err = NCR5380_poll_politely(instance, INITIATOR_COMMAND_REG, ICR_ARBITRATION_PROGRESS, ICR_ARBITRATION_PROGRESS, 5*HZ);
	spin_lock_irq(instance->host_lock);
	if (err < 0) {
		printk(KERN_DEBUG "scsi: arbitration timeout at %d\n", __LINE__);
		NCR5380_write(MODE_REG, MR_BASE);
		NCR5380_write(SELECT_ENABLE_REG, hostdata->id_mask);
		goto failed;
	}

	dprintk(NDEBUG_ARBITRATION, ("scsi%d : arbitration complete\n", instance->host_no));
	dprintk(NDEBUG_ARBITRATION, "scsi%d : arbitration complete\n", instance->host_no);

	/* 
	 * The arbitration delay is 2.2us, but this is a minimum and there is 
	 * no maximum so we can safely sleep for ceil(2.2) usecs to accommodate
	 * the integral nature of udelay().
	 *
	/* The chip now waits for BUS FREE phase. Then after the 800 ns
	 * Bus Free Delay, arbitration will begin.
	 */

	spin_unlock_irq(&hostdata->lock);
	err = NCR5380_poll_politely2(hostdata, MODE_REG, MR_ARBITRATE, 0,
	                INITIATOR_COMMAND_REG, ICR_ARBITRATION_PROGRESS,
	                                       ICR_ARBITRATION_PROGRESS, HZ);
	spin_lock_irq(&hostdata->lock);
	if (!(NCR5380_read(MODE_REG) & MR_ARBITRATE)) {
		/* Reselection interrupt */
		goto out;
	}
	if (!hostdata->selecting) {
		/* Command was aborted */
		NCR5380_write(MODE_REG, MR_BASE);
		goto out;
	}
	if (err < 0) {
		NCR5380_write(MODE_REG, MR_BASE);
		shost_printk(KERN_ERR, instance,
		             "select: arbitration timeout\n");
		goto out;
	}
	spin_unlock_irq(&hostdata->lock);

	/* The SCSI-2 arbitration delay is 2.4 us */
	udelay(3);

	/* Check for lost arbitration */
	if ((NCR5380_read(INITIATOR_COMMAND_REG) & ICR_ARBITRATION_LOST) || (NCR5380_read(CURRENT_SCSI_DATA_REG) & hostdata->id_higher_mask) || (NCR5380_read(INITIATOR_COMMAND_REG) & ICR_ARBITRATION_LOST)) {
		NCR5380_write(MODE_REG, MR_BASE);
		dprintk(NDEBUG_ARBITRATION, ("scsi%d : lost arbitration, deasserting MR_ARBITRATE\n", instance->host_no));
		dprintk(NDEBUG_ARBITRATION, "scsi%d : lost arbitration, deasserting MR_ARBITRATE\n", instance->host_no);
		goto failed;
	}
	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_SEL);

	if (!(hostdata->flags & FLAG_DTC3181E) &&
	    /* RvC: DTC3181E has some trouble with this
	     *      so we simply removed it. Seems to work with
	     *      only Mustek scanner attached
	     */
	    (NCR5380_read(INITIATOR_COMMAND_REG) & ICR_ARBITRATION_LOST)) {
		NCR5380_write(MODE_REG, MR_BASE);
		NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
		dprintk(NDEBUG_ARBITRATION, ("scsi%d : lost arbitration, deasserting ICR_ASSERT_SEL\n", instance->host_no));
		dprintk(NDEBUG_ARBITRATION, "scsi%d : lost arbitration, deasserting ICR_ASSERT_SEL\n", instance->host_no);
		goto failed;
	if ((NCR5380_read(INITIATOR_COMMAND_REG) & ICR_ARBITRATION_LOST) ||
	    (NCR5380_read(CURRENT_SCSI_DATA_REG) & hostdata->id_higher_mask) ||
	    (NCR5380_read(INITIATOR_COMMAND_REG) & ICR_ARBITRATION_LOST)) {
		NCR5380_write(MODE_REG, MR_BASE);
		dsprintk(NDEBUG_ARBITRATION, instance, "lost arbitration, deasserting MR_ARBITRATE\n");
		spin_lock_irq(&hostdata->lock);
		goto out;
	}

	/* After/during arbitration, BSY should be asserted.
	 * IBM DPES-31080 Version S31Q works now
	 * Tnx to Thomas_Roesch@m2.maus.de for finding this! (Roman)
	 */
	NCR5380_write(INITIATOR_COMMAND_REG,
		      ICR_BASE | ICR_ASSERT_SEL | ICR_ASSERT_BSY);

	/*
	 * Again, bus clear + bus settle time is 1.2us, however, this is
	 * a minimum so we'll udelay ceil(1.2)
	 */

	if (hostdata->flags & FLAG_TOSHIBA_DELAY)
		udelay(15);
	else
		udelay(2);

	dprintk(NDEBUG_ARBITRATION, ("scsi%d : won arbitration\n", instance->host_no));
	dprintk(NDEBUG_ARBITRATION, "scsi%d : won arbitration\n", instance->host_no);
	spin_lock_irq(&hostdata->lock);

	/* NCR5380_reselect() clears MODE_REG after a reselection interrupt */
	if (!(NCR5380_read(MODE_REG) & MR_ARBITRATE))
		goto out;

	if (!hostdata->selecting) {
		NCR5380_write(MODE_REG, MR_BASE);
		NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
		goto out;
	}

	dsprintk(NDEBUG_ARBITRATION, instance, "won arbitration\n");

	/*
	 * Now that we have won arbitration, start Selection process, asserting
	 * the host and target ID's on the SCSI bus.
	 */

	NCR5380_write(OUTPUT_DATA_REG, hostdata->id_mask | (1 << scmd_id(cmd)));

	/*
	 * Raise ATN while SEL is true before BSY goes false from arbitration,
	 * since this is the only way to guarantee that we'll get a MESSAGE OUT
	 * phase immediately after selection.
	 */

	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_BSY |
	              ICR_ASSERT_DATA | ICR_ASSERT_ATN | ICR_ASSERT_SEL);
	NCR5380_write(MODE_REG, MR_BASE);

	/*
	 * Reselect interrupts must be turned off prior to the dropping of BSY,
	 * otherwise we will trigger an interrupt.
	 */
	NCR5380_write(SELECT_ENABLE_REG, 0);

	spin_unlock_irq(&hostdata->lock);

	/*
	 * The initiator shall then wait at least two deskew delays and release
	 * the BSY signal.
	 */
	udelay(1);        /* wingel -- wait two bus deskew delay >2*45ns */

	/* Reset BSY */
	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_DATA |
	              ICR_ASSERT_ATN | ICR_ASSERT_SEL);

	/*
	 * Something weird happens when we cease to drive BSY - looks
	 * like the board/chip is letting us do another read before the
	 * appropriate propagation delay has expired, and we're confusing
	 * a BSY signal from ourselves as the target's response to SELECTION.
	 *
	 * A small delay (the 'C++' frontend breaks the pipeline with an
	 * unnecessary jump, making it work on my 386-33/Trantor T128, the
	 * tighter 'C' code breaks and requires this) solves the problem -
	 * the 1 us delay is arbitrary, and only used because this delay will
	 * be the same on other platforms and since it works here, it should
	 * work there.
	 *
	 * wingel suggests that this could be due to failing to wait
	 * one deskew delay.
	 */

	udelay(1);

	dprintk(NDEBUG_SELECTION, ("scsi%d : selecting target %d\n", instance->host_no, scmd_id(cmd)));
	dprintk(NDEBUG_SELECTION, "scsi%d : selecting target %d\n", instance->host_no, scmd_id(cmd));
	dsprintk(NDEBUG_SELECTION, instance, "selecting target %d\n", scmd_id(cmd));

	/*
	 * The SCSI specification calls for a 250 ms timeout for the actual
	 * selection.
	 */

	timeout = jiffies + (250 * HZ / 1000);
	timeout = jiffies + msecs_to_jiffies(250);
	err = NCR5380_poll_politely(hostdata, STATUS_REG, SR_BSY, SR_BSY,
	                            msecs_to_jiffies(250));

	if ((NCR5380_read(STATUS_REG) & (SR_SEL | SR_IO)) == (SR_SEL | SR_IO)) {
		spin_lock_irq(&hostdata->lock);
		NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
		NCR5380_reselect(instance);
		if (!hostdata->connected)
			NCR5380_write(SELECT_ENABLE_REG, hostdata->id_mask);
		shost_printk(KERN_ERR, instance, "reselection after won arbitration?\n");
		goto out;
	}

	if (err < 0) {
		spin_lock_irq(&hostdata->lock);
		NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
		NCR5380_write(SELECT_ENABLE_REG, hostdata->id_mask);
		/* Can't touch cmd if it has been reclaimed by the scsi ML */
		if (hostdata->selecting) {
			cmd->result = DID_BAD_TARGET << 16;
			complete_cmd(instance, cmd);
			dsprintk(NDEBUG_SELECTION, instance, "target did not respond within 250ms\n");
			cmd = NULL;
		}
		goto out;
	}

	/*
	 * No less than two deskew delays after the initiator detects the
	 * BSY signal is true, it shall release the SEL signal and may
	 * change the DATA BUS.                                     -wingel
	 */

	udelay(1);

	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_ATN);

	if (!(NCR5380_read(STATUS_REG) & SR_BSY)) {
		NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
		if (hostdata->targets_present & (1 << scmd_id(cmd))) {
			printk(KERN_DEBUG "scsi%d : weirdness\n", instance->host_no);
			if (hostdata->restart_select)
				printk(KERN_DEBUG "\trestart select\n");
			NCR5380_dprint(NDEBUG_SELECTION, instance);
			NCR5380_write(SELECT_ENABLE_REG, hostdata->id_mask);
			return -1;
		}
		cmd->result = DID_BAD_TARGET << 16;
		collect_stats(hostdata, cmd);
		cmd->scsi_done(cmd);
		NCR5380_write(SELECT_ENABLE_REG, hostdata->id_mask);
		dprintk(NDEBUG_SELECTION, ("scsi%d : target did not respond within 250ms\n", instance->host_no));
		cmd->scsi_done(cmd);
		NCR5380_write(SELECT_ENABLE_REG, hostdata->id_mask);
		dprintk(NDEBUG_SELECTION, "scsi%d : target did not respond within 250ms\n", instance->host_no);
		NCR5380_write(SELECT_ENABLE_REG, hostdata->id_mask);
		return 0;
	}
	hostdata->targets_present |= (1 << scmd_id(cmd));

	/*
	 * Since we followed the SCSI spec, and raised ATN while SEL
	 * was true but before BSY was false during selection, the information
	 * transfer phase should be a MESSAGE OUT phase so that we can send the
	 * IDENTIFY message.
	 */

	/* Wait for start of REQ/ACK handshake */

	err = NCR5380_poll_politely(hostdata, STATUS_REG, SR_REQ, SR_REQ, HZ);
	spin_lock_irq(&hostdata->lock);
	if (err < 0) {
		shost_printk(KERN_ERR, instance, "select: REQ timeout\n");
		NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
		NCR5380_write(SELECT_ENABLE_REG, hostdata->id_mask);
		goto out;
	}
	if (!hostdata->selecting) {
		do_abort(instance);
		goto out;
	}

	dprintk(NDEBUG_SELECTION, ("scsi%d : target %d selected, going into MESSAGE OUT phase.\n", instance->host_no, cmd->device->id));
	tmp[0] = IDENTIFY(((instance->irq == SCSI_IRQ_NONE) ? 0 : 1), cmd->device->lun);
	dprintk(NDEBUG_SELECTION, "scsi%d : target %d selected, going into MESSAGE OUT phase.\n", instance->host_no, cmd->device->id);
	dsprintk(NDEBUG_SELECTION, instance, "target %d selected, going into MESSAGE OUT phase.\n",
	         scmd_id(cmd));
	tmp[0] = IDENTIFY(((instance->irq == NO_IRQ) ? 0 : 1), cmd->device->lun);

	len = 1;
	data = tmp;
	phase = PHASE_MSGOUT;
	NCR5380_transfer_pio(instance, &phase, &len, &data);
	dprintk(NDEBUG_SELECTION, ("scsi%d : nexus established.\n", instance->host_no));
	/* XXX need to handle errors here */
	hostdata->connected = cmd;
	hostdata->busy[cmd->device->id] |= (1 << cmd->device->lun);
	dprintk(NDEBUG_SELECTION, "scsi%d : nexus established.\n", instance->host_no);
	/* XXX need to handle errors here */
	if (len) {
		NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
		cmd->result = DID_ERROR << 16;
		complete_cmd(instance, cmd);
		dsprintk(NDEBUG_SELECTION, instance, "IDENTIFY message transfer failed\n");
		cmd = NULL;
		goto out;
	}

	dsprintk(NDEBUG_SELECTION, instance, "nexus established.\n");

	hostdata->connected = cmd;
	hostdata->busy[cmd->device->id] |= 1 << cmd->device->lun;

#ifdef SUN3_SCSI_VME
	dregs->csr |= CSR_INTR;
#endif

	initialize_SCp(cmd);

	cmd = NULL;

out:
	if (!hostdata->selecting)
		return NULL;
	hostdata->selecting = NULL;
	return cmd;
}

/*
 * Function : int NCR5380_transfer_pio (struct Scsi_Host *instance,
 * unsigned char *phase, int *count, unsigned char **data)
 *
 * Purpose : transfers data in given phase using polled I/O
 *
 * Inputs : instance - instance of driver, *phase - pointer to 
 *      what phase is expected, *count - pointer to number of 
 *      bytes to transfer, **data - pointer to data pointer.
 * 
 * Returns : -1 when different phase is entered without transferring
 *      maximum number of bytes, 0 if all bytes or transfered or exit
 *      maximum number of bytes, 0 if all bytes or transferred or exit
 *      is in same phase.
 * Inputs : instance - instance of driver, *phase - pointer to
 * what phase is expected, *count - pointer to number of
 * bytes to transfer, **data - pointer to data pointer.
 *
 * Returns : -1 when different phase is entered without transferring
 * maximum number of bytes, 0 if all bytes are transferred or exit
 * is in same phase.
 *
 * Also, *phase, *count, *data are modified in place.
 *
 * XXX Note : handling for bus free may be useful.
 */

/*
 * Note : this code is not as quick as it could be, however it
 * IS 100% reliable, and for the actual data transfer where speed
 * counts, we will always do a pseudo DMA or DMA transfer.
 */

static int NCR5380_transfer_pio(struct Scsi_Host *instance,
				unsigned char *phase, int *count,
				unsigned char **data)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	unsigned char p = *phase, tmp;
	int c = *count;
	unsigned char *d = *data;

	/*
	 *      RvC: some administrative data to process polling time
	 */
	int break_allowed = 0;
	struct NCR5380_hostdata *hostdata = (struct NCR5380_hostdata *) instance->hostdata;
	NCR5380_setup(instance);

	if (!(p & SR_IO))
		dprintk(NDEBUG_PIO, ("scsi%d : pio write %d bytes\n", instance->host_no, c));
	else
		dprintk(NDEBUG_PIO, ("scsi%d : pio read %d bytes\n", instance->host_no, c));
		dprintk(NDEBUG_PIO, "scsi%d : pio write %d bytes\n", instance->host_no, c);
	else
		dprintk(NDEBUG_PIO, "scsi%d : pio read %d bytes\n", instance->host_no, c);

	/* 
	 * The NCR5380 chip will only drive the SCSI bus when the 
	 * The NCR5380 chip will only drive the SCSI bus when the
	 * phase specified in the appropriate bits of the TARGET COMMAND
	 * REGISTER match the STATUS REGISTER
	 */

	NCR5380_write(TARGET_COMMAND_REG, PHASE_SR_TO_TCR(p));

	do {
		/*
		 * Wait for assertion of REQ, after which the phase bits will be
		 * valid
		 */

		if (NCR5380_poll_politely(hostdata, STATUS_REG, SR_REQ, SR_REQ, HZ) < 0)
			break;

		dprintk(NDEBUG_HANDSHAKE, ("scsi%d : REQ detected\n", instance->host_no));

		/* Check for phase mismatch */
		if ((tmp & PHASE_MASK) != p) {
			dprintk(NDEBUG_HANDSHAKE, ("scsi%d : phase mismatch\n", instance->host_no));
		dprintk(NDEBUG_HANDSHAKE, "scsi%d : REQ detected\n", instance->host_no);
		dsprintk(NDEBUG_HANDSHAKE, instance, "REQ asserted\n");

		/* Check for phase mismatch */
		if ((NCR5380_read(STATUS_REG) & PHASE_MASK) != p) {
			dsprintk(NDEBUG_PIO, instance, "phase mismatch\n");
			NCR5380_dprint_phase(NDEBUG_PIO, instance);
			break;
		}

		/* Do actual transfer from SCSI bus to / from memory */
		if (!(p & SR_IO))
			NCR5380_write(OUTPUT_DATA_REG, *d);
		else
			*d = NCR5380_read(CURRENT_SCSI_DATA_REG);

		++d;

		/*
		 * The SCSI standard suggests that in MSGOUT phase, the initiator
		 * should drop ATN on the last byte of the message phase
		 * after REQ has been asserted for the handshake but before
		 * the initiator raises ACK.
		 */

		if (!(p & SR_IO)) {
			if (!((p & SR_MSG) && c > 1)) {
				NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_DATA);
				NCR5380_dprint(NDEBUG_PIO, instance);
				NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE |
				              ICR_ASSERT_DATA | ICR_ASSERT_ACK);
			} else {
				NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE |
				              ICR_ASSERT_DATA | ICR_ASSERT_ATN);
				NCR5380_dprint(NDEBUG_PIO, instance);
				NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE |
				              ICR_ASSERT_DATA | ICR_ASSERT_ATN | ICR_ASSERT_ACK);
			}
		} else {
			NCR5380_dprint(NDEBUG_PIO, instance);
			NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_ACK);
		}

		/* FIXME - if this fails bus reset ?? */
		NCR5380_poll_politely(instance, STATUS_REG, SR_REQ, 0, 5*HZ);
		dprintk(NDEBUG_HANDSHAKE, ("scsi%d : req false, handshake complete\n", instance->host_no));
		dprintk(NDEBUG_HANDSHAKE, "scsi%d : req false, handshake complete\n", instance->host_no);
		if (NCR5380_poll_politely(hostdata,
		                          STATUS_REG, SR_REQ, 0, 5 * HZ) < 0)
			break;

		dsprintk(NDEBUG_HANDSHAKE, instance, "REQ negated, handshake complete\n");

/*
 * We have several special cases to consider during REQ/ACK handshaking :
 * 1.  We were in MSGOUT phase, and we are on the last byte of the
 * message.  ATN must be dropped as ACK is dropped.
 *
 * 2.  We are in a MSGIN phase, and we are on the last byte of the
 * message.  We must exit with ACK asserted, so that the calling
 * code may raise ATN before dropping ACK to reject the message.
 *
 * 3.  ACK and ATN are clear and the target may proceed as normal.
 */
		if (!(p == PHASE_MSGIN && c == 1)) {
			if (p == PHASE_MSGOUT && c > 1)
				NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_ATN);
			else
				NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
		}
	} while (--c);

	dprintk(NDEBUG_PIO, ("scsi%d : residual %d\n", instance->host_no, c));
	dprintk(NDEBUG_PIO, "scsi%d : residual %d\n", instance->host_no, c);
	dsprintk(NDEBUG_PIO, instance, "residual %d\n", c);

	*count = c;
	*data = d;
	tmp = NCR5380_read(STATUS_REG);
	/* The phase read from the bus is valid if either REQ is (already)
	 * asserted or if ACK hasn't been released yet. The latter applies if
	 * we're in MSG IN, DATA IN or STATUS and all bytes have been received.
	 */
	if ((tmp & SR_REQ) || ((tmp & SR_IO) && c == 0))
		*phase = tmp & PHASE_MASK;
	else
		*phase = PHASE_UNKNOWN;

	if (!c || (*phase == p))
		return 0;
	else
		return -1;
}

/**
 * do_reset - issue a reset command
 * @instance: adapter to reset
 *
 * Issue a reset sequence to the NCR5380 and try and get the bus
 * back into sane shape.
 *
 * This clears the reset interrupt flag because there may be no handler for
 * it. When the driver is initialized, the NCR5380_intr() handler has not yet
 * been installed. And when in EH we may have released the ST DMA interrupt.
 */

static void do_reset(struct Scsi_Host *instance)
{
	struct NCR5380_hostdata __maybe_unused *hostdata = shost_priv(instance);
	unsigned long flags;

	local_irq_save(flags);
	NCR5380_write(TARGET_COMMAND_REG,
	              PHASE_SR_TO_TCR(NCR5380_read(STATUS_REG) & PHASE_MASK));
	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_RST);
	udelay(50);
	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
	(void)NCR5380_read(RESET_PARITY_INTERRUPT_REG);
	local_irq_restore(flags);
}

/**
 * do_abort - abort the currently established nexus by going to
 * MESSAGE OUT phase and sending an ABORT message.
 * @instance: relevant scsi host instance
 *
 * Returns 0 on success, -1 on failure.
 */

static int do_abort(struct Scsi_Host *instance)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	unsigned char *msgptr, phase, tmp;
	int len;
	int rc;

	/* Request message out phase */
	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_ATN);

	/*
	 * Wait for the target to indicate a valid phase by asserting
	 * REQ.  Once this happens, we'll have either a MSGOUT phase
	 * and can immediately send the ABORT message, or we'll have some
	 * other phase and will have to source/sink data.
	 *
	 * We really don't care what value was on the bus or what value
	 * the target sees, so we just handshake.
	 */

	rc = NCR5380_poll_politely(hostdata, STATUS_REG, SR_REQ, SR_REQ, 10 * HZ);
	if (rc < 0)
		goto timeout;

	tmp = NCR5380_read(STATUS_REG) & PHASE_MASK;

	NCR5380_write(TARGET_COMMAND_REG, PHASE_SR_TO_TCR(tmp));

	if (tmp != PHASE_MSGOUT) {
		NCR5380_write(INITIATOR_COMMAND_REG,
		              ICR_BASE | ICR_ASSERT_ATN | ICR_ASSERT_ACK);
		rc = NCR5380_poll_politely(hostdata, STATUS_REG, SR_REQ, 0, 3 * HZ);
		if (rc < 0)
			goto timeout;
		NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_ATN);
	}

	tmp = ABORT;
	msgptr = &tmp;
	len = 1;
	phase = PHASE_MSGOUT;
	NCR5380_transfer_pio(instance, &phase, &len, &msgptr);

	/*
	 * If we got here, and the command completed successfully,
	 * we're about to go into bus free state.
	 */

	return len ? -1 : 0;

timeout:
	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
	return -1;
}

/*
 * Function : int NCR5380_transfer_dma (struct Scsi_Host *instance,
 * unsigned char *phase, int *count, unsigned char **data)
 *
 * Purpose : transfers data in given phase using either real
 * or pseudo DMA.
 *
 * Inputs : instance - instance of driver, *phase - pointer to
 * what phase is expected, *count - pointer to number of
 * bytes to transfer, **data - pointer to data pointer.
 *
 * Returns : -1 when different phase is entered without transferring
 *      maximum number of bytes, 0 if all bytes or transfered or exit
 *      maximum number of bytes, 0 if all bytes or transferred or exit
 *      is in same phase.
 * maximum number of bytes, 0 if all bytes or transferred or exit
 * is in same phase.
 *
 * Also, *phase, *count, *data are modified in place.
 */


static int NCR5380_transfer_dma(struct Scsi_Host *instance,
				unsigned char *phase, int *count,
				unsigned char **data)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	int c = *count;
	unsigned char p = *phase;
	unsigned char *d = *data;
	unsigned char tmp;
	int result = 0;

	if ((tmp = (NCR5380_read(STATUS_REG) & PHASE_MASK)) != p) {
		*phase = tmp;
		return -1;
	}

	hostdata->connected->SCp.phase = p;

	if (p & SR_IO) {
		if (hostdata->read_overruns)
			c -= hostdata->read_overruns;
		else if (hostdata->flags & FLAG_DMA_FIXUP)
			--c;
	}
#endif
	dprintk(NDEBUG_DMA, ("scsi%d : initializing DMA channel %d for %s, %d bytes %s %0x\n", instance->host_no, instance->dma_channel, (p & SR_IO) ? "reading" : "writing", c, (p & SR_IO) ? "to" : "from", (unsigned) d));
	dprintk(NDEBUG_DMA, "scsi%d : initializing DMA channel %d for %s, %d bytes %s %0x\n", instance->host_no, instance->dma_channel, (p & SR_IO) ? "reading" : "writing", c, (p & SR_IO) ? "to" : "from", (unsigned) d);
	hostdata->dma_len = (p & SR_IO) ? NCR5380_dma_read_setup(instance, d, c) : NCR5380_dma_write_setup(instance, d, c);

	dsprintk(NDEBUG_DMA, instance, "initializing DMA %s: length %d, address %p\n",
	         (p & SR_IO) ? "receive" : "send", c, d);

#ifdef CONFIG_SUN3
	/* send start chain */
	sun3scsi_dma_start(c, *data);
#endif

	NCR5380_write(TARGET_COMMAND_REG, PHASE_SR_TO_TCR(p));
	NCR5380_write(MODE_REG, MR_BASE | MR_DMA_MODE | MR_MONITOR_BSY |
	                        MR_ENABLE_EOP_INTR);

	if (!(hostdata->flags & FLAG_LATE_DMA_SETUP)) {
		/* On the Medusa, it is a must to initialize the DMA before
		 * starting the NCR. This is also the cleaner way for the TT.
		 */
		if (p & SR_IO)
			result = NCR5380_dma_recv_setup(hostdata, d, c);
		else
			result = NCR5380_dma_send_setup(hostdata, d, c);
	}

	/*
	 * Note : on my sample board, watch-dog timeouts occurred when interrupts
	 * were not disabled for the duration of a single DMA transfer, from 
	 * before the setting of DMA mode to after transfer of the last byte.
	 */

#if defined(PSEUDO_DMA) && defined(UNSAFE)
	spin_unlock_irq(instance->host_lock);
#endif
	/* KLL May need eop and parity in 53c400 */
	if (hostdata->flags & FLAG_NCR53C400)
		NCR5380_write(MODE_REG, MR_BASE | MR_DMA_MODE | MR_ENABLE_PAR_CHECK | MR_ENABLE_PAR_INTR | MR_ENABLE_EOP_INTR | MR_DMA_MODE | MR_MONITOR_BSY);
		NCR5380_write(MODE_REG, MR_BASE | MR_DMA_MODE |
				MR_ENABLE_PAR_CHECK | MR_ENABLE_PAR_INTR |
				MR_ENABLE_EOP_INTR | MR_MONITOR_BSY);
	else
		NCR5380_write(MODE_REG, MR_BASE | MR_DMA_MODE);
#endif				/* def REAL_DMA */

	dprintk(NDEBUG_DMA, ("scsi%d : mode reg = 0x%X\n", instance->host_no, NCR5380_read(MODE_REG)));
	dprintk(NDEBUG_DMA, "scsi%d : mode reg = 0x%X\n", instance->host_no, NCR5380_read(MODE_REG));

	/* 
	 *	On the PAS16 at least I/O recovery delays are not needed here.
	 *	Everyone else seems to want them.
	 * On the PAS16 at least I/O recovery delays are not needed here.
	 * Everyone else seems to want them.
	 */

	if (p & SR_IO) {
		NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
		NCR5380_io_delay(1);
		NCR5380_write(START_DMA_INITIATOR_RECEIVE_REG, 0);
	} else {
		NCR5380_io_delay(1);
		NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_DATA);
		NCR5380_io_delay(1);
		NCR5380_write(START_DMA_SEND_REG, 0);
		NCR5380_io_delay(1);
	}

#ifdef CONFIG_SUN3
#ifdef SUN3_SCSI_VME
	dregs->csr |= CSR_DMA_ENABLE;
#endif
	sun3_dma_active = 1;
#endif

	if (hostdata->flags & FLAG_LATE_DMA_SETUP) {
		/* On the Falcon, the DMA setup must be done after the last
		 * NCR access, else the DMA setup gets trashed!
		 */
		if (p & SR_IO)
			result = NCR5380_dma_recv_setup(hostdata, d, c);
		else
			result = NCR5380_dma_send_setup(hostdata, d, c);
	}

	/* On failure, NCR5380_dma_xxxx_setup() returns a negative int. */
	if (result < 0)
		return result;

	/* For real DMA, result is the byte count. DMA interrupt is expected. */
	if (result > 0) {
		hostdata->dma_len = result;
		return 0;
	}

	/* The result is zero iff pseudo DMA send/receive was completed. */
	hostdata->dma_len = c;

/*
 * A note regarding the DMA errata workarounds for early NMOS silicon.
 *
 * For DMA sends, we want to wait until the last byte has been
 * transferred out over the bus before we turn off DMA mode.  Alas, there
 * seems to be no terribly good way of doing this on a 5380 under all
 * conditions.  For non-scatter-gather operations, we can wait until REQ
 * and ACK both go false, or until a phase mismatch occurs.  Gather-sends
 * are nastier, since the device will be expecting more data than we
 * are prepared to send it, and REQ will remain asserted.  On a 53C8[01] we
 * could test Last Byte Sent to assure transfer (I imagine this is precisely
 * why this signal was added to the newer chips) but on the older 538[01]
 * this signal does not exist.  The workaround for this lack is a watchdog;
 * we bail out of the wait-loop after a modest amount of wait-time if
 * the usual exit conditions are not met.  Not a terribly clean or
 * correct solution :-%
 *
 * DMA receive is equally tricky due to a nasty characteristic of the NCR5380.
 * If the chip is in DMA receive mode, it will respond to a target's
 * REQ by latching the SCSI data into the INPUT DATA register and asserting
 * ACK, even if it has _already_ been notified by the DMA controller that
 * the current DMA transfer has completed!  If the NCR5380 is then taken
 * out of DMA mode, this already-acknowledged byte is lost. This is
 * not a problem for "one DMA transfer per READ command", because
 * the situation will never arise... either all of the data is DMA'ed
 * properly, or the target switches to MESSAGE IN phase to signal a
 * disconnection (either operation bringing the DMA to a clean halt).
 * However, in order to handle scatter-receive, we must work around the
 * problem.  The chosen fix is to DMA fewer bytes, then check for the
 * condition before taking the NCR5380 out of DMA mode.  One or two extra
 * bytes are transferred via PIO as necessary to fill out the original
 * request.
 */

	if (p & SR_IO) {
#ifdef READ_OVERRUNS
		udelay(10);
		if (((NCR5380_read(BUS_AND_STATUS_REG) & (BASR_PHASE_MATCH | BASR_ACK)) == (BASR_PHASE_MATCH | BASR_ACK))) {
			saved_data = NCR5380_read(INPUT_DATA_REGISTER);
			overrun = 1;
		}
#endif
	} else {
		int limit = 100;
		while (((tmp = NCR5380_read(BUS_AND_STATUS_REG)) & BASR_ACK) || (NCR5380_read(STATUS_REG) & SR_REQ)) {
			if (!(tmp & BASR_PHASE_MATCH))
				break;
			if (--limit < 0)
				break;
		}
	}

	dprintk(NDEBUG_DMA, ("scsi%d : polled DMA transfer complete, basr 0x%X, sr 0x%X\n", instance->host_no, tmp, NCR5380_read(STATUS_REG)));
	dprintk(NDEBUG_DMA, "scsi%d : polled DMA transfer complete, basr 0x%X, sr 0x%X\n", instance->host_no, tmp, NCR5380_read(STATUS_REG));

	NCR5380_write(MODE_REG, MR_BASE);
	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);

	residue = NCR5380_dma_residual(instance);
	c -= residue;
	*count -= c;
	*data += c;
	*phase = NCR5380_read(STATUS_REG) & PHASE_MASK;

#ifdef READ_OVERRUNS
	if (*phase == p && (p & SR_IO) && residue == 0) {
		if (overrun) {
			dprintk(NDEBUG_DMA, ("Got an input overrun, using saved byte\n"));
			dprintk(NDEBUG_DMA, "Got an input overrun, using saved byte\n");
			**data = saved_data;
			*data += 1;
			*count -= 1;
			cnt = toPIO = 1;
		} else {
			printk("No overrun??\n");
			cnt = toPIO = 2;
		}
		dprintk(NDEBUG_DMA, ("Doing %d-byte PIO to 0x%X\n", cnt, *data));
		dprintk(NDEBUG_DMA, "Doing %d-byte PIO to 0x%X\n", cnt, *data);
		NCR5380_transfer_pio(instance, phase, &cnt, data);
		*count -= toPIO - cnt;
	}
#endif

	dprintk(NDEBUG_DMA, ("Return with data ptr = 0x%X, count %d, last 0x%X, next 0x%X\n", *data, *count, *(*data + *count - 1), *(*data + *count)));
	dprintk(NDEBUG_DMA, "Return with data ptr = 0x%X, count %d, last 0x%X, next 0x%X\n", *data, *count, *(*data + *count - 1), *(*data + *count));
	return 0;

#elif defined(REAL_DMA)
	return 0;
#else				/* defined(REAL_DMA_POLL) */
	if (p & SR_IO) {
#ifdef DMA_WORKS_RIGHT
		foo = NCR5380_pread(instance, d, c);
#else
		int diff = 1;
		if (hostdata->flags & FLAG_NCR53C400) {
			diff = 0;
		}
		if (!(foo = NCR5380_pread(instance, d, c - diff))) {
	if (hostdata->flags & FLAG_DMA_FIXUP) {
		if (p & SR_IO) {
			/*
			 * The workaround was to transfer fewer bytes than we
			 * intended to with the pseudo-DMA read function, wait for
			 * the chip to latch the last byte, read it, and then disable
			 * pseudo-DMA mode.
			 *
			 * After REQ is asserted, the NCR5380 asserts DRQ and ACK.
			 * REQ is deasserted when ACK is asserted, and not reasserted
			 * until ACK goes false.  Since the NCR5380 won't lower ACK
			 * until DACK is asserted, which won't happen unless we twiddle
			 * the DMA port or we take the NCR5380 out of DMA mode, we
			 * can guarantee that we won't handshake another extra
			 * byte.
			 */

			if (NCR5380_poll_politely(hostdata, BUS_AND_STATUS_REG,
			                          BASR_DRQ, BASR_DRQ, HZ) < 0) {
				result = -1;
				shost_printk(KERN_ERR, instance, "PDMA read: DRQ timeout\n");
			}
		}
#endif
	} else {
#ifdef DMA_WORKS_RIGHT
		foo = NCR5380_pwrite(instance, d, c);
#else
		int timeout;
		dprintk(NDEBUG_C400_PWRITE, ("About to pwrite %d bytes\n", c));
		dprintk(NDEBUG_C400_PWRITE, "About to pwrite %d bytes\n", c);
		if (!(foo = NCR5380_pwrite(instance, d, c))) {
			/*
			 * Wait for the last byte to be sent.  If REQ is being asserted for 
			 * the byte we're interested, we'll ACK it and it will go false.  
			 */
			if (!(hostdata->flags & FLAG_HAS_LAST_BYTE_SENT)) {
				timeout = 20000;
				while (!(NCR5380_read(BUS_AND_STATUS_REG) & BASR_DRQ) && (NCR5380_read(BUS_AND_STATUS_REG) & BASR_PHASE_MATCH));

				if (!timeout)
					dprintk(NDEBUG_LAST_BYTE_SENT, ("scsi%d : timed out on last byte\n", instance->host_no));
					dprintk(NDEBUG_LAST_BYTE_SENT, "scsi%d : timed out on last byte\n", instance->host_no);

				if (hostdata->flags & FLAG_CHECK_LAST_BYTE_SENT) {
					hostdata->flags &= ~FLAG_CHECK_LAST_BYTE_SENT;
					if (NCR5380_read(TARGET_COMMAND_REG) & TCR_LAST_BYTE_SENT) {
						hostdata->flags |= FLAG_HAS_LAST_BYTE_SENT;
						dprintk(NDEBUG_LAST_WRITE_SENT, ("scsi%d : last bit sent works\n", instance->host_no));
					}
				}
			} else {
				dprintk(NDEBUG_C400_PWRITE, ("Waiting for LASTBYTE\n"));
				while (!(NCR5380_read(TARGET_COMMAND_REG) & TCR_LAST_BYTE_SENT));
				dprintk(NDEBUG_C400_PWRITE, ("Got LASTBYTE\n"));
						dprintk(NDEBUG_LAST_BYTE_SENT, "scsi%d : last byte sent works\n", instance->host_no);
					}
				}
			} else {
				dprintk(NDEBUG_C400_PWRITE, "Waiting for LASTBYTE\n");
				while (!(NCR5380_read(TARGET_COMMAND_REG) & TCR_LAST_BYTE_SENT));
				dprintk(NDEBUG_C400_PWRITE, "Got LASTBYTE\n");
			}
		}
#endif
	}
	NCR5380_write(MODE_REG, MR_BASE);
	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);

	if ((!(p & SR_IO)) && (hostdata->flags & FLAG_NCR53C400)) {
		dprintk(NDEBUG_C400_PWRITE, ("53C400w: Checking for IRQ\n"));
		if (NCR5380_read(BUS_AND_STATUS_REG) & BASR_IRQ) {
			dprintk(NDEBUG_C400_PWRITE, ("53C400w:    got it, reading reset interrupt reg\n"));
		dprintk(NDEBUG_C400_PWRITE, "53C400w: Checking for IRQ\n");
		if (NCR5380_read(BUS_AND_STATUS_REG) & BASR_IRQ) {
			dprintk(NDEBUG_C400_PWRITE, "53C400w:    got it, reading reset interrupt reg\n");
			NCR5380_read(RESET_PARITY_INTERRUPT_REG);
			if (NCR5380_poll_politely(hostdata, STATUS_REG,
			                          SR_REQ, 0, HZ) < 0) {
				result = -1;
				shost_printk(KERN_ERR, instance, "PDMA read: !REQ timeout\n");
			}
			d[*count - 1] = NCR5380_read(INPUT_DATA_REG);
		} else {
			/*
			 * Wait for the last byte to be sent.  If REQ is being asserted for
			 * the byte we're interested, we'll ACK it and it will go false.
			 */
			if (NCR5380_poll_politely2(hostdata,
			     BUS_AND_STATUS_REG, BASR_DRQ, BASR_DRQ,
			     BUS_AND_STATUS_REG, BASR_PHASE_MATCH, 0, HZ) < 0) {
				result = -1;
				shost_printk(KERN_ERR, instance, "PDMA write: DRQ and phase timeout\n");
			}
		}
	}

	NCR5380_dma_complete(instance);
	return result;
}

/*
 * Function : NCR5380_information_transfer (struct Scsi_Host *instance)
 *
 * Purpose : run through the various SCSI phases and do as the target
 * directs us to.  Operates on the currently connected command,
 * instance->connected.
 *
 * Inputs : instance, instance for which we are doing commands
 *
 * Side effects : SCSI things happen, the disconnected queue will be
 * modified if a command disconnects, *instance->connected will
 * change.
 *
 * XXX Note : we need to watch for bus free or a reset condition here
 * to recover from an unexpected bus free condition.
 */

static void NCR5380_information_transfer(struct Scsi_Host *instance)
	__releases(&hostdata->lock) __acquires(&hostdata->lock)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	unsigned char msgout = NOP;
	int sink = 0;
	int len;
	int transfersize;
	unsigned char *data;
	unsigned char phase, tmp, extended_msg[10], old_phase = 0xff;
	Scsi_Cmnd *cmd = (Scsi_Cmnd *) hostdata->connected;
	struct scsi_cmnd *cmd = (struct scsi_cmnd *) hostdata->connected;
	/* RvC: we need to set the end of the polling time */
	unsigned long poll_time = jiffies + USLEEP_POLL;
	struct scsi_cmnd *cmd;

#ifdef SUN3_SCSI_VME
	dregs->csr |= CSR_INTR;
#endif

	while ((cmd = hostdata->connected)) {
		struct NCR5380_cmd *ncmd = scsi_cmd_priv(cmd);

		tmp = NCR5380_read(STATUS_REG);
		/* We only have a valid SCSI phase when REQ is asserted */
		if (tmp & SR_REQ) {
			phase = (tmp & PHASE_MASK);
			if (phase != old_phase) {
				old_phase = phase;
				NCR5380_dprint_phase(NDEBUG_INFORMATION, instance);
			}
#ifdef CONFIG_SUN3
			if (phase == PHASE_CMDOUT &&
			    sun3_dma_setup_done != cmd) {
				int count;

				if (!cmd->SCp.this_residual && cmd->SCp.buffers_residual) {
					++cmd->SCp.buffer;
					--cmd->SCp.buffers_residual;
					cmd->SCp.this_residual = cmd->SCp.buffer->length;
					cmd->SCp.ptr = sg_virt(cmd->SCp.buffer);
				}

				count = sun3scsi_dma_xfer_len(hostdata, cmd);

				if (count > 0) {
					if (rq_data_dir(cmd->request))
						sun3scsi_dma_send_setup(hostdata,
						                        cmd->SCp.ptr, count);
					else
						sun3scsi_dma_recv_setup(hostdata,
						                        cmd->SCp.ptr, count);
					sun3_dma_setup_done = cmd;
				}
#ifdef SUN3_SCSI_VME
				dregs->csr |= CSR_INTR;
#endif
			}
#endif /* CONFIG_SUN3 */

			if (sink && (phase != PHASE_MSGOUT)) {
				NCR5380_write(TARGET_COMMAND_REG, PHASE_SR_TO_TCR(tmp));

				NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_ATN |
				              ICR_ASSERT_ACK);
				while (NCR5380_read(STATUS_REG) & SR_REQ)
					;
				NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE |
				              ICR_ASSERT_ATN);
				sink = 0;
				continue;
			}

			switch (phase) {
			case PHASE_DATAOUT:
#if (NDEBUG & NDEBUG_NO_DATAOUT)
				shost_printk(KERN_DEBUG, instance, "NDEBUG_NO_DATAOUT set, attempted DATAOUT aborted\n");
				sink = 1;
				do_abort(instance);
				cmd->result = DID_ERROR << 16;
				complete_cmd(instance, cmd);
				hostdata->connected = NULL;
				return;
#endif
			case PHASE_DATAIN:
				/*
				 * If there is no room left in the current buffer in the
				 * scatter-gather list, move onto the next one.
				 */

				if (!cmd->SCp.this_residual && cmd->SCp.buffers_residual) {
					++cmd->SCp.buffer;
					--cmd->SCp.buffers_residual;
					cmd->SCp.this_residual = cmd->SCp.buffer->length;
					cmd->SCp.ptr = sg_virt(cmd->SCp.buffer);
					dprintk(NDEBUG_INFORMATION, ("scsi%d : %d bytes and %d buffers left\n", instance->host_no, cmd->SCp.this_residual, cmd->SCp.buffers_residual));
					dprintk(NDEBUG_INFORMATION, "scsi%d : %d bytes and %d buffers left\n", instance->host_no, cmd->SCp.this_residual, cmd->SCp.buffers_residual);
					dsprintk(NDEBUG_INFORMATION, instance, "%d bytes and %d buffers left\n",
					         cmd->SCp.this_residual,
					         cmd->SCp.buffers_residual);
				}

				/*
				 * The preferred transfer method is going to be
				 * PSEUDO-DMA for systems that are strictly PIO,
				 * since we can let the hardware do the handshaking.
				 *
				 * For this to work, we need to know the transfersize
				 * ahead of time, since the pseudo-DMA code will sit
				 * in an unconditional loop.
				 */

				transfersize = 0;
				if (!cmd->device->borken)
					transfersize = NCR5380_dma_xfer_len(hostdata, cmd);

				if (transfersize > 0) {
					len = transfersize;
					if (NCR5380_transfer_dma(instance, &phase,
					    &len, (unsigned char **)&cmd->SCp.ptr)) {
						/*
						 * If the watchdog timer fires, all future
						 * accesses to this device will use the
						 * polled-IO.
						 */
						scmd_printk(KERN_INFO, cmd,
							"switching to slow handshake\n");
						cmd->device->borken = 1;
						sink = 1;
						do_abort(instance);
						cmd->result = DID_ERROR << 16;
						/* XXX - need to source or sink data here, as appropriate */
					}
				} else {
					/* Transfer a small chunk so that the
					 * irq mode lock is not held too long.
					 */
					transfersize = min(cmd->SCp.this_residual,
							   NCR5380_PIO_CHUNK_SIZE);
					len = transfersize;
					NCR5380_transfer_pio(instance, &phase, &len,
					                     (unsigned char **)&cmd->SCp.ptr);
					cmd->SCp.this_residual -= transfersize - len;
				}
#ifdef CONFIG_SUN3
				if (sun3_dma_setup_done == cmd)
					sun3_dma_setup_done = NULL;
#endif
				return;
			case PHASE_MSGIN:
				len = 1;
				data = &tmp;
				NCR5380_transfer_pio(instance, &phase, &len, &data);
				cmd->SCp.Message = tmp;

				switch (tmp) {
					/*
					 * Linking lets us reduce the time required to get the 
					 * next command out to the device, hopefully this will
					 * mean we don't waste another revolution due to the delays
					 * required by ARBITRATION and another SELECTION.
					 *
					 * In the current implementation proposal, low level drivers
					 * merely have to start the next command, pointed to by 
					 * next_link, done() is called as with unlinked commands.
					 */
#ifdef LINKED
				case LINKED_CMD_COMPLETE:
				case LINKED_FLG_CMD_COMPLETE:
					/* Accept message by clearing ACK */
					NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
					dprintk(NDEBUG_LINKED, ("scsi%d : target %d lun %d linked command complete.\n", instance->host_no, cmd->device->id, cmd->device->lun));
					dprintk(NDEBUG_LINKED, "scsi%d : target %d lun %llu linked command complete.\n", instance->host_no, cmd->device->id, cmd->device->lun);
					/* 
					 * Sanity check : A linked command should only terminate with
					 * one of these messages if there are more linked commands
					 * available.
					 */
					if (!cmd->next_link) {
						printk("scsi%d : target %d lun %d linked command complete, no next_link\n" instance->host_no, cmd->device->id, cmd->device->lun);
					    printk("scsi%d : target %d lun %llu linked command complete, no next_link\n" instance->host_no, cmd->device->id, cmd->device->lun);
						sink = 1;
						do_abort(instance);
						return;
					}
					initialize_SCp(cmd->next_link);
					/* The next command is still part of this process */
					cmd->next_link->tag = cmd->tag;
					cmd->result = cmd->SCp.Status | (cmd->SCp.Message << 8);
					dprintk(NDEBUG_LINKED, ("scsi%d : target %d lun %d linked request done, calling scsi_done().\n", instance->host_no, cmd->device->id, cmd->device->lun));
					collect_stats(hostdata, cmd);
					dprintk(NDEBUG_LINKED, "scsi%d : target %d lun %llu linked request done, calling scsi_done().\n", instance->host_no, cmd->device->id, cmd->device->lun);
					cmd->scsi_done(cmd);
					cmd = hostdata->connected;
					break;
#endif				/* def LINKED */
				case ABORT:
				case COMMAND_COMPLETE:
					/* Accept message by clearing ACK */
					sink = 1;
					NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
					dsprintk(NDEBUG_QUEUES, instance,
					         "COMMAND COMPLETE %p target %d lun %llu\n",
					         cmd, scmd_id(cmd), cmd->device->lun);

					hostdata->connected = NULL;
					dprintk(NDEBUG_QUEUES, ("scsi%d : command for target %d, lun %d completed\n", instance->host_no, cmd->device->id, cmd->device->lun));
					hostdata->busy[cmd->device->id] &= ~(1 << cmd->device->lun);
					dprintk(NDEBUG_QUEUES, "scsi%d : command for target %d, lun %llu completed\n", instance->host_no, cmd->device->id, cmd->device->lun);
					hostdata->busy[cmd->device->id] &= ~(1 << (cmd->device->lun & 0xFF));

					cmd->result &= ~0xffff;
					cmd->result |= cmd->SCp.Status;
					cmd->result |= cmd->SCp.Message << 8;

					if (cmd->cmnd[0] != REQUEST_SENSE)
						cmd->result = cmd->SCp.Status | (cmd->SCp.Message << 8);
					else if (status_byte(cmd->SCp.Status) != GOOD)
						cmd->result = (cmd->result & 0x00ffff) | (DID_ERROR << 16);

#ifdef AUTOSENSE
					if ((cmd->cmnd[0] == REQUEST_SENSE) &&
						hostdata->ses.cmd_len) {
						scsi_eh_restore_cmnd(cmd, &hostdata->ses);
						hostdata->ses.cmd_len = 0 ;
					}

					if ((cmd->cmnd[0] != REQUEST_SENSE) && (status_byte(cmd->SCp.Status) == CHECK_CONDITION)) {
						scsi_eh_prep_cmnd(cmd, &hostdata->ses, NULL, 0, ~0);

						dprintk(NDEBUG_AUTOSENSE, ("scsi%d : performing request sense\n", instance->host_no));
						dprintk(NDEBUG_AUTOSENSE, "scsi%d : performing request sense\n", instance->host_no);

						LIST(cmd, hostdata->issue_queue);
						cmd->host_scribble = (unsigned char *)
						    hostdata->issue_queue;
						hostdata->issue_queue = (Scsi_Cmnd *) cmd;
						dprintk(NDEBUG_QUEUES, ("scsi%d : REQUEST SENSE added to head of issue queue\n", instance->host_no));
					} else
#endif				/* def AUTOSENSE */
					{
						collect_stats(hostdata, cmd);
						hostdata->issue_queue = (struct scsi_cmnd *) cmd;
						dprintk(NDEBUG_QUEUES, "scsi%d : REQUEST SENSE added to head of issue queue\n", instance->host_no);
					} else {
						cmd->scsi_done(cmd);
					}

					NCR5380_write(SELECT_ENABLE_REG, hostdata->id_mask);
					/* 
					 * Restore phase bits to 0 so an interrupted selection, 
					if (cmd->cmnd[0] == REQUEST_SENSE)
						complete_cmd(instance, cmd);
					else {
						if (cmd->SCp.Status == SAM_STAT_CHECK_CONDITION ||
						    cmd->SCp.Status == SAM_STAT_COMMAND_TERMINATED) {
							dsprintk(NDEBUG_QUEUES, instance, "autosense: adding cmd %p to tail of autosense queue\n",
							         cmd);
							list_add_tail(&ncmd->list,
							              &hostdata->autosense);
						} else
							complete_cmd(instance, cmd);
					}

					/*
					 * Restore phase bits to 0 so an interrupted selection,
					 * arbitration can resume.
					 */
					NCR5380_write(TARGET_COMMAND_REG, 0);

					/* Enable reselect interrupts */
					NCR5380_write(SELECT_ENABLE_REG, hostdata->id_mask);

					maybe_release_dma_irq(instance);
					return;
				case MESSAGE_REJECT:
					/* Accept message by clearing ACK */
					NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
					switch (hostdata->last_message) {
					case HEAD_OF_QUEUE_TAG:
					case ORDERED_QUEUE_TAG:
					case SIMPLE_QUEUE_TAG:
						cmd->device->simple_tags = 0;
						hostdata->busy[cmd->device->id] |= (1 << cmd->device->lun);
						hostdata->busy[cmd->device->id] |= (1 << (cmd->device->lun & 0xFF));
						break;
					default:
						break;
					}
				case DISCONNECT:{
						/* Accept message by clearing ACK */
						NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
						cmd->device->disconnect = 1;
						LIST(cmd, hostdata->disconnected_queue);
						cmd->host_scribble = (unsigned char *)
						    hostdata->disconnected_queue;
						hostdata->connected = NULL;
						hostdata->disconnected_queue = cmd;
						dprintk(NDEBUG_QUEUES, ("scsi%d : command for target %d lun %d was moved from connected to" "  the disconnected_queue\n", instance->host_no, cmd->device->id, cmd->device->lun));
						dprintk(NDEBUG_QUEUES, "scsi%d : command for target %d lun %llu was moved from connected to" "  the disconnected_queue\n", instance->host_no, cmd->device->id, cmd->device->lun);
						/* 
						 * Restore phase bits to 0 so an interrupted selection, 
						 * arbitration can resume.
						 */
						NCR5380_write(TARGET_COMMAND_REG, 0);
					break;
				case DISCONNECT:
					/* Accept message by clearing ACK */
					NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
					hostdata->connected = NULL;
					list_add(&ncmd->list, &hostdata->disconnected);
					dsprintk(NDEBUG_INFORMATION | NDEBUG_QUEUES,
					         instance, "connected command %p for target %d lun %llu moved to disconnected queue\n",
					         cmd, scmd_id(cmd), cmd->device->lun);

					/*
					 * Restore phase bits to 0 so an interrupted selection,
					 * arbitration can resume.
					 */
					NCR5380_write(TARGET_COMMAND_REG, 0);

					/* Enable reselect interrupts */
					NCR5380_write(SELECT_ENABLE_REG, hostdata->id_mask);
#ifdef SUN3_SCSI_VME
					dregs->csr |= CSR_DMA_ENABLE;
#endif
					return;
					/*
					 * The SCSI data pointer is *IMPLICITLY* saved on a disconnect
					 * operation, in violation of the SCSI spec so we can safely
					 * ignore SAVE/RESTORE pointers calls.
					 *
					 * Unfortunately, some disks violate the SCSI spec and
					 * don't issue the required SAVE_POINTERS message before
					 * disconnecting, and we have to break spec to remain
					 * compatible.
					 */
				case SAVE_POINTERS:
				case RESTORE_POINTERS:
					/* Accept message by clearing ACK */
					NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
					break;
				case EXTENDED_MESSAGE:
					/*
					 * Start the message buffer with the EXTENDED_MESSAGE
					 * byte, since spi_print_msg() wants the whole thing.
					 */
					extended_msg[0] = EXTENDED_MESSAGE;
					/* Accept first byte by clearing ACK */
					NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
					dprintk(NDEBUG_EXTENDED, ("scsi%d : receiving extended message\n", instance->host_no));
					dprintk(NDEBUG_EXTENDED, "scsi%d : receiving extended message\n", instance->host_no);

					spin_unlock_irq(&hostdata->lock);

					dsprintk(NDEBUG_EXTENDED, instance, "receiving extended message\n");

					len = 2;
					data = extended_msg + 1;
					phase = PHASE_MSGIN;
					NCR5380_transfer_pio(instance, &phase, &len, &data);
					dsprintk(NDEBUG_EXTENDED, instance, "length %d, code 0x%02x\n",
					         (int)extended_msg[1],
					         (int)extended_msg[2]);

					dprintk(NDEBUG_EXTENDED, ("scsi%d : length=%d, code=0x%02x\n", instance->host_no, (int) extended_msg[1], (int) extended_msg[2]));
					dprintk(NDEBUG_EXTENDED, "scsi%d : length=%d, code=0x%02x\n", instance->host_no, (int) extended_msg[1], (int) extended_msg[2]);

					if (!len && extended_msg[1] <= (sizeof(extended_msg) - 1)) {
					if (!len && extended_msg[1] > 0 &&
					    extended_msg[1] <= sizeof(extended_msg) - 2) {
						/* Accept third byte by clearing ACK */
						NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
						len = extended_msg[1] - 1;
						data = extended_msg + 3;
						phase = PHASE_MSGIN;

						NCR5380_transfer_pio(instance, &phase, &len, &data);
						dprintk(NDEBUG_EXTENDED, ("scsi%d : message received, residual %d\n", instance->host_no, len));
						dprintk(NDEBUG_EXTENDED, "scsi%d : message received, residual %d\n", instance->host_no, len);
						dsprintk(NDEBUG_EXTENDED, instance, "message received, residual %d\n",
						         len);

						switch (extended_msg[2]) {
						case EXTENDED_SDTR:
						case EXTENDED_WDTR:
							tmp = 0;
						}
					} else if (len) {
						shost_printk(KERN_ERR, instance, "error receiving extended message\n");
						tmp = 0;
					} else {
						shost_printk(KERN_NOTICE, instance, "extended message code %02x length %d is too long\n",
						             extended_msg[2], extended_msg[1]);
						tmp = 0;
					}

					spin_lock_irq(&hostdata->lock);
					if (!hostdata->connected)
						return;

					/* Fall through to reject message */

					/*
					 * If we get something weird that we aren't expecting,
					 * reject it.
					 */
				default:
					if (tmp == EXTENDED_MESSAGE)
						scmd_printk(KERN_INFO, cmd,
						            "rejecting unknown extended message code %02x, length %d\n",
						            extended_msg[2], extended_msg[1]);
					else if (tmp)
						scmd_printk(KERN_INFO, cmd,
						            "rejecting unknown message code %02x\n",
						            tmp);

					msgout = MESSAGE_REJECT;
					NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_ATN);
					break;
				} /* switch (tmp) */
				break;
			case PHASE_MSGOUT:
				len = 1;
				data = &msgout;
				hostdata->last_message = msgout;
				NCR5380_transfer_pio(instance, &phase, &len, &data);
				if (msgout == ABORT) {
					hostdata->busy[cmd->device->id] &= ~(1 << cmd->device->lun);
					hostdata->connected = NULL;
					cmd->result = DID_ERROR << 16;
					collect_stats(hostdata, cmd);
					hostdata->busy[cmd->device->id] &= ~(1 << (cmd->device->lun & 0xFF));
					hostdata->connected = NULL;
					cmd->result = DID_ERROR << 16;
					complete_cmd(instance, cmd);
					maybe_release_dma_irq(instance);
					NCR5380_write(SELECT_ENABLE_REG, hostdata->id_mask);
					return;
				}
				msgout = NOP;
				break;
			case PHASE_CMDOUT:
				len = cmd->cmd_len;
				data = cmd->cmnd;
				/*
				 * XXX for performance reasons, on machines with a
				 * PSEUDO-DMA architecture we should probably
				 * use the dma transfer function.
				 */
				NCR5380_transfer_pio(instance, &phase, &len, &data);
				if (!cmd->device->disconnect && should_disconnect(cmd->cmnd[0])) {
					NCR5380_set_timer(hostdata, USLEEP_SLEEP);
					dprintk(NDEBUG_USLEEP, ("scsi%d : issued command, sleeping until %ul\n", instance->host_no, hostdata->time_expires));
					dprintk(NDEBUG_USLEEP, "scsi%d : issued command, sleeping until %lu\n", instance->host_no, hostdata->time_expires);
					return;
				}
				break;
			case PHASE_STATIN:
				len = 1;
				data = &tmp;
				NCR5380_transfer_pio(instance, &phase, &len, &data);
				cmd->SCp.Status = tmp;
				break;
			default:
				printk("scsi%d : unknown phase\n", instance->host_no);
				NCR5380_dprint(NDEBUG_ALL, instance);
				NCR5380_dprint(NDEBUG_ANY, instance);
			}	/* switch(phase) */
		}		/* if (tmp * SR_REQ) */
		else {
			/* RvC: go to sleep if polling time expired
			 */
			if (!cmd->device->disconnect && time_after_eq(jiffies, poll_time)) {
				NCR5380_set_timer(hostdata, USLEEP_SLEEP);
				dprintk(NDEBUG_USLEEP, ("scsi%d : poll timed out, sleeping until %ul\n", instance->host_no, hostdata->time_expires));
				dprintk(NDEBUG_USLEEP, "scsi%d : poll timed out, sleeping until %lu\n", instance->host_no, hostdata->time_expires);
				return;
			}
				shost_printk(KERN_ERR, instance, "unknown phase\n");
				NCR5380_dprint(NDEBUG_ANY, instance);
			} /* switch(phase) */
		} else {
			spin_unlock_irq(&hostdata->lock);
			NCR5380_poll_politely(hostdata, STATUS_REG, SR_REQ, SR_REQ, HZ);
			spin_lock_irq(&hostdata->lock);
		}
	}
}

/*
 * Function : void NCR5380_reselect (struct Scsi_Host *instance)
 *
 * Purpose : does reselection, initializing the instance->connected 
 *      field to point to the Scsi_Cmnd for which the I_T_L or I_T_L_Q 
 *      field to point to the scsi_cmnd for which the I_T_L or I_T_L_Q
 *      nexus has been reestablished,
 *      
 * Inputs : instance - this instance of the NCR5380.
 * Purpose : does reselection, initializing the instance->connected
 * field to point to the scsi_cmnd for which the I_T_L or I_T_L_Q
 * nexus has been reestablished,
 *
 * Inputs : instance - this instance of the NCR5380.
 */

static void NCR5380_reselect(struct Scsi_Host *instance)
{
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	unsigned char target_mask;
	unsigned char lun;
	unsigned char msg[3];
	unsigned char *data;
	Scsi_Cmnd *tmp = NULL, *prev;
	struct scsi_cmnd *tmp = NULL, *prev;
	int abort = 0;
	NCR5380_setup(instance);
	struct NCR5380_cmd *ncmd;
	struct scsi_cmnd *tmp;

	/*
	 * Disable arbitration, etc. since the host adapter obviously
	 * lost, and tell an interrupted NCR5380_select() to restart.
	 */

	NCR5380_write(MODE_REG, MR_BASE);

	target_mask = NCR5380_read(CURRENT_SCSI_DATA_REG) & ~(hostdata->id_mask);
	dprintk(NDEBUG_SELECTION, ("scsi%d : reselect\n", instance->host_no));
	dprintk(NDEBUG_SELECTION, "scsi%d : reselect\n", instance->host_no);

	dsprintk(NDEBUG_RESELECTION, instance, "reselect\n");

	/*
	 * At this point, we have detected that our SCSI ID is on the bus,
	 * SEL is true and BSY was false for at least one bus settle delay
	 * (400 ns).
	 *
	 * We must assert BSY ourselves, until the target drops the SEL
	 * signal.
	 */

	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_BSY);
	if (NCR5380_poll_politely(hostdata,
	                          STATUS_REG, SR_SEL, 0, 2 * HZ) < 0) {
		NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);
		return;
	}
	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);

	/*
	 * Wait for target to go into MSGIN.
	 */

	if (NCR5380_poll_politely(hostdata,
	                          STATUS_REG, SR_REQ, SR_REQ, 2 * HZ) < 0) {
		do_abort(instance);
		return;
	}

#ifdef CONFIG_SUN3
	/* acknowledge toggle to MSGIN */
	NCR5380_write(TARGET_COMMAND_REG, PHASE_SR_TO_TCR(PHASE_MSGIN));

	/* peek at the byte without really hitting the bus */
	msg[0] = NCR5380_read(CURRENT_SCSI_DATA_REG);
#else
	{
		int len = 1;
		unsigned char *data = msg;
		unsigned char phase = PHASE_MSGIN;

		NCR5380_transfer_pio(instance, &phase, &len, &data);

		if (len) {
			do_abort(instance);
			return;
		}
	}
#endif /* CONFIG_SUN3 */

	if (!(msg[0] & 0x80)) {
		shost_printk(KERN_ERR, instance, "expecting IDENTIFY message, got ");
		spi_print_msg(msg);
		printk("\n");
		do_abort(instance);
		return;
	}
	lun = msg[0] & 0x07;

	/*
	 * We need to add code for SCSI-II to track which devices have
	 * I_T_L_Q nexuses established, and which have simple I_T_L
	 * nexuses so we can chose to do additional data transfer.
	 */

	/*
	 * Find the command corresponding to the I_T_L or I_T_L_Q  nexus we
	 * just reestablished, and remove it from the disconnected queue.
	 */

	tmp = NULL;
	list_for_each_entry(ncmd, &hostdata->disconnected, list) {
		struct scsi_cmnd *cmd = NCR5380_to_scmd(ncmd);

		for (tmp = (Scsi_Cmnd *) hostdata->disconnected_queue, prev = NULL; tmp; prev = tmp, tmp = (Scsi_Cmnd *) tmp->host_scribble)
			if ((target_mask == (1 << tmp->device->id)) && (lun == tmp->device->lun)
		for (tmp = (struct scsi_cmnd *) hostdata->disconnected_queue, prev = NULL; tmp; prev = tmp, tmp = (struct scsi_cmnd *) tmp->host_scribble)
			if ((target_mask == (1 << tmp->device->id)) && (lun == (u8)tmp->device->lun)
			    ) {
				if (prev) {
					REMOVE(prev, prev->host_scribble, tmp, tmp->host_scribble);
					prev->host_scribble = tmp->host_scribble;
				} else {
					REMOVE(-1, hostdata->disconnected_queue, tmp, tmp->host_scribble);
					hostdata->disconnected_queue = (Scsi_Cmnd *) tmp->host_scribble;
					hostdata->disconnected_queue = (struct scsi_cmnd *) tmp->host_scribble;
				}
				tmp->host_scribble = NULL;
				break;
			}
		if (!tmp) {
			printk(KERN_ERR "scsi%d : warning : target bitmask %02x lun %d not in disconnect_queue.\n", instance->host_no, target_mask, lun);
			/* 
			 * Since we have an established nexus that we can't do anything with,
			 * we must abort it.  
			 */
			abort = 1;
		if (target_mask == (1 << scmd_id(cmd)) &&
		    lun == (u8)cmd->device->lun) {
			list_del(&ncmd->list);
			tmp = cmd;
			break;
		}
	}

	if (tmp) {
		dsprintk(NDEBUG_RESELECTION | NDEBUG_QUEUES, instance,
		         "reselect: removed %p from disconnected queue\n", tmp);
	} else {
		hostdata->connected = tmp;
		dprintk(NDEBUG_RESELECTION, ("scsi%d : nexus established, target = %d, lun = %d, tag = %d\n", instance->host_no, tmp->target, tmp->lun, tmp->tag));
		dprintk(NDEBUG_RESELECTION, "scsi%d : nexus established, target = %d, lun = %llu, tag = %d\n", instance->host_no, tmp->device->id, tmp->device->lun, tmp->tag);
		shost_printk(KERN_ERR, instance, "target bitmask 0x%02x lun %d not in disconnected queue.\n",
		             target_mask, lun);
		/*
		 * Since we have an established nexus that we can't do anything
		 * with, we must abort it.
		 */
		do_abort(instance);
		return;
	}

/*
 * Function : void NCR5380_dma_complete (struct Scsi_Host *instance)
 *
 * Purpose : called by interrupt handler when DMA finishes or a phase
 *      mismatch occurs (which would finish the DMA transfer).  
 *
 * Inputs : instance - this instance of the NCR5380.
 *
 * Returns : pointer to the Scsi_Cmnd structure for which the I_T_L
 * Returns : pointer to the scsi_cmnd structure for which the I_T_L
 *      nexus has been reestablished, on failure NULL is returned.
 */
#ifdef CONFIG_SUN3
	if (sun3_dma_setup_done != tmp) {
		int count;

		if (!tmp->SCp.this_residual && tmp->SCp.buffers_residual) {
			++tmp->SCp.buffer;
			--tmp->SCp.buffers_residual;
			tmp->SCp.this_residual = tmp->SCp.buffer->length;
			tmp->SCp.ptr = sg_virt(tmp->SCp.buffer);
		}

		count = sun3scsi_dma_xfer_len(hostdata, tmp);

		if (count > 0) {
			if (rq_data_dir(tmp->request))
				sun3scsi_dma_send_setup(hostdata,
				                        tmp->SCp.ptr, count);
			else
				sun3scsi_dma_recv_setup(hostdata,
				                        tmp->SCp.ptr, count);
			sun3_dma_setup_done = tmp;
		}
	}

	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE | ICR_ASSERT_ACK);
#endif /* CONFIG_SUN3 */

	/* Accept message by clearing ACK */
	NCR5380_write(INITIATOR_COMMAND_REG, ICR_BASE);

	hostdata->connected = tmp;
	dsprintk(NDEBUG_RESELECTION, instance, "nexus established, target %d, lun %llu\n",
	         scmd_id(tmp), tmp->device->lun);
}

/*
 * Function : int NCR5380_abort (Scsi_Cmnd *cmd)
 *
 * Purpose : abort a command
 *
 * Inputs : cmd - the Scsi_Cmnd to abort, code - code to set the 
 *      host byte of the result field to, if zero DID_ABORTED is 
 *      used.
 *
 * Returns : 0 - success, -1 on failure.
 *
 *	XXX - there is no way to abort the command that is currently 
 *	connected, you have to wait for it to complete.  If this is 
 * Function : int NCR5380_abort (struct scsi_cmnd *cmd)
/**
 * list_find_cmd - test for presence of a command in a linked list
 * @haystack: list of commands
 * @needle: command to search for
 */

static bool list_find_cmd(struct list_head *haystack,
                          struct scsi_cmnd *needle)
{
	struct NCR5380_cmd *ncmd;

	list_for_each_entry(ncmd, haystack, list)
		if (NCR5380_to_scmd(ncmd) == needle)
			return true;
	return false;
}

/**
 * list_remove_cmd - remove a command from linked list
 * @haystack: list of commands
 * @needle: command to remove
 */

static bool list_del_cmd(struct list_head *haystack,
                         struct scsi_cmnd *needle)
{
	if (list_find_cmd(haystack, needle)) {
		struct NCR5380_cmd *ncmd = scsi_cmd_priv(needle);

		list_del(&ncmd->list);
		return true;
	}
	return false;
}

/**
 * NCR5380_abort - scsi host eh_abort_handler() method
 * @cmd: the command to be aborted
 *
 * Try to abort a given command by removing it from queues and/or sending
 * the target an abort message. This may not succeed in causing a target
 * to abort the command. Nonetheless, the low-level driver must forget about
 * the command because the mid-layer reclaims it and it may be re-issued.
 *
 * The normal path taken by a command is as follows. For EH we trace this
 * same path to locate and abort the command.
 *
 * unissued -> selecting -> [unissued -> selecting ->]... connected ->
 * [disconnected -> connected ->]...
 * [autosense -> connected ->] done
 *
 * If cmd was not found at all then presumably it has already been completed,
 * in which case return SUCCESS to try to avoid further EH measures.
 *
 * If the command has not completed yet, we must not fail to find it.
 * We have no option but to forget the aborted command (even if it still
 * lacks sense data). The mid-layer may re-issue a command that is in error
 * recovery (see scsi_send_eh_cmnd), but the logic and data structures in
 * this driver are such that a command can appear on one queue only.
 *
 * The lock protects driver data structures, but EH handlers also use it
 * to serialize their own execution and prevent their own re-entry.
 */

static int NCR5380_abort(Scsi_Cmnd * cmd) {
	NCR5380_local_declare();
	struct Scsi_Host *instance = cmd->device->host;
	struct NCR5380_hostdata *hostdata = (struct NCR5380_hostdata *) instance->hostdata;
	Scsi_Cmnd *tmp, **prev;
	
	printk(KERN_WARNING "scsi%d : aborting command\n", instance->host_no);
	scsi_print_command(cmd);
static int NCR5380_abort(struct scsi_cmnd *cmd)
{
	struct Scsi_Host *instance = cmd->device->host;
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	unsigned long flags;
	int result = SUCCESS;

	spin_lock_irqsave(&hostdata->lock, flags);

#if (NDEBUG & NDEBUG_ANY)
	scmd_printk(KERN_INFO, cmd, __func__);
#endif
	NCR5380_dprint(NDEBUG_ANY, instance);
	NCR5380_dprint_phase(NDEBUG_ANY, instance);

	if (list_del_cmd(&hostdata->unissued, cmd)) {
		dsprintk(NDEBUG_ABORT, instance,
		         "abort: removed %p from issue queue\n", cmd);
		cmd->result = DID_ABORT << 16;
		cmd->scsi_done(cmd); /* No tag or busy flag to worry about */
		goto out;
	}

	dprintk(NDEBUG_ABORT, ("scsi%d : abort called\n", instance->host_no));
	dprintk(NDEBUG_ABORT, ("        basr 0x%X, sr 0x%X\n", NCR5380_read(BUS_AND_STATUS_REG), NCR5380_read(STATUS_REG)));
	dprintk(NDEBUG_ABORT, "scsi%d : abort called\n", instance->host_no);
	dprintk(NDEBUG_ABORT, "        basr 0x%X, sr 0x%X\n", NCR5380_read(BUS_AND_STATUS_REG), NCR5380_read(STATUS_REG));
	if (hostdata->selecting == cmd) {
		dsprintk(NDEBUG_ABORT, instance,
		         "abort: cmd %p == selecting\n", cmd);
		hostdata->selecting = NULL;
		cmd->result = DID_ABORT << 16;
		complete_cmd(instance, cmd);
		goto out;
	}

	if (list_del_cmd(&hostdata->disconnected, cmd)) {
		dsprintk(NDEBUG_ABORT, instance,
		         "abort: removed %p from disconnected list\n", cmd);
		/* Can't call NCR5380_select() and send ABORT because that
		 * means releasing the lock. Need a bus reset.
		 */
		set_host_byte(cmd, DID_ERROR);
		complete_cmd(instance, cmd);
		result = FAILED;
		goto out;
	}

	if (hostdata->connected == cmd) {
		dprintk(NDEBUG_ABORT, ("scsi%d : aborting connected command\n", instance->host_no));
		dprintk(NDEBUG_ABORT, "scsi%d : aborting connected command\n", instance->host_no);
		hostdata->aborted = 1;
/*
 * We should perform BSY checking, and make sure we haven't slipped
 * into BUS FREE.
 */

		NCR5380_write(INITIATOR_COMMAND_REG, ICR_ASSERT_ATN);
/* 
 * Since we can't change phases until we've completed the current 
 * handshake, we have to source or sink a byte of data if the current
 * phase is not MSGOUT.
 */

/* 
 * Return control to the executing NCR drive so we can clear the
 * aborted flag and get back into our main loop.
 */

		return 0;
		return SUCCESS;
	}
#endif

/* 
 * Case 2 : If the command hasn't been issued yet, we simply remove it 
 *          from the issue queue.
 */
 
	dprintk(NDEBUG_ABORT, ("scsi%d : abort going into loop.\n", instance->host_no));
	for (prev = (Scsi_Cmnd **) & (hostdata->issue_queue), tmp = (Scsi_Cmnd *) hostdata->issue_queue; tmp; prev = (Scsi_Cmnd **) & (tmp->host_scribble), tmp = (Scsi_Cmnd *) tmp->host_scribble)
		if (cmd == tmp) {
			REMOVE(5, *prev, tmp, tmp->host_scribble);
			(*prev) = (Scsi_Cmnd *) tmp->host_scribble;
			tmp->host_scribble = NULL;
			tmp->result = DID_ABORT << 16;
			dprintk(NDEBUG_ABORT, ("scsi%d : abort removed command from issue queue.\n", instance->host_no));
	dprintk(NDEBUG_ABORT, "scsi%d : abort going into loop.\n", instance->host_no);
	for (prev = (struct scsi_cmnd **) &(hostdata->issue_queue), tmp = (struct scsi_cmnd *) hostdata->issue_queue; tmp; prev = (struct scsi_cmnd **) &(tmp->host_scribble), tmp = (struct scsi_cmnd *) tmp->host_scribble)
		if (cmd == tmp) {
			REMOVE(5, *prev, tmp, tmp->host_scribble);
			(*prev) = (struct scsi_cmnd *) tmp->host_scribble;
			tmp->host_scribble = NULL;
			tmp->result = DID_ABORT << 16;
			dprintk(NDEBUG_ABORT, "scsi%d : abort removed command from issue queue.\n", instance->host_no);
			tmp->scsi_done(tmp);
			return SUCCESS;
		}
#if (NDEBUG  & NDEBUG_ABORT)
	/* KLL */
		else if (prev == tmp)
			printk(KERN_ERR "scsi%d : LOOP\n", instance->host_no);
#endif

/* 
 * Case 3 : If any commands are connected, we're going to fail the abort
 *          and let the high level SCSI driver retry at a later time or 
 *          issue a reset.
 *
 *          Timeouts, and therefore aborted commands, will be highly unlikely
 *          and handling them cleanly in this situation would make the common
 *          case of noresets less efficient, and would pollute our code.  So,
 *          we fail.
 */

	if (hostdata->connected) {
		dprintk(NDEBUG_ABORT, ("scsi%d : abort failed, command connected.\n", instance->host_no));
		dprintk(NDEBUG_ABORT, "scsi%d : abort failed, command connected.\n", instance->host_no);
		return FAILED;
		dsprintk(NDEBUG_ABORT, instance, "abort: cmd %p is connected\n", cmd);
		hostdata->connected = NULL;
		hostdata->dma_len = 0;
		if (do_abort(instance)) {
			set_host_byte(cmd, DID_ERROR);
			complete_cmd(instance, cmd);
			result = FAILED;
			goto out;
		}
		set_host_byte(cmd, DID_ABORT);
		complete_cmd(instance, cmd);
		goto out;
	}

	for (tmp = (Scsi_Cmnd *) hostdata->disconnected_queue; tmp; tmp = (Scsi_Cmnd *) tmp->host_scribble)
		if (cmd == tmp) {
			dprintk(NDEBUG_ABORT, ("scsi%d : aborting disconnected command.\n", instance->host_no));

			if (NCR5380_select(instance, cmd, (int) cmd->tag))
				return FAILED;
			dprintk(NDEBUG_ABORT, ("scsi%d : nexus reestablished.\n", instance->host_no));

			do_abort(instance);

			for (prev = (Scsi_Cmnd **) & (hostdata->disconnected_queue), tmp = (Scsi_Cmnd *) hostdata->disconnected_queue; tmp; prev = (Scsi_Cmnd **) & (tmp->host_scribble), tmp = (Scsi_Cmnd *) tmp->host_scribble)
				if (cmd == tmp) {
					REMOVE(5, *prev, tmp, tmp->host_scribble);
					*prev = (Scsi_Cmnd *) tmp->host_scribble;
	for (tmp = (struct scsi_cmnd *) hostdata->disconnected_queue; tmp; tmp = (struct scsi_cmnd *) tmp->host_scribble)
		if (cmd == tmp) {
			dprintk(NDEBUG_ABORT, "scsi%d : aborting disconnected command.\n", instance->host_no);
	if (list_del_cmd(&hostdata->autosense, cmd)) {
		dsprintk(NDEBUG_ABORT, instance,
		         "abort: removed %p from sense queue\n", cmd);
		set_host_byte(cmd, DID_ERROR);
		complete_cmd(instance, cmd);
	}

out:
	if (result == FAILED)
		dsprintk(NDEBUG_ABORT, instance, "abort: failed to abort %p\n", cmd);
	else
		dsprintk(NDEBUG_ABORT, instance, "abort: successfully aborted %p\n", cmd);

	queue_work(hostdata->work_q, &hostdata->main_task);
	maybe_release_dma_irq(instance);
	spin_unlock_irqrestore(&hostdata->lock, flags);

	return result;
}


/* 
 * Function : int NCR5380_bus_reset (Scsi_Cmnd *cmd)
 * Function : int NCR5380_bus_reset (struct scsi_cmnd *cmd)
 * 
 * Purpose : reset the SCSI bus.
/**
 * NCR5380_host_reset - reset the SCSI host
 * @cmd: SCSI command undergoing EH
 *
 * Returns SUCCESS
 */

static int NCR5380_bus_reset(Scsi_Cmnd * cmd)
static int NCR5380_bus_reset(struct scsi_cmnd *cmd)
static int NCR5380_host_reset(struct scsi_cmnd *cmd)
{
	struct Scsi_Host *instance = cmd->device->host;
	struct NCR5380_hostdata *hostdata = shost_priv(instance);
	int i;
	unsigned long flags;
	struct NCR5380_cmd *ncmd;

	spin_lock_irqsave(&hostdata->lock, flags);

#if (NDEBUG & NDEBUG_ANY)
	scmd_printk(KERN_INFO, cmd, __func__);
#endif
	NCR5380_dprint(NDEBUG_ANY, instance);
	NCR5380_dprint_phase(NDEBUG_ANY, instance);

	do_reset(instance);

	/* reset NCR registers */
	NCR5380_write(MODE_REG, MR_BASE);
	NCR5380_write(TARGET_COMMAND_REG, 0);
	NCR5380_write(SELECT_ENABLE_REG, 0);

	/* After the reset, there are no more connected or disconnected commands
	 * and no busy units; so clear the low-level status here to avoid
	 * conflicts when the mid-level code tries to wake up the affected
	 * commands!
	 */

	if (list_del_cmd(&hostdata->unissued, cmd)) {
		cmd->result = DID_RESET << 16;
		cmd->scsi_done(cmd);
	}

	if (hostdata->selecting) {
		hostdata->selecting->result = DID_RESET << 16;
		complete_cmd(instance, hostdata->selecting);
		hostdata->selecting = NULL;
	}

	list_for_each_entry(ncmd, &hostdata->disconnected, list) {
		struct scsi_cmnd *cmd = NCR5380_to_scmd(ncmd);

		set_host_byte(cmd, DID_RESET);
		complete_cmd(instance, cmd);
	}
	INIT_LIST_HEAD(&hostdata->disconnected);

	list_for_each_entry(ncmd, &hostdata->autosense, list) {
		struct scsi_cmnd *cmd = NCR5380_to_scmd(ncmd);

		set_host_byte(cmd, DID_RESET);
		cmd->scsi_done(cmd);
	}
	INIT_LIST_HEAD(&hostdata->autosense);

	if (hostdata->connected) {
		set_host_byte(hostdata->connected, DID_RESET);
		complete_cmd(instance, hostdata->connected);
		hostdata->connected = NULL;
	}

	for (i = 0; i < 8; ++i)
		hostdata->busy[i] = 0;
	hostdata->dma_len = 0;

	queue_work(hostdata->work_q, &hostdata->main_task);
	maybe_release_dma_irq(instance);
	spin_unlock_irqrestore(&hostdata->lock, flags);

	return SUCCESS;
}
