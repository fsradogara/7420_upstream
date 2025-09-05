/*
 * Low level x86 E820 memory map handling functions.
 *
 * The firmware and bootloader passes us the "E820 table", which is the primary
 * physical memory layout description available about x86 systems.
 *
 * The kernel takes the E820 memory layout and optionally modifies it with
 * quirks and other tweaks, and feeds that into the generic Linux memory
 * allocation code routines via a platform independent interface (memblock, etc.).
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/bootmem.h>
#include <linux/ioport.h>
#include <linux/string.h>
#include <linux/kexec.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/pfn.h>
#include <linux/suspend.h>
#include <linux/firmware-map.h>

#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/e820.h>
#include <asm/proto.h>
#include <asm/setup.h>
#include <asm/trampoline.h>
#include <linux/crash_dump.h>
#include <linux/bootmem.h>
#include <linux/suspend.h>
#include <linux/acpi.h>
#include <linux/firmware-map.h>
#include <linux/memblock.h>
#include <linux/sort.h>

#include <asm/e820/api.h>
#include <asm/setup.h>

/*
 * We organize the E820 table into three main data structures:
 *
 * - 'e820_table_firmware': the original firmware version passed to us by the
 *   bootloader - not modified by the kernel. It is composed of two parts:
 *   the first 128 E820 memory entries in boot_params.e820_table and the remaining
 *   (if any) entries of the SETUP_E820_EXT nodes. We use this to:
 *
 *       - inform the user about the firmware's notion of memory layout
 *         via /sys/firmware/memmap
 *
 *       - the hibernation code uses it to generate a kernel-independent MD5
 *         fingerprint of the physical memory layout of a system.
 *
 * - 'e820_table_kexec': a slightly modified (by the kernel) firmware version
 *   passed to us by the bootloader - the major difference between
 *   e820_table_firmware[] and this one is that, the latter marks the setup_data
 *   list created by the EFI boot stub as reserved, so that kexec can reuse the
 *   setup_data information in the second kernel. Besides, e820_table_kexec[]
 *   might also be modified by the kexec itself to fake a mptable.
 *   We use this to:
 *
 *       - kexec, which is a bootloader in disguise, uses the original E820
 *         layout to pass to the kexec-ed kernel. This way the original kernel
 *         can have a restricted E820 map while the kexec()-ed kexec-kernel
 *         can have access to full memory - etc.
 *
 * - 'e820_table': this is the main E820 table that is massaged by the
 *   low level x86 platform code, or modified by boot parameters, before
 *   passed on to higher level MM layers.
 *
 * Once the E820 map has been converted to the standard Linux memory layout
 * information its role stops - modifying it has no effect and does not get
 * re-propagated. So itsmain role is a temporary bootstrap storage of firmware
 * specific memory layout data during early bootup.
 */
static struct e820_table e820_table_init		__initdata;
static struct e820_table e820_table_kexec_init		__initdata;
static struct e820_table e820_table_firmware_init	__initdata;

struct e820_table *e820_table __refdata			= &e820_table_init;
struct e820_table *e820_table_kexec __refdata		= &e820_table_kexec_init;
struct e820_table *e820_table_firmware __refdata	= &e820_table_firmware_init;

/* For PCI or other memory-mapped resources */
unsigned long pci_mem_start = 0xaeedbabe;
#ifdef CONFIG_PCI
EXPORT_SYMBOL(pci_mem_start);
#endif

/*
 * This function checks if any part of the range <start,end> is mapped
 * with type.
 */
bool e820__mapped_any(u64 start, u64 end, enum e820_type type)
{
	int i;

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		if (type && entry->type != type)
			continue;
		if (entry->addr >= end || entry->addr + entry->size <= start)
			continue;
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(e820__mapped_any);

/*
 * This function checks if the entire <start,end> range is mapped with 'type'.
 *
 * Note: this function only works correctly once the E820 table is sorted and
 * not-overlapping (at least for the range specified), which is the case normally.
 */
static struct e820_entry *__e820__mapped_all(u64 start, u64 end,
					     enum e820_type type)
{
	int i;

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		if (type && entry->type != type)
			continue;

		/* Is the region (part) in overlap with the current region? */
		if (entry->addr >= end || entry->addr + entry->size <= start)
			continue;

		/*
		 * If the region is at the beginning of <start,end> we move
		 * 'start' to the end of the region since it's ok until there
		 */
		if (entry->addr <= start)
			start = entry->addr + entry->size;

		/*
		 * If 'start' is now at or beyond 'end', we're done, full
		 * coverage of the desired range exists:
		 */
		if (start >= end)
			return entry;
	}

	return NULL;
}

/*
 * This function checks if the entire range <start,end> is mapped with type.
 */
bool __init e820__mapped_all(u64 start, u64 end, enum e820_type type)
{
	return __e820__mapped_all(start, end, type);
}

/*
 * This function returns the type associated with the range <start,end>.
 */
void __init e820_add_region(u64 start, u64 size, int type)
{
	int x = e820.nr_map;

	if (x == ARRAY_SIZE(e820.map)) {
		printk(KERN_ERR "Ooops! Too many entries in the memory map!\n");
		return;
	}

	e820.map[x].addr = start;
	e820.map[x].size = size;
	e820.map[x].type = type;
	e820.nr_map++;
static void __init __e820_add_region(struct e820map *e820x, u64 start, u64 size,
					 int type)
int e820__get_entry_type(u64 start, u64 end)
{
	struct e820_entry *entry = __e820__mapped_all(start, end, 0);

	return entry ? entry->type : -EINVAL;
}

/*
 * Add a memory region to the kernel E820 map.
 */
static void __init __e820__range_add(struct e820_table *table, u64 start, u64 size, enum e820_type type)
{
	int x = table->nr_entries;

	if (x >= ARRAY_SIZE(table->entries)) {
		pr_err("e820: too many entries; ignoring [mem %#010llx-%#010llx]\n", start, start + size - 1);
		return;
	}

	table->entries[x].addr = start;
	table->entries[x].size = size;
	table->entries[x].type = type;
	table->nr_entries++;
}

void __init e820__range_add(u64 start, u64 size, enum e820_type type)
{
	__e820__range_add(e820_table, start, size, type);
}

static void __init e820_print_type(enum e820_type type)
{
	switch (type) {
	case E820_TYPE_RAM:		/* Fall through: */
	case E820_TYPE_RESERVED_KERN:	pr_cont("usable");			break;
	case E820_TYPE_RESERVED:	pr_cont("reserved");			break;
	case E820_TYPE_ACPI:		pr_cont("ACPI data");			break;
	case E820_TYPE_NVS:		pr_cont("ACPI NVS");			break;
	case E820_TYPE_UNUSABLE:	pr_cont("unusable");			break;
	case E820_TYPE_PMEM:		/* Fall through: */
	case E820_TYPE_PRAM:		pr_cont("persistent (type %u)", type);	break;
	default:			pr_cont("type %u", type);		break;
	}
}

void __init e820__print_table(char *who)
{
	int i;

	for (i = 0; i < e820.nr_map; i++) {
		printk(KERN_INFO " %s: %016Lx - %016Lx ", who,
		       (unsigned long long) e820.map[i].addr,
		       (unsigned long long)
		       (e820.map[i].addr + e820.map[i].size));
		switch (e820.map[i].type) {
		case E820_RAM:
		case E820_RESERVED_KERN:
			printk(KERN_CONT "(usable)\n");
			break;
		case E820_RESERVED:
			printk(KERN_CONT "(reserved)\n");
			break;
		case E820_ACPI:
			printk(KERN_CONT "(ACPI data)\n");
			break;
		case E820_NVS:
			printk(KERN_CONT "(ACPI NVS)\n");
			break;
		default:
			printk(KERN_CONT "type %u\n", e820.map[i].type);
			break;
		}
		printk(KERN_INFO "%s: [mem %#018Lx-%#018Lx] ", who,
		       (unsigned long long) e820.map[i].addr,
		       (unsigned long long)
		       (e820.map[i].addr + e820.map[i].size - 1));
		e820_print_type(e820.map[i].type);
		printk(KERN_CONT "\n");
	for (i = 0; i < e820_table->nr_entries; i++) {
		pr_info("%s: [mem %#018Lx-%#018Lx] ", who,
		       e820_table->entries[i].addr,
		       e820_table->entries[i].addr + e820_table->entries[i].size - 1);

		e820_print_type(e820_table->entries[i].type);
		pr_cont("\n");
	}
}

/*
 * Sanitize an E820 map.
 *
 * Some E820 layouts include overlapping entries. The following
 * replaces the original E820 map with a new one, removing overlaps,
 * and resolving conflicting memory types in favor of highest
 * numbered type.
 *
 * The input parameter 'entries' points to an array of 'struct
 * e820_entry' which on entry has elements in the range [0, *nr_entries)
 * valid, and which has space for up to max_nr_entries entries.
 * On return, the resulting sanitized E820 map entries will be in
 * overwritten in the same location, starting at 'entries'.
 *
 * The integer pointed to by pnr_map must be valid on entry (the
 * current number of valid entries located at biosmap) and will
 * be updated on return, with the new number of valid entries
 * (something no more than max_nr_map.)
 * current number of valid entries located at biosmap). If the
 * sanitizing succeeds the *pnr_map will be updated with the new
 * number of valid entries (something no more than max_nr_map).
 * The integer pointed to by nr_entries must be valid on entry (the
 * current number of valid entries located at 'entries'). If the
 * sanitizing succeeds the *nr_entries will be updated with the new
 * number of valid entries (something no more than max_nr_entries).
 *
 * The return value from e820__update_table() is zero if it
 * successfully 'sanitized' the map entries passed in, and is -1
 * if it did nothing, which can happen if either of (1) it was
 * only passed one map entry, or (2) any of the input map entries
 * were invalid (start + size < start, meaning that the size was
 * so big the described memory range wrapped around through zero.)
 *
 *	Visually we're performing the following
 *	(1,2,3,4 = memory types)...
 *
 *	Sample memory map (w/overlaps):
 *	   ____22__________________
 *	   ______________________4_
 *	   ____1111________________
 *	   _44_____________________
 *	   11111111________________
 *	   ____________________33__
 *	   ___________44___________
 *	   __________33333_________
 *	   ______________22________
 *	   ___________________2222_
 *	   _________111111111______
 *	   _____________________11_
 *	   _________________4______
 *
 *	Sanitized equivalent (no overlap):
 *	   1_______________________
 *	   _44_____________________
 *	   ___1____________________
 *	   ____22__________________
 *	   ______11________________
 *	   _________1______________
 *	   __________3_____________
 *	   ___________44___________
 *	   _____________33_________
 *	   _______________2________
 *	   ________________1_______
 *	   _________________4______
 *	   ___________________2____
 *	   ____________________33__
 *	   ______________________4_
 */

int __init sanitize_e820_map(struct e820entry *biosmap, int max_nr_map,
				int *pnr_map)
{
	struct change_member {
		struct e820entry *pbios; /* pointer to original bios entry */
		unsigned long long addr; /* address for this change point */
	};
struct change_member {
	/* Pointer to the original entry: */
	struct e820_entry	*entry;
	/* Address for this change point: */
	unsigned long long	addr;
};

static struct change_member	change_point_list[2*E820_MAX_ENTRIES]	__initdata;
static struct change_member	*change_point[2*E820_MAX_ENTRIES]	__initdata;
static struct e820_entry	*overlap_list[E820_MAX_ENTRIES]		__initdata;
static struct e820_entry	new_entries[E820_MAX_ENTRIES]		__initdata;

static int __init cpcompare(const void *a, const void *b)
{
	struct change_member * const *app = a, * const *bpp = b;
	const struct change_member *ap = *app, *bp = *bpp;

	/*
	 * Inputs are pointers to two elements of change_point[].  If their
	 * addresses are not equal, their difference dominates.  If the addresses
	 * are equal, then consider one that represents the end of its region
	 * to be greater than one that does not.
	 */
	if (ap->addr != bp->addr)
		return ap->addr > bp->addr ? 1 : -1;

	return (ap->addr != ap->entry->addr) - (bp->addr != bp->entry->addr);
}

int __init e820__update_table(struct e820_table *table)
{
	static struct change_member change_point_list[2*E820_X_MAX] __initdata;
	static struct change_member *change_point[2*E820_X_MAX] __initdata;
	static struct e820entry *overlap_list[E820_X_MAX] __initdata;
	static struct e820entry new_bios[E820_X_MAX] __initdata;
	struct change_member *change_tmp;
	unsigned long current_type, last_type;
	unsigned long long last_addr;
	int chgidx, still_changing;
	unsigned long current_type, last_type;
	struct e820_entry *entries = table->entries;
	u32 max_nr_entries = ARRAY_SIZE(table->entries);
	enum e820_type current_type, last_type;
	unsigned long long last_addr;
	u32 new_nr_entries, overlap_entries;
	u32 i, chg_idx, chg_nr;

	/* If there's only one memory region, don't bother: */
	if (table->nr_entries < 2)
		return -1;

	BUG_ON(table->nr_entries > max_nr_entries);

	/* Bail out if we find any unreasonable addresses in the map: */
	for (i = 0; i < table->nr_entries; i++) {
		if (entries[i].addr + entries[i].size < entries[i].addr)
			return -1;
	}

	/* Create pointers for initial change-point information (for sorting): */
	for (i = 0; i < 2 * table->nr_entries; i++)
		change_point[i] = &change_point_list[i];

	/*
	 * Record all known change-points (starting and ending addresses),
	 * omitting empty memory regions:
	 */
	chg_idx = 0;
	for (i = 0; i < table->nr_entries; i++)	{
		if (entries[i].size != 0) {
			change_point[chg_idx]->addr	= entries[i].addr;
			change_point[chg_idx++]->entry	= &entries[i];
			change_point[chg_idx]->addr	= entries[i].addr + entries[i].size;
			change_point[chg_idx++]->entry	= &entries[i];
		}
	}
	chg_nr = chg_idx;

	/* sort change-point list by memory addresses (low -> high) */
	still_changing = 1;
	while (still_changing)	{
		still_changing = 0;
		for (i = 1; i < chg_nr; i++)  {
			unsigned long long curaddr, lastaddr;
			unsigned long long curpbaddr, lastpbaddr;

			curaddr = change_point[i]->addr;
			lastaddr = change_point[i - 1]->addr;
			curpbaddr = change_point[i]->pbios->addr;
			lastpbaddr = change_point[i - 1]->pbios->addr;

			/*
			 * swap entries, when:
			 *
			 * curaddr > lastaddr or
			 * curaddr == lastaddr and curaddr == curpbaddr and
			 * lastaddr != lastpbaddr
			 */
			if (curaddr < lastaddr ||
			    (curaddr == lastaddr && curaddr == curpbaddr &&
			     lastaddr != lastpbaddr)) {
				change_tmp = change_point[i];
				change_point[i] = change_point[i-1];
				change_point[i-1] = change_tmp;
				still_changing = 1;
			}
		}
	}
	sort(change_point, chg_nr, sizeof *change_point, cpcompare, NULL);
	/* Sort change-point list by memory addresses (low -> high): */
	sort(change_point, chg_nr, sizeof(*change_point), cpcompare, NULL);

	/* Create a new memory map, removing overlaps: */
	overlap_entries = 0;	 /* Number of entries in the overlap table */
	new_nr_entries = 0;	 /* Index for creating new map entries */
	last_type = 0;		 /* Start with undefined memory type */
	last_addr = 0;		 /* Start with 0 as last starting address */

	/* Loop through change-points, determining effect on the new map: */
	for (chg_idx = 0; chg_idx < chg_nr; chg_idx++) {
		/* Keep track of all overlapping entries */
		if (change_point[chg_idx]->addr == change_point[chg_idx]->entry->addr) {
			/* Add map entry to overlap list (> 1 entry implies an overlap) */
			overlap_list[overlap_entries++] = change_point[chg_idx]->entry;
		} else {
			/* Remove entry from list (order independent, so swap with last): */
			for (i = 0; i < overlap_entries; i++) {
				if (overlap_list[i] == change_point[chg_idx]->entry)
					overlap_list[i] = overlap_list[overlap_entries-1];
			}
			overlap_entries--;
		}
		/*
		 * If there are overlapping entries, decide which
		 * "type" to use (larger value takes precedence --
		 * 1=usable, 2,3,4,4+=unusable)
		 */
		current_type = 0;
		for (i = 0; i < overlap_entries; i++) {
			if (overlap_list[i]->type > current_type)
				current_type = overlap_list[i]->type;
		/*
		 * continue building up new bios map based on this
		 * information
		 */
		if (current_type != last_type)	{
		if (current_type != last_type || current_type == E820_PRAM) {
		}

		/* Continue building up new map based on this information: */
		if (current_type != last_type || current_type == E820_TYPE_PRAM) {
			if (last_type != 0)	 {
				new_entries[new_nr_entries].size = change_point[chg_idx]->addr - last_addr;
				/* Move forward only if the new size was non-zero: */
				if (new_entries[new_nr_entries].size != 0)
					/* No more space left for new entries? */
					if (++new_nr_entries >= max_nr_entries)
						break;
			}
			if (current_type != 0)	{
				new_entries[new_nr_entries].addr = change_point[chg_idx]->addr;
				new_entries[new_nr_entries].type = current_type;
				last_addr = change_point[chg_idx]->addr;
			}
			last_type = current_type;
		}
	}

	/* Copy the new entries into the original location: */
	memcpy(entries, new_entries, new_nr_entries*sizeof(*entries));
	table->nr_entries = new_nr_entries;

	return 0;
}

static int __init __append_e820_table(struct boot_e820_entry *entries, u32 nr_entries)
{
	struct boot_e820_entry *entry = entries;

	while (nr_entries) {
		u64 start = entry->addr;
		u64 size = entry->size;
		u64 end = start + size - 1;
		u32 type = entry->type;

		/* Ignore the entry on 64-bit overflow: */
		if (start > end && likely(size))
			return -1;

		e820__range_add(start, size, type);

		entry++;
		nr_entries--;
	}
	return 0;
}

/*
 * Copy the BIOS E820 map into a safe place.
 *
 * Sanity-check it while we're at it..
 *
 * If we're lucky and live on a modern system, the setup code
 * will have given us a memory map that we can use to properly
 * set up memory.  If we aren't, we'll fake a memory map.
 */
static int __init append_e820_table(struct boot_e820_entry *entries, u32 nr_entries)
{
	/* Only one memory region (or negative)? Ignore it */
	if (nr_entries < 2)
		return -1;

	return __append_e820_table(entries, nr_entries);
}

static u64 __init e820_update_range_map(struct e820map *e820x, u64 start,
					u64 size, unsigned old_type,
					unsigned new_type)
{
	int i;
static u64 __init __e820_update_range(struct e820map *e820x, u64 start,
					u64 size, unsigned old_type,
					unsigned new_type)
static u64 __init
__e820__range_update(struct e820_table *table, u64 start, u64 size, enum e820_type old_type, enum e820_type new_type)
{
	u64 end;
	unsigned int i;
	u64 real_updated_size = 0;

	BUG_ON(old_type == new_type);

	if (size > (ULLONG_MAX - start))
		size = ULLONG_MAX - start;

	for (i = 0; i < e820.nr_map; i++) {
		struct e820entry *ei = &e820x->map[i];
		u64 final_start, final_end;
		if (ei->type != old_type)
			continue;
		/* totally covered? */
		if (ei->addr >= start &&
		    (ei->addr + ei->size) <= (start + size)) {
	end = start + size;
	printk(KERN_DEBUG "e820: update [mem %#010Lx-%#010Lx] ", start, end - 1);
	e820_print_type(old_type);
	pr_cont(" ==> ");
	e820_print_type(new_type);
	pr_cont("\n");

	for (i = 0; i < table->nr_entries; i++) {
		struct e820_entry *entry = &table->entries[i];
		u64 final_start, final_end;
		u64 entry_end;

		if (entry->type != old_type)
			continue;

		entry_end = entry->addr + entry->size;

		/* Completely covered by new range? */
		if (entry->addr >= start && entry_end <= end) {
			entry->type = new_type;
			real_updated_size += entry->size;
			continue;
		}
		/* partially covered */
		final_start = max(start, ei->addr);
		final_end = min(start + size, ei->addr + ei->size);
		if (final_start >= final_end)
			continue;
		e820_add_region(final_start, final_end - final_start,
					 new_type);
		real_updated_size += final_end - final_start;


		/* New range is completely covered? */
		if (entry->addr < start && entry_end > end) {
			__e820__range_add(table, start, size, new_type);
			__e820__range_add(table, end, entry_end - end, entry->type);
			entry->size = start - entry->addr;
			real_updated_size += size;
			continue;
		}

		/* Partially covered: */
		final_start = max(start, entry->addr);
		final_end = min(end, entry_end);
		if (final_start >= final_end)
			continue;

		__e820__range_add(table, final_start, final_end - final_start, new_type);

		real_updated_size += final_end - final_start;

		/*
		 * Left range could be head or tail, so need to update
		 * its size first:
		 */
		entry->size -= final_end - final_start;
		if (entry->addr < final_start)
			continue;

		entry->addr = final_end;
	}
	return real_updated_size;
}

u64 __init e820__range_update(u64 start, u64 size, enum e820_type old_type, enum e820_type new_type)
{
	return e820_update_range_map(&e820, start, size, old_type, new_type);
	return __e820_update_range(&e820, start, size, old_type, new_type);
	return __e820__range_update(e820_table, start, size, old_type, new_type);
}

static u64 __init e820__range_update_kexec(u64 start, u64 size, enum e820_type old_type, enum e820_type  new_type)
{
	return e820_update_range_map(&e820_saved, start, size, old_type,
	return __e820_update_range(&e820_saved, start, size, old_type,
				     new_type);
	return __e820__range_update(e820_table_kexec, start, size, old_type, new_type);
}

/* Remove a range of memory from the E820 table: */
u64 __init e820__range_remove(u64 start, u64 size, enum e820_type old_type, bool check_type)
{
	int i;
	u64 end;
	u64 real_removed_size = 0;

	if (size > (ULLONG_MAX - start))
		size = ULLONG_MAX - start;

	for (i = 0; i < e820.nr_map; i++) {
		struct e820entry *ei = &e820.map[i];
		u64 final_start, final_end;

		if (checktype && ei->type != old_type)
			continue;
		/* totally covered? */
		if (ei->addr >= start &&
		    (ei->addr + ei->size) <= (start + size)) {
	end = start + size;
	printk(KERN_DEBUG "e820: remove [mem %#010Lx-%#010Lx] ", start, end - 1);
	if (check_type)
		e820_print_type(old_type);
	pr_cont("\n");

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];
		u64 final_start, final_end;
		u64 entry_end;

		if (check_type && entry->type != old_type)
			continue;

		entry_end = entry->addr + entry->size;

		/* Completely covered? */
		if (entry->addr >= start && entry_end <= end) {
			real_removed_size += entry->size;
			memset(entry, 0, sizeof(*entry));
			continue;
		}
		/* partially covered */
		final_start = max(start, ei->addr);
		final_end = min(start + size, ei->addr + ei->size);

		/* Is the new range completely covered? */
		if (entry->addr < start && entry_end > end) {
			e820__range_add(end, entry_end - end, entry->type);
			entry->size = start - entry->addr;
			real_removed_size += size;
			continue;
		}

		/* Partially covered: */
		final_start = max(start, entry->addr);
		final_end = min(end, entry_end);
		if (final_start >= final_end)
			continue;

		real_removed_size += final_end - final_start;

		/*
		 * Left range could be head or tail, so need to update
		 * the size first:
		 */
		entry->size -= final_end - final_start;
		if (entry->addr < final_start)
			continue;

		entry->addr = final_end;
	}
	return real_removed_size;
}

void __init e820__update_table_print(void)
{
	int nr_map;

	nr_map = e820.nr_map;
	if (sanitize_e820_map(e820.map, ARRAY_SIZE(e820.map), &nr_map))
		return;
	e820.nr_map = nr_map;
	printk(KERN_INFO "modified physical RAM map:\n");
	if (sanitize_e820_map(e820.map, ARRAY_SIZE(e820.map), &e820.nr_map))
	if (e820__update_table(e820_table))
		return;

	pr_info("e820: modified physical RAM map:\n");
	e820__print_table("modified");
}

static void __init e820__update_table_kexec(void)
{
	int nr_map;

	nr_map = e820_saved.nr_map;
	if (sanitize_e820_map(e820_saved.map, ARRAY_SIZE(e820_saved.map), &nr_map))
		return;
	e820_saved.nr_map = nr_map;
	sanitize_e820_map(e820_saved.map, ARRAY_SIZE(e820_saved.map),
				&e820_saved.nr_map);
	e820__update_table(e820_table_kexec);
}

#define MAX_GAP_END 0x100000000ull

/*
 * Search for a gap in the E820 memory space from 0 to MAX_GAP_END (4GB).
 */
static int __init e820_search_gap(unsigned long *gapstart, unsigned long *gapsize)
{
	unsigned long long last = MAX_GAP_END;
	int i = e820_table->nr_entries;
	int found = 0;

	while (--i >= 0) {
		unsigned long long start = e820_table->entries[i].addr;
		unsigned long long end = start + e820_table->entries[i].size;

		/*
		 * Since "last" is at most 4GB, we know we'll
		 * fit in 32 bits if this condition is true:
		 */
		if (last > end) {
			unsigned long gap = last - end;

			if (gap >= *gapsize) {
				*gapsize = gap;
				*gapstart = end;
				found = 1;
			}
		}
		if (start < last)
			last = start;
	}
	return found;
}

/*
 * Search for the biggest gap in the low 32 bits of the E820
 * memory space. We pass this space to the PCI subsystem, so
 * that it can assign MMIO resources for hotplug or
 * unconfigured devices in.
 *
 * Hopefully the BIOS let enough space left.
 */
__init void e820__setup_pci_gap(void)
{
	unsigned long gapstart, gapsize, round;
	unsigned long gapstart, gapsize;
	int found;

	gapsize = 0x400000;
	found  = e820_search_gap(&gapstart, &gapsize);

	if (!found) {
#ifdef CONFIG_X86_64
		gapstart = (max_pfn << PAGE_SHIFT) + 1024*1024;
		printk(KERN_ERR "PCI: Warning: Cannot find a gap in the 32bit "
		       "address range\n"
		       KERN_ERR "PCI: Unassigned devices with 32bit resource "
		       "registers may break!\n");
		printk(KERN_ERR
	"e820: cannot find a gap in the 32bit address range\n"
	"e820: PCI devices with unassigned 32bit BARs may break!\n");
	}
		pr_err(
			"e820: Cannot find an available gap in the 32-bit address range\n"
			"e820: PCI devices with unassigned 32-bit BARs may not work!\n");
#else
		gapstart = 0x10000000;
#endif
	}

	/*
	 * See how much we want to round up: start off with
	 * rounding to the next 1MB area.
	 */
	round = 0x100000;
	while ((gapsize >> 4) > round)
		round += round;
	/* Fun with two's complement */
	pci_mem_start = (gapstart + round) & -round;

	printk(KERN_INFO
	       "Allocating PCI resources starting at %lx (gap: %lx:%lx)\n",
	       pci_mem_start, gapstart, gapsize);
	 * e820_reserve_resources_late protect stolen RAM already
	 * e820__reserve_resources_late() protects stolen RAM already:
	 */
	pci_mem_start = gapstart;

	pr_info("e820: [mem %#010lx-%#010lx] available for PCI devices\n", gapstart, gapstart + gapsize - 1);
}

/*
 * Called late during init, in free_initmem().
 *
 * Initial e820_table and e820_table_kexec are largish __initdata arrays.
 *
 * Copy them to a (usually much smaller) dynamically allocated area that is
 * sized precisely after the number of e820 entries.
 *
 * This is done after we've performed all the fixes and tweaks to the tables.
 * All functions which modify them are __init functions, which won't exist
 * after free_initmem().
 */
void __init parse_e820_ext(struct setup_data *sdata, unsigned long pa_data)
{
	u32 map_len;
	int entries;
	struct e820entry *extmap;

	entries = sdata->len / sizeof(struct e820entry);
	map_len = sdata->len + sizeof(struct setup_data);
	if (map_len > PAGE_SIZE)
		sdata = early_ioremap(pa_data, map_len);
	extmap = (struct e820entry *)(sdata->data);
	__append_e820_map(extmap, entries);
	sanitize_e820_map(e820.map, ARRAY_SIZE(e820.map), &e820.nr_map);
	if (map_len > PAGE_SIZE)
		early_iounmap(sdata, map_len);
	printk(KERN_INFO "extended physical RAM map:\n");
void __init parse_e820_ext(u64 phys_addr, u32 data_len)
__init void e820__reallocate_tables(void)
{
	struct e820_table *n;
	int size;

	size = offsetof(struct e820_table, entries) + sizeof(struct e820_entry)*e820_table->nr_entries;
	n = kmalloc(size, GFP_KERNEL);
	BUG_ON(!n);
	memcpy(n, e820_table, size);
	e820_table = n;

	size = offsetof(struct e820_table, entries) + sizeof(struct e820_entry)*e820_table_kexec->nr_entries;
	n = kmalloc(size, GFP_KERNEL);
	BUG_ON(!n);
	memcpy(n, e820_table_kexec, size);
	e820_table_kexec = n;

	size = offsetof(struct e820_table, entries) + sizeof(struct e820_entry)*e820_table_firmware->nr_entries;
	n = kmalloc(size, GFP_KERNEL);
	BUG_ON(!n);
	memcpy(n, e820_table_firmware, size);
	e820_table_firmware = n;
}

/*
 * Because of the small fixed size of struct boot_params, only the first
 * 128 E820 memory entries are passed to the kernel via boot_params.e820_table,
 * the remaining (if any) entries are passed via the SETUP_E820_EXT node of
 * struct setup_data, which is parsed here.
 */
void __init e820__memory_setup_extended(u64 phys_addr, u32 data_len)
{
	int entries;
	struct boot_e820_entry *extmap;
	struct setup_data *sdata;

	sdata = early_memremap(phys_addr, data_len);
	entries = sdata->len / sizeof(*extmap);
	extmap = (struct boot_e820_entry *)(sdata->data);

	__append_e820_table(extmap, entries);
	e820__update_table(e820_table);

	memcpy(e820_table_kexec, e820_table, sizeof(*e820_table_kexec));
	memcpy(e820_table_firmware, e820_table, sizeof(*e820_table_firmware));

	early_memunmap(sdata, data_len);
	pr_info("e820: extended physical RAM map:\n");
	e820__print_table("extended");
}

/*
 * Find the ranges of physical addresses that do not correspond to
 * E820 RAM areas and register the corresponding pages as 'nosave' for
 * hibernation (32-bit) or software suspend and suspend to RAM (64-bit).
 *
 * This function requires the e820 map to be sorted and without any
 * overlapping entries and assumes the first e820 area to be RAM.
 * This function requires the E820 map to be sorted and without any
 * overlapping entries.
 */
void __init e820__register_nosave_regions(unsigned long limit_pfn)
{
	int i;
	unsigned long pfn;

	pfn = PFN_DOWN(e820.map[0].addr + e820.map[0].size);
	for (i = 1; i < e820.nr_map; i++) {
	unsigned long pfn = 0;

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		if (pfn < PFN_UP(entry->addr))
			register_nosave_region(pfn, PFN_UP(entry->addr));

		pfn = PFN_DOWN(entry->addr + entry->size);

		if (entry->type != E820_TYPE_RAM && entry->type != E820_TYPE_RESERVED_KERN)
			register_nosave_region(PFN_UP(entry->addr), pfn);

		if (pfn >= limit_pfn)
			break;
	}
}

/*
 * Early reserved memory areas.
 */
#define MAX_EARLY_RES 20

struct early_res {
	u64 start, end;
	char name[16];
	char overlap_ok;
};
static struct early_res early_res[MAX_EARLY_RES] __initdata = {
	{ 0, PAGE_SIZE, "BIOS data page" },	/* BIOS data page */
#if defined(CONFIG_X86_64) && defined(CONFIG_X86_TRAMPOLINE)
	{ TRAMPOLINE_BASE, TRAMPOLINE_BASE + 2 * PAGE_SIZE, "TRAMPOLINE" },
#endif
#if defined(CONFIG_X86_32) && defined(CONFIG_SMP)
	/*
	 * But first pinch a few for the stack/trampoline stuff
	 * FIXME: Don't need the extra page at 4K, but need to fix
	 * trampoline before removing it. (see the GDT stuff)
	 */
	{ PAGE_SIZE, PAGE_SIZE + PAGE_SIZE, "EX TRAMPOLINE" },
	/*
	 * Has to be in very low memory so we can execute
	 * real-mode AP code.
	 */
	{ TRAMPOLINE_BASE, TRAMPOLINE_BASE + PAGE_SIZE, "TRAMPOLINE" },
#endif
	{}
};

static int __init find_overlapped_early(u64 start, u64 end)
{
	int i;
	struct early_res *r;

	for (i = 0; i < MAX_EARLY_RES && early_res[i].end; i++) {
		r = &early_res[i];
		if (end > r->start && start < r->end)
			break;
	}

	return i;
}

/*
 * Drop the i-th range from the early reservation map,
 * by copying any higher ranges down one over it, and
 * clearing what had been the last slot.
 */
static void __init drop_range(int i)
{
	int j;

	for (j = i + 1; j < MAX_EARLY_RES && early_res[j].end; j++)
		;

	memmove(&early_res[i], &early_res[i + 1],
	       (j - 1 - i) * sizeof(struct early_res));

	early_res[j - 1].end = 0;
}

/*
 * Split any existing ranges that:
 *  1) are marked 'overlap_ok', and
 *  2) overlap with the stated range [start, end)
 * into whatever portion (if any) of the existing range is entirely
 * below or entirely above the stated range.  Drop the portion
 * of the existing range that overlaps with the stated range,
 * which will allow the caller of this routine to then add that
 * stated range without conflicting with any existing range.
 */
static void __init drop_overlaps_that_are_ok(u64 start, u64 end)
{
	int i;
	struct early_res *r;
	u64 lower_start, lower_end;
	u64 upper_start, upper_end;
	char name[16];

	for (i = 0; i < MAX_EARLY_RES && early_res[i].end; i++) {
		r = &early_res[i];

		/* Continue past non-overlapping ranges */
		if (end <= r->start || start >= r->end)
			continue;

		/*
		 * Leave non-ok overlaps as is; let caller
		 * panic "Overlapping early reservations"
		 * when it hits this overlap.
		 */
		if (!r->overlap_ok)
			return;

		/*
		 * We have an ok overlap.  We will drop it from the early
		 * reservation map, and add back in any non-overlapping
		 * portions (lower or upper) as separate, overlap_ok,
		 * non-overlapping ranges.
		 */

		/* 1. Note any non-overlapping (lower or upper) ranges. */
		strncpy(name, r->name, sizeof(name) - 1);

		lower_start = lower_end = 0;
		upper_start = upper_end = 0;
		if (r->start < start) {
		 	lower_start = r->start;
			lower_end = start;
		}
		if (r->end > end) {
			upper_start = end;
			upper_end = r->end;
		}

		/* 2. Drop the original ok overlapping range */
		drop_range(i);

		i--;		/* resume for-loop on copied down entry */

		/* 3. Add back in any non-overlapping ranges. */
		if (lower_end)
			reserve_early_overlap_ok(lower_start, lower_end, name);
		if (upper_end)
			reserve_early_overlap_ok(upper_start, upper_end, name);
	}
}

static void __init __reserve_early(u64 start, u64 end, char *name,
						int overlap_ok)
{
	int i;
	struct early_res *r;

	i = find_overlapped_early(start, end);
	if (i >= MAX_EARLY_RES)
		panic("Too many early reservations");
	r = &early_res[i];
	if (r->end)
		panic("Overlapping early reservations "
		      "%llx-%llx %s to %llx-%llx %s\n",
		      start, end - 1, name?name:"", r->start,
		      r->end - 1, r->name);
	r->start = start;
	r->end = end;
	r->overlap_ok = overlap_ok;
	if (name)
		strncpy(r->name, name, sizeof(r->name) - 1);
}

/*
 * A few early reservtations come here.
 *
 * The 'overlap_ok' in the name of this routine does -not- mean it
 * is ok for these reservations to overlap an earlier reservation.
 * Rather it means that it is ok for subsequent reservations to
 * overlap this one.
 *
 * Use this entry point to reserve early ranges when you are doing
 * so out of "Paranoia", reserving perhaps more memory than you need,
 * just in case, and don't mind a subsequent overlapping reservation
 * that is known to be needed.
 *
 * The drop_overlaps_that_are_ok() call here isn't really needed.
 * It would be needed if we had two colliding 'overlap_ok'
 * reservations, so that the second such would not panic on the
 * overlap with the first.  We don't have any such as of this
 * writing, but might as well tolerate such if it happens in
 * the future.
 */
void __init reserve_early_overlap_ok(u64 start, u64 end, char *name)
{
	drop_overlaps_that_are_ok(start, end);
	__reserve_early(start, end, name, 1);
}

/*
 * Most early reservations come here.
 *
 * We first have drop_overlaps_that_are_ok() drop any pre-existing
 * 'overlap_ok' ranges, so that we can then reserve this memory
 * range without risk of panic'ing on an overlapping overlap_ok
 * early reservation.
 */
void __init reserve_early(u64 start, u64 end, char *name)
{
	drop_overlaps_that_are_ok(start, end);
	__reserve_early(start, end, name, 0);
}

void __init free_early(u64 start, u64 end)
{
	struct early_res *r;
	int i;

	i = find_overlapped_early(start, end);
	r = &early_res[i];
	if (i >= MAX_EARLY_RES || r->end != end || r->start != start)
		panic("free_early on not reserved area: %llx-%llx!",
			 start, end - 1);

	drop_range(i);
}

void __init early_res_to_bootmem(u64 start, u64 end)
{
	int i, count;
	u64 final_start, final_end;

	count  = 0;
	for (i = 0; i < MAX_EARLY_RES && early_res[i].end; i++)
		count++;

	printk(KERN_INFO "(%d early reservations) ==> bootmem [%010llx - %010llx]\n",
			 count, start, end);
	for (i = 0; i < count; i++) {
		struct early_res *r = &early_res[i];
		printk(KERN_INFO "  #%d [%010llx - %010llx] %16s", i,
			r->start, r->end, r->name);
		final_start = max(start, r->start);
		final_end = min(end, r->end);
		if (final_start >= final_end) {
			printk(KERN_CONT "\n");
			continue;
		}
		printk(KERN_CONT " ==> [%010llx - %010llx]\n",
			final_start, final_end);
		reserve_bootmem_generic(final_start, final_end - final_start,
				BOOTMEM_DEFAULT);
	}
}

/* Check for already reserved areas */
static inline int __init bad_addr(u64 *addrp, u64 size, u64 align)
{
	int i;
	u64 addr = *addrp;
	int changed = 0;
	struct early_res *r;
again:
	i = find_overlapped_early(addr, addr + size);
	r = &early_res[i];
	if (i < MAX_EARLY_RES && r->end) {
		*addrp = addr = round_up(r->end, align);
		changed = 1;
		goto again;
	}
	return changed;
}

/* Check for already reserved areas */
static inline int __init bad_addr_size(u64 *addrp, u64 *sizep, u64 align)
{
	int i;
	u64 addr = *addrp, last;
	u64 size = *sizep;
	int changed = 0;
again:
	last = addr + size;
	for (i = 0; i < MAX_EARLY_RES && early_res[i].end; i++) {
		struct early_res *r = &early_res[i];
		if (last > r->start && addr < r->start) {
			size = r->start - addr;
			changed = 1;
			goto again;
		}
		if (last > r->end && addr < r->end) {
			addr = round_up(r->end, align);
			size = last - addr;
			changed = 1;
			goto again;
		}
		if (last <= r->end && addr >= r->start) {
			(*sizep)++;
			return 0;
		}
	}
	if (changed) {
		*addrp = addr;
		*sizep = size;
	}
	return changed;
}

/*
 * Find a free area with specified alignment in a specific range.
 */
u64 __init find_e820_area(u64 start, u64 end, u64 size, u64 align)
#ifdef CONFIG_ACPI
/*
 * Register ACPI NVS memory regions, so that we can save/restore them during
 * hibernation and the subsequent resume:
 */
static int __init e820__register_nvs_regions(void)
{
	int i;

	for (i = 0; i < e820.nr_map; i++) {
		struct e820entry *ei = &e820.map[i];
		u64 addr, last;
		u64 ei_last;

		if (ei->type != E820_RAM)
			continue;
		addr = round_up(ei->addr, align);
		ei_last = ei->addr + ei->size;
		if (addr < start)
			addr = round_up(start, align);
		if (addr >= ei_last)
			continue;
		while (bad_addr(&addr, size, align) && addr+size <= ei_last)
			;
		last = addr + size;
		if (last > ei_last)
			continue;
		if (last > end)
			continue;
		return addr;
	}
	return -1ULL;
}

/*
 * Find next free range after *start
 */
u64 __init find_e820_area_size(u64 start, u64 *sizep, u64 align)
{
	int i;

	for (i = 0; i < e820.nr_map; i++) {
		struct e820entry *ei = &e820.map[i];
		u64 addr, last;
		u64 ei_last;

		if (ei->type != E820_RAM)
			continue;
		addr = round_up(ei->addr, align);
		ei_last = ei->addr + ei->size;
		if (addr < start)
			addr = round_up(start, align);
		if (addr >= ei_last)
			continue;
		*sizep = ei_last - addr;
		while (bad_addr_size(&addr, sizep, align) &&
			addr + *sizep <= ei_last)
			;
		last = addr + *sizep;
		if (last > ei_last)
			continue;
		return addr;
	}
	return -1UL;

}

/*
 * pre allocated 4k and reserved it in e820
 */
u64 __init early_reserve_e820(u64 startt, u64 sizet, u64 align)
{
	u64 size = 0;
	u64 addr;
	u64 start;

	start = startt;
	while (size < sizet)
		start = find_e820_area_size(start, &size, align);

	if (size < sizet)
		return 0;

	addr = round_down(start + size - sizet, align);
	e820_update_range(addr, sizet, E820_RAM, E820_RESERVED);
	e820_update_range_saved(addr, sizet, E820_RAM, E820_RESERVED);
	printk(KERN_INFO "update e820 for early_reserve_e820\n");
	update_e820();
	update_e820_saved();
	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		if (entry->type == E820_TYPE_NVS)
			acpi_nvs_register(entry->addr, entry->size);
	}

	return 0;
}
core_initcall(e820__register_nvs_regions);
#endif

/*
 * Allocate the requested number of bytes with the requsted alignment
 * and return (the physical address) to the caller. Also register this
 * range in the 'kexec' E820 table as a reserved range.
 *
 * This allows kexec to fake a new mptable, as if it came from the real
 * system.
 */
u64 __init e820__memblock_alloc_reserved(u64 size, u64 align)
{
	u64 addr;

	addr = __memblock_alloc_base(size, align, MEMBLOCK_ALLOC_ACCESSIBLE);
	if (addr) {
		e820__range_update_kexec(addr, size, E820_TYPE_RAM, E820_TYPE_RESERVED);
		pr_info("e820: update e820_table_kexec for e820__memblock_alloc_reserved()\n");
		e820__update_table_kexec();
	}

	return addr;
}

#ifdef CONFIG_X86_32
# ifdef CONFIG_X86_PAE
#  define MAX_ARCH_PFN		(1ULL<<(36-PAGE_SHIFT))
# else
#  define MAX_ARCH_PFN		(1ULL<<(32-PAGE_SHIFT))
# endif
#else /* CONFIG_X86_32 */
# define MAX_ARCH_PFN MAXMEM>>PAGE_SHIFT
#endif

/*
 * Find the highest page frame number we have available
 */
static unsigned long __init e820_end_pfn(unsigned long limit_pfn, unsigned type)
static unsigned long __init e820_end_pfn(unsigned long limit_pfn)
static unsigned long __init e820_end_pfn(unsigned long limit_pfn, enum e820_type type)
{
	int i;
	unsigned long last_pfn = 0;
	unsigned long max_arch_pfn = MAX_ARCH_PFN;

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];
		unsigned long start_pfn;
		unsigned long end_pfn;

		if (ei->type != type)
		/*
		 * Persistent memory is accounted as ram for purposes of
		 * establishing max_pfn and mem_map.
		 */
		if (ei->type != E820_RAM && ei->type != E820_PRAM)
		if (entry->type != type)
			continue;

		start_pfn = entry->addr >> PAGE_SHIFT;
		end_pfn = (entry->addr + entry->size) >> PAGE_SHIFT;

		if (start_pfn >= limit_pfn)
			continue;
		if (end_pfn > limit_pfn) {
			last_pfn = limit_pfn;
			break;
		}
		if (end_pfn > last_pfn)
			last_pfn = end_pfn;
	}

	if (last_pfn > max_arch_pfn)
		last_pfn = max_arch_pfn;

	printk(KERN_INFO "last_pfn = %#lx max_arch_pfn = %#lx\n",
	printk(KERN_INFO "e820: last_pfn = %#lx max_arch_pfn = %#lx\n",
	pr_info("e820: last_pfn = %#lx max_arch_pfn = %#lx\n",
			 last_pfn, max_arch_pfn);
	return last_pfn;
}

unsigned long __init e820__end_of_ram_pfn(void)
{
	return e820_end_pfn(MAX_ARCH_PFN, E820_RAM);
	return e820_end_pfn(MAX_ARCH_PFN);
	return e820_end_pfn(MAX_ARCH_PFN, E820_TYPE_RAM);
}

unsigned long __init e820__end_of_low_ram_pfn(void)
{
	return e820_end_pfn(1UL<<(32 - PAGE_SHIFT), E820_RAM);
}
/*
 * Finds an active region in the address range from start_pfn to last_pfn and
 * returns its range in ei_startpfn and ei_endpfn for the e820 entry.
 */
int __init e820_find_active_region(const struct e820entry *ei,
				  unsigned long start_pfn,
				  unsigned long last_pfn,
				  unsigned long *ei_startpfn,
				  unsigned long *ei_endpfn)
{
	u64 align = PAGE_SIZE;

	*ei_startpfn = round_up(ei->addr, align) >> PAGE_SHIFT;
	*ei_endpfn = round_down(ei->addr + ei->size, align) >> PAGE_SHIFT;

	/* Skip map entries smaller than a page */
	if (*ei_startpfn >= *ei_endpfn)
		return 0;

	/* Skip if map is outside the node */
	if (ei->type != E820_RAM || *ei_endpfn <= start_pfn ||
				    *ei_startpfn >= last_pfn)
		return 0;

	/* Check for overlaps */
	if (*ei_startpfn < start_pfn)
		*ei_startpfn = start_pfn;
	if (*ei_endpfn > last_pfn)
		*ei_endpfn = last_pfn;

	return 1;
}

/* Walk the e820 map and register active regions within a node */
void __init e820_register_active_regions(int nid, unsigned long start_pfn,
					 unsigned long last_pfn)
{
	unsigned long ei_startpfn;
	unsigned long ei_endpfn;
	int i;

	for (i = 0; i < e820.nr_map; i++)
		if (e820_find_active_region(&e820.map[i],
					    start_pfn, last_pfn,
					    &ei_startpfn, &ei_endpfn))
			add_active_range(nid, ei_startpfn, ei_endpfn);
}

/*
 * Find the hole size (in bytes) in the memory range.
 * @start: starting address of the memory range to scan
 * @end: ending address of the memory range to scan
 */
u64 __init e820_hole_size(u64 start, u64 end)
{
	unsigned long start_pfn = start >> PAGE_SHIFT;
	unsigned long last_pfn = end >> PAGE_SHIFT;
	unsigned long ei_startpfn, ei_endpfn, ram = 0;
	int i;

	for (i = 0; i < e820.nr_map; i++) {
		if (e820_find_active_region(&e820.map[i],
					    start_pfn, last_pfn,
					    &ei_startpfn, &ei_endpfn))
			ram += ei_endpfn - ei_startpfn;
	}
	return end - start - ((u64)ram << PAGE_SHIFT);
	return e820_end_pfn(1UL << (32-PAGE_SHIFT));
	return e820_end_pfn(1UL << (32 - PAGE_SHIFT), E820_TYPE_RAM);
}

static void __init early_panic(char *msg)
{
	early_printk(msg);
	panic(msg);
}

static int userdef __initdata;

/* The "mem=nopentium" boot option disables 4MB page tables on 32-bit kernels: */
static int __init parse_memopt(char *p)
{
	u64 mem_size;

	if (!p)
		return -EINVAL;

#ifdef CONFIG_X86_32
	if (!strcmp(p, "nopentium")) {
		setup_clear_cpu_cap(X86_FEATURE_PSE);
		return 0;
	}
#endif

	userdef = 1;
	mem_size = memparse(p, &p);
	if (!strcmp(p, "nopentium")) {
#ifdef CONFIG_X86_32
		setup_clear_cpu_cap(X86_FEATURE_PSE);
		return 0;
#else
		pr_warn("mem=nopentium ignored! (only supported on x86_32)\n");
		return -EINVAL;
#endif
	}

	userdef = 1;
	mem_size = memparse(p, &p);

	/* Don't remove all memory when getting "mem={invalid}" parameter: */
	if (mem_size == 0)
		return -EINVAL;

	e820__range_remove(mem_size, ULLONG_MAX - mem_size, E820_TYPE_RAM, 1);

	return 0;
}
early_param("mem", parse_memopt);

static int __init parse_memmap_opt(char *p)
static int __init parse_memmap_one(char *p)
{
	char *oldp;
	u64 start_at, mem_size;

	if (!p)
		return -EINVAL;

	if (!strncmp(p, "exactmap", 8)) {
#ifdef CONFIG_CRASH_DUMP
		/*
		 * If we are doing a crash dump, we still need to know
		 * the real memory size before the original memory map is
		 * reset.
		 */
		saved_max_pfn = e820__end_of_ram_pfn();
#endif
		e820_table->nr_entries = 0;
		userdef = 1;
		return 0;
	}

	oldp = p;
	mem_size = memparse(p, &p);
	if (p == oldp)
		return -EINVAL;

	userdef = 1;
	if (*p == '@') {
		start_at = memparse(p+1, &p);
		e820__range_add(start_at, mem_size, E820_TYPE_RAM);
	} else if (*p == '#') {
		start_at = memparse(p+1, &p);
		e820__range_add(start_at, mem_size, E820_TYPE_ACPI);
	} else if (*p == '$') {
		start_at = memparse(p+1, &p);
		e820__range_add(start_at, mem_size, E820_TYPE_RESERVED);
	} else if (*p == '!') {
		start_at = memparse(p+1, &p);
		e820__range_add(start_at, mem_size, E820_TYPE_PRAM);
	} else {
		e820__range_remove(mem_size, ULLONG_MAX - mem_size, E820_TYPE_RAM, 1);
	}

	return *p == '\0' ? 0 : -EINVAL;
}

static int __init parse_memmap_opt(char *str)
{
	while (str) {
		char *k = strchr(str, ',');

		if (k)
			*k++ = 0;

		parse_memmap_one(str);
		str = k;
	}

	return 0;
}
early_param("memmap", parse_memmap_opt);

/*
 * Reserve all entries from the bootloader's extensible data nodes list,
 * because if present we are going to use it later on to fetch e820
 * entries from it:
 */
void __init e820__reserve_setup_data(void)
{
	struct setup_data *data;
	u64 pa_data;

	pa_data = boot_params.hdr.setup_data;
	if (!pa_data)
		return;

	while (pa_data) {
		data = early_memremap(pa_data, sizeof(*data));
		e820__range_update(pa_data, sizeof(*data)+data->len, E820_TYPE_RAM, E820_TYPE_RESERVED_KERN);
		e820__range_update_kexec(pa_data, sizeof(*data)+data->len, E820_TYPE_RAM, E820_TYPE_RESERVED_KERN);
		pa_data = data->next;
		early_memunmap(data, sizeof(*data));
	}

	e820__update_table(e820_table);
	e820__update_table(e820_table_kexec);

	pr_info("extended physical RAM map:\n");
	e820__print_table("reserve setup_data");
}

/*
 * Called after parse_early_param(), after early parameters (such as mem=)
 * have been processed, in which case we already have an E820 table filled in
 * via the parameter callback function(s), but it's not sorted and printed yet:
 */
void __init e820__finish_early_params(void)
{
	if (userdef) {
		int nr = e820.nr_map;

		if (sanitize_e820_map(e820.map, ARRAY_SIZE(e820.map), &nr) < 0)
			early_panic("Invalid user supplied memory map");
		e820.nr_map = nr;

		printk(KERN_INFO "user-defined physical RAM map:\n");
		if (sanitize_e820_map(e820.map, ARRAY_SIZE(e820.map),
					&e820.nr_map) < 0)
		if (e820__update_table(e820_table) < 0)
			early_panic("Invalid user supplied memory map");

		pr_info("e820: user-defined physical RAM map:\n");
		e820__print_table("user");
	}
}

static inline const char *e820_type_to_string(int e820_type)
static const char *e820_type_to_string(int e820_type)
static const char *__init e820_type_to_string(struct e820_entry *entry)
{
	switch (entry->type) {
	case E820_TYPE_RESERVED_KERN:	/* Fall-through: */
	case E820_TYPE_RAM:		return "System RAM";
	case E820_TYPE_ACPI:		return "ACPI Tables";
	case E820_TYPE_NVS:		return "ACPI Non-volatile Storage";
	case E820_TYPE_UNUSABLE:	return "Unusable memory";
	case E820_TYPE_PRAM:		return "Persistent Memory (legacy)";
	case E820_TYPE_PMEM:		return "Persistent Memory";
	case E820_TYPE_RESERVED:	return "Reserved";
	default:			return "Unknown E820 type";
	}
}

/*
 * Mark e820 reserved areas as busy for the resource manager.
 */
static bool do_mark_busy(u32 type, struct resource *res)
static unsigned long __init e820_type_to_iomem_type(struct e820_entry *entry)
{
	switch (entry->type) {
	case E820_TYPE_RESERVED_KERN:	/* Fall-through: */
	case E820_TYPE_RAM:		return IORESOURCE_SYSTEM_RAM;
	case E820_TYPE_ACPI:		/* Fall-through: */
	case E820_TYPE_NVS:		/* Fall-through: */
	case E820_TYPE_UNUSABLE:	/* Fall-through: */
	case E820_TYPE_PRAM:		/* Fall-through: */
	case E820_TYPE_PMEM:		/* Fall-through: */
	case E820_TYPE_RESERVED:	/* Fall-through: */
	default:			return IORESOURCE_MEM;
	}
}

static unsigned long __init e820_type_to_iores_desc(struct e820_entry *entry)
{
	switch (entry->type) {
	case E820_TYPE_ACPI:		return IORES_DESC_ACPI_TABLES;
	case E820_TYPE_NVS:		return IORES_DESC_ACPI_NV_STORAGE;
	case E820_TYPE_PMEM:		return IORES_DESC_PERSISTENT_MEMORY;
	case E820_TYPE_PRAM:		return IORES_DESC_PERSISTENT_MEMORY_LEGACY;
	case E820_TYPE_RESERVED_KERN:	/* Fall-through: */
	case E820_TYPE_RAM:		/* Fall-through: */
	case E820_TYPE_UNUSABLE:	/* Fall-through: */
	case E820_TYPE_RESERVED:	/* Fall-through: */
	default:			return IORES_DESC_NONE;
	}
}

static bool __init do_mark_busy(enum e820_type type, struct resource *res)
{
	/* this is the legacy bios/dos rom-shadow + mmio region */
	if (res->start < (1ULL<<20))
		return true;

	/*
	 * Treat persistent memory like device memory, i.e. reserve it
	 * for exclusive use of a driver
	 */
	switch (type) {
	case E820_TYPE_RESERVED:
	case E820_TYPE_PRAM:
	case E820_TYPE_PMEM:
		return false;
	case E820_TYPE_RESERVED_KERN:
	case E820_TYPE_RAM:
	case E820_TYPE_ACPI:
	case E820_TYPE_NVS:
	case E820_TYPE_UNUSABLE:
	default:
		return true;
	}
}

/*
 * Mark E820 reserved areas as busy for the resource manager:
 */

static struct resource __initdata *e820_res;

void __init e820__reserve_resources(void)
{
	int i;
	struct resource *res;
	u64 end;

	res = alloc_bootmem_low(sizeof(struct resource) * e820.nr_map);
	for (i = 0; i < e820.nr_map; i++) {
		end = e820.map[i].addr + e820.map[i].size - 1;
#ifndef CONFIG_RESOURCES_64BIT
		if (end > 0x100000000ULL) {
			res++;
			continue;
		}
#endif
	res = alloc_bootmem(sizeof(struct resource) * e820.nr_map);
	res = alloc_bootmem(sizeof(*res) * e820_table->nr_entries);
	e820_res = res;

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = e820_table->entries + i;

		end = entry->addr + entry->size - 1;
		if (end != (resource_size_t)end) {
			res++;
			continue;
		}
		res->name = e820_type_to_string(e820.map[i].type);
		res->start = e820.map[i].addr;
		res->end = end;

		res->flags = IORESOURCE_MEM | IORESOURCE_BUSY;
		insert_resource(&iomem_resource, res);
		res->flags = IORESOURCE_MEM;
		res->start = entry->addr;
		res->end   = end;
		res->name  = e820_type_to_string(entry);
		res->flags = e820_type_to_iomem_type(entry);
		res->desc  = e820_type_to_iores_desc(entry);

		/*
		 * Don't register the region that could be conflicted with
		 * PCI device BAR resources and insert them later in
		 * pcibios_resource_survey():
		 */
		if (do_mark_busy(entry->type, res)) {
			res->flags |= IORESOURCE_BUSY;
			insert_resource(&iomem_resource, res);
		}
		res++;
	}

	for (i = 0; i < e820_saved.nr_map; i++) {
		struct e820entry *entry = &e820_saved.map[i];
		firmware_map_add_early(entry->addr,
			entry->addr + entry->size - 1,
			entry->addr + entry->size,
			e820_type_to_string(entry->type));
	}
}

char *__init default_machine_specific_memory_setup(void)
{
	char *who = "BIOS-e820";
	int new_nr;
/* How much should we pad RAM ending depending on where it is? */
static unsigned long ram_alignment(resource_size_t pos)
	/* Expose the bootloader-provided memory layout to the sysfs. */
	for (i = 0; i < e820_table_firmware->nr_entries; i++) {
		struct e820_entry *entry = e820_table_firmware->entries + i;

		firmware_map_add_early(entry->addr, entry->addr + entry->size, e820_type_to_string(entry));
	}
}

/*
 * How much should we pad the end of RAM, depending on where it is?
 */
static unsigned long __init ram_alignment(resource_size_t pos)
{
	unsigned long mb = pos >> 20;

	/* To 64kB in the first megabyte */
	if (!mb)
		return 64*1024;

	/* To 1MB in the first 16MB */
	if (mb < 16)
		return 1024*1024;

	/* To 64MB for anything above that */
	return 64*1024*1024;
}

#define MAX_RESOURCE_SIZE ((resource_size_t)-1)

void __init e820__reserve_resources_late(void)
{
	int i;
	struct resource *res;

	res = e820_res;
	for (i = 0; i < e820_table->nr_entries; i++) {
		if (!res->parent && res->end)
			insert_resource_expand_to_fit(&iomem_resource, res);
		res++;
	}

	/*
	 * Try to bump up RAM regions to reasonable boundaries, to
	 * avoid stolen RAM:
	 */
	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];
		u64 start, end;

		if (entry->type != E820_TYPE_RAM)
			continue;

		start = entry->addr + entry->size;
		end = round_up(start, ram_alignment(start)) - 1;
		if (end > MAX_RESOURCE_SIZE)
			end = MAX_RESOURCE_SIZE;
		if (start >= end)
			continue;

		printk(KERN_DEBUG "e820: reserve RAM buffer [mem %#010llx-%#010llx]\n", start, end);
		reserve_region_with_split(&iomem_resource, start, end, "RAM buffer");
	}
}

/*
 * Pass the firmware (bootloader) E820 map to the kernel and process it:
 */
char *__init e820__memory_setup_default(void)
{
	char *who = "BIOS-e820";

	/*
	 * Try to copy the BIOS-supplied E820-map.
	 *
	 * Otherwise fake a memory map; one section from 0k->640k,
	 * the next section from 1mb->appropriate_mem_k
	 */
	if (append_e820_table(boot_params.e820_table, boot_params.e820_entries) < 0) {
		u64 mem_size;

		/* Compare results from other methods and take the one that gives more RAM: */
		if (boot_params.alt_mem_k < boot_params.screen_info.ext_mem_k) {
			mem_size = boot_params.screen_info.ext_mem_k;
			who = "BIOS-88";
		} else {
			mem_size = boot_params.alt_mem_k;
			who = "BIOS-e801";
		}

		e820_table->nr_entries = 0;
		e820__range_add(0, LOWMEMSIZE(), E820_TYPE_RAM);
		e820__range_add(HIGH_MEMORY, mem_size << 10, E820_TYPE_RAM);
	}

	/* We just appended a lot of ranges, sanitize the table: */
	e820__update_table(e820_table);

	return who;
}

char *__init __attribute__((weak)) machine_specific_memory_setup(void)
{
	if (x86_quirks->arch_memory_setup) {
		char *who = x86_quirks->arch_memory_setup();

		if (who)
			return who;
	}
	return default_machine_specific_memory_setup();
}

/* Overridden in paravirt.c if CONFIG_PARAVIRT */
char * __init __attribute__((weak)) memory_setup(void)
{
	return machine_specific_memory_setup();
}

void __init setup_memory_map(void)
{
	char *who;

	who = memory_setup();
	memcpy(&e820_saved, &e820, sizeof(struct e820map));
	printk(KERN_INFO "BIOS-provided physical RAM map:\n");
	e820_print_map(who);
}
/*
 * Calls e820__memory_setup_default() in essence to pick up the firmware/bootloader
 * E820 map - with an optional platform quirk available for virtual platforms
 * to override this method of boot environment processing:
 */
void __init e820__memory_setup(void)
{
	char *who;

	/* This is a firmware interface ABI - make sure we don't break it: */
	BUILD_BUG_ON(sizeof(struct boot_e820_entry) != 20);

	who = x86_init.resources.memory_setup();

	memcpy(e820_table_kexec, e820_table, sizeof(*e820_table_kexec));
	memcpy(e820_table_firmware, e820_table, sizeof(*e820_table_firmware));

	pr_info("e820: BIOS-provided physical RAM map:\n");
	e820__print_table(who);
}

void __init e820__memblock_setup(void)
{
	int i;
	u64 end;

	/*
	 * The bootstrap memblock region count maximum is 128 entries
	 * (INIT_MEMBLOCK_REGIONS), but EFI might pass us more E820 entries
	 * than that - so allow memblock resizing.
	 *
	 * This is safe, because this call happens pretty late during x86 setup,
	 * so we know about reserved memory regions already. (This is important
	 * so that memblock resizing does no stomp over reserved areas.)
	 */
	memblock_allow_resize();

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		end = entry->addr + entry->size;
		if (end != (resource_size_t)end)
			continue;

		if (entry->type != E820_TYPE_RAM && entry->type != E820_TYPE_RESERVED_KERN)
			continue;

		memblock_add(entry->addr, entry->size);
	}

	/* Throw away partial pages: */
	memblock_trim_memory(PAGE_SIZE);

	memblock_dump_all();
}
