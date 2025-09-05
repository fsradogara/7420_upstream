/*
   raid0.c : Multiple Devices driver for Linux
             Copyright (C) 1994-96 Marc ZYNGIER
	     <zyngier@ufr-info-p7.ibp.fr> or
	     <maz@gloups.fdn.fr>
             Copyright (C) 1999, 2000 Ingo Molnar, Red Hat

	     Copyright (C) 1994-96 Marc ZYNGIER
	     <zyngier@ufr-info-p7.ibp.fr> or
	     <maz@gloups.fdn.fr>
	     Copyright (C) 1999, 2000 Ingo Molnar, Red Hat

   RAID-0 management functions.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.
   
   You should have received a copy of the GNU General Public License
   (for example /usr/src/linux/COPYING); if not, write to the Free
   Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  
*/

#include <linux/module.h>
#include <linux/raid/raid0.h>

#define MAJOR_NR MD_MAJOR
#define MD_DRIVER
#define MD_PERSONALITY

static void raid0_unplug(struct request_queue *q)
{
	mddev_t *mddev = q->queuedata;
	raid0_conf_t *conf = mddev_to_conf(mddev);
	mdk_rdev_t **devlist = conf->strip_zone[0].dev;
	int i;

	for (i=0; i<mddev->raid_disks; i++) {
		struct request_queue *r_queue = bdev_get_queue(devlist[i]->bdev);

		blk_unplug(r_queue);
	}
}

static int raid0_congested(void *data, int bits)
{
	mddev_t *mddev = data;
	raid0_conf_t *conf = mddev_to_conf(mddev);
	mdk_rdev_t **devlist = conf->strip_zone[0].dev;
	int i, ret = 0;

	for (i = 0; i < mddev->raid_disks && !ret ; i++) {

   You should have received a copy of the GNU General Public License
   (for example /usr/src/linux/COPYING); if not, write to the Free
   Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <linux/blkdev.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <trace/events/block.h>
#include "md.h"
#include "raid0.h"
#include "raid5.h"

#define UNSUPPORTED_MDDEV_FLAGS		\
	((1L << MD_HAS_JOURNAL) |	\
	 (1L << MD_JOURNAL_CLEAN) |	\
	 (1L << MD_FAILFAST_SUPPORTED) |\
	 (1L << MD_HAS_PPL) |		\
	 (1L << MD_HAS_MULTIPLE_PPLS))

static int raid0_congested(struct mddev *mddev, int bits)
{
	struct r0conf *conf = mddev->private;
	struct md_rdev **devlist = conf->devlist;
	int raid_disks = conf->strip_zone[0].nb_dev;
	int i, ret = 0;

	for (i = 0; i < raid_disks && !ret ; i++) {
		struct request_queue *q = bdev_get_queue(devlist[i]->bdev);

		ret |= bdi_congested(q->backing_dev_info, bits);
	}
	return ret;
}


static int create_strip_zones (mddev_t *mddev)
{
	int i, c, j;
	sector_t current_offset, curr_zone_offset;
	sector_t min_spacing;
	raid0_conf_t *conf = mddev_to_conf(mddev);
	mdk_rdev_t *smallest, *rdev1, *rdev2, *rdev;
	struct list_head *tmp1, *tmp2;
	struct strip_zone *zone;
	int cnt;
	char b[BDEVNAME_SIZE];
 
	/*
	 * The number of 'same size groups'
	 */
	conf->nr_strip_zones = 0;
 
	rdev_for_each(rdev1, tmp1, mddev) {
		printk("raid0: looking at %s\n",
			bdevname(rdev1->bdev,b));
		c = 0;
		rdev_for_each(rdev2, tmp2, mddev) {
			printk("raid0:   comparing %s(%llu)",
			       bdevname(rdev1->bdev,b),
			       (unsigned long long)rdev1->size);
			printk(" with %s(%llu)\n",
			       bdevname(rdev2->bdev,b),
			       (unsigned long long)rdev2->size);
			if (rdev2 == rdev1) {
				printk("raid0:   END\n");
				break;
			}
			if (rdev2->size == rdev1->size)
			{
/*
 * inform the user of the raid configuration
*/
static void dump_zones(struct mddev *mddev)
{
	int j, k;
	sector_t zone_size = 0;
	sector_t zone_start = 0;
	char b[BDEVNAME_SIZE];
	struct r0conf *conf = mddev->private;
	int raid_disks = conf->strip_zone[0].nb_dev;
	pr_debug("md: RAID0 configuration for %s - %d zone%s\n",
		 mdname(mddev),
		 conf->nr_strip_zones, conf->nr_strip_zones==1?"":"s");
	for (j = 0; j < conf->nr_strip_zones; j++) {
		char line[200];
		int len = 0;

		for (k = 0; k < conf->strip_zone[j].nb_dev; k++)
			len += snprintf(line+len, 200-len, "%s%s", k?"/":"",
					bdevname(conf->devlist[j*raid_disks
							       + k]->bdev, b));
		pr_debug("md: zone%d=[%s]\n", j, line);

		zone_size  = conf->strip_zone[j].zone_end - zone_start;
		pr_debug("      zone-offset=%10lluKB, device-offset=%10lluKB, size=%10lluKB\n",
			(unsigned long long)zone_start>>1,
			(unsigned long long)conf->strip_zone[j].dev_start>>1,
			(unsigned long long)zone_size>>1);
		zone_start = conf->strip_zone[j].zone_end;
	}
}

static int create_strip_zones(struct mddev *mddev, struct r0conf **private_conf)
{
	int i, c, err;
	sector_t curr_zone_end, sectors;
	struct md_rdev *smallest, *rdev1, *rdev2, *rdev, **dev;
	struct strip_zone *zone;
	int cnt;
	char b[BDEVNAME_SIZE];
	char b2[BDEVNAME_SIZE];
	struct r0conf *conf = kzalloc(sizeof(*conf), GFP_KERNEL);
	unsigned short blksize = 512;

	*private_conf = ERR_PTR(-ENOMEM);
	if (!conf)
		return -ENOMEM;
	rdev_for_each(rdev1, mddev) {
		pr_debug("md/raid0:%s: looking at %s\n",
			 mdname(mddev),
			 bdevname(rdev1->bdev, b));
		c = 0;

		/* round size to chunk_size */
		sectors = rdev1->sectors;
		sector_div(sectors, mddev->chunk_sectors);
		rdev1->sectors = sectors * mddev->chunk_sectors;

		blksize = max(blksize, queue_logical_block_size(
				      rdev1->bdev->bd_disk->queue));

		rdev_for_each(rdev2, mddev) {
			pr_debug("md/raid0:%s:   comparing %s(%llu)"
				 " with %s(%llu)\n",
				 mdname(mddev),
				 bdevname(rdev1->bdev,b),
				 (unsigned long long)rdev1->sectors,
				 bdevname(rdev2->bdev,b2),
				 (unsigned long long)rdev2->sectors);
			if (rdev2 == rdev1) {
				pr_debug("md/raid0:%s:   END\n",
					 mdname(mddev));
				break;
			}
			if (rdev2->sectors == rdev1->sectors) {
				/*
				 * Not unique, don't count it as a new
				 * group
				 */
				printk("raid0:   EQUAL\n");
				c = 1;
				break;
			}
			printk("raid0:   NOT EQUAL\n");
		}
		if (!c) {
			printk("raid0:   ==> UNIQUE\n");
			conf->nr_strip_zones++;
			printk("raid0: %d zones\n", conf->nr_strip_zones);
		}
	}
	printk("raid0: FINAL %d zones\n", conf->nr_strip_zones);

	conf->strip_zone = kzalloc(sizeof(struct strip_zone)*
				conf->nr_strip_zones, GFP_KERNEL);
	if (!conf->strip_zone)
		return 1;
	conf->devlist = kzalloc(sizeof(mdk_rdev_t*)*
				conf->nr_strip_zones*mddev->raid_disks,
				GFP_KERNEL);
	if (!conf->devlist)
		return 1;
				pr_debug("md/raid0:%s:   EQUAL\n",
					 mdname(mddev));
				c = 1;
				break;
			}
			pr_debug("md/raid0:%s:   NOT EQUAL\n",
				 mdname(mddev));
		}
		if (!c) {
			pr_debug("md/raid0:%s:   ==> UNIQUE\n",
				 mdname(mddev));
			conf->nr_strip_zones++;
			pr_debug("md/raid0:%s: %d zones\n",
				 mdname(mddev), conf->nr_strip_zones);
		}
	}
	pr_debug("md/raid0:%s: FINAL %d zones\n",
		 mdname(mddev), conf->nr_strip_zones);
	/*
	 * now since we have the hard sector sizes, we can make sure
	 * chunk size is a multiple of that sector size
	 */
	if ((mddev->chunk_sectors << 9) % blksize) {
		pr_warn("md/raid0:%s: chunk_size of %d not multiple of block size %d\n",
			mdname(mddev),
			mddev->chunk_sectors << 9, blksize);
		err = -EINVAL;
		goto abort;
	}

	err = -ENOMEM;
	conf->strip_zone = kzalloc(sizeof(struct strip_zone)*
				conf->nr_strip_zones, GFP_KERNEL);
	if (!conf->strip_zone)
		goto abort;
	conf->devlist = kzalloc(sizeof(struct md_rdev*)*
				conf->nr_strip_zones*mddev->raid_disks,
				GFP_KERNEL);
	if (!conf->devlist)
		goto abort;

	/* The first zone must contain all devices, so here we check that
	 * there is a proper alignment of slots to devices and find them all
	 */
	zone = &conf->strip_zone[0];
	cnt = 0;
	smallest = NULL;
	zone->dev = conf->devlist;
	rdev_for_each(rdev1, tmp1, mddev) {
		int j = rdev1->raid_disk;

		if (j < 0 || j >= mddev->raid_disks) {
			printk("raid0: bad disk number %d - aborting!\n", j);
			goto abort;
		}
		if (zone->dev[j]) {
			printk("raid0: multiple devices for %d - aborting!\n",
				j);
			goto abort;
		}
		zone->dev[j] = rdev1;

		blk_queue_stack_limits(mddev->queue,
				       rdev1->bdev->bd_disk->queue);
		/* as we don't honour merge_bvec_fn, we must never risk
		 * violating it, so limit ->max_sector to one PAGE, as
		 * a one page request is never in violation.
		 */

		if (rdev1->bdev->bd_disk->queue->merge_bvec_fn &&
		    mddev->queue->max_sectors > (PAGE_SIZE>>9))
			blk_queue_max_sectors(mddev->queue, PAGE_SIZE>>9);

		if (!smallest || (rdev1->size <smallest->size))
	dev = conf->devlist;
	err = -EINVAL;
	rdev_for_each(rdev1, mddev) {
		int j = rdev1->raid_disk;

		if (mddev->level == 10) {
			/* taking over a raid10-n2 array */
			j /= 2;
			rdev1->new_raid_disk = j;
		}

		if (mddev->level == 1) {
			/* taiking over a raid1 array-
			 * we have only one active disk
			 */
			j = 0;
			rdev1->new_raid_disk = j;
		}

		if (j < 0) {
			pr_warn("md/raid0:%s: remove inactive devices before converting to RAID0\n",
				mdname(mddev));
			goto abort;
		}
		if (j >= mddev->raid_disks) {
			pr_warn("md/raid0:%s: bad disk number %d - aborting!\n",
				mdname(mddev), j);
			goto abort;
		}
		if (dev[j]) {
			pr_warn("md/raid0:%s: multiple devices for %d - aborting!\n",
				mdname(mddev), j);
			goto abort;
		}
		dev[j] = rdev1;

		if (!smallest || (rdev1->sectors < smallest->sectors))
			smallest = rdev1;
		cnt++;
	}
	if (cnt != mddev->raid_disks) {
		printk("raid0: too few disks (%d of %d) - aborting!\n",
			cnt, mddev->raid_disks);
		goto abort;
	}
	zone->nb_dev = cnt;
	zone->size = smallest->size * cnt;
	zone->zone_offset = 0;

	current_offset = smallest->size;
	curr_zone_offset = zone->size;
		printk(KERN_ERR "md/raid0:%s: too few disks (%d of %d) - "
		       "aborting!\n", mdname(mddev), cnt, mddev->raid_disks);
		pr_warn("md/raid0:%s: too few disks (%d of %d) - aborting!\n",
			mdname(mddev), cnt, mddev->raid_disks);
		goto abort;
	}
	zone->nb_dev = cnt;
	zone->zone_end = smallest->sectors * cnt;

	curr_zone_end = zone->zone_end;

	/* now do the other zones */
	for (i = 1; i < conf->nr_strip_zones; i++)
	{
		zone = conf->strip_zone + i;
		zone->dev = conf->strip_zone[i-1].dev + mddev->raid_disks;

		printk("raid0: zone %d\n", i);
		zone->dev_offset = current_offset;
		int j;

		zone = conf->strip_zone + i;
		dev = conf->devlist + i * mddev->raid_disks;

		pr_debug("md/raid0:%s: zone %d\n", mdname(mddev), i);
		zone->dev_start = smallest->sectors;
		smallest = NULL;
		c = 0;

		for (j=0; j<cnt; j++) {
			char b[BDEVNAME_SIZE];
			rdev = conf->strip_zone[0].dev[j];
			printk("raid0: checking %s ...", bdevname(rdev->bdev,b));
			if (rdev->size > current_offset)
			{
				printk(" contained as device %d\n", c);
				zone->dev[c] = rdev;
				c++;
				if (!smallest || (rdev->size <smallest->size)) {
					smallest = rdev;
					printk("  (%llu) is smallest!.\n", 
						(unsigned long long)rdev->size);
				}
			} else
				printk(" nope.\n");
		}

		zone->nb_dev = c;
		zone->size = (smallest->size - current_offset) * c;
		printk("raid0: zone->nb_dev: %d, size: %llu\n",
			zone->nb_dev, (unsigned long long)zone->size);

		zone->zone_offset = curr_zone_offset;
		curr_zone_offset += zone->size;

		current_offset = smallest->size;
		printk("raid0: current zone offset: %llu\n",
			(unsigned long long)current_offset);
	}

	/* Now find appropriate hash spacing.
	 * We want a number which causes most hash entries to cover
	 * at most two strips, but the hash table must be at most
	 * 1 PAGE.  We choose the smallest strip, or contiguous collection
	 * of strips, that has big enough size.  We never consider the last
	 * strip though as it's size has no bearing on the efficacy of the hash
	 * table.
	 */
	conf->hash_spacing = curr_zone_offset;
	min_spacing = curr_zone_offset;
	sector_div(min_spacing, PAGE_SIZE/sizeof(struct strip_zone*));
	for (i=0; i < conf->nr_strip_zones-1; i++) {
		sector_t sz = 0;
		for (j=i; j<conf->nr_strip_zones-1 &&
			     sz < min_spacing ; j++)
			sz += conf->strip_zone[j].size;
		if (sz >= min_spacing && sz < conf->hash_spacing)
			conf->hash_spacing = sz;
	}

	mddev->queue->unplug_fn = raid0_unplug;

	mddev->queue->backing_dev_info.congested_fn = raid0_congested;
	mddev->queue->backing_dev_info.congested_data = mddev;

	printk("raid0: done.\n");
	return 0;
 abort:
	return 1;
}

/**
 *	raid0_mergeable_bvec -- tell bio layer if a two requests can be merged
 *	@q: request queue
 *	@bvm: properties of new bio
 *	@biovec: the request that could be merged to it.
 *
 *	Return amount of bytes we can accept at this offset
 */
static int raid0_mergeable_bvec(struct request_queue *q,
				struct bvec_merge_data *bvm,
				struct bio_vec *biovec)
{
	mddev_t *mddev = q->queuedata;
	sector_t sector = bvm->bi_sector + get_start_sect(bvm->bi_bdev);
	int max;
	unsigned int chunk_sectors = mddev->chunk_size >> 9;
	unsigned int bio_sectors = bvm->bi_size >> 9;

	max =  (chunk_sectors - ((sector & (chunk_sectors - 1)) + bio_sectors)) << 9;
	if (max < 0) max = 0; /* bio_add cannot handle a negative return */
	if (max <= biovec->bv_len && bio_sectors == 0)
		return biovec->bv_len;
	else 
		return max;
}

static int raid0_run (mddev_t *mddev)
{
	unsigned  cur=0, i=0, nb_zone;
	s64 size;
	raid0_conf_t *conf;
	mdk_rdev_t *rdev;
	struct list_head *tmp;

	if (mddev->chunk_size == 0) {
		printk(KERN_ERR "md/raid0: non-zero chunk size required.\n");
		return -EINVAL;
	}
	printk(KERN_INFO "%s: setting max_sectors to %d, segment boundary to %d\n",
	       mdname(mddev),
	       mddev->chunk_size >> 9,
	       (mddev->chunk_size>>1)-1);
	blk_queue_max_sectors(mddev->queue, mddev->chunk_size >> 9);
	blk_queue_segment_boundary(mddev->queue, (mddev->chunk_size>>1) - 1);
	mddev->queue->queue_lock = &mddev->queue->__queue_lock;

	conf = kmalloc(sizeof (raid0_conf_t), GFP_KERNEL);
	if (!conf)
		goto out;
	mddev->private = (void *)conf;
 
	conf->strip_zone = NULL;
	conf->devlist = NULL;
	if (create_strip_zones (mddev)) 
		goto out_free_conf;

	/* calculate array device size */
	mddev->array_sectors = 0;
	rdev_for_each(rdev, tmp, mddev)
		mddev->array_sectors += rdev->size * 2;

	printk("raid0 : md_size is %llu blocks.\n", 
		(unsigned long long)mddev->array_sectors / 2);
	printk("raid0 : conf->hash_spacing is %llu blocks.\n",
		(unsigned long long)conf->hash_spacing);
	{
		sector_t s = mddev->array_sectors / 2;
		sector_t space = conf->hash_spacing;
		int round;
		conf->preshift = 0;
		if (sizeof(sector_t) > sizeof(u32)) {
			/*shift down space and s so that sector_div will work */
			while (space > (sector_t) (~(u32)0)) {
				s >>= 1;
				space >>= 1;
				s += 1; /* force round-up */
				conf->preshift++;
			}
		}
		round = sector_div(s, (u32)space) ? 1 : 0;
		nb_zone = s + round;
	}
	printk("raid0 : nb_zone is %d.\n", nb_zone);

	printk("raid0 : Allocating %Zd bytes for hash.\n",
				nb_zone*sizeof(struct strip_zone*));
	conf->hash_table = kmalloc (sizeof (struct strip_zone *)*nb_zone, GFP_KERNEL);
	if (!conf->hash_table)
		goto out_free_conf;
	size = conf->strip_zone[cur].size;

	conf->hash_table[0] = conf->strip_zone + cur;
	for (i=1; i< nb_zone; i++) {
		while (size <= conf->hash_spacing) {
			cur++;
			size += conf->strip_zone[cur].size;
		}
		size -= conf->hash_spacing;
		conf->hash_table[i] = conf->strip_zone + cur;
	}
	if (conf->preshift) {
		conf->hash_spacing >>= conf->preshift;
		/* round hash_spacing up so when we divide by it, we
		 * err on the side of too-low, which is safest
		 */
		conf->hash_spacing++;
	}

	/* calculate the max read-ahead size.
	 * For read-ahead of large files to be effective, we need to
	 * readahead at least twice a whole stripe. i.e. number of devices
	 * multiplied by chunk size times 2.
	 * If an individual device has an ra_pages greater than the
	 * chunk size, then we will not drive that device as hard as it
	 * wants.  We consider this a configuration error: a larger
	 * chunksize should be used in that case.
	 */
	{
		int stripe = mddev->raid_disks * mddev->chunk_size / PAGE_SIZE;
			rdev = conf->devlist[j];
			if (rdev->sectors <= zone->dev_start) {
				pr_debug("md/raid0:%s: checking %s ... nope\n",
					 mdname(mddev),
					 bdevname(rdev->bdev, b));
				continue;
			}
			pr_debug("md/raid0:%s: checking %s ..."
				 " contained as device %d\n",
				 mdname(mddev),
				 bdevname(rdev->bdev, b), c);
			dev[c] = rdev;
			c++;
			if (!smallest || rdev->sectors < smallest->sectors) {
				smallest = rdev;
				pr_debug("md/raid0:%s:  (%llu) is smallest!.\n",
					 mdname(mddev),
					 (unsigned long long)rdev->sectors);
			}
		}

		zone->nb_dev = c;
		sectors = (smallest->sectors - zone->dev_start) * c;
		pr_debug("md/raid0:%s: zone->nb_dev: %d, sectors: %llu\n",
			 mdname(mddev),
			 zone->nb_dev, (unsigned long long)sectors);

		curr_zone_end += sectors;
		zone->zone_end = curr_zone_end;

		pr_debug("md/raid0:%s: current zone start: %llu\n",
			 mdname(mddev),
			 (unsigned long long)smallest->sectors);
	}

	pr_debug("md/raid0:%s: done.\n", mdname(mddev));
	*private_conf = conf;

	return 0;
abort:
	kfree(conf->strip_zone);
	kfree(conf->devlist);
	kfree(conf);
	*private_conf = ERR_PTR(err);
	return err;
}

/* Find the zone which holds a particular offset
 * Update *sectorp to be an offset in that zone
 */
static struct strip_zone *find_zone(struct r0conf *conf,
				    sector_t *sectorp)
{
	int i;
	struct strip_zone *z = conf->strip_zone;
	sector_t sector = *sectorp;

	for (i = 0; i < conf->nr_strip_zones; i++)
		if (sector < z[i].zone_end) {
			if (i)
				*sectorp = sector - z[i-1].zone_end;
			return z + i;
		}
	BUG();
}

/*
 * remaps the bio to the target device. we separate two flows.
 * power 2 flow and a general flow for the sake of performance
*/
static struct md_rdev *map_sector(struct mddev *mddev, struct strip_zone *zone,
				sector_t sector, sector_t *sector_offset)
{
	unsigned int sect_in_chunk;
	sector_t chunk;
	struct r0conf *conf = mddev->private;
	int raid_disks = conf->strip_zone[0].nb_dev;
	unsigned int chunk_sects = mddev->chunk_sectors;

	if (is_power_of_2(chunk_sects)) {
		int chunksect_bits = ffz(~chunk_sects);
		/* find the sector offset inside the chunk */
		sect_in_chunk  = sector & (chunk_sects - 1);
		sector >>= chunksect_bits;
		/* chunk in zone */
		chunk = *sector_offset;
		/* quotient is the chunk in real device*/
		sector_div(chunk, zone->nb_dev << chunksect_bits);
	} else{
		sect_in_chunk = sector_div(sector, chunk_sects);
		chunk = *sector_offset;
		sector_div(chunk, chunk_sects * zone->nb_dev);
	}
	/*
	*  position the bio over the real device
	*  real sector = chunk in device + starting of zone
	*	+ the position in the chunk
	*/
	*sector_offset = (chunk * chunk_sects) + sect_in_chunk;
	return conf->devlist[(zone - conf->strip_zone)*raid_disks
			     + sector_div(sector, zone->nb_dev)];
}

static sector_t raid0_size(struct mddev *mddev, sector_t sectors, int raid_disks)
{
	sector_t array_sectors = 0;
	struct md_rdev *rdev;

	WARN_ONCE(sectors || raid_disks,
		  "%s does not support generic reshape\n", __func__);

	rdev_for_each(rdev, mddev)
		array_sectors += (rdev->sectors &
				  ~(sector_t)(mddev->chunk_sectors-1));

	return array_sectors;
}

static void raid0_free(struct mddev *mddev, void *priv);

static int raid0_run(struct mddev *mddev)
{
	struct r0conf *conf;
	int ret;

	if (mddev->chunk_sectors == 0) {
		pr_warn("md/raid0:%s: chunk size must be set.\n", mdname(mddev));
		return -EINVAL;
	}
	if (md_check_no_bitmap(mddev))
		return -EINVAL;

	/* if private is not null, we are here after takeover */
	if (mddev->private == NULL) {
		ret = create_strip_zones(mddev, &conf);
		if (ret < 0)
			return ret;
		mddev->private = conf;
	}
	conf = mddev->private;
	if (mddev->queue) {
		struct md_rdev *rdev;
		bool discard_supported = false;

		blk_queue_max_hw_sectors(mddev->queue, mddev->chunk_sectors);
		blk_queue_max_write_same_sectors(mddev->queue, mddev->chunk_sectors);
		blk_queue_max_write_zeroes_sectors(mddev->queue, mddev->chunk_sectors);
		blk_queue_max_discard_sectors(mddev->queue, UINT_MAX);

		blk_queue_io_min(mddev->queue, mddev->chunk_sectors << 9);
		blk_queue_io_opt(mddev->queue,
				 (mddev->chunk_sectors << 9) * mddev->raid_disks);

		rdev_for_each(rdev, mddev) {
			disk_stack_limits(mddev->gendisk, rdev->bdev,
					  rdev->data_offset << 9);
			if (blk_queue_discard(bdev_get_queue(rdev->bdev)))
				discard_supported = true;
		}
		if (!discard_supported)
			queue_flag_clear_unlocked(QUEUE_FLAG_DISCARD, mddev->queue);
		else
			queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, mddev->queue);
	}

	/* calculate array device size */
	md_set_array_sectors(mddev, raid0_size(mddev, 0, 0));

	pr_debug("md/raid0:%s: md_size is %llu sectors.\n",
		 mdname(mddev),
		 (unsigned long long)mddev->array_sectors);

	if (mddev->queue) {
		/* calculate the max read-ahead size.
		 * For read-ahead of large files to be effective, we need to
		 * readahead at least twice a whole stripe. i.e. number of devices
		 * multiplied by chunk size times 2.
		 * If an individual device has an ra_pages greater than the
		 * chunk size, then we will not drive that device as hard as it
		 * wants.  We consider this a configuration error: a larger
		 * chunksize should be used in that case.
		 */
		int stripe = mddev->raid_disks *
			(mddev->chunk_sectors << 9) / PAGE_SIZE;
		if (mddev->queue->backing_dev_info->ra_pages < 2* stripe)
			mddev->queue->backing_dev_info->ra_pages = 2* stripe;
	}


	blk_queue_merge_bvec(mddev->queue, raid0_mergeable_bvec);
	return 0;

out_free_conf:
	kfree(conf->strip_zone);
	kfree(conf->devlist);
	kfree(conf);
	mddev->private = NULL;
out:
	return -ENOMEM;
}

static int raid0_stop (mddev_t *mddev)
{
	raid0_conf_t *conf = mddev_to_conf(mddev);

	blk_sync_queue(mddev->queue); /* the unplug fn references 'conf'*/
	kfree(conf->hash_table);
	conf->hash_table = NULL;
	kfree(conf->strip_zone);
	conf->strip_zone = NULL;
	kfree(conf);
	mddev->private = NULL;

	return 0;
}

static int raid0_make_request (struct request_queue *q, struct bio *bio)
{
	mddev_t *mddev = q->queuedata;
	unsigned int sect_in_chunk, chunksize_bits,  chunk_size, chunk_sects;
	raid0_conf_t *conf = mddev_to_conf(mddev);
	struct strip_zone *zone;
	mdk_rdev_t *tmp_dev;
	sector_t chunk;
	sector_t block, rsect;
	const int rw = bio_data_dir(bio);

	if (unlikely(bio_barrier(bio))) {
		bio_endio(bio, -EOPNOTSUPP);
		return 0;
	}

	disk_stat_inc(mddev->gendisk, ios[rw]);
	disk_stat_add(mddev->gendisk, sectors[rw], bio_sectors(bio));

	chunk_size = mddev->chunk_size >> 10;
	chunk_sects = mddev->chunk_size >> 9;
	chunksize_bits = ffz(~chunk_size);
	block = bio->bi_sector >> 1;
	

	if (unlikely(chunk_sects < (bio->bi_sector & (chunk_sects - 1)) + (bio->bi_size >> 9))) {
		struct bio_pair *bp;
		/* Sanity check -- queue functions should prevent this happening */
		if (bio->bi_vcnt != 1 ||
		    bio->bi_idx != 0)
			goto bad_map;
		/* This is a one page bio that upper layers
		 * refuse to split for us, so we need to split it.
		 */
		bp = bio_split(bio, bio_split_pool, chunk_sects - (bio->bi_sector & (chunk_sects - 1)) );
		if (raid0_make_request(q, &bp->bio1))
			generic_make_request(&bp->bio1);
		if (raid0_make_request(q, &bp->bio2))
			generic_make_request(&bp->bio2);

		bio_pair_release(bp);
		return 0;
	}
 

	{
		sector_t x = block >> conf->preshift;
		sector_div(x, (u32)conf->hash_spacing);
		zone = conf->hash_table[x];
	}
 
	while (block >= (zone->zone_offset + zone->size)) 
		zone++;
    
	sect_in_chunk = bio->bi_sector & ((chunk_size<<1) -1);


	{
		sector_t x =  (block - zone->zone_offset) >> chunksize_bits;

		sector_div(x, zone->nb_dev);
		chunk = x;

		x = block >> chunksize_bits;
		tmp_dev = zone->dev[sector_div(x, zone->nb_dev)];
	}
	rsect = (((chunk << chunksize_bits) + zone->dev_offset)<<1)
		+ sect_in_chunk;
 
	bio->bi_bdev = tmp_dev->bdev;
	bio->bi_sector = rsect + tmp_dev->data_offset;

	/*
	 * Let the main block layer submit the IO and resolve recursion:
	 */
	return 1;

bad_map:
	printk("raid0_make_request bug: can't convert block across chunks"
		" or bigger than %dk %llu %d\n", chunk_size, 
		(unsigned long long)bio->bi_sector, bio->bi_size >> 10);

	bio_io_error(bio);
	return 0;
}

static void raid0_status (struct seq_file *seq, mddev_t *mddev)
{
#undef MD_DEBUG
#ifdef MD_DEBUG
	int j, k, h;
	char b[BDEVNAME_SIZE];
	raid0_conf_t *conf = mddev_to_conf(mddev);

	h = 0;
	for (j = 0; j < conf->nr_strip_zones; j++) {
		seq_printf(seq, "      z%d", j);
		if (conf->hash_table[h] == conf->strip_zone+j)
			seq_printf(seq, "(h%d)", h++);
		seq_printf(seq, "=[");
		for (k = 0; k < conf->strip_zone[j].nb_dev; k++)
			seq_printf(seq, "%s/", bdevname(
				conf->strip_zone[j].dev[k]->bdev,b));

		seq_printf(seq, "] zo=%d do=%d s=%d\n",
				conf->strip_zone[j].zone_offset,
				conf->strip_zone[j].dev_offset,
				conf->strip_zone[j].size);
	}
#endif
	seq_printf(seq, " %dk chunks", mddev->chunk_size/1024);
	return;
}

static struct mdk_personality raid0_personality=
	dump_zones(mddev);

	ret = md_integrity_register(mddev);

	return ret;
}

static void raid0_free(struct mddev *mddev, void *priv)
{
	struct r0conf *conf = priv;

	kfree(conf->strip_zone);
	kfree(conf->devlist);
	kfree(conf);
}

/*
 * Is io distribute over 1 or more chunks ?
*/
static inline int is_io_in_chunk_boundary(struct mddev *mddev,
			unsigned int chunk_sects, struct bio *bio)
{
	if (likely(is_power_of_2(chunk_sects))) {
		return chunk_sects >=
			((bio->bi_iter.bi_sector & (chunk_sects-1))
					+ bio_sectors(bio));
	} else{
		sector_t sector = bio->bi_iter.bi_sector;
		return chunk_sects >= (sector_div(sector, chunk_sects)
						+ bio_sectors(bio));
	}
}

static void raid0_handle_discard(struct mddev *mddev, struct bio *bio)
{
	struct r0conf *conf = mddev->private;
	struct strip_zone *zone;
	sector_t start = bio->bi_iter.bi_sector;
	sector_t end;
	unsigned int stripe_size;
	sector_t first_stripe_index, last_stripe_index;
	sector_t start_disk_offset;
	unsigned int start_disk_index;
	sector_t end_disk_offset;
	unsigned int end_disk_index;
	unsigned int disk;

	zone = find_zone(conf, &start);

	if (bio_end_sector(bio) > zone->zone_end) {
		struct bio *split = bio_split(bio,
			zone->zone_end - bio->bi_iter.bi_sector, GFP_NOIO,
			mddev->bio_set);
		bio_chain(split, bio);
		generic_make_request(bio);
		bio = split;
		end = zone->zone_end;
	} else
		end = bio_end_sector(bio);

	if (zone != conf->strip_zone)
		end = end - zone[-1].zone_end;

	/* Now start and end is the offset in zone */
	stripe_size = zone->nb_dev * mddev->chunk_sectors;

	first_stripe_index = start;
	sector_div(first_stripe_index, stripe_size);
	last_stripe_index = end;
	sector_div(last_stripe_index, stripe_size);

	start_disk_index = (int)(start - first_stripe_index * stripe_size) /
		mddev->chunk_sectors;
	start_disk_offset = ((int)(start - first_stripe_index * stripe_size) %
		mddev->chunk_sectors) +
		first_stripe_index * mddev->chunk_sectors;
	end_disk_index = (int)(end - last_stripe_index * stripe_size) /
		mddev->chunk_sectors;
	end_disk_offset = ((int)(end - last_stripe_index * stripe_size) %
		mddev->chunk_sectors) +
		last_stripe_index * mddev->chunk_sectors;

	for (disk = 0; disk < zone->nb_dev; disk++) {
		sector_t dev_start, dev_end;
		struct bio *discard_bio = NULL;
		struct md_rdev *rdev;

		if (disk < start_disk_index)
			dev_start = (first_stripe_index + 1) *
				mddev->chunk_sectors;
		else if (disk > start_disk_index)
			dev_start = first_stripe_index * mddev->chunk_sectors;
		else
			dev_start = start_disk_offset;

		if (disk < end_disk_index)
			dev_end = (last_stripe_index + 1) * mddev->chunk_sectors;
		else if (disk > end_disk_index)
			dev_end = last_stripe_index * mddev->chunk_sectors;
		else
			dev_end = end_disk_offset;

		if (dev_end <= dev_start)
			continue;

		rdev = conf->devlist[(zone - conf->strip_zone) *
			conf->strip_zone[0].nb_dev + disk];
		if (__blkdev_issue_discard(rdev->bdev,
			dev_start + zone->dev_start + rdev->data_offset,
			dev_end - dev_start, GFP_NOIO, 0, &discard_bio) ||
		    !discard_bio)
			continue;
		bio_chain(discard_bio, bio);
		bio_clone_blkcg_association(discard_bio, bio);
		if (mddev->gendisk)
			trace_block_bio_remap(bdev_get_queue(rdev->bdev),
				discard_bio, disk_devt(mddev->gendisk),
				bio->bi_iter.bi_sector);
		generic_make_request(discard_bio);
	}
	bio_endio(bio);
}

static bool raid0_make_request(struct mddev *mddev, struct bio *bio)
{
	struct strip_zone *zone;
	struct md_rdev *tmp_dev;
	sector_t bio_sector;
	sector_t sector;
	unsigned chunk_sects;
	unsigned sectors;

	if (unlikely(bio->bi_opf & REQ_PREFLUSH)) {
		md_flush_request(mddev, bio);
		return true;
	}

	if (unlikely((bio_op(bio) == REQ_OP_DISCARD))) {
		raid0_handle_discard(mddev, bio);
		return true;
	}

	bio_sector = bio->bi_iter.bi_sector;
	sector = bio_sector;
	chunk_sects = mddev->chunk_sectors;

	sectors = chunk_sects -
		(likely(is_power_of_2(chunk_sects))
		 ? (sector & (chunk_sects-1))
		 : sector_div(sector, chunk_sects));

	/* Restore due to sector_div */
	sector = bio_sector;

	if (sectors < bio_sectors(bio)) {
		struct bio *split = bio_split(bio, sectors, GFP_NOIO, mddev->bio_set);
		bio_chain(split, bio);
		generic_make_request(bio);
		bio = split;
	}

	zone = find_zone(mddev->private, &sector);
	tmp_dev = map_sector(mddev, zone, sector, &sector);
	bio_set_dev(bio, tmp_dev->bdev);
	bio->bi_iter.bi_sector = sector + zone->dev_start +
		tmp_dev->data_offset;

	if (mddev->gendisk)
		trace_block_bio_remap(bio->bi_disk->queue, bio,
				disk_devt(mddev->gendisk), bio_sector);
	mddev_check_writesame(mddev, bio);
	mddev_check_write_zeroes(mddev, bio);
	generic_make_request(bio);
	return true;
}

static void raid0_status(struct seq_file *seq, struct mddev *mddev)
{
	seq_printf(seq, " %dk chunks", mddev->chunk_sectors / 2);
	return;
}

static void *raid0_takeover_raid45(struct mddev *mddev)
{
	struct md_rdev *rdev;
	struct r0conf *priv_conf;

	if (mddev->degraded != 1) {
		pr_warn("md/raid0:%s: raid5 must be degraded! Degraded disks: %d\n",
			mdname(mddev),
			mddev->degraded);
		return ERR_PTR(-EINVAL);
	}

	rdev_for_each(rdev, mddev) {
		/* check slot number for a disk */
		if (rdev->raid_disk == mddev->raid_disks-1) {
			pr_warn("md/raid0:%s: raid5 must have missing parity disk!\n",
				mdname(mddev));
			return ERR_PTR(-EINVAL);
		}
		rdev->sectors = mddev->dev_sectors;
	}

	/* Set new parameters */
	mddev->new_level = 0;
	mddev->new_layout = 0;
	mddev->new_chunk_sectors = mddev->chunk_sectors;
	mddev->raid_disks--;
	mddev->delta_disks = -1;
	/* make sure it will be not marked as dirty */
	mddev->recovery_cp = MaxSector;
	mddev_clear_unsupported_flags(mddev, UNSUPPORTED_MDDEV_FLAGS);

	create_strip_zones(mddev, &priv_conf);

	return priv_conf;
}

static void *raid0_takeover_raid10(struct mddev *mddev)
{
	struct r0conf *priv_conf;

	/* Check layout:
	 *  - far_copies must be 1
	 *  - near_copies must be 2
	 *  - disks number must be even
	 *  - all mirrors must be already degraded
	 */
	if (mddev->layout != ((1 << 8) + 2)) {
		pr_warn("md/raid0:%s:: Raid0 cannot takeover layout: 0x%x\n",
			mdname(mddev),
			mddev->layout);
		return ERR_PTR(-EINVAL);
	}
	if (mddev->raid_disks & 1) {
		pr_warn("md/raid0:%s: Raid0 cannot takeover Raid10 with odd disk number.\n",
			mdname(mddev));
		return ERR_PTR(-EINVAL);
	}
	if (mddev->degraded != (mddev->raid_disks>>1)) {
		pr_warn("md/raid0:%s: All mirrors must be already degraded!\n",
			mdname(mddev));
		return ERR_PTR(-EINVAL);
	}

	/* Set new parameters */
	mddev->new_level = 0;
	mddev->new_layout = 0;
	mddev->new_chunk_sectors = mddev->chunk_sectors;
	mddev->delta_disks = - mddev->raid_disks / 2;
	mddev->raid_disks += mddev->delta_disks;
	mddev->degraded = 0;
	/* make sure it will be not marked as dirty */
	mddev->recovery_cp = MaxSector;
	mddev_clear_unsupported_flags(mddev, UNSUPPORTED_MDDEV_FLAGS);

	create_strip_zones(mddev, &priv_conf);
	return priv_conf;
}

static void *raid0_takeover_raid1(struct mddev *mddev)
{
	struct r0conf *priv_conf;
	int chunksect;

	/* Check layout:
	 *  - (N - 1) mirror drives must be already faulty
	 */
	if ((mddev->raid_disks - 1) != mddev->degraded) {
		pr_err("md/raid0:%s: (N - 1) mirrors drives must be already faulty!\n",
		       mdname(mddev));
		return ERR_PTR(-EINVAL);
	}

	/*
	 * a raid1 doesn't have the notion of chunk size, so
	 * figure out the largest suitable size we can use.
	 */
	chunksect = 64 * 2; /* 64K by default */

	/* The array must be an exact multiple of chunksize */
	while (chunksect && (mddev->array_sectors & (chunksect - 1)))
		chunksect >>= 1;

	if ((chunksect << 9) < PAGE_SIZE)
		/* array size does not allow a suitable chunk size */
		return ERR_PTR(-EINVAL);

	/* Set new parameters */
	mddev->new_level = 0;
	mddev->new_layout = 0;
	mddev->new_chunk_sectors = chunksect;
	mddev->chunk_sectors = chunksect;
	mddev->delta_disks = 1 - mddev->raid_disks;
	mddev->raid_disks = 1;
	/* make sure it will be not marked as dirty */
	mddev->recovery_cp = MaxSector;
	mddev_clear_unsupported_flags(mddev, UNSUPPORTED_MDDEV_FLAGS);

	create_strip_zones(mddev, &priv_conf);
	return priv_conf;
}

static void *raid0_takeover(struct mddev *mddev)
{
	/* raid0 can take over:
	 *  raid4 - if all data disks are active.
	 *  raid5 - providing it is Raid4 layout and one disk is faulty
	 *  raid10 - assuming we have all necessary active disks
	 *  raid1 - with (N -1) mirror drives faulty
	 */

	if (mddev->bitmap) {
		pr_warn("md/raid0: %s: cannot takeover array with bitmap\n",
			mdname(mddev));
		return ERR_PTR(-EBUSY);
	}
	if (mddev->level == 4)
		return raid0_takeover_raid45(mddev);

	if (mddev->level == 5) {
		if (mddev->layout == ALGORITHM_PARITY_N)
			return raid0_takeover_raid45(mddev);

		pr_warn("md/raid0:%s: Raid can only takeover Raid5 with layout: %d\n",
			mdname(mddev), ALGORITHM_PARITY_N);
	}

	if (mddev->level == 10)
		return raid0_takeover_raid10(mddev);

	if (mddev->level == 1)
		return raid0_takeover_raid1(mddev);

	pr_warn("Takeover from raid%i to raid0 not supported\n",
		mddev->level);

	return ERR_PTR(-EINVAL);
}

static void raid0_quiesce(struct mddev *mddev, int quiesce)
{
}

static struct md_personality raid0_personality=
{
	.name		= "raid0",
	.level		= 0,
	.owner		= THIS_MODULE,
	.make_request	= raid0_make_request,
	.run		= raid0_run,
	.stop		= raid0_stop,
	.status		= raid0_status,
	.free		= raid0_free,
	.status		= raid0_status,
	.size		= raid0_size,
	.takeover	= raid0_takeover,
	.quiesce	= raid0_quiesce,
	.congested	= raid0_congested,
};

static int __init raid0_init (void)
{
	return register_md_personality (&raid0_personality);
}

static void raid0_exit (void)
{
	unregister_md_personality (&raid0_personality);
}

module_init(raid0_init);
module_exit(raid0_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RAID0 (striping) personality for MD");
MODULE_ALIAS("md-personality-2"); /* RAID0 */
MODULE_ALIAS("md-raid0");
MODULE_ALIAS("md-level-0");
