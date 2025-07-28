/*
 * param.c
 *
 * Parameter read & save driver on param partition.
 *
 * COPYRIGHT(C) Samsung Electronics Co.Ltd. 2006-2010 All Right Reserved.  
 *
 * Author: Jeonghwan Min <jeonghwan.min@samsung.com>
 *
 * 20080226. Supprot on BML layer.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/blkpg.h>
#include <linux/hdreg.h>
#include <linux/genhd.h>
#include <linux/sched.h>
#include <linux/ctype.h>
#include <linux/vmalloc.h>

#include <mach/hardware.h>
#include <mach/param.h>

#include <XsrTypes.h>
#include <BML.h>

#define SECTOR_BITS		9

#define SPP(volume)		(vs[volume].nSctsPerPg)
#define SPB(volume)		(vs[volume].nSctsPerPg * vs[volume].nPgsPerBlk)

extern BMLVolSpec		*xsr_get_vol_spec(UINT32 volume);
extern XSRPartI			*xsr_get_part_spec(UINT32 volume);

#define PARAM_LEN		(32 * 2048) 

int write_param_block(unsigned int dev_id, unsigned char *addr)
{
	unsigned int i, err;
	unsigned int first;
	unsigned int nBytesReturned = 0;
	unsigned int nPart[2] = {PARAM_PART_ID, BML_PI_ATTR_RW};
	unsigned char *pbuf, *buf;
	BMLVolSpec *vs;
	XSRPartI *pi;
	
	if (addr == NULL) {
		printk(KERN_ERR "%s: wrong address\n", __FUNCTION__);
		return -EINVAL;
	}	
		
	buf = vmalloc(PARAM_LEN);
	if (!buf)
		return -ENOMEM;
	
	/* get vol info */
	vs = xsr_get_vol_spec(0);
	
	/* get part info */
	pi = xsr_get_part_spec(0);

	for (i = 0 ; i < pi->nNumOfPartEntry ; i++) {
		if (pi->stPEntry[i].nID == PARAM_PART_ID) {
			break;
		}
	}

	/* start sector */
	first = (pi->stPEntry[i].n1stVbn + 1) * SPB(0);

	err = BML_IOCtl(0, BML_IOCTL_CHANGE_PART_ATTR,
		(unsigned char *)&nPart, sizeof(unsigned int) * 2, NULL, 0, &nBytesReturned);
	if (err!= BML_SUCCESS) {
		printk(KERN_ERR "%s: ioctl error\n", __FUNCTION__);
		return -EIO;
	}
	
	pbuf = buf;
	
	for (i = 0 ; i < (SPB(0)/2) ; i += SPP(0))	{
		err = BML_Read(0, first + i, SPP(0), pbuf, NULL, BML_FLAG_SYNC_OP | BML_FLAG_ECC_ON);
		if (err != BML_SUCCESS)	{
			printk(KERN_ERR "%s: read page error\n", __FUNCTION__);
			return -EIO;
		}
		pbuf += (SPP(0) << SECTOR_BITS);
	}

	/* erase block before write */
	err = BML_EraseBlk(0, first/SPB(0), BML_FLAG_SYNC_OP);
	if(err != BML_SUCCESS){
		printk(KERN_ERR "%s: erase block error\n", __FUNCTION__);
		err = -EIO;
		goto fail2;
	}
	
	pbuf = buf;
	
	for (i = 0 ; i < (SPB(0)/2) ; i += SPP(0))	{
		err = BML_Write(0, first + i, SPP(0), pbuf, NULL, BML_FLAG_SYNC_OP | BML_FLAG_ECC_ON);
		if (err != BML_SUCCESS)	{
			printk(KERN_ERR "%s: write page error\n", __FUNCTION__);
			err = -EIO;
			goto fail2;
		}
		pbuf += (SPP(0) << SECTOR_BITS);
	}

	for (i = (SPB(0)/2) ; i < SPB(0) ; i += SPP(0))	{
		err = BML_Write(0, first + i, SPP(0), addr, NULL, BML_FLAG_SYNC_OP | BML_FLAG_ECC_ON);
		if (err != BML_SUCCESS)	{
			printk(KERN_ERR "%s: write page error\n", __FUNCTION__);
			err = -EIO;
			goto fail2;
		}
		addr += (SPP(0) << SECTOR_BITS);
	}

fail2:
	nPart[1] = BML_PI_ATTR_RO;
	err = BML_IOCtl(0, BML_IOCTL_CHANGE_PART_ATTR,
		(unsigned char *)&nPart, sizeof(unsigned int) * 2, NULL, 0, &nBytesReturned);
	if (err != BML_SUCCESS) {
		printk(KERN_ERR "%s: ioctl error\n", __FUNCTION__);
		err = -EIO;
		goto fail1;	
	}

	vfree(buf);
	return 0;

fail1:
	vfree(buf);
	return err;
}

int write_param_backup_block(unsigned int dev_id, unsigned char *addr)
{
	unsigned int i, err;
	unsigned int first;
	unsigned int nBytesReturned = 0;
	unsigned int nPart[2] = {PARAM_PART_ID, BML_PI_ATTR_RW};
	unsigned char *pbuf, *buf;
	BMLVolSpec *vs;
	XSRPartI *pi;
	
	if (addr == NULL) {
		printk(KERN_ERR "%s: wrong address\n", __FUNCTION__);
		return -EINVAL;
	}	
		
	buf = vmalloc(PARAM_LEN);
	if (!buf)
		return -ENOMEM;
	
	/* get vol info */
	vs = xsr_get_vol_spec(0);
	
	/* get part info */
	pi = xsr_get_part_spec(0);

	for (i = 0 ; i < pi->nNumOfPartEntry ; i++) {
		if (pi->stPEntry[i].nID == PARAM_PART_ID) {
			break;
		}
	}

	/* start sector */
	first = (pi->stPEntry[i].n1stVbn + 2) * SPB(0);

	err = BML_IOCtl(0, BML_IOCTL_CHANGE_PART_ATTR,
		(unsigned char *)&nPart, sizeof(unsigned int) * 2, NULL, 0, &nBytesReturned);
	if (err!= BML_SUCCESS) {
		printk(KERN_ERR "%s: ioctl error\n", __FUNCTION__);
		return -EIO;
	}
	
	pbuf = buf;
	
	for (i = 0 ; i < (SPB(0)/2) ; i += SPP(0))	{
		err = BML_Read(0, first + i, SPP(0), pbuf, NULL, BML_FLAG_SYNC_OP | BML_FLAG_ECC_ON);
		if (err != BML_SUCCESS)	{
			printk(KERN_ERR "%s: read page error\n", __FUNCTION__);
			return -EIO;
		}
		pbuf += (SPP(0) << SECTOR_BITS);
	}

	/* erase block before write */
	err = BML_EraseBlk(0, first/SPB(0), BML_FLAG_SYNC_OP);
	if(err != BML_SUCCESS){
		printk(KERN_ERR "%s: erase block error\n", __FUNCTION__);
		err = -EIO;
		goto fail2;
	}
	
	pbuf = buf;
	
	for (i = 0 ; i < (SPB(0)/2) ; i += SPP(0))	{
		err = BML_Write(0, first + i, SPP(0), pbuf, NULL, BML_FLAG_SYNC_OP | BML_FLAG_ECC_ON);
		if (err != BML_SUCCESS)	{
			printk(KERN_ERR "%s: write page error\n", __FUNCTION__);
			err = -EIO;
			goto fail2;
		}
		pbuf += (SPP(0) << SECTOR_BITS);
	}

	for (i = (SPB(0)/2) ; i < SPB(0) ; i += SPP(0))	{
		err = BML_Write(0, first + i, SPP(0), addr, NULL, BML_FLAG_SYNC_OP | BML_FLAG_ECC_ON);
		if (err != BML_SUCCESS)	{
			printk(KERN_ERR "%s: write page error\n", __FUNCTION__);
			err = -EIO;
			goto fail2;
		}
		addr += (SPP(0) << SECTOR_BITS);
	}

fail2:
	nPart[1] = BML_PI_ATTR_RO;
	err = BML_IOCtl(0, BML_IOCTL_CHANGE_PART_ATTR,
		(unsigned char *)&nPart, sizeof(unsigned int) * 2, NULL, 0, &nBytesReturned);
	if (err != BML_SUCCESS) {
		printk(KERN_ERR "%s: ioctl error\n", __FUNCTION__);
		err = -EIO;
		goto fail1;	
	}

	vfree(buf);
	return 0;

fail1:
	vfree(buf);
	return err;
}


int read_param_block(unsigned int dev_id, unsigned char *addr)
{
	unsigned int i, err;
	unsigned int first;
	BMLVolSpec *vs;
	XSRPartI *pi;
	
	if (addr == NULL){
		printk(KERN_ERR "%s: wrong address\n", __FUNCTION__);
		return -EINVAL;
	}	
		
	/* Get vol info */
	vs = xsr_get_vol_spec(0);
	
	/* get part info */
	pi = xsr_get_part_spec(0);

	for (i = 0 ; i < pi->nNumOfPartEntry ; i++) {
		if (pi->stPEntry[i].nID == PARAM_PART_ID) {
			break;
		}
	}

	/* Start sector */
	first = (pi->stPEntry[i].n1stVbn + 1) * SPB(0);
	
	for (i = (SPB(0)/2) ; i < SPB(0) ; i += SPP(0))	{
		err = BML_Read(0, first + i, SPP(0), addr, NULL, BML_FLAG_SYNC_OP | BML_FLAG_ECC_ON);
		if (err != BML_SUCCESS)	{
			printk(KERN_ERR "%s: read page error\n", __FUNCTION__);
			return -EIO;
		}
		addr += (SPP(0) << SECTOR_BITS);
	}

	return 0;
}

int read_param_backup_block(unsigned int dev_id, unsigned char *addr)
{
	unsigned int i, err;
	unsigned int first;
	BMLVolSpec *vs;
	XSRPartI *pi;
	
	if (addr == NULL){
		printk(KERN_ERR "%s: wrong address\n", __FUNCTION__);
		return -EINVAL;
	}	
		
	/* Get vol info */
	vs = xsr_get_vol_spec(0);
	
	/* get part info */
	pi = xsr_get_part_spec(0);

	for (i = 0 ; i < pi->nNumOfPartEntry ; i++) {
		if (pi->stPEntry[i].nID == PARAM_PART_ID) {
			break;
		}
	}

	/* Start sector */
	first = (pi->stPEntry[i].n1stVbn + 2) * SPB(0);
	
	for (i = (SPB(0)/2) ; i < SPB(0) ; i += SPP(0))	{
		err = BML_Read(0, first + i, SPP(0), addr, NULL, BML_FLAG_SYNC_OP | BML_FLAG_ECC_ON);
		if (err != BML_SUCCESS)	{
			printk(KERN_ERR "%s: read page error\n", __FUNCTION__);
			return -EIO;
		}
		addr += (SPP(0) << SECTOR_BITS);
	}

	return 0;
}


static status_t param_status;

static int load_param_value(void)
{
	unsigned char *addr = NULL;
	unsigned int err = 0, dev_id = 0;

	status_t *status;

	addr = vmalloc(PARAM_LEN);
	if (!addr)
		return -ENOMEM;

	err = BML_Open(dev_id);
	if (err) {
		printk(KERN_ERR "%s: open error\n", __FUNCTION__);
		goto fail;
	}

	err = read_param_block(dev_id, addr);
	if (err) {
		printk(KERN_ERR "%s: read param error\n", __FUNCTION__);
		goto fail;
	}

	status = (status_t *)addr;

	if ((status->param_magic == PARAM_MAGIC) &&
			(status->param_version == PARAM_VERSION)) {
		memcpy(&param_status, (char *)status, sizeof(status_t));			
	}
	else {
		
		printk(KERN_ERR "%s: no param info in first param block\n", __FUNCTION__);

		err = read_param_backup_block(dev_id, addr);
		if (err) {
		    printk(KERN_ERR "%s: read backup param error\n", __FUNCTION__);
		    goto fail;
	    }

	    status = (status_t *)addr;

	    if ((status->param_magic == PARAM_MAGIC) &&
			(status->param_version == PARAM_VERSION)) {
		    memcpy(&param_status, (char *)status, sizeof(status_t));			
	    }
	    else {
			printk(KERN_ERR "%s: no param info in backup param block\n", __FUNCTION__);
		    err = -1;
	    }
	}	

fail:
	vfree(addr);
	BML_Close(dev_id);
	
	return err;
}

int save_param_value(void)
{
	unsigned int err = 0, dev_id = 0;
	unsigned char *addr = NULL;

	addr = vmalloc(PARAM_LEN);
	if (!addr)
		return -ENOMEM;

	err = BML_Open(dev_id);
	if (err) {
		printk(KERN_ERR "%s: open error\n", __FUNCTION__);
		goto fail;
	}

	memset(addr, 0, PARAM_LEN);
	memcpy(addr, &param_status, sizeof(status_t));
	
	err = write_param_block(dev_id, addr);
	if (err) {
		printk(KERN_ERR "%s: read param error\n", __FUNCTION__);
		goto fail;
	}

	err = write_param_backup_block(dev_id, addr);
	if (err) {
		printk(KERN_ERR "%s: read backup param error\n", __FUNCTION__);
		goto fail;
	}

fail:
	vfree(addr);
	BML_Close(dev_id);
	
	return err;
}
EXPORT_SYMBOL(save_param_value);

void set_param_value(int idx, void *value)
{
	int i, str_i;

	for (i = 0; i < MAX_PARAM; i++) {
		if (i < (MAX_PARAM - MAX_STRING_PARAM)) {	
			if(param_status.param_list[i].ident == idx) {
				param_status.param_list[i].value = *(int *)value;
			}
		}
		else {
			str_i = (i - (MAX_PARAM - MAX_STRING_PARAM));
			if(param_status.param_str_list[str_i].ident == idx) {
				strlcpy(param_status.param_str_list[str_i].value, 
					(char *)value, PARAM_STRING_SIZE);
			}
		}
	}
	
	save_param_value();
}
EXPORT_SYMBOL(set_param_value);

void get_param_value(int idx, void *value)
{
	int i, str_i;

	for (i = 0 ; i < MAX_PARAM; i++) {
		if (i < (MAX_PARAM - MAX_STRING_PARAM)) {	
			if(param_status.param_list[i].ident == idx) {
				*(int *)value = param_status.param_list[i].value;
			}
		}
		else {
			str_i = (i - (MAX_PARAM - MAX_STRING_PARAM));
			if(param_status.param_str_list[str_i].ident == idx) {
				strlcpy((char *)value, 
					param_status.param_str_list[str_i].value, PARAM_STRING_SIZE);
			}
		}
	}
}
EXPORT_SYMBOL(get_param_value);

extern struct class *sec_class;

static struct device *param_dev;

static ssize_t lcd_level_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int value;

	get_param_value(__LCD_LEVEL, &value);

	return sprintf(buf, "%d\n", value);
}

static ssize_t lcd_level_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
	int ret = 0;
	char *after;
	unsigned long value = simple_strtoul(buf, &after, 10);	
	unsigned int count = (after - buf);

	if (*after && isspace(*after))
		count++;

	if (count == size) {
		ret = count;

		set_param_value(__LCD_LEVEL, &value);
	}

	return ret;
}

static DEVICE_ATTR(lcd_level, S_IRUGO | S_IWUSR, lcd_level_show, lcd_level_store);

static ssize_t switch_sel_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int value;

	get_param_value(__SWITCH_SEL, &value);

	return sprintf(buf, "%d\n", value);
}

static ssize_t switch_sel_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
	int ret = 0;
	char *after;
	unsigned long value = simple_strtoul(buf, &after, 10);	
	unsigned int count = (after - buf);

	if (*after && isspace(*after))
		count++;

	if (count == size) {
		ret = count;

		set_param_value(__SWITCH_SEL, &value);
	}

	return ret;
}

static DEVICE_ATTR(switch_sel, S_IRUGO | S_IWUSR, switch_sel_show, switch_sel_store);

static ssize_t melody_mode_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int value;

	get_param_value(__MELODY_MODE, &value);

	return sprintf(buf, "%d\n", value);
}

static ssize_t melody_mode_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
	int ret = 0;
	char *after;
	unsigned long value = simple_strtoul(buf, &after, 10);	
	unsigned int count = (after - buf);

	if (*after && isspace(*after))
		count++;

	if (count == size) {
		ret = count;

		set_param_value(__MELODY_MODE, &value);
	}

	return ret;
}

static DEVICE_ATTR(melody_mode, S_IRUGO | S_IWUSR, melody_mode_show, melody_mode_store);

static ssize_t download_mode_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int value;

	get_param_value(__REBOOT_MODE, &value);

	return sprintf(buf, "%d\n", value);
}

static ssize_t download_mode_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
	int ret = 0;
	char *after;
	unsigned long value = simple_strtoul(buf, &after, 10);	
	unsigned int count = (after - buf);

	if (*after && isspace(*after))
		count++;

	if (count == size) {
		ret = count;

		set_param_value(__REBOOT_MODE, &value);
	}

	return ret;
}

static DEVICE_ATTR(download_mode, S_IRUGO | S_IWUSR, download_mode_show, download_mode_store);

static ssize_t nation_sel_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int value;

	get_param_value(__NATION_SEL, &value);

	return sprintf(buf, "%d\n", value);
}

static ssize_t nation_sel_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
	int ret = 0;
	char *after;
	unsigned long value = simple_strtoul(buf, &after, 10);	
	unsigned int count = (after - buf);

	if (*after && isspace(*after))
		count++;

	if (count == size) {
		ret = count;

		set_param_value(__NATION_SEL, &value);
	}

	return ret;
}

static DEVICE_ATTR(nation_sel, S_IRUGO | S_IWUSR, nation_sel_show, nation_sel_store);

static ssize_t set_default_param_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int value;

	get_param_value(__SET_DEFAULT_PARAM, &value);

	return sprintf(buf, "%d\n", value);
}

static ssize_t set_default_param_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
	int ret = 0;
	char *after;
	unsigned long value = simple_strtoul(buf, &after, 10);	
	unsigned int count = (after - buf);

	if (*after && isspace(*after))
		count++;

	if (count == size) {
		ret = count;

		set_param_value(__SET_DEFAULT_PARAM, &value);
	}

	return ret;
}

static DEVICE_ATTR(set_default_param, S_IRUGO | S_IWUSR, set_default_param_show, set_default_param_store);
#if 0
static DEVICE_ATTR(serial_speed, S_IRUGO | S_IWUSR, serial_speed_show, serial_speed_store);
static DEVICE_ATTR(load_ramdisk, S_IRUGO | S_IWUSR, load_ramdisk_show, load_ramdisk_store);
static DEVICE_ATTR(boot_delay, S_IRUGO | S_IWUSR, boot_delay_show, boot_delay_store);
static DEVICE_ATTR(phone_debug_on, S_IRUGO | S_IWUSR, phone_debug_on_show, phone_debug_on_store);
static DEVICE_ATTR(bl_dim_time, S_IRUGO | S_IWUSR, bl_dim_time_show, bl_dim_time_store);

static DEVICE_ATTR(version, S_IRUGO | S_IWUSR, version_show, version_store);
static DEVICE_ATTR(command_line, S_IRUGO | S_IWUSR, command_line_show, command_line_store);
#endif

static void *dev_attr[] = {
	&dev_attr_lcd_level,
	&dev_attr_switch_sel,
	&dev_attr_melody_mode,
	&dev_attr_download_mode,
	&dev_attr_nation_sel,
	&dev_attr_set_default_param,
#if 0
	&dev_attr_serial_speed,
	&dev_attr_load_ramdisk,
	&dev_attr_boot_delay,
	&dev_attr_phone_debug_on,
	&dev_attr_bl_dim_time,
	&dev_attr_version
	&dev_attr_command_line
#endif
};

static int param_init(void)
{
	int ret, i = 0;

	param_dev = device_create_drvdata(sec_class, NULL, 0, NULL, "param");
	if (IS_ERR(param_dev)) {
		pr_err("Failed to create device(param)!\n");
		return PTR_ERR(param_dev);	
	}

	for (; i < ARRAY_SIZE(dev_attr); i++) {
		ret = device_create_file(param_dev, dev_attr[i]);
		if (ret < 0) {
			pr_err("Failed to create device file(%s)!\n",
					((struct device_attribute *)dev_attr[i])->attr.name);
			goto fail;
		}	
	}

	ret = load_param_value();
	if (ret < 0) {
		printk(KERN_ERR "%s -> relocated to default value!\n", __FUNCTION__);

		memset(&param_status, 0, sizeof(status_t));

		param_status.param_magic = PARAM_MAGIC;
		param_status.param_version = PARAM_VERSION;
		param_status.param_list[0].ident = __SERIAL_SPEED;
		param_status.param_list[0].value = SERIAL_SPEED;
		param_status.param_list[1].ident = __LOAD_RAMDISK;
		param_status.param_list[1].value = LOAD_RAMDISK;
		param_status.param_list[2].ident = __BOOT_DELAY;
		param_status.param_list[2].value = BOOT_DELAY;
		param_status.param_list[3].ident = __LCD_LEVEL;
		param_status.param_list[3].value = LCD_LEVEL;
		param_status.param_list[4].ident = __SWITCH_SEL;
		param_status.param_list[4].value = SWITCH_SEL;
		param_status.param_list[5].ident = __PHONE_DEBUG_ON;
		param_status.param_list[5].value = PHONE_DEBUG_ON;
		param_status.param_list[6].ident = __LCD_DIM_LEVEL;
		param_status.param_list[6].value = LCD_DIM_LEVEL;
		param_status.param_list[7].ident = __MELODY_MODE;
		param_status.param_list[7].value = MELODY_MODE;
		param_status.param_list[8].ident = __REBOOT_MODE;
		param_status.param_list[8].value = REBOOT_MODE;
		param_status.param_list[9].ident = __NATION_SEL;
		param_status.param_list[9].value = NATION_SEL;
		param_status.param_list[10].ident = __SET_DEFAULT_PARAM;
		param_status.param_list[10].value = SET_DEFAULT_PARAM;
		param_status.param_str_list[0].ident = __VERSION;
		strlcpy(param_status.param_str_list[0].value,
				VERSION_LINE, PARAM_STRING_SIZE);
		param_status.param_str_list[1].ident = __CMDLINE;
		strlcpy(param_status.param_str_list[1].value,
				COMMAND_LINE, PARAM_STRING_SIZE);
	}

	sec_set_param_value = set_param_value;
	sec_get_param_value = get_param_value;

	return 0;	

fail:
	for (--i; i >= 0; i--) 
		device_remove_file(param_dev, dev_attr[i]);

	return ret;
}

static void param_exit(void)
{
	int i = (ARRAY_SIZE(dev_attr) - 1);

	for (; i >= 0; i--) 
		device_remove_file(param_dev, dev_attr[i]);
}

module_init(param_init);
module_exit(param_exit);

MODULE_AUTHOR("Jeonghwan Min <jh78.min@samsung.com>");
MODULE_DESCRIPTION("Param Interface Driver");
MODULE_LICENSE("GPL");
