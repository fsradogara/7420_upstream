/*
 * Dallas DS1302 RTC Support
 *
 *  Copyright (C) 2002  David McCullough
 *  Copyright (C) 2003 - 2007  Paul Mundt
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License version 2.  See the file "COPYING" in the main directory of
 * this archive for more details.
 */
 *  Copyright (C) 2002 David McCullough
 *  Copyright (C) 2003 - 2007 Paul Mundt
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License version 2. See the file "COPYING" in the main directory of
 * this archive for more details.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <linux/spinlock.h>
#include <linux/io.h>
#include <linux/bcd.h>
#include <asm/rtc.h>

#define DRV_NAME	"rtc-ds1302"
#define DRV_VERSION	"0.1.0"
#include <linux/rtc.h>
#include <linux/io.h>
#include <linux/bcd.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/rtc.h>
#include <linux/spi/spi.h>

#define DRV_NAME	"rtc-ds1302"

#define	RTC_CMD_READ	0x81		/* Read command */
#define	RTC_CMD_WRITE	0x80		/* Write command */

#define RTC_ADDR_RAM0	0x20		/* Address of RAM0 */
#define RTC_ADDR_TCR	0x08		/* Address of trickle charge register */
#define	RTC_CMD_WRITE_ENABLE	0x00		/* Write enable */
#define	RTC_CMD_WRITE_DISABLE	0x80		/* Write disable */

#define RTC_ADDR_RAM0	0x20		/* Address of RAM0 */
#define RTC_ADDR_TCR	0x08		/* Address of trickle charge register */
#define RTC_CLCK_BURST	0x1F		/* Address of clock burst */
#define	RTC_CLCK_LEN	0x08		/* Size of clock burst */
#define	RTC_ADDR_CTRL	0x07		/* Address of control register */
#define	RTC_ADDR_YEAR	0x06		/* Address of year register */
#define	RTC_ADDR_DAY	0x05		/* Address of day of week register */
#define	RTC_ADDR_MON	0x04		/* Address of month register */
#define	RTC_ADDR_DATE	0x03		/* Address of day of month register */
#define	RTC_ADDR_HOUR	0x02		/* Address of hour register */
#define	RTC_ADDR_MIN	0x01		/* Address of minute register */
#define	RTC_ADDR_SEC	0x00		/* Address of second register */

#ifdef CONFIG_SH_SECUREEDGE5410
#include <asm/rtc.h>
#include <mach/secureedge5410.h>

#define	RTC_RESET	0x1000
#define	RTC_IODATA	0x0800
#define	RTC_SCLK	0x0400

#ifdef CONFIG_SH_SECUREEDGE5410
#include <asm/snapgear.h>
#define set_dp(x)	SECUREEDGE_WRITE_IOPORT(x, 0x1c00)
#define get_dp()	SECUREEDGE_READ_IOPORT()
#define set_dp(x)	SECUREEDGE_WRITE_IOPORT(x, 0x1c00)
#define get_dp()	SECUREEDGE_READ_IOPORT()
#define ds1302_set_tx()
#define ds1302_set_rx()

static inline int ds1302_hw_init(void)
static int ds1302_rtc_set_time(struct device *dev, struct rtc_time *time)
{
	struct spi_device	*spi = dev_get_drvdata(dev);
	u8		buf[1 + RTC_CLCK_LEN];
	u8		*bp = buf;
	int		status;

	/* Enable writing */
	bp = buf;
	*bp++ = RTC_ADDR_CTRL << 1 | RTC_CMD_WRITE;
	*bp++ = RTC_CMD_WRITE_ENABLE;

	status = spi_write_then_read(spi, buf, 2,
			NULL, 0);
	if (status)
		return status;

	/* Write registers starting at the first time/date address. */
	bp = buf;
	*bp++ = RTC_CLCK_BURST << 1 | RTC_CMD_WRITE;

	*bp++ = bin2bcd(time->tm_sec);
	*bp++ = bin2bcd(time->tm_min);
	*bp++ = bin2bcd(time->tm_hour);
	*bp++ = bin2bcd(time->tm_mday);
	*bp++ = bin2bcd(time->tm_mon + 1);
	*bp++ = time->tm_wday + 1;
	*bp++ = bin2bcd(time->tm_year % 100);
	*bp++ = RTC_CMD_WRITE_DISABLE;

	/* use write-then-read since dma from stack is nonportable */
	return spi_write_then_read(spi, buf, sizeof(buf),
			NULL, 0);
}

static int ds1302_rtc_get_time(struct device *dev, struct rtc_time *time)
{
	struct spi_device	*spi = dev_get_drvdata(dev);
	u8		addr = RTC_CLCK_BURST << 1 | RTC_CMD_READ;
	u8		buf[RTC_CLCK_LEN - 1];
	int		status;

	/* Use write-then-read to get all the date/time registers
	 * since dma from stack is nonportable
	 */
	status = spi_write_then_read(spi, &addr, sizeof(addr),
			buf, sizeof(buf));
	if (status < 0)
		return status;

	/* Decode the registers */
	time->tm_sec = bcd2bin(buf[RTC_ADDR_SEC]);
	time->tm_min = bcd2bin(buf[RTC_ADDR_MIN]);
	time->tm_hour = bcd2bin(buf[RTC_ADDR_HOUR]);
	time->tm_wday = buf[RTC_ADDR_DAY] - 1;
	time->tm_mday = bcd2bin(buf[RTC_ADDR_DATE]);
	time->tm_mon = bcd2bin(buf[RTC_ADDR_MON]) - 1;
	time->tm_year = bcd2bin(buf[RTC_ADDR_YEAR]) + 100;

	/* Time may not be set */
	return rtc_valid_tm(time);
}

static inline void ds1302_clock(void)
{
	set_dp(get_dp() | RTC_SCLK);	/* clock high */
	set_dp(get_dp() & ~RTC_SCLK);	/* clock low */
}

static inline void ds1302_start(void)
{
	set_dp(get_dp() | RTC_RESET);
}

static inline void ds1302_stop(void)
{
	set_dp(get_dp() & ~RTC_RESET);
}

static inline void ds1302_txbit(int bit)
{
	set_dp((get_dp() & ~RTC_IODATA) | (bit ? RTC_IODATA : 0));
}

static inline int ds1302_rxbit(void)
{
	return !!(get_dp() & RTC_IODATA);
}

#else
#error "Add support for your platform"
#endif

struct ds1302_rtc {
	struct rtc_device *rtc_dev;
	spinlock_t lock;
};

static void ds1302_sendbits(unsigned int val)
{
	int i;

	for (i = 8; (i); i--, val >>= 1) {
		set_dp((get_dp() & ~RTC_IODATA) | ((val & 0x1) ?
			RTC_IODATA : 0));
		set_dp(get_dp() | RTC_SCLK);	/* clock high */
		set_dp(get_dp() & ~RTC_SCLK);	/* clock low */
	ds1302_set_tx();

	for (i = 8; (i); i--, val >>= 1) {
		ds1302_txbit(val & 0x1);
		ds1302_clock();
	}
}

static unsigned int ds1302_recvbits(void)
{
	unsigned int val;
	int i;

	for (i = 0, val = 0; (i < 8); i++) {
		val |= (((get_dp() & RTC_IODATA) ? 1 : 0) << i);
		set_dp(get_dp() | RTC_SCLK);	/* clock high */
		set_dp(get_dp() & ~RTC_SCLK);	/* clock low */
	ds1302_set_rx();

	for (i = 0, val = 0; (i < 8); i++) {
		val |= (ds1302_rxbit() << i);
		ds1302_clock();
	}

	return val;
}

static unsigned int ds1302_readbyte(unsigned int addr)
{
	unsigned int val;

	set_dp(get_dp() & ~(RTC_RESET | RTC_IODATA | RTC_SCLK));

	set_dp(get_dp() | RTC_RESET);
	ds1302_sendbits(((addr & 0x3f) << 1) | RTC_CMD_READ);
	val = ds1302_recvbits();
	set_dp(get_dp() & ~RTC_RESET);
	ds1302_reset();

	ds1302_start();
	ds1302_sendbits(((addr & 0x3f) << 1) | RTC_CMD_READ);
	val = ds1302_recvbits();
	ds1302_stop();

	return val;
}

static void ds1302_writebyte(unsigned int addr, unsigned int val)
{
	set_dp(get_dp() & ~(RTC_RESET | RTC_IODATA | RTC_SCLK));
	set_dp(get_dp() | RTC_RESET);
	ds1302_sendbits(((addr & 0x3f) << 1) | RTC_CMD_WRITE);
	ds1302_sendbits(val);
	set_dp(get_dp() & ~RTC_RESET);
	ds1302_reset();

	ds1302_start();
	ds1302_sendbits(((addr & 0x3f) << 1) | RTC_CMD_WRITE);
	ds1302_sendbits(val);
	ds1302_stop();
}

static int ds1302_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	struct ds1302_rtc *rtc = dev_get_drvdata(dev);

	spin_lock_irq(&rtc->lock);

	tm->tm_sec	= BCD2BIN(ds1302_readbyte(RTC_ADDR_SEC));
	tm->tm_min	= BCD2BIN(ds1302_readbyte(RTC_ADDR_MIN));
	tm->tm_hour	= BCD2BIN(ds1302_readbyte(RTC_ADDR_HOUR));
	tm->tm_wday	= BCD2BIN(ds1302_readbyte(RTC_ADDR_DAY));
	tm->tm_mday	= BCD2BIN(ds1302_readbyte(RTC_ADDR_DATE));
	tm->tm_mon	= BCD2BIN(ds1302_readbyte(RTC_ADDR_MON)) - 1;
	tm->tm_year	= BCD2BIN(ds1302_readbyte(RTC_ADDR_YEAR));
	tm->tm_sec	= bcd2bin(ds1302_readbyte(RTC_ADDR_SEC));
	tm->tm_min	= bcd2bin(ds1302_readbyte(RTC_ADDR_MIN));
	tm->tm_hour	= bcd2bin(ds1302_readbyte(RTC_ADDR_HOUR));
	tm->tm_wday	= bcd2bin(ds1302_readbyte(RTC_ADDR_DAY));
	tm->tm_mday	= bcd2bin(ds1302_readbyte(RTC_ADDR_DATE));
	tm->tm_mon	= bcd2bin(ds1302_readbyte(RTC_ADDR_MON)) - 1;
	tm->tm_year	= bcd2bin(ds1302_readbyte(RTC_ADDR_YEAR));

	if (tm->tm_year < 70)
		tm->tm_year += 100;

	spin_unlock_irq(&rtc->lock);

	dev_dbg(dev, "%s: tm is secs=%d, mins=%d, hours=%d, "
		"mday=%d, mon=%d, year=%d, wday=%d\n",
		__func__,
		tm->tm_sec, tm->tm_min, tm->tm_hour,
		tm->tm_mday, tm->tm_mon + 1, tm->tm_year, tm->tm_wday);

	if (rtc_valid_tm(tm) < 0)
		dev_err(dev, "invalid date\n");

	return 0;
	return rtc_valid_tm(tm);
}

static int ds1302_rtc_set_time(struct device *dev, struct rtc_time *tm)
{
	struct ds1302_rtc *rtc = dev_get_drvdata(dev);

	spin_lock_irq(&rtc->lock);

	/* Stop RTC */
	ds1302_writebyte(RTC_ADDR_SEC, ds1302_readbyte(RTC_ADDR_SEC) | 0x80);

	ds1302_writebyte(RTC_ADDR_SEC, BIN2BCD(tm->tm_sec));
	ds1302_writebyte(RTC_ADDR_MIN, BIN2BCD(tm->tm_min));
	ds1302_writebyte(RTC_ADDR_HOUR, BIN2BCD(tm->tm_hour));
	ds1302_writebyte(RTC_ADDR_DAY, BIN2BCD(tm->tm_wday));
	ds1302_writebyte(RTC_ADDR_DATE, BIN2BCD(tm->tm_mday));
	ds1302_writebyte(RTC_ADDR_MON, BIN2BCD(tm->tm_mon + 1));
	ds1302_writebyte(RTC_ADDR_YEAR, BIN2BCD(tm->tm_year % 100));
	ds1302_writebyte(RTC_ADDR_CTRL, RTC_CMD_WRITE_ENABLE);
	/* Stop RTC */
	ds1302_writebyte(RTC_ADDR_SEC, ds1302_readbyte(RTC_ADDR_SEC) | 0x80);

	ds1302_writebyte(RTC_ADDR_SEC, bin2bcd(tm->tm_sec));
	ds1302_writebyte(RTC_ADDR_MIN, bin2bcd(tm->tm_min));
	ds1302_writebyte(RTC_ADDR_HOUR, bin2bcd(tm->tm_hour));
	ds1302_writebyte(RTC_ADDR_DAY, bin2bcd(tm->tm_wday));
	ds1302_writebyte(RTC_ADDR_DATE, bin2bcd(tm->tm_mday));
	ds1302_writebyte(RTC_ADDR_MON, bin2bcd(tm->tm_mon + 1));
	ds1302_writebyte(RTC_ADDR_YEAR, bin2bcd(tm->tm_year % 100));

	/* Start RTC */
	ds1302_writebyte(RTC_ADDR_SEC, ds1302_readbyte(RTC_ADDR_SEC) & ~0x80);

	spin_unlock_irq(&rtc->lock);
	ds1302_writebyte(RTC_ADDR_CTRL, RTC_CMD_WRITE_DISABLE);

	return 0;
}

static int ds1302_rtc_ioctl(struct device *dev, unsigned int cmd,
			    unsigned long arg)
{
	switch (cmd) {
#ifdef RTC_SET_CHARGE
	case RTC_SET_CHARGE:
	{
		struct ds1302_rtc *rtc = dev_get_drvdata(dev);
		int tcs_val;

		if (copy_from_user(&tcs_val, (int __user *)arg, sizeof(int)))
			return -EFAULT;

		spin_lock_irq(&rtc->lock);
		ds1302_writebyte(RTC_ADDR_TCR, (0xa0 | tcs_val * 0xf));
		spin_unlock_irq(&rtc->lock);
		ds1302_writebyte(RTC_ADDR_TCR, (0xa0 | tcs_val * 0xf));
		return 0;
	}
#endif
	}

	return -ENOIOCTLCMD;
}

static struct rtc_class_ops ds1302_rtc_ops = {
	.read_time	= ds1302_rtc_read_time,
static const struct rtc_class_ops ds1302_rtc_ops = {
	.read_time	= ds1302_rtc_get_time,
	.set_time	= ds1302_rtc_set_time,
};

static int __devinit ds1302_rtc_probe(struct platform_device *pdev)
{
	struct ds1302_rtc *rtc;
	int ret;

	/* Reset */
	set_dp(get_dp() & ~(RTC_RESET | RTC_IODATA | RTC_SCLK));

	/* Write a magic value to the DS1302 RAM, and see if it sticks. */
	ds1302_writebyte(RTC_ADDR_RAM0, 0x42);
	if (ds1302_readbyte(RTC_ADDR_RAM0) != 0x42)
		return -ENODEV;

	rtc = kzalloc(sizeof(struct ds1302_rtc), GFP_KERNEL);
	if (unlikely(!rtc))
		return -ENOMEM;

	spin_lock_init(&rtc->lock);
	rtc->rtc_dev = rtc_device_register("ds1302", &pdev->dev,
					   &ds1302_rtc_ops, THIS_MODULE);
	if (IS_ERR(rtc->rtc_dev)) {
		ret = PTR_ERR(rtc->rtc_dev);
		goto out;
	}

	platform_set_drvdata(pdev, rtc);

	return 0;
out:
	kfree(rtc);
	return ret;
}

static int __devexit ds1302_rtc_remove(struct platform_device *pdev)
{
	struct ds1302_rtc *rtc = platform_get_drvdata(pdev);

	if (likely(rtc->rtc_dev))
		rtc_device_unregister(rtc->rtc_dev);

	platform_set_drvdata(pdev, NULL);

	kfree(rtc);

	return 0;
static int __init ds1302_rtc_probe(struct platform_device *pdev)
static int ds1302_probe(struct spi_device *spi)
{
	struct rtc_device	*rtc;
	u8		addr;
	u8		buf[4];
	u8		*bp = buf;
	int		status;

	/* Sanity check board setup data.  This may be hooked up
	 * in 3wire mode, but we don't care.  Note that unless
	 * there's an inverter in place, this needs SPI_CS_HIGH!
	 */
	if (spi->bits_per_word && (spi->bits_per_word != 8)) {
		dev_err(&spi->dev, "bad word length\n");
		return -EINVAL;
	} else if (spi->max_speed_hz > 2000000) {
		dev_err(&spi->dev, "speed is too high\n");
		return -EINVAL;
	} else if (spi->mode & SPI_CPHA) {
		dev_err(&spi->dev, "bad mode\n");
		return -EINVAL;
	}

	addr = RTC_ADDR_CTRL << 1 | RTC_CMD_READ;
	status = spi_write_then_read(spi, &addr, sizeof(addr), buf, 1);
	if (status < 0) {
		dev_err(&spi->dev, "control register read error %d\n",
				status);
		return status;
	}

	if ((buf[0] & ~RTC_CMD_WRITE_DISABLE) != 0) {
		status = spi_write_then_read(spi, &addr, sizeof(addr), buf, 1);
		if (status < 0) {
			dev_err(&spi->dev, "control register read error %d\n",
					status);
			return status;
		}

		if ((buf[0] & ~RTC_CMD_WRITE_DISABLE) != 0) {
			dev_err(&spi->dev, "junk in control register\n");
			return -ENODEV;
		}
	}
	if (buf[0] == 0) {
		bp = buf;
		*bp++ = RTC_ADDR_CTRL << 1 | RTC_CMD_WRITE;
		*bp++ = RTC_CMD_WRITE_DISABLE;

		status = spi_write_then_read(spi, buf, 2, NULL, 0);
		if (status < 0) {
			dev_err(&spi->dev, "control register write error %d\n",
					status);
			return status;
		}

		addr = RTC_ADDR_CTRL << 1 | RTC_CMD_READ;
		status = spi_write_then_read(spi, &addr, sizeof(addr), buf, 1);
		if (status < 0) {
			dev_err(&spi->dev,
					"error %d reading control register\n",
					status);
			return status;
		}

		if (buf[0] != RTC_CMD_WRITE_DISABLE) {
			dev_err(&spi->dev, "failed to detect chip\n");
			return -ENODEV;
		}
	}

	spi_set_drvdata(spi, spi);

	rtc = devm_rtc_device_register(&spi->dev, "ds1302",
			&ds1302_rtc_ops, THIS_MODULE);
	if (IS_ERR(rtc)) {
		status = PTR_ERR(rtc);
		dev_err(&spi->dev, "error %d registering rtc\n", status);
		return status;
	}

	return 0;
}

static struct platform_driver ds1302_platform_driver = {
	.driver		= {
		.name	= DRV_NAME,
		.owner	= THIS_MODULE,
	},
	.probe		= ds1302_rtc_probe,
	.remove		= __devexit_p(ds1302_rtc_remove),
};

static int __init ds1302_rtc_init(void)
{
	return platform_driver_register(&ds1302_platform_driver);
}

static void __exit ds1302_rtc_exit(void)
{
	platform_driver_unregister(&ds1302_platform_driver);
}

module_init(ds1302_rtc_init);
module_exit(ds1302_rtc_exit);
	},
static int ds1302_remove(struct spi_device *spi)
{
	spi_set_drvdata(spi, NULL);
	return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id ds1302_dt_ids[] = {
	{ .compatible = "maxim,ds1302", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, ds1302_dt_ids);
#endif

static struct spi_driver ds1302_driver = {
	.driver.name	= "rtc-ds1302",
	.driver.of_match_table = of_match_ptr(ds1302_dt_ids),
	.probe		= ds1302_probe,
	.remove		= ds1302_remove,
};

module_spi_driver(ds1302_driver);

MODULE_DESCRIPTION("Dallas DS1302 RTC driver");
MODULE_AUTHOR("Paul Mundt, David McCullough");
MODULE_LICENSE("GPL v2");
