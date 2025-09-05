/*
 * cdc-acm.c
 *
 * Copyright (c) 1999 Armin Fuerst	<fuerst@in.tum.de>
 * Copyright (c) 1999 Pavel Machek	<pavel@suse.cz>
 * Copyright (c) 1999 Pavel Machek	<pavel@ucw.cz>
 * Copyright (c) 1999 Johannes Erdfelt	<johannes@erdfelt.com>
 * Copyright (c) 2000 Vojtech Pavlik	<vojtech@suse.cz>
 * Copyright (c) 2004 Oliver Neukum	<oliver@neukum.name>
 * Copyright (c) 2005 David Kubicek	<dave@awk.cz>
 * Copyright (c) 2011 Johan Hovold	<jhovold@gmail.com>
 *
 * USB Abstract Control Model driver for USB modems and ISDN adapters
 *
 * Sponsored by SuSE
 *
 * ChangeLog:
 *	v0.9  - thorough cleaning, URBification, almost a rewrite
 *	v0.10 - some more cleanups
 *	v0.11 - fixed flow control, read error doesn't stop reads
 *	v0.12 - added TIOCM ioctls, added break handling, made struct acm kmalloced
 *	v0.13 - added termios, added hangup
 *	v0.14 - sized down struct acm
 *	v0.15 - fixed flow control again - characters could be lost
 *	v0.16 - added code for modems with swapped data and control interfaces
 *	v0.17 - added new style probing
 *	v0.18 - fixed new style probing for devices with more configurations
 *	v0.19 - fixed CLOCAL handling (thanks to Richard Shih-Ping Chan)
 *	v0.20 - switched to probing on interface (rather than device) class
 *	v0.21 - revert to probing on device for devices with multiple configs
 *	v0.22 - probe only the control interface. if usbcore doesn't choose the
 *		config we want, sysadmin changes bConfigurationValue in sysfs.
 *	v0.23 - use softirq for rx processing, as needed by tty layer
 *	v0.24 - change probe method to evaluate CDC union descriptor
 *	v0.25 - downstream tasks paralelized to maximize throughput
 *	v0.26 - multiple write urbs, writesize increased
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#undef DEBUG
#undef VERBOSE_DEBUG

#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/log2.h>
#include <linux/tty.h>
#include <linux/serial.h>
#include <linux/tty_driver.h>
#include <linux/tty_flip.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <asm/uaccess.h>
#include <linux/uaccess.h>
#include <linux/usb.h>
#include <linux/usb/cdc.h>
#include <asm/byteorder.h>
#include <asm/unaligned.h>
#include <linux/idr.h>
#include <linux/list.h>

#include "cdc-acm.h"


#define ACM_CLOSE_TIMEOUT	15	/* seconds to let writes drain */

/*
 * Version Information
 */
#define DRIVER_VERSION "v0.26"
#define DRIVER_AUTHOR "Armin Fuerst, Pavel Machek, Johannes Erdfelt, Vojtech Pavlik, David Kubicek"
#define DRIVER_AUTHOR "Armin Fuerst, Pavel Machek, Johannes Erdfelt, Vojtech Pavlik, David Kubicek, Johan Hovold"
#define DRIVER_DESC "USB Abstract Control Model driver for USB modems and ISDN adapters"

static struct usb_driver acm_driver;
static struct tty_driver *acm_tty_driver;
static struct acm *acm_table[ACM_TTY_MINORS];

static DEFINE_MUTEX(open_mutex);

#define ACM_READY(acm)	(acm && acm->dev && acm->used)

#ifdef VERBOSE_DEBUG
#define verbose	1
#else
#define verbose	0
#endif

static DEFINE_IDR(acm_minors);
static DEFINE_MUTEX(acm_minors_lock);

static void acm_tty_set_termios(struct tty_struct *tty,
				struct ktermios *termios_old);

/*
 * acm_minors accessors
 */

/*
 * Look up an ACM structure by minor. If found and not disconnected, increment
 * its refcount and return it with its mutex held.
 */
static struct acm *acm_get_by_minor(unsigned int minor)
{
	struct acm *acm;

	mutex_lock(&acm_minors_lock);
	acm = idr_find(&acm_minors, minor);
	if (acm) {
		mutex_lock(&acm->mutex);
		if (acm->disconnected) {
			mutex_unlock(&acm->mutex);
			acm = NULL;
		} else {
			tty_port_get(&acm->port);
			mutex_unlock(&acm->mutex);
		}
	}
	mutex_unlock(&acm_minors_lock);
	return acm;
}

/*
 * Try to find an available minor number and if found, associate it with 'acm'.
 */
static int acm_alloc_minor(struct acm *acm)
{
	int minor;

	mutex_lock(&acm_minors_lock);
	minor = idr_alloc(&acm_minors, acm, 0, ACM_TTY_MINORS, GFP_KERNEL);
	mutex_unlock(&acm_minors_lock);

	return minor;
}

/* Release the minor number associated with 'acm'.  */
static void acm_release_minor(struct acm *acm)
{
	mutex_lock(&acm_minors_lock);
	idr_remove(&acm_minors, acm->minor);
	mutex_unlock(&acm_minors_lock);
}

/*
 * Functions for ACM control messages.
 */

static int acm_ctrl_msg(struct acm *acm, int request, int value, void *buf, int len)
{
	int retval = usb_control_msg(acm->dev, usb_sndctrlpipe(acm->dev, 0),
		request, USB_RT_ACM, value,
		acm->control->altsetting[0].desc.bInterfaceNumber,
		buf, len, 5000);
	dbg("acm_control_msg: rq: 0x%02x val: %#x len: %#x result: %d", request, value, len, retval);
static int acm_ctrl_msg(struct acm *acm, int request, int value,
							void *buf, int len)
{
	int retval;

	retval = usb_autopm_get_interface(acm->control);
	if (retval)
		return retval;

	retval = usb_control_msg(acm->dev, usb_sndctrlpipe(acm->dev, 0),
		request, USB_RT_ACM, value,
		acm->control->altsetting[0].desc.bInterfaceNumber,
		buf, len, 5000);

	dev_dbg(&acm->control->dev,
		"%s - rq 0x%02x, val %#x, len %#x, result %d\n",
		__func__, request, value, len, retval);

	usb_autopm_put_interface(acm->control);

	return retval < 0 ? retval : 0;
}

/* devices aren't required to support these requests.
 * the cdc acm descriptor tells whether they do...
 */
#define acm_set_control(acm, control) \
	acm_ctrl_msg(acm, USB_CDC_REQ_SET_CONTROL_LINE_STATE, control, NULL, 0)
static inline int acm_set_control(struct acm *acm, int control)
{
	if (acm->quirks & QUIRK_CONTROL_LINE_STATE)
		return -EOPNOTSUPP;

	return acm_ctrl_msg(acm, USB_CDC_REQ_SET_CONTROL_LINE_STATE,
			control, NULL, 0);
}

#define acm_set_line(acm, line) \
	acm_ctrl_msg(acm, USB_CDC_REQ_SET_LINE_CODING, 0, line, sizeof *(line))
#define acm_send_break(acm, ms) \
	acm_ctrl_msg(acm, USB_CDC_REQ_SEND_BREAK, ms, NULL, 0)

static void acm_kill_urbs(struct acm *acm)
{
	int i;

	usb_kill_urb(acm->ctrlurb);
	for (i = 0; i < ACM_NW; i++)
		usb_kill_urb(acm->wb[i].urb);
	for (i = 0; i < acm->rx_buflimit; i++)
		usb_kill_urb(acm->read_urbs[i]);
}

/*
 * Write buffer management.
 * All of these assume proper locks taken by the caller.
 */

static int acm_wb_alloc(struct acm *acm)
{
	int i, wbn;
	struct acm_wb *wb;

	wbn = 0;
	i = 0;
	for (;;) {
		wb = &acm->wb[wbn];
		if (!wb->use) {
			wb->use = 1;
			wb->len = 0;
			return wbn;
		}
		wbn = (wbn + 1) % ACM_NW;
		if (++i >= ACM_NW)
			return -1;
	}
}

static int acm_wb_is_avail(struct acm *acm)
{
	int i, n;
	unsigned long flags;

	n = ACM_NW;
	spin_lock_irqsave(&acm->write_lock, flags);
	for (i = 0; i < ACM_NW; i++) {
		n -= acm->wb[i].use;
	}
	for (i = 0; i < ACM_NW; i++)
		n -= acm->wb[i].use;
	spin_unlock_irqrestore(&acm->write_lock, flags);
	return n;
}

/*
 * Finish write.
 */
static void acm_write_done(struct acm *acm, struct acm_wb *wb)
{
	unsigned long flags;

	spin_lock_irqsave(&acm->write_lock, flags);
	wb->use = 0;
	acm->transmitting--;
	spin_unlock_irqrestore(&acm->write_lock, flags);
 * Finish write. Caller must hold acm->write_lock
 */
static void acm_write_done(struct acm *acm, struct acm_wb *wb)
{
	wb->use = 0;
	acm->transmitting--;
	usb_autopm_put_interface_async(acm->control);
}

/*
 * Poke write.
 *
 * the caller is responsible for locking
 */

static int acm_start_wb(struct acm *acm, struct acm_wb *wb)
{
	int rc;

	acm->transmitting++;

	wb->urb->transfer_buffer = wb->buf;
	wb->urb->transfer_dma = wb->dmah;
	wb->urb->transfer_buffer_length = wb->len;
	wb->urb->dev = acm->dev;

	if ((rc = usb_submit_urb(wb->urb, GFP_ATOMIC)) < 0) {
		dbg("usb_submit_urb(write bulk) failed: %d", rc);
	rc = usb_submit_urb(wb->urb, GFP_ATOMIC);
	if (rc < 0) {
		dev_err(&acm->data->dev,
			"%s - usb_submit_urb(write bulk) failed: %d\n",
			__func__, rc);
		acm_write_done(acm, wb);
	}
	return rc;
}

static int acm_write_start(struct acm *acm, int wbn)
{
	unsigned long flags;
	struct acm_wb *wb = &acm->wb[wbn];
	int rc;

	spin_lock_irqsave(&acm->write_lock, flags);
	if (!acm->dev) {
		wb->use = 0;
		spin_unlock_irqrestore(&acm->write_lock, flags);
		return -ENODEV;
	}

	dbg("%s susp_count: %d", __func__, acm->susp_count);
	if (acm->susp_count) {
		acm->delayed_wb = wb;
		schedule_work(&acm->waker);
		spin_unlock_irqrestore(&acm->write_lock, flags);
		return 0;	/* A white lie */
	}
	usb_mark_last_busy(acm->dev);

	rc = acm_start_wb(acm, wb);
	spin_unlock_irqrestore(&acm->write_lock, flags);

	return rc;

}
/*
 * attributes exported through sysfs
 */
static ssize_t show_caps
(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct acm *acm = usb_get_intfdata(intf);

	return sprintf(buf, "%d", acm->ctrl_caps);
}
static DEVICE_ATTR(bmCapabilities, S_IRUGO, show_caps, NULL);

static ssize_t show_country_codes
(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct acm *acm = usb_get_intfdata(intf);

	memcpy(buf, acm->country_codes, acm->country_code_size);
	return acm->country_code_size;
}

static DEVICE_ATTR(wCountryCodes, S_IRUGO, show_country_codes, NULL);

static ssize_t show_country_rel_date
(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct acm *acm = usb_get_intfdata(intf);

	return sprintf(buf, "%d", acm->country_rel_date);
}

static DEVICE_ATTR(iCountryCodeRelDate, S_IRUGO, show_country_rel_date, NULL);
/*
 * Interrupt handlers for various ACM device responses
 */

static void acm_process_notification(struct acm *acm, unsigned char *buf)
{
	int newctrl;
	int difference;
	struct usb_cdc_notification *dr = (struct usb_cdc_notification *)buf;
	unsigned char *data = buf + sizeof(struct usb_cdc_notification);

	switch (status) {
	case 0:
		/* success */
		break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		/* this urb is terminated, clean up */
		dbg("%s - urb shutting down with status: %d", __func__, status);
		return;
	default:
		dbg("%s - nonzero urb status received: %d", __func__, status);
		goto exit;
	}

	if (!ACM_READY(acm))
		goto exit;

	data = (unsigned char *)(dr + 1);
	switch (dr->bNotificationType) {

		case USB_CDC_NOTIFY_NETWORK_CONNECTION:

			dbg("%s network", dr->wValue ? "connected to" : "disconnected from");
			break;

		case USB_CDC_NOTIFY_SERIAL_STATE:

			newctrl = get_unaligned_le16(data);

			if (acm->tty && !acm->clocal && (acm->ctrlin & ~newctrl & ACM_CTRL_DCD)) {
				dbg("calling hangup");
				tty_hangup(acm->tty);
			}

			acm->ctrlin = newctrl;

			dbg("input control lines: dcd%c dsr%c break%c ring%c framing%c parity%c overrun%c",
				acm->ctrlin & ACM_CTRL_DCD ? '+' : '-',	acm->ctrlin & ACM_CTRL_DSR ? '+' : '-',
				acm->ctrlin & ACM_CTRL_BRK ? '+' : '-',	acm->ctrlin & ACM_CTRL_RI  ? '+' : '-',
				acm->ctrlin & ACM_CTRL_FRAMING ? '+' : '-',	acm->ctrlin & ACM_CTRL_PARITY ? '+' : '-',
				acm->ctrlin & ACM_CTRL_OVERRUN ? '+' : '-');

			break;

		default:
			dbg("unknown notification %d received: index %d len %d data0 %d data1 %d",
				dr->bNotificationType, dr->wIndex,
				dr->wLength, data[0], data[1]);
			break;
	}
exit:
	usb_mark_last_busy(acm->dev);
	retval = usb_submit_urb (urb, GFP_ATOMIC);
	if (retval)
		err ("%s - usb_submit_urb failed with result %d",
		     __func__, retval);
}

/* data interface returns incoming bytes, or we got unthrottled */
static void acm_read_bulk(struct urb *urb)
{
	struct acm_rb *buf;
	struct acm_ru *rcv = urb->context;
	struct acm *acm = rcv->instance;
	int status = urb->status;

	dbg("Entering acm_read_bulk with status %d", status);

	if (!ACM_READY(acm)) {
		dev_dbg(&acm->data->dev, "Aborting, acm not ready");
		return;
	}
	usb_mark_last_busy(acm->dev);

	if (status)
		dev_dbg(&acm->data->dev, "bulk rx status %d\n", status);

	buf = rcv->buffer;
	buf->size = urb->actual_length;

	if (likely(status == 0)) {
		spin_lock(&acm->read_lock);
		acm->processing++;
		list_add_tail(&rcv->list, &acm->spare_read_urbs);
		list_add_tail(&buf->list, &acm->filled_read_bufs);
		spin_unlock(&acm->read_lock);
	} else {
		/* we drop the buffer due to an error */
		spin_lock(&acm->read_lock);
		list_add_tail(&rcv->list, &acm->spare_read_urbs);
		list_add(&buf->list, &acm->spare_read_bufs);
		spin_unlock(&acm->read_lock);
		/* nevertheless the tasklet must be kicked unconditionally
		so the queue cannot dry up */
	}
	if (likely(!acm->susp_count))
		tasklet_schedule(&acm->urb_task);
}

static void acm_rx_tasklet(unsigned long _acm)
{
	struct acm *acm = (void *)_acm;
	struct acm_rb *buf;
	struct tty_struct *tty = acm->tty;
	struct acm_ru *rcv;
	unsigned long flags;
	unsigned char throttled;

	dbg("Entering acm_rx_tasklet");

	if (!ACM_READY(acm))
	{
		dbg("acm_rx_tasklet: ACM not ready");
		return;
	}

	spin_lock_irqsave(&acm->throttle_lock, flags);
	throttled = acm->throttle;
	spin_unlock_irqrestore(&acm->throttle_lock, flags);
	if (throttled)
	{
		dbg("acm_rx_tasklet: throttled");
		return;
	}

next_buffer:
	spin_lock_irqsave(&acm->read_lock, flags);
	if (list_empty(&acm->filled_read_bufs)) {
		spin_unlock_irqrestore(&acm->read_lock, flags);
		goto urbs;
	}
	buf = list_entry(acm->filled_read_bufs.next,
			 struct acm_rb, list);
	list_del(&buf->list);
	spin_unlock_irqrestore(&acm->read_lock, flags);

	dbg("acm_rx_tasklet: procesing buf 0x%p, size = %d", buf, buf->size);

	tty_buffer_request_room(tty, buf->size);
	spin_lock_irqsave(&acm->throttle_lock, flags);
	throttled = acm->throttle;
	spin_unlock_irqrestore(&acm->throttle_lock, flags);
	if (!throttled)
		tty_insert_flip_string(tty, buf->base, buf->size);
	tty_flip_buffer_push(tty);

	if (throttled) {
		dbg("Throttling noticed");
		spin_lock_irqsave(&acm->read_lock, flags);
		list_add(&buf->list, &acm->filled_read_bufs);
		spin_unlock_irqrestore(&acm->read_lock, flags);
		return;
	}

	spin_lock_irqsave(&acm->read_lock, flags);
	list_add(&buf->list, &acm->spare_read_bufs);
	spin_unlock_irqrestore(&acm->read_lock, flags);
	goto next_buffer;

urbs:
	while (!list_empty(&acm->spare_read_bufs)) {
		spin_lock_irqsave(&acm->read_lock, flags);
		if (list_empty(&acm->spare_read_urbs)) {
			acm->processing = 0;
			spin_unlock_irqrestore(&acm->read_lock, flags);
			return;
		}
		rcv = list_entry(acm->spare_read_urbs.next,
				 struct acm_ru, list);
		list_del(&rcv->list);
		spin_unlock_irqrestore(&acm->read_lock, flags);

		buf = list_entry(acm->spare_read_bufs.next,
				 struct acm_rb, list);
		list_del(&buf->list);

		rcv->buffer = buf;

		usb_fill_bulk_urb(rcv->urb, acm->dev,
				  acm->rx_endpoint,
				  buf->base,
				  acm->readsize,
				  acm_read_bulk, rcv);
		rcv->urb->transfer_dma = buf->dma;
		rcv->urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;

		/* This shouldn't kill the driver as unsuccessful URBs are returned to the
		   free-urbs-pool and resubmited ASAP */
		spin_lock_irqsave(&acm->read_lock, flags);
		if (acm->susp_count || usb_submit_urb(rcv->urb, GFP_ATOMIC) < 0) {
			list_add(&buf->list, &acm->spare_read_bufs);
			list_add(&rcv->list, &acm->spare_read_urbs);
			acm->processing = 0;
			spin_unlock_irqrestore(&acm->read_lock, flags);
			return;
		} else {
			spin_unlock_irqrestore(&acm->read_lock, flags);
			dbg("acm_rx_tasklet: sending urb 0x%p, rcv 0x%p, buf 0x%p", rcv->urb, rcv, buf);
		}
	}
	spin_lock_irqsave(&acm->read_lock, flags);
	acm->processing = 0;
	spin_unlock_irqrestore(&acm->read_lock, flags);
		dev_dbg(&acm->control->dev,
				"%s - urb shutting down with status: %d\n",
				__func__, status);
		return;
	default:
		dev_dbg(&acm->control->dev,
				"%s - nonzero urb status received: %d\n",
				__func__, status);
		goto exit;
	}

	usb_mark_last_busy(acm->dev);

	data = (unsigned char *)(dr + 1);
	switch (dr->bNotificationType) {
	case USB_CDC_NOTIFY_NETWORK_CONNECTION:
		dev_dbg(&acm->control->dev,
			"%s - network connection: %d\n", __func__, dr->wValue);
		break;

	case USB_CDC_NOTIFY_SERIAL_STATE:
		if (le16_to_cpu(dr->wLength) != 2) {
			dev_dbg(&acm->control->dev,
				"%s - malformed serial state\n", __func__);
			break;
		}

		newctrl = get_unaligned_le16(data);
		dev_dbg(&acm->control->dev,
			"%s - serial state: 0x%x\n", __func__, newctrl);

		if (!acm->clocal && (acm->ctrlin & ~newctrl & ACM_CTRL_DCD)) {
			dev_dbg(&acm->control->dev,
				"%s - calling hangup\n", __func__);
			tty_port_tty_hangup(&acm->port, false);
		}

		difference = acm->ctrlin ^ newctrl;
		spin_lock(&acm->read_lock);
		acm->ctrlin = newctrl;
		acm->oldcount = acm->iocount;

		if (difference & ACM_CTRL_DSR)
			acm->iocount.dsr++;
		if (difference & ACM_CTRL_BRK)
			acm->iocount.brk++;
		if (difference & ACM_CTRL_RI)
			acm->iocount.rng++;
		if (difference & ACM_CTRL_DCD)
			acm->iocount.dcd++;
		if (difference & ACM_CTRL_FRAMING)
			acm->iocount.frame++;
		if (difference & ACM_CTRL_PARITY)
			acm->iocount.parity++;
		if (difference & ACM_CTRL_OVERRUN)
			acm->iocount.overrun++;
		spin_unlock(&acm->read_lock);

		if (difference)
			wake_up_all(&acm->wioctl);

		break;

	default:
		dev_dbg(&acm->control->dev,
			"%s - unknown notification %d received: index %d len %d\n",
			__func__,
			dr->bNotificationType, dr->wIndex, dr->wLength);
	}
}

/* control interface reports status changes with "interrupt" transfers */
static void acm_ctrl_irq(struct urb *urb)
{
	struct acm *acm = urb->context;
	struct usb_cdc_notification *dr = urb->transfer_buffer;
	unsigned int current_size = urb->actual_length;
	unsigned int expected_size, copy_size, alloc_size;
	int retval;
	int status = urb->status;

	switch (status) {
	case 0:
		/* success */
		break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		/* this urb is terminated, clean up */
		acm->nb_index = 0;
		dev_dbg(&acm->control->dev,
			"%s - urb shutting down with status: %d\n",
			__func__, status);
		return;
	default:
		dev_dbg(&acm->control->dev,
			"%s - nonzero urb status received: %d\n",
			__func__, status);
		goto exit;
	}

	usb_mark_last_busy(acm->dev);

	if (acm->nb_index)
		dr = (struct usb_cdc_notification *)acm->notification_buffer;

	/* size = notification-header + (optional) data */
	expected_size = sizeof(struct usb_cdc_notification) +
					le16_to_cpu(dr->wLength);

	if (current_size < expected_size) {
		/* notification is transmitted fragmented, reassemble */
		if (acm->nb_size < expected_size) {
			if (acm->nb_size) {
				kfree(acm->notification_buffer);
				acm->nb_size = 0;
			}
			alloc_size = roundup_pow_of_two(expected_size);
			/*
			 * kmalloc ensures a valid notification_buffer after a
			 * use of kfree in case the previous allocation was too
			 * small. Final freeing is done on disconnect.
			 */
			acm->notification_buffer =
				kmalloc(alloc_size, GFP_ATOMIC);
			if (!acm->notification_buffer)
				goto exit;
			acm->nb_size = alloc_size;
		}

		copy_size = min(current_size,
				expected_size - acm->nb_index);

		memcpy(&acm->notification_buffer[acm->nb_index],
		       urb->transfer_buffer, copy_size);
		acm->nb_index += copy_size;
		current_size = acm->nb_index;
	}

	if (current_size >= expected_size) {
		/* notification complete */
		acm_process_notification(acm, (unsigned char *)dr);
		acm->nb_index = 0;
	}

exit:
	retval = usb_submit_urb(urb, GFP_ATOMIC);
	if (retval && retval != -EPERM)
		dev_err(&acm->control->dev,
			"%s - usb_submit_urb failed: %d\n", __func__, retval);
}

static int acm_submit_read_urb(struct acm *acm, int index, gfp_t mem_flags)
{
	int res;

	if (!test_and_clear_bit(index, &acm->read_urbs_free))
		return 0;

	res = usb_submit_urb(acm->read_urbs[index], mem_flags);
	if (res) {
		if (res != -EPERM && res != -ENODEV) {
			dev_err(&acm->data->dev,
				"urb %d failed submission with %d\n",
				index, res);
		}
		set_bit(index, &acm->read_urbs_free);
		return res;
	} else {
		dev_vdbg(&acm->data->dev, "submitted urb %d\n", index);
	}

	return 0;
}

static int acm_submit_read_urbs(struct acm *acm, gfp_t mem_flags)
{
	int res;
	int i;

	for (i = 0; i < acm->rx_buflimit; ++i) {
		res = acm_submit_read_urb(acm, i, mem_flags);
		if (res)
			return res;
	}

	return 0;
}

static void acm_process_read_urb(struct acm *acm, struct urb *urb)
{
	if (!urb->actual_length)
		return;

	tty_insert_flip_string(&acm->port, urb->transfer_buffer,
			urb->actual_length);
	tty_flip_buffer_push(&acm->port);
}

static void acm_read_bulk_callback(struct urb *urb)
{
	struct acm_rb *rb = urb->context;
	struct acm *acm = rb->instance;
	unsigned long flags;
	int status = urb->status;

	dev_vdbg(&acm->data->dev, "got urb %d, len %d, status %d\n",
		rb->index, urb->actual_length, status);

	set_bit(rb->index, &acm->read_urbs_free);

	if (!acm->dev) {
		dev_dbg(&acm->data->dev, "%s - disconnected\n", __func__);
		return;
	}

	switch (status) {
	case 0:
		usb_mark_last_busy(acm->dev);
		acm_process_read_urb(acm, urb);
		break;
	case -EPIPE:
		set_bit(EVENT_RX_STALL, &acm->flags);
		schedule_work(&acm->work);
		return;
	case -ENOENT:
	case -ECONNRESET:
	case -ESHUTDOWN:
		dev_dbg(&acm->data->dev,
			"%s - urb shutting down with status: %d\n",
			__func__, status);
		return;
	default:
		dev_dbg(&acm->data->dev,
			"%s - nonzero urb status received: %d\n",
			__func__, status);
		break;
	}

	/*
	 * Unthrottle may run on another CPU which needs to see events
	 * in the same order. Submission has an implict barrier
	 */
	smp_mb__before_atomic();

	/* throttle device if requested by tty */
	spin_lock_irqsave(&acm->read_lock, flags);
	acm->throttled = acm->throttle_req;
	if (!acm->throttled) {
		spin_unlock_irqrestore(&acm->read_lock, flags);
		acm_submit_read_urb(acm, rb->index, GFP_ATOMIC);
	} else {
		spin_unlock_irqrestore(&acm->read_lock, flags);
	}
}

/* data interface wrote those outgoing bytes */
static void acm_write_bulk(struct urb *urb)
{
	struct acm_wb *wb = urb->context;
	struct acm *acm = wb->instance;

	if (verbose || urb->status
			|| (urb->actual_length != urb->transfer_buffer_length))
		dev_dbg(&acm->data->dev, "tx %d/%d bytes -- > %d\n",
			urb->actual_length,
			urb->transfer_buffer_length,
			urb->status);

	acm_write_done(acm, wb);
	if (ACM_READY(acm))
		schedule_work(&acm->work);
	else
		wake_up_interruptible(&acm->drain_wait);
	unsigned long flags;
	int status = urb->status;

	if (status || (urb->actual_length != urb->transfer_buffer_length))
		dev_vdbg(&acm->data->dev, "wrote len %d/%d, status %d\n",
			urb->actual_length,
			urb->transfer_buffer_length,
			status);

	spin_lock_irqsave(&acm->write_lock, flags);
	acm_write_done(acm, wb);
	spin_unlock_irqrestore(&acm->write_lock, flags);
	set_bit(EVENT_TTY_WAKEUP, &acm->flags);
	schedule_work(&acm->work);
}

static void acm_softint(struct work_struct *work)
{
	int i;
	struct acm *acm = container_of(work, struct acm, work);

	dev_vdbg(&acm->data->dev, "tx work\n");
	if (!ACM_READY(acm))
		return;
	tty_wakeup(acm->tty);
}

static void acm_waker(struct work_struct *waker)
{
	struct acm *acm = container_of(waker, struct acm, waker);
	int rv;

	rv = usb_autopm_get_interface(acm->control);
	if (rv < 0) {
		err("Autopm failure in %s", __func__);
		return;
	}
	if (acm->delayed_wb) {
		acm_start_wb(acm, acm->delayed_wb);
		acm->delayed_wb = NULL;
	}
	usb_autopm_put_interface(acm->control);
	dev_vdbg(&acm->data->dev, "%s\n", __func__);
	if (test_bit(EVENT_RX_STALL, &acm->flags)) {
		if (!(usb_autopm_get_interface(acm->data))) {
			for (i = 0; i < acm->rx_buflimit; i++)
				usb_kill_urb(acm->read_urbs[i]);
			usb_clear_halt(acm->dev, acm->in);
			acm_submit_read_urbs(acm, GFP_KERNEL);
			usb_autopm_put_interface(acm->data);
		}
		clear_bit(EVENT_RX_STALL, &acm->flags);
	}

	if (test_bit(EVENT_TTY_WAKEUP, &acm->flags)) {
		tty_port_tty_wakeup(&acm->port);
		clear_bit(EVENT_TTY_WAKEUP, &acm->flags);
	}
}

/*
 * TTY handlers
 */

static int acm_tty_open(struct tty_struct *tty, struct file *filp)
{
	struct acm *acm;
	int rv = -EINVAL;
	int i;
	dbg("Entering acm_tty_open.");

	mutex_lock(&open_mutex);

	acm = acm_table[tty->index];
	if (!acm || !acm->dev)
		goto err_out;
	else
		rv = 0;

	set_bit(TTY_NO_WRITE_SPLIT, &tty->flags);
	tty->driver_data = acm;
	acm->tty = tty;

	/* force low_latency on so that our tty_push actually forces the data through,
	   otherwise it is scheduled, and with high data rates data can get lost. */
	tty->low_latency = 1;

	if (usb_autopm_get_interface(acm->control) < 0)
		goto early_bail;
	else
		acm->control->needs_remote_wakeup = 1;

	mutex_lock(&acm->mutex);
	if (acm->used++) {
		usb_autopm_put_interface(acm->control);
		goto done;
        }


	acm->ctrlurb->dev = acm->dev;
	if (usb_submit_urb(acm->ctrlurb, GFP_KERNEL)) {
		dbg("usb_submit_urb(ctrl irq) failed");
		goto bail_out;
	}

	if (0 > acm_set_control(acm, acm->ctrlout = ACM_CTRL_DTR | ACM_CTRL_RTS) &&
	    (acm->ctrl_caps & USB_CDC_CAP_LINE))
		goto full_bailout;
	usb_autopm_put_interface(acm->control);

	INIT_LIST_HEAD(&acm->spare_read_urbs);
	INIT_LIST_HEAD(&acm->spare_read_bufs);
	INIT_LIST_HEAD(&acm->filled_read_bufs);
	for (i = 0; i < acm->rx_buflimit; i++) {
		list_add(&(acm->ru[i].list), &acm->spare_read_urbs);
	}
	for (i = 0; i < acm->rx_buflimit; i++) {
		list_add(&(acm->rb[i].list), &acm->spare_read_bufs);
	}

	acm->throttle = 0;

	tasklet_schedule(&acm->urb_task);

done:
	mutex_unlock(&acm->mutex);
err_out:
	mutex_unlock(&open_mutex);
	return rv;

full_bailout:
	usb_kill_urb(acm->ctrlurb);
bail_out:
	usb_autopm_put_interface(acm->control);
	acm->used--;
	mutex_unlock(&acm->mutex);
early_bail:
	mutex_unlock(&open_mutex);
	return -EIO;
}

static void acm_tty_unregister(struct acm *acm)
{
	int i,nr;

	nr = acm->rx_buflimit;
	tty_unregister_device(acm_tty_driver, acm->minor);
	usb_put_intf(acm->control);
	acm_table[acm->minor] = NULL;
	usb_free_urb(acm->ctrlurb);
	for (i = 0; i < ACM_NW; i++)
		usb_free_urb(acm->wb[i].urb);
	for (i = 0; i < nr; i++)
		usb_free_urb(acm->ru[i].urb);
static int acm_tty_install(struct tty_driver *driver, struct tty_struct *tty)
{
	struct acm *acm;
	int retval;

	acm = acm_get_by_minor(tty->index);
	if (!acm)
		return -ENODEV;

	retval = tty_standard_install(driver, tty);
	if (retval)
		goto error_init_termios;

	tty->driver_data = acm;

	return 0;

error_init_termios:
	tty_port_put(&acm->port);
	return retval;
}

static int acm_tty_open(struct tty_struct *tty, struct file *filp)
{
	struct acm *acm = tty->driver_data;

	return tty_port_open(&acm->port, tty, filp);
}

static void acm_port_dtr_rts(struct tty_port *port, int raise)
{
	struct acm *acm = container_of(port, struct acm, port);
	int val;
	int res;

	if (raise)
		val = ACM_CTRL_DTR | ACM_CTRL_RTS;
	else
		val = 0;

	/* FIXME: add missing ctrlout locking throughout driver */
	acm->ctrlout = val;

	res = acm_set_control(acm, val);
	if (res && (acm->ctrl_caps & USB_CDC_CAP_LINE))
		dev_err(&acm->control->dev, "failed to set dtr/rts\n");
}

static int acm_port_activate(struct tty_port *port, struct tty_struct *tty)
{
	struct acm *acm = container_of(port, struct acm, port);
	int retval = -ENODEV;
	int i;

	mutex_lock(&acm->mutex);
	if (acm->disconnected)
		goto disconnected;

	retval = usb_autopm_get_interface(acm->control);
	if (retval)
		goto error_get_interface;

	/*
	 * FIXME: Why do we need this? Allocating 64K of physically contiguous
	 * memory is really nasty...
	 */
	set_bit(TTY_NO_WRITE_SPLIT, &tty->flags);
	acm->control->needs_remote_wakeup = 1;

	acm->ctrlurb->dev = acm->dev;
	retval = usb_submit_urb(acm->ctrlurb, GFP_KERNEL);
	if (retval) {
		dev_err(&acm->control->dev,
			"%s - usb_submit_urb(ctrl irq) failed\n", __func__);
		goto error_submit_urb;
	}

	acm_tty_set_termios(tty, NULL);

	/*
	 * Unthrottle device in case the TTY was closed while throttled.
	 */
	spin_lock_irq(&acm->read_lock);
	acm->throttled = 0;
	acm->throttle_req = 0;
	spin_unlock_irq(&acm->read_lock);

	retval = acm_submit_read_urbs(acm, GFP_KERNEL);
	if (retval)
		goto error_submit_read_urbs;

	usb_autopm_put_interface(acm->control);

	mutex_unlock(&acm->mutex);

	return 0;

error_submit_read_urbs:
	for (i = 0; i < acm->rx_buflimit; i++)
		usb_kill_urb(acm->read_urbs[i]);
	usb_kill_urb(acm->ctrlurb);
error_submit_urb:
	usb_autopm_put_interface(acm->control);
error_get_interface:
disconnected:
	mutex_unlock(&acm->mutex);

	return usb_translate_errors(retval);
}

static void acm_port_destruct(struct tty_port *port)
{
	struct acm *acm = container_of(port, struct acm, port);

	acm_release_minor(acm);
	usb_put_intf(acm->control);
	kfree(acm->country_codes);
	kfree(acm);
}

static int acm_tty_chars_in_buffer(struct tty_struct *tty);
static void acm_port_shutdown(struct tty_port *port)
{
	struct acm *acm = container_of(port, struct acm, port);
	struct urb *urb;
	struct acm_wb *wb;

	/*
	 * Need to grab write_lock to prevent race with resume, but no need to
	 * hold it due to the tty-port initialised flag.
	 */
	spin_lock_irq(&acm->write_lock);
	spin_unlock_irq(&acm->write_lock);

	usb_autopm_get_interface_no_resume(acm->control);
	acm->control->needs_remote_wakeup = 0;
	usb_autopm_put_interface(acm->control);

	for (;;) {
		urb = usb_get_from_anchor(&acm->delayed);
		if (!urb)
			break;
		wb = urb->context;
		wb->use = 0;
		usb_autopm_put_interface_async(acm->control);
	}

	acm_kill_urbs(acm);
}

static void acm_tty_cleanup(struct tty_struct *tty)
{
	struct acm *acm = tty->driver_data;

	tty_port_put(&acm->port);
}

static void acm_tty_hangup(struct tty_struct *tty)
{
	struct acm *acm = tty->driver_data;

	tty_port_hangup(&acm->port);
}

static void acm_tty_close(struct tty_struct *tty, struct file *filp)
{
	struct acm *acm = tty->driver_data;
	int i,nr;

	if (!acm || !acm->used)
		return;

	nr = acm->rx_buflimit;
	mutex_lock(&open_mutex);
	if (!--acm->used) {
		if (acm->dev) {
			usb_autopm_get_interface(acm->control);
			acm_set_control(acm, acm->ctrlout = 0);

			/* try letting the last writes drain naturally */
			wait_event_interruptible_timeout(acm->drain_wait,
					(ACM_NW == acm_wb_is_avail(acm))
						|| !acm->dev,
					ACM_CLOSE_TIMEOUT * HZ);

			usb_kill_urb(acm->ctrlurb);
			for (i = 0; i < ACM_NW; i++)
				usb_kill_urb(acm->wb[i].urb);
			for (i = 0; i < nr; i++)
				usb_kill_urb(acm->ru[i].urb);
			acm->control->needs_remote_wakeup = 0;
			usb_autopm_put_interface(acm->control);
		} else
			acm_tty_unregister(acm);
	}
	mutex_unlock(&open_mutex);
}

static int acm_tty_write(struct tty_struct *tty, const unsigned char *buf, int count)
	dev_dbg(&acm->control->dev, "%s\n", __func__);

	tty_port_close(&acm->port, tty, filp);
}

static int acm_tty_write(struct tty_struct *tty,
					const unsigned char *buf, int count)
{
	struct acm *acm = tty->driver_data;
	int stat;
	unsigned long flags;
	int wbn;
	struct acm_wb *wb;

	dbg("Entering acm_tty_write to write %d bytes,", count);

	if (!ACM_READY(acm))
		return -EINVAL;
	if (!count)
		return 0;

	spin_lock_irqsave(&acm->write_lock, flags);
	if ((wbn = acm_wb_alloc(acm)) < 0) {
	if (!count)
		return 0;

	dev_vdbg(&acm->data->dev, "%d bytes from tty layer\n", count);

	spin_lock_irqsave(&acm->write_lock, flags);
	wbn = acm_wb_alloc(acm);
	if (wbn < 0) {
		spin_unlock_irqrestore(&acm->write_lock, flags);
		return 0;
	}
	wb = &acm->wb[wbn];

	count = (count > acm->writesize) ? acm->writesize : count;
	dbg("Get %d bytes...", count);
	memcpy(wb->buf, buf, count);
	wb->len = count;
	spin_unlock_irqrestore(&acm->write_lock, flags);

	if ((stat = acm_write_start(acm, wbn)) < 0)
	if (!acm->dev) {
		wb->use = 0;
		spin_unlock_irqrestore(&acm->write_lock, flags);
		return -ENODEV;
	}

	count = (count > acm->writesize) ? acm->writesize : count;
	dev_vdbg(&acm->data->dev, "writing %d bytes\n", count);
	memcpy(wb->buf, buf, count);
	wb->len = count;

	stat = usb_autopm_get_interface_async(acm->control);
	if (stat) {
		wb->use = 0;
		spin_unlock_irqrestore(&acm->write_lock, flags);
		return stat;
	}

	if (acm->susp_count) {
		if (acm->putbuffer) {
			/* now to preserve order */
			usb_anchor_urb(acm->putbuffer->urb, &acm->delayed);
			acm->putbuffer = NULL;
		}
		usb_anchor_urb(wb->urb, &acm->delayed);
		spin_unlock_irqrestore(&acm->write_lock, flags);
		return count;
	} else {
		if (acm->putbuffer) {
			/* at this point there is no good way to handle errors */
			acm_start_wb(acm, acm->putbuffer);
			acm->putbuffer = NULL;
		}
	}

	stat = acm_start_wb(acm, wb);
	spin_unlock_irqrestore(&acm->write_lock, flags);

	if (stat < 0)
		return stat;
	return count;
}

static void acm_tty_flush_chars(struct tty_struct *tty)
{
	struct acm *acm = tty->driver_data;
	struct acm_wb *cur;
	int err;
	unsigned long flags;

	spin_lock_irqsave(&acm->write_lock, flags);

	cur = acm->putbuffer;
	if (!cur) /* nothing to do */
		goto out;

	acm->putbuffer = NULL;
	err = usb_autopm_get_interface_async(acm->control);
	if (err < 0) {
		cur->use = 0;
		acm->putbuffer = cur;
		goto out;
	}

	if (acm->susp_count)
		usb_anchor_urb(cur->urb, &acm->delayed);
	else
		acm_start_wb(acm, cur);
out:
	spin_unlock_irqrestore(&acm->write_lock, flags);
	return;
}

static int acm_tty_put_char(struct tty_struct *tty, unsigned char ch)
{
	struct acm *acm = tty->driver_data;
	struct acm_wb *cur;
	int wbn;
	unsigned long flags;

overflow:
	cur = acm->putbuffer;
	if (!cur) {
		spin_lock_irqsave(&acm->write_lock, flags);
		wbn = acm_wb_alloc(acm);
		if (wbn >= 0) {
			cur = &acm->wb[wbn];
			acm->putbuffer = cur;
		}
		spin_unlock_irqrestore(&acm->write_lock, flags);
		if (!cur)
			return 0;
	}

	if (cur->len == acm->writesize) {
		acm_tty_flush_chars(tty);
		goto overflow;
	}

	cur->buf[cur->len++] = ch;
	return 1;
}

static int acm_tty_write_room(struct tty_struct *tty)
{
	struct acm *acm = tty->driver_data;
	if (!ACM_READY(acm))
		return -EINVAL;
	/*
	 * Do not let the line discipline to know that we have a reserve,
	 * or it might get too enthusiastic.
	 */
	return acm_wb_is_avail(acm) ? acm->writesize : 0;
}

static int acm_tty_chars_in_buffer(struct tty_struct *tty)
{
	struct acm *acm = tty->driver_data;
	if (!ACM_READY(acm))
		return -EINVAL;
	/*
	 * if the device was unplugged then any remaining characters fell out
	 * of the connector ;)
	 */
	if (acm->disconnected)
		return 0;
	/*
	 * This is inaccurate (overcounts), but it works.
	 */
	return (ACM_NW - acm_wb_is_avail(acm)) * acm->writesize;
}

static void acm_tty_throttle(struct tty_struct *tty)
{
	struct acm *acm = tty->driver_data;
	if (!ACM_READY(acm))
		return;
	spin_lock_bh(&acm->throttle_lock);
	acm->throttle = 1;
	spin_unlock_bh(&acm->throttle_lock);

	spin_lock_irq(&acm->read_lock);
	acm->throttle_req = 1;
	spin_unlock_irq(&acm->read_lock);
}

static void acm_tty_unthrottle(struct tty_struct *tty)
{
	struct acm *acm = tty->driver_data;
	if (!ACM_READY(acm))
		return;
	spin_lock_bh(&acm->throttle_lock);
	acm->throttle = 0;
	spin_unlock_bh(&acm->throttle_lock);
	tasklet_schedule(&acm->urb_task);
	unsigned int was_throttled;

	spin_lock_irq(&acm->read_lock);
	was_throttled = acm->throttled;
	acm->throttled = 0;
	acm->throttle_req = 0;
	spin_unlock_irq(&acm->read_lock);

	if (was_throttled)
		acm_submit_read_urbs(acm, GFP_KERNEL);
}

static int acm_tty_break_ctl(struct tty_struct *tty, int state)
{
	struct acm *acm = tty->driver_data;
	int retval;
	if (!ACM_READY(acm))
		return -EINVAL;
	retval = acm_send_break(acm, state ? 0xffff : 0);
	if (retval < 0)
		dbg("send break failed");
	return retval;
}

static int acm_tty_tiocmget(struct tty_struct *tty, struct file *file)
{
	struct acm *acm = tty->driver_data;

	if (!ACM_READY(acm))
		return -EINVAL;


	retval = acm_send_break(acm, state ? 0xffff : 0);
	if (retval < 0)
		dev_dbg(&acm->control->dev,
			"%s - send break failed\n", __func__);
	return retval;
}

static int acm_tty_tiocmget(struct tty_struct *tty)
{
	struct acm *acm = tty->driver_data;

	return (acm->ctrlout & ACM_CTRL_DTR ? TIOCM_DTR : 0) |
	       (acm->ctrlout & ACM_CTRL_RTS ? TIOCM_RTS : 0) |
	       (acm->ctrlin  & ACM_CTRL_DSR ? TIOCM_DSR : 0) |
	       (acm->ctrlin  & ACM_CTRL_RI  ? TIOCM_RI  : 0) |
	       (acm->ctrlin  & ACM_CTRL_DCD ? TIOCM_CD  : 0) |
	       TIOCM_CTS;
}

static int acm_tty_tiocmset(struct tty_struct *tty, struct file *file,
static int acm_tty_tiocmset(struct tty_struct *tty,
			    unsigned int set, unsigned int clear)
{
	struct acm *acm = tty->driver_data;
	unsigned int newctrl;

	if (!ACM_READY(acm))
		return -EINVAL;

	newctrl = acm->ctrlout;
	set = (set & TIOCM_DTR ? ACM_CTRL_DTR : 0) | (set & TIOCM_RTS ? ACM_CTRL_RTS : 0);
	clear = (clear & TIOCM_DTR ? ACM_CTRL_DTR : 0) | (clear & TIOCM_RTS ? ACM_CTRL_RTS : 0);
	newctrl = acm->ctrlout;
	set = (set & TIOCM_DTR ? ACM_CTRL_DTR : 0) |
					(set & TIOCM_RTS ? ACM_CTRL_RTS : 0);
	clear = (clear & TIOCM_DTR ? ACM_CTRL_DTR : 0) |
					(clear & TIOCM_RTS ? ACM_CTRL_RTS : 0);

	newctrl = (newctrl & ~clear) | set;

	if (acm->ctrlout == newctrl)
		return 0;
	return acm_set_control(acm, acm->ctrlout = newctrl);
}

static int acm_tty_ioctl(struct tty_struct *tty, struct file *file, unsigned int cmd, unsigned long arg)
{
	struct acm *acm = tty->driver_data;

	if (!ACM_READY(acm))
		return -EINVAL;

	return -ENOIOCTLCMD;
}

static const __u32 acm_tty_speed[] = {
	0, 50, 75, 110, 134, 150, 200, 300, 600,
	1200, 1800, 2400, 4800, 9600, 19200, 38400,
	57600, 115200, 230400, 460800, 500000, 576000,
	921600, 1000000, 1152000, 1500000, 2000000,
	2500000, 3000000, 3500000, 4000000
};

static const __u8 acm_tty_size[] = {
	5, 6, 7, 8
};

static void acm_tty_set_termios(struct tty_struct *tty, struct ktermios *termios_old)
{
	struct acm *acm = tty->driver_data;
	struct ktermios *termios = tty->termios;
	struct usb_cdc_line_coding newline;
	int newctrl = acm->ctrlout;

	if (!ACM_READY(acm))
		return;

	newline.dwDTERate = cpu_to_le32p(acm_tty_speed +
		(termios->c_cflag & CBAUD & ~CBAUDEX) + (termios->c_cflag & CBAUDEX ? 15 : 0));
	newline.bCharFormat = termios->c_cflag & CSTOPB ? 2 : 0;
	newline.bParityType = termios->c_cflag & PARENB ?
		(termios->c_cflag & PARODD ? 1 : 2) + (termios->c_cflag & CMSPAR ? 2 : 0) : 0;
	newline.bDataBits = acm_tty_size[(termios->c_cflag & CSIZE) >> 4];

	acm->clocal = ((termios->c_cflag & CLOCAL) != 0);

	if (!newline.dwDTERate) {
		newline.dwDTERate = acm->line.dwDTERate;
		newctrl &= ~ACM_CTRL_DTR;
	} else  newctrl |=  ACM_CTRL_DTR;
static int get_serial_info(struct acm *acm, struct serial_struct __user *info)
{
	struct serial_struct tmp;

	memset(&tmp, 0, sizeof(tmp));
	tmp.xmit_fifo_size = acm->writesize;
	tmp.baud_base = le32_to_cpu(acm->line.dwDTERate);
	tmp.close_delay	= acm->port.close_delay / 10;
	tmp.closing_wait = acm->port.closing_wait == ASYNC_CLOSING_WAIT_NONE ?
				ASYNC_CLOSING_WAIT_NONE :
				acm->port.closing_wait / 10;

	if (copy_to_user(info, &tmp, sizeof(tmp)))
		return -EFAULT;
	else
		return 0;
}

static int set_serial_info(struct acm *acm,
				struct serial_struct __user *newinfo)
{
	struct serial_struct new_serial;
	unsigned int closing_wait, close_delay;
	int retval = 0;

	if (copy_from_user(&new_serial, newinfo, sizeof(new_serial)))
		return -EFAULT;

	close_delay = new_serial.close_delay * 10;
	closing_wait = new_serial.closing_wait == ASYNC_CLOSING_WAIT_NONE ?
			ASYNC_CLOSING_WAIT_NONE : new_serial.closing_wait * 10;

	mutex_lock(&acm->port.mutex);

	if (!capable(CAP_SYS_ADMIN)) {
		if ((close_delay != acm->port.close_delay) ||
		    (closing_wait != acm->port.closing_wait))
			retval = -EPERM;
		else
			retval = -EOPNOTSUPP;
	} else {
		acm->port.close_delay  = close_delay;
		acm->port.closing_wait = closing_wait;
	}

	mutex_unlock(&acm->port.mutex);
	return retval;
}

static int wait_serial_change(struct acm *acm, unsigned long arg)
{
	int rv = 0;
	DECLARE_WAITQUEUE(wait, current);
	struct async_icount old, new;

	do {
		spin_lock_irq(&acm->read_lock);
		old = acm->oldcount;
		new = acm->iocount;
		acm->oldcount = new;
		spin_unlock_irq(&acm->read_lock);

		if ((arg & TIOCM_DSR) &&
			old.dsr != new.dsr)
			break;
		if ((arg & TIOCM_CD)  &&
			old.dcd != new.dcd)
			break;
		if ((arg & TIOCM_RI) &&
			old.rng != new.rng)
			break;

		add_wait_queue(&acm->wioctl, &wait);
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
		remove_wait_queue(&acm->wioctl, &wait);
		if (acm->disconnected) {
			if (arg & TIOCM_CD)
				break;
			else
				rv = -ENODEV;
		} else {
			if (signal_pending(current))
				rv = -ERESTARTSYS;
		}
	} while (!rv);

	

	return rv;
}

static int acm_tty_get_icount(struct tty_struct *tty,
					struct serial_icounter_struct *icount)
{
	struct acm *acm = tty->driver_data;

	icount->dsr = acm->iocount.dsr;
	icount->rng = acm->iocount.rng;
	icount->dcd = acm->iocount.dcd;
	icount->frame = acm->iocount.frame;
	icount->overrun = acm->iocount.overrun;
	icount->parity = acm->iocount.parity;
	icount->brk = acm->iocount.brk;

	return 0;
}

static int acm_tty_ioctl(struct tty_struct *tty,
					unsigned int cmd, unsigned long arg)
{
	struct acm *acm = tty->driver_data;
	int rv = -ENOIOCTLCMD;

	switch (cmd) {
	case TIOCGSERIAL: /* gets serial port data */
		rv = get_serial_info(acm, (struct serial_struct __user *) arg);
		break;
	case TIOCSSERIAL:
		rv = set_serial_info(acm, (struct serial_struct __user *) arg);
		break;
	case TIOCMIWAIT:
		rv = usb_autopm_get_interface(acm->control);
		if (rv < 0) {
			rv = -EIO;
			break;
		}
		rv = wait_serial_change(acm, arg);
		usb_autopm_put_interface(acm->control);
		break;
	}

	return rv;
}

static void acm_tty_set_termios(struct tty_struct *tty,
						struct ktermios *termios_old)
{
	struct acm *acm = tty->driver_data;
	struct ktermios *termios = &tty->termios;
	struct usb_cdc_line_coding newline;
	int newctrl = acm->ctrlout;

	newline.dwDTERate = cpu_to_le32(tty_get_baud_rate(tty));
	newline.bCharFormat = termios->c_cflag & CSTOPB ? 2 : 0;
	newline.bParityType = termios->c_cflag & PARENB ?
				(termios->c_cflag & PARODD ? 1 : 2) +
				(termios->c_cflag & CMSPAR ? 2 : 0) : 0;
	switch (termios->c_cflag & CSIZE) {
	case CS5:
		newline.bDataBits = 5;
		break;
	case CS6:
		newline.bDataBits = 6;
		break;
	case CS7:
		newline.bDataBits = 7;
		break;
	case CS8:
	default:
		newline.bDataBits = 8;
		break;
	}
	/* FIXME: Needs to clear unsupported bits in the termios */
	acm->clocal = ((termios->c_cflag & CLOCAL) != 0);

	if (C_BAUD(tty) == B0) {
		newline.dwDTERate = acm->line.dwDTERate;
		newctrl &= ~ACM_CTRL_DTR;
	} else if (termios_old && (termios_old->c_cflag & CBAUD) == B0) {
		newctrl |=  ACM_CTRL_DTR;
	}

	if (newctrl != acm->ctrlout)
		acm_set_control(acm, acm->ctrlout = newctrl);

	if (memcmp(&acm->line, &newline, sizeof newline)) {
		memcpy(&acm->line, &newline, sizeof newline);
		dbg("set line: %d %d %d %d", le32_to_cpu(newline.dwDTERate),
		dev_dbg(&acm->control->dev, "%s - set line: %d %d %d %d\n",
			__func__,
			le32_to_cpu(newline.dwDTERate),
			newline.bCharFormat, newline.bParityType,
			newline.bDataBits);
		acm_set_line(acm, &acm->line);
	}
}

static const struct tty_port_operations acm_port_ops = {
	.dtr_rts = acm_port_dtr_rts,
	.shutdown = acm_port_shutdown,
	.activate = acm_port_activate,
	.destruct = acm_port_destruct,
};

/*
 * USB probe and disconnect routines.
 */

/* Little helpers: write/read buffers free */
static void acm_write_buffers_free(struct acm *acm)
{
	int i;
	struct acm_wb *wb;

	for (wb = &acm->wb[0], i = 0; i < ACM_NW; i++, wb++) {
		usb_buffer_free(acm->dev, acm->writesize, wb->buf, wb->dmah);
	}
	struct usb_device *usb_dev = interface_to_usbdev(acm->control);

	for (wb = &acm->wb[0], i = 0; i < ACM_NW; i++, wb++)
		usb_free_coherent(acm->dev, acm->writesize, wb->buf, wb->dmah);
}

static void acm_read_buffers_free(struct acm *acm)
{
	struct usb_device *usb_dev = interface_to_usbdev(acm->control);
	int i, n = acm->rx_buflimit;

	for (i = 0; i < n; i++)
		usb_buffer_free(usb_dev, acm->readsize, acm->rb[i].base, acm->rb[i].dma);
	int i;

	for (i = 0; i < acm->rx_buflimit; i++)
		usb_free_coherent(acm->dev, acm->readsize,
			  acm->read_buffers[i].base, acm->read_buffers[i].dma);
}

/* Little helper: write buffers allocate */
static int acm_write_buffers_alloc(struct acm *acm)
{
	int i;
	struct acm_wb *wb;

	for (wb = &acm->wb[0], i = 0; i < ACM_NW; i++, wb++) {
		wb->buf = usb_buffer_alloc(acm->dev, acm->writesize, GFP_KERNEL,
		wb->buf = usb_alloc_coherent(acm->dev, acm->writesize, GFP_KERNEL,
		    &wb->dmah);
		if (!wb->buf) {
			while (i != 0) {
				--i;
				--wb;
				usb_buffer_free(acm->dev, acm->writesize,
				usb_free_coherent(acm->dev, acm->writesize,
				    wb->buf, wb->dmah);
			}
			return -ENOMEM;
		}
	}
	return 0;
}

static int acm_probe (struct usb_interface *intf,
		      const struct usb_device_id *id)
static int acm_probe(struct usb_interface *intf,
		     const struct usb_device_id *id)
{
	struct usb_cdc_union_desc *union_header = NULL;
	struct usb_cdc_call_mgmt_descriptor *cmgmd = NULL;
	unsigned char *buffer = intf->altsetting->extra;
	int buflen = intf->altsetting->extralen;
	struct usb_interface *control_interface;
	struct usb_interface *data_interface;
	struct usb_endpoint_descriptor *epctrl;
	struct usb_endpoint_descriptor *epread;
	struct usb_endpoint_descriptor *epwrite;
	struct usb_device *usb_dev = interface_to_usbdev(intf);
	struct acm *acm;
	int minor;
	int ctrlsize,readsize;
	struct usb_endpoint_descriptor *epctrl = NULL;
	struct usb_endpoint_descriptor *epread = NULL;
	struct usb_endpoint_descriptor *epwrite = NULL;
	struct usb_device *usb_dev = interface_to_usbdev(intf);
	struct usb_cdc_parsed_header h;
	struct acm *acm;
	int minor;
	int ctrlsize, readsize;
	u8 *buf;
	u8 ac_management_function = 0;
	u8 call_management_function = 0;
	int call_interface_num = -1;
	int data_interface_num;
	unsigned long quirks;
	int num_rx_buf;
	int i;

	/* normal quirks */
	quirks = (unsigned long)id->driver_info;
	int data_interface_num = -1;
	int call_intf_num = -1;
	int data_intf_num = -1;
	unsigned long quirks;
	int num_rx_buf;
	int i;
	int combined_interfaces = 0;
	struct device *tty_dev;
	int rv = -ENOMEM;
	int res;

	/* normal quirks */
	quirks = (unsigned long)id->driver_info;

	if (quirks == IGNORE_DEVICE)
		return -ENODEV;

	memset(&h, 0x00, sizeof(struct usb_cdc_parsed_header));

	num_rx_buf = (quirks == SINGLE_RX_URB) ? 1 : ACM_NR;

	/* handle quirks deadly to normal probing*/
	if (quirks == NO_UNION_NORMAL) {
		data_interface = usb_ifnum_to_if(usb_dev, 1);
		control_interface = usb_ifnum_to_if(usb_dev, 0);
		/* we would crash */
		if (!data_interface || !control_interface)
			return -ENODEV;
		goto skip_normal_probe;
	}
	
	/* normal probing*/
	if (!buffer) {
		err("Weird descriptor references\n");

	/* normal probing*/
	if (!buffer) {
		dev_err(&intf->dev, "Weird descriptor references\n");
		return -EINVAL;
	}

	if (!intf->cur_altsetting)
		return -EINVAL;

	if (!buflen) {
		if (intf->cur_altsetting->endpoint->extralen && intf->cur_altsetting->endpoint->extra) {
			dev_dbg(&intf->dev,"Seeking extra descriptors on endpoint\n");
			buflen = intf->cur_altsetting->endpoint->extralen;
			buffer = intf->cur_altsetting->endpoint->extra;
		} else {
			err("Zero length descriptor references\n");
		if (intf->cur_altsetting->endpoint &&
				intf->cur_altsetting->endpoint->extralen &&
				intf->cur_altsetting->endpoint->extra) {
			dev_dbg(&intf->dev,
				"Seeking extra descriptors on endpoint\n");
			buflen = intf->cur_altsetting->endpoint->extralen;
			buffer = intf->cur_altsetting->endpoint->extra;
		} else {
			dev_err(&intf->dev,
				"Zero length descriptor references\n");
			return -EINVAL;
		}
	}

	while (buflen > 0) {
		if (buffer [1] != USB_DT_CS_INTERFACE) {
			err("skipping garbage\n");
			goto next_desc;
		}

		switch (buffer [2]) {
			case USB_CDC_UNION_TYPE: /* we've found it */
				if (union_header) {
					err("More than one union descriptor, skipping ...");
					goto next_desc;
				}
				union_header = (struct usb_cdc_union_desc *)
							buffer;
				break;
			case USB_CDC_COUNTRY_TYPE: /* export through sysfs*/
				cfd = (struct usb_cdc_country_functional_desc *)buffer;
				break;
			case USB_CDC_HEADER_TYPE: /* maybe check version */ 
				break; /* for now we ignore it */ 
			case USB_CDC_ACM_TYPE:
				ac_management_function = buffer[3];
				break;
			case USB_CDC_CALL_MANAGEMENT_TYPE:
				call_management_function = buffer[3];
				call_interface_num = buffer[4];
				if ((call_management_function & 3) != 3)
					err("This device cannot do calls on its own. It is no modem.");
				break;
			default:
				/* there are LOTS more CDC descriptors that
				 * could legitimately be found here.
				 */
				dev_dbg(&intf->dev, "Ignoring descriptor: "
						"type %02x, length %d\n",
						buffer[2], buffer[0]);
				break;
			}
next_desc:
		buflen -= buffer[0];
		buffer += buffer[0];
		elength = buffer[0];
		if (!elength) {
			dev_err(&intf->dev, "skipping garbage byte\n");
			elength = 1;
			goto next_desc;
		}
		if (buffer[1] != USB_DT_CS_INTERFACE) {
			dev_err(&intf->dev, "skipping garbage\n");
			goto next_desc;
		}

		switch (buffer[2]) {
		case USB_CDC_UNION_TYPE: /* we've found it */
			if (elength < sizeof(struct usb_cdc_union_desc))
				goto next_desc;
			if (union_header) {
				dev_err(&intf->dev, "More than one "
					"union descriptor, skipping ...\n");
				goto next_desc;
			}
			union_header = (struct usb_cdc_union_desc *)buffer;
			break;
		case USB_CDC_COUNTRY_TYPE: /* export through sysfs*/
			if (elength < sizeof(struct usb_cdc_country_functional_desc))
				goto next_desc;
			cfd = (struct usb_cdc_country_functional_desc *)buffer;
			break;
		case USB_CDC_HEADER_TYPE: /* maybe check version */
			break; /* for now we ignore it */
		case USB_CDC_ACM_TYPE:
			if (elength < 4)
				goto next_desc;
			ac_management_function = buffer[3];
			break;
		case USB_CDC_CALL_MANAGEMENT_TYPE:
			if (elength < 5)
				goto next_desc;
			call_management_function = buffer[3];
			call_interface_num = buffer[4];
			break;
		default:
			/*
			 * there are LOTS more CDC descriptors that
			 * could legitimately be found here.
			 */
			dev_dbg(&intf->dev, "Ignoring descriptor: "
					"type %02x, length %ud\n",
					buffer[2], elength);
			break;
		}
next_desc:
		buflen -= elength;
		buffer += elength;
	}

	if (!union_header) {
		if (call_interface_num > 0) {
			dev_dbg(&intf->dev,"No union descriptor, using call management descriptor\n");
			data_interface = usb_ifnum_to_if(usb_dev, (data_interface_num = call_interface_num));
			control_interface = intf;
		} else {
			dev_dbg(&intf->dev,"No union descriptor, giving up\n");
			return -ENODEV;
	cdc_parse_cdc_header(&h, intf, buffer, buflen);
	union_header = h.usb_cdc_union_desc;
	cmgmd = h.usb_cdc_call_mgmt_descriptor;
	if (cmgmd)
		call_intf_num = cmgmd->bDataInterface;

	if (!union_header) {
		if (call_intf_num > 0) {
			dev_dbg(&intf->dev, "No union descriptor, using call management descriptor\n");
			/* quirks for Droids MuIn LCD */
			if (quirks & NO_DATA_INTERFACE) {
				data_interface = usb_ifnum_to_if(usb_dev, 0);
			} else {
				data_intf_num = call_intf_num;
				data_interface = usb_ifnum_to_if(usb_dev, data_intf_num);
			}
			control_interface = intf;
		} else {
			if (intf->cur_altsetting->desc.bNumEndpoints != 3) {
				dev_dbg(&intf->dev,"No union descriptor, giving up\n");
				return -ENODEV;
			} else {
				dev_warn(&intf->dev,"No union descriptor, testing for castrated device\n");
				combined_interfaces = 1;
				control_interface = data_interface = intf;
				goto look_for_collapsed_interface;
			}
		}
	} else {
		data_intf_num = union_header->bSlaveInterface0;
		control_interface = usb_ifnum_to_if(usb_dev, union_header->bMasterInterface0);
		data_interface = usb_ifnum_to_if(usb_dev, (data_interface_num = union_header->bSlaveInterface0));
		if (!control_interface || !data_interface) {
			dev_dbg(&intf->dev,"no interfaces\n");
			return -ENODEV;
		}
	}
	
	if (data_interface_num != call_interface_num)
		dev_dbg(&intf->dev,"Separate call control interface. That is not fully supported.\n");
		data_interface = usb_ifnum_to_if(usb_dev, data_intf_num);
	}

	if (!control_interface || !data_interface) {
		dev_dbg(&intf->dev, "no interfaces\n");
		return -ENODEV;
	}
	if (!data_interface->cur_altsetting || !control_interface->cur_altsetting)
		return -ENODEV;

	if (data_intf_num != call_intf_num)
		dev_dbg(&intf->dev, "Separate call control interface. That is not fully supported.\n");

	if (control_interface == data_interface) {
		/* some broken devices designed for windows work this way */
		dev_warn(&intf->dev,"Control and data interfaces are not separated!\n");
		combined_interfaces = 1;
		/* a popular other OS doesn't use it */
		quirks |= NO_CAP_LINE;
		if (data_interface->cur_altsetting->desc.bNumEndpoints != 3) {
			dev_err(&intf->dev, "This needs exactly 3 endpoints\n");
			return -EINVAL;
		}
look_for_collapsed_interface:
		res = usb_find_common_endpoints(data_interface->cur_altsetting,
				&epread, &epwrite, &epctrl, NULL);
		if (res)
			return res;

		goto made_compressed_probe;
	}

skip_normal_probe:

	/*workaround for switched interfaces */
	if (data_interface->cur_altsetting->desc.bInterfaceClass != CDC_DATA_INTERFACE_TYPE) {
		if (control_interface->cur_altsetting->desc.bInterfaceClass == CDC_DATA_INTERFACE_TYPE) {
			struct usb_interface *t;
			dev_dbg(&intf->dev,"Your device has switched interfaces.\n");

			t = control_interface;
			control_interface = data_interface;
			data_interface = t;
	if (data_interface->cur_altsetting->desc.bInterfaceClass
						!= CDC_DATA_INTERFACE_TYPE) {
		if (control_interface->cur_altsetting->desc.bInterfaceClass
						== CDC_DATA_INTERFACE_TYPE) {
			dev_dbg(&intf->dev,
				"Your device has switched interfaces.\n");
			swap(control_interface, data_interface);
		} else {
			return -EINVAL;
		}
	}

	/* Accept probe requests only for the control interface */
	if (intf != control_interface)
		return -ENODEV;
	
	if (usb_interface_claimed(data_interface)) { /* valid in this context */
		dev_dbg(&intf->dev,"The data interface isn't available\n");
	if (!combined_interfaces && intf != control_interface)
		return -ENODEV;

	if (!combined_interfaces && usb_interface_claimed(data_interface)) {
		/* valid in this context */
		dev_dbg(&intf->dev, "The data interface isn't available\n");
		return -EBUSY;
	}


	if (data_interface->cur_altsetting->desc.bNumEndpoints < 2)
	if (data_interface->cur_altsetting->desc.bNumEndpoints < 2 ||
	    control_interface->cur_altsetting->desc.bNumEndpoints == 0)
		return -EINVAL;

	epctrl = &control_interface->cur_altsetting->endpoint[0].desc;
	epread = &data_interface->cur_altsetting->endpoint[0].desc;
	epwrite = &data_interface->cur_altsetting->endpoint[1].desc;


	/* workaround for switched endpoints */
	if (!usb_endpoint_dir_in(epread)) {
		/* descriptors are swapped */
		struct usb_endpoint_descriptor *t;
		dev_dbg(&intf->dev,"The data interface has switched endpoints\n");
		
		t = epread;
		epread = epwrite;
		epwrite = t;
	}
	dbg("interfaces are valid");
	for (minor = 0; minor < ACM_TTY_MINORS && acm_table[minor]; minor++);

	if (minor == ACM_TTY_MINORS) {
		err("no more free acm devices");
		return -ENODEV;
	}

	if (!(acm = kzalloc(sizeof(struct acm), GFP_KERNEL))) {
		dev_dbg(&intf->dev, "out of memory (acm kzalloc)\n");
		goto alloc_fail;
	}

	ctrlsize = le16_to_cpu(epctrl->wMaxPacketSize);
	readsize = le16_to_cpu(epread->wMaxPacketSize)* ( quirks == SINGLE_RX_URB ? 1 : 2);
	acm->writesize = le16_to_cpu(epwrite->wMaxPacketSize) * 20;
		dev_dbg(&intf->dev,
			"The data interface has switched endpoints\n");
		swap(epread, epwrite);
	}
made_compressed_probe:
	dev_dbg(&intf->dev, "interfaces are valid\n");

	acm = kzalloc(sizeof(struct acm), GFP_KERNEL);
	if (acm == NULL)
		goto alloc_fail;

	minor = acm_alloc_minor(acm);
	if (minor < 0)
		goto alloc_fail1;

	ctrlsize = usb_endpoint_maxp(epctrl);
	readsize = usb_endpoint_maxp(epread) *
				(quirks == SINGLE_RX_URB ? 1 : 2);
	acm->combined_interfaces = combined_interfaces;
	acm->writesize = usb_endpoint_maxp(epwrite) * 20;
	acm->control = control_interface;
	acm->data = data_interface;
	acm->minor = minor;
	acm->dev = usb_dev;
	acm->ctrl_caps = ac_management_function;
	acm->ctrlsize = ctrlsize;
	acm->readsize = readsize;
	acm->rx_buflimit = num_rx_buf;
	acm->urb_task.func = acm_rx_tasklet;
	acm->urb_task.data = (unsigned long) acm;
	INIT_WORK(&acm->work, acm_softint);
	INIT_WORK(&acm->waker, acm_waker);
	init_waitqueue_head(&acm->drain_wait);
	spin_lock_init(&acm->throttle_lock);
	if (h.usb_cdc_acm_descriptor)
		acm->ctrl_caps = h.usb_cdc_acm_descriptor->bmCapabilities;
	if (quirks & NO_CAP_LINE)
		acm->ctrl_caps &= ~USB_CDC_CAP_LINE;
	acm->ctrlsize = ctrlsize;
	acm->readsize = readsize;
	acm->rx_buflimit = num_rx_buf;
	INIT_WORK(&acm->work, acm_softint);
	init_waitqueue_head(&acm->wioctl);
	spin_lock_init(&acm->write_lock);
	spin_lock_init(&acm->read_lock);
	mutex_init(&acm->mutex);
	acm->rx_endpoint = usb_rcvbulkpipe(usb_dev, epread->bEndpointAddress);

	buf = usb_buffer_alloc(usb_dev, ctrlsize, GFP_KERNEL, &acm->ctrl_dma);
	if (!buf) {
		dev_dbg(&intf->dev, "out of memory (ctrl buffer alloc)\n");
		goto alloc_fail2;
	}
	acm->ctrl_buffer = buf;

	if (acm_write_buffers_alloc(acm) < 0) {
		dev_dbg(&intf->dev, "out of memory (write buffer alloc)\n");
		goto alloc_fail4;
	}

	acm->ctrlurb = usb_alloc_urb(0, GFP_KERNEL);
	if (!acm->ctrlurb) {
		dev_dbg(&intf->dev, "out of memory (ctrlurb kmalloc)\n");
		goto alloc_fail5;
	}
	for (i = 0; i < num_rx_buf; i++) {
		struct acm_ru *rcv = &(acm->ru[i]);

		if (!(rcv->urb = usb_alloc_urb(0, GFP_KERNEL))) {
			dev_dbg(&intf->dev, "out of memory (read urbs usb_alloc_urb)\n");
			goto alloc_fail7;
		}

		rcv->urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
		rcv->instance = acm;
	}
	for (i = 0; i < num_rx_buf; i++) {
		struct acm_rb *rb = &(acm->rb[i]);

		rb->base = usb_buffer_alloc(acm->dev, readsize,
				GFP_KERNEL, &rb->dma);
		if (!rb->base) {
			dev_dbg(&intf->dev, "out of memory (read bufs usb_buffer_alloc)\n");
			goto alloc_fail7;
		}
	}
	for(i = 0; i < ACM_NW; i++)
	{
		struct acm_wb *snd = &(acm->wb[i]);

		if (!(snd->urb = usb_alloc_urb(0, GFP_KERNEL))) {
			dev_dbg(&intf->dev, "out of memory (write urbs usb_alloc_urb)");
			goto alloc_fail7;
		}

		usb_fill_bulk_urb(snd->urb, usb_dev, usb_sndbulkpipe(usb_dev, epwrite->bEndpointAddress),
	acm->is_int_ep = usb_endpoint_xfer_int(epread);
	if (acm->is_int_ep)
	if (usb_endpoint_xfer_int(epread)) {
		acm->bInterval = epread->bInterval;
		acm->in = usb_rcvintpipe(usb_dev, epread->bEndpointAddress);
	} else {
		acm->in = usb_rcvbulkpipe(usb_dev, epread->bEndpointAddress);
	}
	if (usb_endpoint_xfer_int(epwrite))
		acm->out = usb_sndintpipe(usb_dev, epwrite->bEndpointAddress);
	else
		acm->out = usb_sndbulkpipe(usb_dev, epwrite->bEndpointAddress);
	tty_port_init(&acm->port);
	acm->port.ops = &acm_port_ops;
	init_usb_anchor(&acm->delayed);
	acm->quirks = quirks;

	buf = usb_alloc_coherent(usb_dev, ctrlsize, GFP_KERNEL, &acm->ctrl_dma);
	if (!buf)
		goto alloc_fail2;
	acm->ctrl_buffer = buf;

	if (acm_write_buffers_alloc(acm) < 0)
		goto alloc_fail4;

	acm->ctrlurb = usb_alloc_urb(0, GFP_KERNEL);
	if (!acm->ctrlurb)
		goto alloc_fail5;

	for (i = 0; i < num_rx_buf; i++) {
		struct acm_rb *rb = &(acm->read_buffers[i]);
		struct urb *urb;

		rb->base = usb_alloc_coherent(acm->dev, readsize, GFP_KERNEL,
								&rb->dma);
		if (!rb->base)
			goto alloc_fail6;
		rb->index = i;
		rb->instance = acm;

		urb = usb_alloc_urb(0, GFP_KERNEL);
		if (!urb)
			goto alloc_fail6;

		urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
		urb->transfer_dma = rb->dma;
		if (usb_endpoint_xfer_int(epread))
			usb_fill_int_urb(urb, acm->dev, acm->in, rb->base,
					 acm->readsize,
					 acm_read_bulk_callback, rb,
					 acm->bInterval);
		else
			usb_fill_bulk_urb(urb, acm->dev, acm->in, rb->base,
					  acm->readsize,
					  acm_read_bulk_callback, rb);

		acm->read_urbs[i] = urb;
		__set_bit(i, &acm->read_urbs_free);
	}
	for (i = 0; i < ACM_NW; i++) {
		struct acm_wb *snd = &(acm->wb[i]);

		snd->urb = usb_alloc_urb(0, GFP_KERNEL);
		if (snd->urb == NULL)
			goto alloc_fail7;

		if (usb_endpoint_xfer_int(epwrite))
			usb_fill_int_urb(snd->urb, usb_dev, acm->out,
				NULL, acm->writesize, acm_write_bulk, snd, epwrite->bInterval);
		else
			usb_fill_bulk_urb(snd->urb, usb_dev, acm->out,
				NULL, acm->writesize, acm_write_bulk, snd);
		snd->urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
		if (quirks & SEND_ZERO_PACKET)
			snd->urb->transfer_flags |= URB_ZERO_PACKET;
		snd->instance = acm;
	}

	usb_set_intfdata (intf, acm);

	i = device_create_file(&intf->dev, &dev_attr_bmCapabilities);
	if (i < 0)
		goto alloc_fail8;
	usb_set_intfdata(intf, acm);

	i = device_create_file(&intf->dev, &dev_attr_bmCapabilities);
	if (i < 0)
		goto alloc_fail7;

	if (h.usb_cdc_country_functional_desc) { /* export the country data */
		struct usb_cdc_country_functional_desc * cfd =
					h.usb_cdc_country_functional_desc;

		acm->country_codes = kmalloc(cfd->bLength - 4, GFP_KERNEL);
		if (!acm->country_codes)
			goto skip_countries;
		acm->country_code_size = cfd->bLength - 4;
		memcpy(acm->country_codes, (u8 *)&cfd->wCountyCode0, cfd->bLength - 4);
		memcpy(acm->country_codes, (u8 *)&cfd->wCountyCode0,
							cfd->bLength - 4);
		acm->country_rel_date = cfd->iCountryCodeRelDate;

		i = device_create_file(&intf->dev, &dev_attr_wCountryCodes);
		if (i < 0) {
			kfree(acm->country_codes);
			goto skip_countries;
		}

		i = device_create_file(&intf->dev, &dev_attr_iCountryCodeRelDate);
		if (i < 0) {
			kfree(acm->country_codes);
			acm->country_codes = NULL;
			acm->country_code_size = 0;
			goto skip_countries;
		}

		i = device_create_file(&intf->dev,
						&dev_attr_iCountryCodeRelDate);
		if (i < 0) {
			device_remove_file(&intf->dev, &dev_attr_wCountryCodes);
			kfree(acm->country_codes);
			acm->country_codes = NULL;
			acm->country_code_size = 0;
			goto skip_countries;
		}
	}

skip_countries:
	usb_fill_int_urb(acm->ctrlurb, usb_dev, usb_rcvintpipe(usb_dev, epctrl->bEndpointAddress),
			 acm->ctrl_buffer, ctrlsize, acm_ctrl_irq, acm, epctrl->bInterval);
	usb_fill_int_urb(acm->ctrlurb, usb_dev,
			 usb_rcvintpipe(usb_dev, epctrl->bEndpointAddress),
			 acm->ctrl_buffer, ctrlsize, acm_ctrl_irq, acm,
			 /* works around buggy devices */
			 epctrl->bInterval ? epctrl->bInterval : 16);
	acm->ctrlurb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
	acm->ctrlurb->transfer_dma = acm->ctrl_dma;
	acm->notification_buffer = NULL;
	acm->nb_index = 0;
	acm->nb_size = 0;

	dev_info(&intf->dev, "ttyACM%d: USB ACM device\n", minor);

	acm_set_control(acm, acm->ctrlout);

	acm->line.dwDTERate = cpu_to_le32(9600);
	acm->line.bDataBits = 8;
	acm_set_line(acm, &acm->line);

	usb_driver_claim_interface(&acm_driver, data_interface, acm);
	usb_set_intfdata(data_interface, acm);

	usb_get_intf(control_interface);
	tty_register_device(acm_tty_driver, minor, &control_interface->dev);

	acm_table[minor] = acm;

	return 0;
alloc_fail8:
	for (i = 0; i < ACM_NW; i++)
		usb_free_urb(acm->wb[i].urb);
alloc_fail7:
	acm_read_buffers_free(acm);
	for (i = 0; i < num_rx_buf; i++)
		usb_free_urb(acm->ru[i].urb);
	tty_dev = tty_port_register_device(&acm->port, acm_tty_driver, minor,
			&control_interface->dev);
	if (IS_ERR(tty_dev)) {
		rv = PTR_ERR(tty_dev);
		goto alloc_fail8;
	}

	if (quirks & CLEAR_HALT_CONDITIONS) {
		usb_clear_halt(usb_dev, acm->in);
		usb_clear_halt(usb_dev, acm->out);
	}

	return 0;
alloc_fail8:
	if (acm->country_codes) {
		device_remove_file(&acm->control->dev,
				&dev_attr_wCountryCodes);
		device_remove_file(&acm->control->dev,
				&dev_attr_iCountryCodeRelDate);
		kfree(acm->country_codes);
	}
	device_remove_file(&acm->control->dev, &dev_attr_bmCapabilities);
alloc_fail7:
	usb_set_intfdata(intf, NULL);
	for (i = 0; i < ACM_NW; i++)
		usb_free_urb(acm->wb[i].urb);
alloc_fail6:
	for (i = 0; i < num_rx_buf; i++)
		usb_free_urb(acm->read_urbs[i]);
	acm_read_buffers_free(acm);
	usb_free_urb(acm->ctrlurb);
alloc_fail5:
	acm_write_buffers_free(acm);
alloc_fail4:
	usb_buffer_free(usb_dev, ctrlsize, acm->ctrl_buffer, acm->ctrl_dma);
alloc_fail2:
	kfree(acm);
alloc_fail:
	return -ENOMEM;
	usb_free_coherent(usb_dev, ctrlsize, acm->ctrl_buffer, acm->ctrl_dma);
alloc_fail2:
	acm_release_minor(acm);
alloc_fail1:
	kfree(acm);
alloc_fail:
	return rv;
}

static void stop_data_traffic(struct acm *acm)
{
	int i;
	dbg("Entering stop_data_traffic");

	tasklet_disable(&acm->urb_task);

	usb_kill_urb(acm->ctrlurb);
	for(i = 0; i < ACM_NW; i++)
		usb_kill_urb(acm->wb[i].urb);
	for (i = 0; i < acm->rx_buflimit; i++)
		usb_kill_urb(acm->ru[i].urb);

	tasklet_enable(&acm->urb_task);

	cancel_work_sync(&acm->work);
	cancel_work_sync(&acm->waker);

	dev_dbg(&acm->control->dev, "%s\n", __func__);

	usb_kill_urb(acm->ctrlurb);
	for (i = 0; i < ACM_NW; i++)
		usb_kill_urb(acm->wb[i].urb);
	for (i = 0; i < acm->rx_buflimit; i++)
		usb_kill_urb(acm->read_urbs[i]);

	cancel_work_sync(&acm->work);
}

static void acm_disconnect(struct usb_interface *intf)
{
	struct acm *acm = usb_get_intfdata(intf);
	struct tty_struct *tty;

	/* sibling interface is already cleaning up */
	if (!acm)
		return;

	mutex_lock(&open_mutex);
	if (acm->country_codes){
	mutex_lock(&acm->mutex);
	acm->disconnected = true;
	if (acm->country_codes) {
		device_remove_file(&acm->control->dev,
				&dev_attr_wCountryCodes);
		device_remove_file(&acm->control->dev,
				&dev_attr_iCountryCodeRelDate);
	}
	device_remove_file(&acm->control->dev, &dev_attr_bmCapabilities);
	acm->dev = NULL;
	usb_set_intfdata(acm->control, NULL);
	usb_set_intfdata(acm->data, NULL);

	stop_data_traffic(acm);

	acm_write_buffers_free(acm);
	usb_buffer_free(usb_dev, acm->ctrlsize, acm->ctrl_buffer, acm->ctrl_dma);
	acm_read_buffers_free(acm);

	usb_driver_release_interface(&acm_driver, intf == acm->control ?
					acm->data : acm->control);

	if (!acm->used) {
		acm_tty_unregister(acm);
		mutex_unlock(&open_mutex);
		return;
	}

	mutex_unlock(&open_mutex);

	if (acm->tty)
		tty_hangup(acm->tty);
	wake_up_all(&acm->wioctl);
	device_remove_file(&acm->control->dev, &dev_attr_bmCapabilities);
	usb_set_intfdata(acm->control, NULL);
	usb_set_intfdata(acm->data, NULL);
	mutex_unlock(&acm->mutex);

	tty = tty_port_tty_get(&acm->port);
	if (tty) {
		tty_vhangup(tty);
		tty_kref_put(tty);
	}

	acm_kill_urbs(acm);
	cancel_work_sync(&acm->work);

	tty_unregister_device(acm_tty_driver, acm->minor);

	acm_write_buffers_free(acm);
	usb_free_coherent(acm->dev, acm->ctrlsize, acm->ctrl_buffer, acm->ctrl_dma);
	acm_read_buffers_free(acm);

	kfree(acm->notification_buffer);

	if (!acm->combined_interfaces)
		usb_driver_release_interface(&acm_driver, intf == acm->control ?
					acm->data : acm->control);

	tty_port_put(&acm->port);
}

#ifdef CONFIG_PM
static int acm_suspend(struct usb_interface *intf, pm_message_t message)
{
	struct acm *acm = usb_get_intfdata(intf);
	int cnt;

	if (acm->dev->auto_pm) {
		int b;

		spin_lock_irq(&acm->read_lock);
		spin_lock(&acm->write_lock);
		b = acm->processing + acm->transmitting;
		spin_unlock(&acm->write_lock);
		spin_unlock_irq(&acm->read_lock);
		if (b)
			return -EBUSY;
	}

	spin_lock_irq(&acm->read_lock);
	spin_lock(&acm->write_lock);
	cnt = acm->susp_count++;
	spin_unlock(&acm->write_lock);
	spin_unlock_irq(&acm->read_lock);

	if (cnt)
		return 0;
	/*
	we treat opened interfaces differently,
	we must guard against open
	*/
	mutex_lock(&acm->mutex);

	if (acm->used)
		stop_data_traffic(acm);

	mutex_unlock(&acm->mutex);
	spin_lock_irq(&acm->write_lock);
	if (PMSG_IS_AUTO(message)) {
		if (acm->transmitting) {
			spin_unlock_irq(&acm->write_lock);
			return -EBUSY;
		}
	}
	cnt = acm->susp_count++;
	spin_unlock_irq(&acm->write_lock);

	if (cnt)
		return 0;

	acm_kill_urbs(acm);
	cancel_work_sync(&acm->work);

	return 0;
}

static int acm_resume(struct usb_interface *intf)
{
	struct acm *acm = usb_get_intfdata(intf);
	int rv = 0;
	int cnt;

	spin_lock_irq(&acm->read_lock);
	acm->susp_count -= 1;
	cnt = acm->susp_count;
	spin_unlock_irq(&acm->read_lock);

	if (cnt)
		return 0;

	mutex_lock(&acm->mutex);
	if (acm->used) {
		rv = usb_submit_urb(acm->ctrlurb, GFP_NOIO);
		if (rv < 0)
			goto err_out;

		tasklet_schedule(&acm->urb_task);
	}

err_out:
	mutex_unlock(&acm->mutex);
	return rv;
}

#endif /* CONFIG_PM */
	struct urb *urb;
	int rv = 0;

	spin_lock_irq(&acm->write_lock);

	if (--acm->susp_count)
		goto out;

	if (tty_port_initialized(&acm->port)) {
		rv = usb_submit_urb(acm->ctrlurb, GFP_ATOMIC);

		for (;;) {
			urb = usb_get_from_anchor(&acm->delayed);
			if (!urb)
				break;

			acm_start_wb(acm, urb->context);
		}

		/*
		 * delayed error checking because we must
		 * do the write path at all cost
		 */
		if (rv < 0)
			goto out;

		rv = acm_submit_read_urbs(acm, GFP_ATOMIC);
	}
out:
	spin_unlock_irq(&acm->write_lock);

	return rv;
}

static int acm_reset_resume(struct usb_interface *intf)
{
	struct acm *acm = usb_get_intfdata(intf);

	if (tty_port_initialized(&acm->port))
		tty_port_tty_hangup(&acm->port, false);

	return acm_resume(intf);
}

#endif /* CONFIG_PM */

static int acm_pre_reset(struct usb_interface *intf)
{
	struct acm *acm = usb_get_intfdata(intf);

	clear_bit(EVENT_RX_STALL, &acm->flags);

	return 0;
}

#define NOKIA_PCSUITE_ACM_INFO(x) \
		USB_DEVICE_AND_INTERFACE_INFO(0x0421, x, \
		USB_CLASS_COMM, USB_CDC_SUBCLASS_ACM, \
		USB_CDC_ACM_PROTO_VENDOR)

#define SAMSUNG_PCSUITE_ACM_INFO(x) \
		USB_DEVICE_AND_INTERFACE_INFO(0x04e7, x, \
		USB_CLASS_COMM, USB_CDC_SUBCLASS_ACM, \
		USB_CDC_ACM_PROTO_VENDOR)

/*
 * USB driver structure.
 */

static struct usb_device_id acm_ids[] = {
	/* quirky and broken devices */
static const struct usb_device_id acm_ids[] = {
	/* quirky and broken devices */
	{ USB_DEVICE(0x076d, 0x0006), /* Denso Cradle CU-321 */
	.driver_info = NO_UNION_NORMAL, },/* has no union descriptor */
	{ USB_DEVICE(0x17ef, 0x7000), /* Lenovo USB modem */
	.driver_info = NO_UNION_NORMAL, },/* has no union descriptor */
	{ USB_DEVICE(0x0870, 0x0001), /* Metricom GS Modem */
	.driver_info = NO_UNION_NORMAL, /* has no union descriptor */
	},
	{ USB_DEVICE(0x0e8d, 0x0003), /* FIREFLY, MediaTek Inc; andrey.arapov@gmail.com */
	.driver_info = NO_UNION_NORMAL, /* has no union descriptor */
	},
	{ USB_DEVICE(0x0e8d, 0x3329), /* MediaTek Inc GPS */
	.driver_info = NO_UNION_NORMAL, /* has no union descriptor */
	},
	{ USB_DEVICE(0x0482, 0x0203), /* KYOCERA AH-K3001V */
	.driver_info = NO_UNION_NORMAL, /* has no union descriptor */
	},
	{ USB_DEVICE(0x079b, 0x000f), /* BT On-Air USB MODEM */
	.driver_info = NO_UNION_NORMAL, /* has no union descriptor */
	},
	{ USB_DEVICE(0x0ace, 0x1602), /* ZyDAS 56K USB MODEM */
	.driver_info = SINGLE_RX_URB,
	},
	{ USB_DEVICE(0x0ace, 0x1608), /* ZyDAS 56K USB MODEM */
	.driver_info = SINGLE_RX_URB, /* firmware bug */
	},
	{ USB_DEVICE(0x0ace, 0x1611), /* ZyDAS 56K USB MODEM - new version */
	.driver_info = SINGLE_RX_URB, /* firmware bug */
	},
	{ USB_DEVICE(0x11ca, 0x0201), /* VeriFone Mx870 Gadget Serial */
	.driver_info = SINGLE_RX_URB,
	},
	{ USB_DEVICE(0x1965, 0x0018), /* Uniden UBC125XLT */
	.driver_info = NO_UNION_NORMAL, /* has no union descriptor */
	},
	{ USB_DEVICE(0x22b8, 0x7000), /* Motorola Q Phone */
	.driver_info = NO_UNION_NORMAL, /* has no union descriptor */
	},
	{ USB_DEVICE(0x0803, 0x3095), /* Zoom Telephonics Model 3095F USB MODEM */
	.driver_info = NO_UNION_NORMAL, /* has no union descriptor */
	},
	{ USB_DEVICE(0x0572, 0x1321), /* Conexant USB MODEM CX93010 */
	.driver_info = NO_UNION_NORMAL, /* has no union descriptor */
	},
	{ USB_DEVICE(0x0572, 0x1324), /* Conexant USB MODEM RD02-D400 */
	.driver_info = NO_UNION_NORMAL, /* has no union descriptor */
	},
	{ USB_DEVICE(0x0572, 0x1328), /* Shiro / Aztech USB MODEM UM-3100 */
	.driver_info = NO_UNION_NORMAL, /* has no union descriptor */
	},
	{ USB_DEVICE(0x20df, 0x0001), /* Simtec Electronics Entropy Key */
	.driver_info = QUIRK_CONTROL_LINE_STATE, },
	{ USB_DEVICE(0x2184, 0x001c) },	/* GW Instek AFG-2225 */
	{ USB_DEVICE(0x2184, 0x0036) },	/* GW Instek AFG-125 */
	{ USB_DEVICE(0x22b8, 0x6425), /* Motorola MOTOMAGX phones */
	},
	/* Motorola H24 HSPA module: */
	{ USB_DEVICE(0x22b8, 0x2d91) }, /* modem                                */
	{ USB_DEVICE(0x22b8, 0x2d92),   /* modem           + diagnostics        */
	.driver_info = NO_UNION_NORMAL, /* handle only modem interface          */
	},
	{ USB_DEVICE(0x22b8, 0x2d93),   /* modem + AT port                      */
	.driver_info = NO_UNION_NORMAL, /* handle only modem interface          */
	},
	{ USB_DEVICE(0x22b8, 0x2d95),   /* modem + AT port + diagnostics        */
	.driver_info = NO_UNION_NORMAL, /* handle only modem interface          */
	},
	{ USB_DEVICE(0x22b8, 0x2d96),   /* modem                         + NMEA */
	.driver_info = NO_UNION_NORMAL, /* handle only modem interface          */
	},
	{ USB_DEVICE(0x22b8, 0x2d97),   /* modem           + diagnostics + NMEA */
	.driver_info = NO_UNION_NORMAL, /* handle only modem interface          */
	},
	{ USB_DEVICE(0x22b8, 0x2d99),   /* modem + AT port               + NMEA */
	.driver_info = NO_UNION_NORMAL, /* handle only modem interface          */
	},
	{ USB_DEVICE(0x22b8, 0x2d9a),   /* modem + AT port + diagnostics + NMEA */
	.driver_info = NO_UNION_NORMAL, /* handle only modem interface          */
	},

	{ USB_DEVICE(0x0572, 0x1329), /* Hummingbird huc56s (Conexant) */
	.driver_info = NO_UNION_NORMAL, /* union descriptor misplaced on
					   data interface instead of
					   communications interface.
					   Maybe we should define a new
					   quirk for this. */
	},
	{ USB_DEVICE(0x0572, 0x1340), /* Conexant CX93010-2x UCMxx */
	.driver_info = NO_UNION_NORMAL,
	},
	{ USB_DEVICE(0x05f9, 0x4002), /* PSC Scanning, Magellan 800i */
	.driver_info = NO_UNION_NORMAL,
	},
	{ USB_DEVICE(0x1bbb, 0x0003), /* Alcatel OT-I650 */
	.driver_info = NO_UNION_NORMAL, /* reports zero length descriptor */
	},
	{ USB_DEVICE(0x1576, 0x03b1), /* Maretron USB100 */
	.driver_info = NO_UNION_NORMAL, /* reports zero length descriptor */
	},
	{ USB_DEVICE(0xfff0, 0x0100), /* DATECS FP-2000 */
	.driver_info = NO_UNION_NORMAL, /* reports zero length descriptor */
	},
	{ USB_DEVICE(0x09d8, 0x0320), /* Elatec GmbH TWN3 */
	.driver_info = NO_UNION_NORMAL, /* has misplaced union descriptor */
	},
	{ USB_DEVICE(0x0ca6, 0xa050), /* Castles VEGA3000 */
	.driver_info = NO_UNION_NORMAL, /* reports zero length descriptor */
	},

	{ USB_DEVICE(0x2912, 0x0001), /* ATOL FPrint */
	.driver_info = CLEAR_HALT_CONDITIONS,
	},

	/* Nokia S60 phones expose two ACM channels. The first is
	 * a modem and is picked up by the standard AT-command
	 * information below. The second is 'vendor-specific' but
	 * is treated as a serial device at the S60 end, so we want
	 * to expose it on Linux too. */
	{ NOKIA_PCSUITE_ACM_INFO(0x042D), }, /* Nokia 3250 */
	{ NOKIA_PCSUITE_ACM_INFO(0x04D8), }, /* Nokia 5500 Sport */
	{ NOKIA_PCSUITE_ACM_INFO(0x04C9), }, /* Nokia E50 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0419), }, /* Nokia E60 */
	{ NOKIA_PCSUITE_ACM_INFO(0x044D), }, /* Nokia E61 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0001), }, /* Nokia E61i */
	{ NOKIA_PCSUITE_ACM_INFO(0x0475), }, /* Nokia E62 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0508), }, /* Nokia E65 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0418), }, /* Nokia E70 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0425), }, /* Nokia N71 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0486), }, /* Nokia N73 */
	{ NOKIA_PCSUITE_ACM_INFO(0x04DF), }, /* Nokia N75 */
	{ NOKIA_PCSUITE_ACM_INFO(0x000e), }, /* Nokia N77 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0445), }, /* Nokia N80 */
	{ NOKIA_PCSUITE_ACM_INFO(0x042F), }, /* Nokia N91 & N91 8GB */
	{ NOKIA_PCSUITE_ACM_INFO(0x048E), }, /* Nokia N92 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0420), }, /* Nokia N93 */
	{ NOKIA_PCSUITE_ACM_INFO(0x04E6), }, /* Nokia N93i  */
	{ NOKIA_PCSUITE_ACM_INFO(0x04B2), }, /* Nokia 5700 XpressMusic */
	{ NOKIA_PCSUITE_ACM_INFO(0x0134), }, /* Nokia 6110 Navigator (China) */
	{ NOKIA_PCSUITE_ACM_INFO(0x046E), }, /* Nokia 6110 Navigator */
	{ NOKIA_PCSUITE_ACM_INFO(0x002f), }, /* Nokia 6120 classic &  */
	{ NOKIA_PCSUITE_ACM_INFO(0x0088), }, /* Nokia 6121 classic */
	{ NOKIA_PCSUITE_ACM_INFO(0x00fc), }, /* Nokia 6124 classic */
	{ NOKIA_PCSUITE_ACM_INFO(0x0042), }, /* Nokia E51 */
	{ NOKIA_PCSUITE_ACM_INFO(0x00b0), }, /* Nokia E66 */
	{ NOKIA_PCSUITE_ACM_INFO(0x00ab), }, /* Nokia E71 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0481), }, /* Nokia N76 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0007), }, /* Nokia N81 & N81 8GB */
	{ NOKIA_PCSUITE_ACM_INFO(0x0071), }, /* Nokia N82 */
	{ NOKIA_PCSUITE_ACM_INFO(0x04F0), }, /* Nokia N95 & N95-3 NAM */
	{ NOKIA_PCSUITE_ACM_INFO(0x0070), }, /* Nokia N95 8GB  */
	{ NOKIA_PCSUITE_ACM_INFO(0x00e9), }, /* Nokia 5320 XpressMusic */
	{ NOKIA_PCSUITE_ACM_INFO(0x0099), }, /* Nokia 6210 Navigator, RM-367 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0128), }, /* Nokia 6210 Navigator, RM-419 */
	{ NOKIA_PCSUITE_ACM_INFO(0x008f), }, /* Nokia 6220 Classic */
	{ NOKIA_PCSUITE_ACM_INFO(0x00a0), }, /* Nokia 6650 */
	{ NOKIA_PCSUITE_ACM_INFO(0x007b), }, /* Nokia N78 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0094), }, /* Nokia N85 */
	{ NOKIA_PCSUITE_ACM_INFO(0x003a), }, /* Nokia N96 & N96-3  */
	{ NOKIA_PCSUITE_ACM_INFO(0x00e9), }, /* Nokia 5320 XpressMusic */
	{ NOKIA_PCSUITE_ACM_INFO(0x0108), }, /* Nokia 5320 XpressMusic 2G */
	{ NOKIA_PCSUITE_ACM_INFO(0x01f5), }, /* Nokia N97, RM-505 */
	{ NOKIA_PCSUITE_ACM_INFO(0x02e3), }, /* Nokia 5230, RM-588 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0178), }, /* Nokia E63 */
	{ NOKIA_PCSUITE_ACM_INFO(0x010e), }, /* Nokia E75 */
	{ NOKIA_PCSUITE_ACM_INFO(0x02d9), }, /* Nokia 6760 Slide */
	{ NOKIA_PCSUITE_ACM_INFO(0x01d0), }, /* Nokia E52 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0223), }, /* Nokia E72 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0275), }, /* Nokia X6 */
	{ NOKIA_PCSUITE_ACM_INFO(0x026c), }, /* Nokia N97 Mini */
	{ NOKIA_PCSUITE_ACM_INFO(0x0154), }, /* Nokia 5800 XpressMusic */
	{ NOKIA_PCSUITE_ACM_INFO(0x04ce), }, /* Nokia E90 */
	{ NOKIA_PCSUITE_ACM_INFO(0x01d4), }, /* Nokia E55 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0302), }, /* Nokia N8 */
	{ NOKIA_PCSUITE_ACM_INFO(0x0335), }, /* Nokia E7 */
	{ NOKIA_PCSUITE_ACM_INFO(0x03cd), }, /* Nokia C7 */
	{ SAMSUNG_PCSUITE_ACM_INFO(0x6651), }, /* Samsung GTi8510 (INNOV8) */

	/* Support for Owen devices */
	{ USB_DEVICE(0x03eb, 0x0030), }, /* Owen SI30 */

	/* NOTE: non-Nokia COMM/ACM/0xff is likely MSFT RNDIS... NOT a modem! */

	/* Support for Droids MuIn LCD */
	{ USB_DEVICE(0x04d8, 0x000b),
	.driver_info = NO_DATA_INTERFACE,
	},

#if IS_ENABLED(CONFIG_INPUT_IMS_PCU)
	{ USB_DEVICE(0x04d8, 0x0082),	/* Application mode */
	.driver_info = IGNORE_DEVICE,
	},
	{ USB_DEVICE(0x04d8, 0x0083),	/* Bootloader mode */
	.driver_info = IGNORE_DEVICE,
	},
#endif

	/*Samsung phone in firmware update mode */
	{ USB_DEVICE(0x04e8, 0x685d),
	.driver_info = IGNORE_DEVICE,
	},

	/* Exclude Infineon Flash Loader utility */
	{ USB_DEVICE(0x058b, 0x0041),
	.driver_info = IGNORE_DEVICE,
	},

	/* control interfaces without any protocol set */
	{ USB_INTERFACE_INFO(USB_CLASS_COMM, USB_CDC_SUBCLASS_ACM,
		USB_CDC_PROTO_NONE) },

	/* control interfaces with various AT-command sets */
	{ USB_INTERFACE_INFO(USB_CLASS_COMM, USB_CDC_SUBCLASS_ACM,
		USB_CDC_ACM_PROTO_AT_V25TER) },
	{ USB_INTERFACE_INFO(USB_CLASS_COMM, USB_CDC_SUBCLASS_ACM,
		USB_CDC_ACM_PROTO_AT_PCCA101) },
	{ USB_INTERFACE_INFO(USB_CLASS_COMM, USB_CDC_SUBCLASS_ACM,
		USB_CDC_ACM_PROTO_AT_PCCA101_WAKE) },
	{ USB_INTERFACE_INFO(USB_CLASS_COMM, USB_CDC_SUBCLASS_ACM,
		USB_CDC_ACM_PROTO_AT_GSM) },
	{ USB_INTERFACE_INFO(USB_CLASS_COMM, USB_CDC_SUBCLASS_ACM,
		USB_CDC_ACM_PROTO_AT_3G	) },
	{ USB_INTERFACE_INFO(USB_CLASS_COMM, USB_CDC_SUBCLASS_ACM,
		USB_CDC_ACM_PROTO_AT_CDMA) },

	/* NOTE:  COMM/ACM/0xff is likely MSFT RNDIS ... NOT a modem!! */
	{ }
};

MODULE_DEVICE_TABLE (usb, acm_ids);
		USB_CDC_ACM_PROTO_AT_3G) },
	{ USB_INTERFACE_INFO(USB_CLASS_COMM, USB_CDC_SUBCLASS_ACM,
		USB_CDC_ACM_PROTO_AT_CDMA) },

	{ USB_DEVICE(0x1519, 0x0452), /* Intel 7260 modem */
	.driver_info = SEND_ZERO_PACKET,
	},

	{ }
};

MODULE_DEVICE_TABLE(usb, acm_ids);

static struct usb_driver acm_driver = {
	.name =		"cdc_acm",
	.probe =	acm_probe,
	.disconnect =	acm_disconnect,
#ifdef CONFIG_PM
	.suspend =	acm_suspend,
	.resume =	acm_resume,
	.reset_resume =	acm_reset_resume,
#endif
	.pre_reset =	acm_pre_reset,
	.id_table =	acm_ids,
#ifdef CONFIG_PM
	.supports_autosuspend = 1,
#endif
	.disable_hub_initiated_lpm = 1,
};

/*
 * TTY driver structures.
 */

static const struct tty_operations acm_ops = {
	.open =			acm_tty_open,
	.close =		acm_tty_close,
	.install =		acm_tty_install,
	.open =			acm_tty_open,
	.close =		acm_tty_close,
	.cleanup =		acm_tty_cleanup,
	.hangup =		acm_tty_hangup,
	.write =		acm_tty_write,
	.put_char =		acm_tty_put_char,
	.flush_chars =		acm_tty_flush_chars,
	.write_room =		acm_tty_write_room,
	.ioctl =		acm_tty_ioctl,
	.throttle =		acm_tty_throttle,
	.unthrottle =		acm_tty_unthrottle,
	.chars_in_buffer =	acm_tty_chars_in_buffer,
	.break_ctl =		acm_tty_break_ctl,
	.set_termios =		acm_tty_set_termios,
	.tiocmget =		acm_tty_tiocmget,
	.tiocmset =		acm_tty_tiocmset,
	.get_icount =		acm_tty_get_icount,
};

/*
 * Init / exit.
 */

static int __init acm_init(void)
{
	int retval;
	acm_tty_driver = alloc_tty_driver(ACM_TTY_MINORS);
	if (!acm_tty_driver)
		return -ENOMEM;
	acm_tty_driver->owner = THIS_MODULE,
	acm_tty_driver->driver_name = "acm",
	acm_tty_driver->name = "ttyACM",
	acm_tty_driver->major = ACM_TTY_MAJOR,
	acm_tty_driver->minor_start = 0,
	acm_tty_driver->type = TTY_DRIVER_TYPE_SERIAL,
	acm_tty_driver->subtype = SERIAL_TYPE_NORMAL,
	acm_tty_driver->flags = TTY_DRIVER_REAL_RAW | TTY_DRIVER_DYNAMIC_DEV;
	acm_tty_driver->init_termios = tty_std_termios;
	acm_tty_driver->init_termios.c_cflag = B9600 | CS8 | CREAD | HUPCL | CLOCAL;
	acm_tty_driver->init_termios.c_cflag = B9600 | CS8 | CREAD |
								HUPCL | CLOCAL;
	tty_set_operations(acm_tty_driver, &acm_ops);

	retval = tty_register_driver(acm_tty_driver);
	if (retval) {
		put_tty_driver(acm_tty_driver);
		return retval;
	}

	retval = usb_register(&acm_driver);
	if (retval) {
		tty_unregister_driver(acm_tty_driver);
		put_tty_driver(acm_tty_driver);
		return retval;
	}

	info(DRIVER_VERSION ":" DRIVER_DESC);
	printk(KERN_INFO KBUILD_MODNAME ": " DRIVER_DESC "\n");

	return 0;
}

static void __exit acm_exit(void)
{
	usb_deregister(&acm_driver);
	tty_unregister_driver(acm_tty_driver);
	put_tty_driver(acm_tty_driver);
	idr_destroy(&acm_minors);
}

module_init(acm_init);
module_exit(acm_exit);

MODULE_AUTHOR( DRIVER_AUTHOR );
MODULE_DESCRIPTION( DRIVER_DESC );
MODULE_LICENSE("GPL");

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");
MODULE_ALIAS_CHARDEV_MAJOR(ACM_TTY_MAJOR);
