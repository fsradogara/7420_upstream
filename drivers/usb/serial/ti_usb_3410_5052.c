// SPDX-License-Identifier: GPL-2.0+
/*
 * TI 3410/5052 USB Serial Driver
 *
 * Copyright (C) 2004 Texas Instruments
 *
 * This driver is based on the Linux io_ti driver, which is
 *   Copyright (C) 2000-2002 Inside Out Networks
 *   Copyright (C) 2001-2002 Greg Kroah-Hartman
 *
 * For questions or problems with this driver, contact Texas Instruments
 * technical support, or Al Borchers <alborchers@steinerpoint.com>, or
 * Peter Berger <pberger@brimson.com>.
 *
 * This driver needs this hotplug script in /etc/hotplug/usb/ti_usb_3410_5052
 * or in /etc/hotplug.d/usb/ti_usb_3410_5052.hotplug to set the device
 * configuration.
 *
 * #!/bin/bash
 *
 * BOOT_CONFIG=1
 * ACTIVE_CONFIG=2
 *
 * if [[ "$ACTION" != "add" ]]
 * then
 * 	exit
 * fi
 *
 * CONFIG_PATH=/sys${DEVPATH%/?*}/bConfigurationValue
 *
 * if [[ 0`cat $CONFIG_PATH` -ne $BOOT_CONFIG ]]
 * then
 * 	exit
 * fi
 *
 * PRODUCT=${PRODUCT%/?*}		# delete version
 * VENDOR_ID=`printf "%d" 0x${PRODUCT%/?*}`
 * PRODUCT_ID=`printf "%d" 0x${PRODUCT#*?/}`
 *
 * PARAM_PATH=/sys/module/ti_usb_3410_5052/parameters
 *
 * function scan() {
 * 	s=$1
 * 	shift
 * 	for i
 * 	do
 * 		if [[ $s -eq $i ]]
 * 		then
 * 			return 0
 * 		fi
 * 	done
 * 	return 1
 * }
 *
 * IFS=$IFS,
 *
 * if (scan $VENDOR_ID 1105 `cat $PARAM_PATH/vendor_3410` &&
 * scan $PRODUCT_ID 13328 `cat $PARAM_PATH/product_3410`) ||
 * (scan $VENDOR_ID 1105 `cat $PARAM_PATH/vendor_5052` &&
 * scan $PRODUCT_ID 20562 20818 20570 20575 `cat $PARAM_PATH/product_5052`)
 * then
 * 	echo $ACTIVE_CONFIG > $CONFIG_PATH
 * fi
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/firmware.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/tty_flip.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/ioctl.h>
#include <linux/serial.h>
#include <linux/circ_buf.h>
#include <linux/kfifo.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/usb.h>
#include <linux/usb/serial.h>
#include <linux/firmware.h>

/* Configuration ids */
#define TI_BOOT_CONFIG			1
#define TI_ACTIVE_CONFIG		2

/* Vendor and product ids */
#define TI_VENDOR_ID			0x0451
#define IBM_VENDOR_ID			0x04b3
#define TI_3410_PRODUCT_ID		0x3410
#define IBM_4543_PRODUCT_ID		0x4543
#define IBM_454B_PRODUCT_ID		0x454b
#define IBM_454C_PRODUCT_ID		0x454c
#define TI_3410_EZ430_ID		0xF430  /* TI ez430 development tool */
#define TI_5052_BOOT_PRODUCT_ID		0x5052	/* no EEPROM, no firmware */
#define TI_5152_BOOT_PRODUCT_ID		0x5152	/* no EEPROM, no firmware */
#define TI_5052_EEPROM_PRODUCT_ID	0x505A	/* EEPROM, no firmware */
#define TI_5052_FIRMWARE_PRODUCT_ID	0x505F	/* firmware is running */
#define FRI2_PRODUCT_ID			0x5053  /* Fish River Island II */

/* Multi-Tech vendor and product ids */
#define MTS_VENDOR_ID			0x06E0
#define MTS_GSM_NO_FW_PRODUCT_ID	0xF108
#define MTS_CDMA_NO_FW_PRODUCT_ID	0xF109
#define MTS_CDMA_PRODUCT_ID		0xF110
#define MTS_GSM_PRODUCT_ID		0xF111
#define MTS_EDGE_PRODUCT_ID		0xF112
#define MTS_MT9234MU_PRODUCT_ID		0xF114
#define MTS_MT9234ZBA_PRODUCT_ID	0xF115
#define MTS_MT9234ZBAOLD_PRODUCT_ID	0x0319

/* Abbott Diabetics vendor and product ids */
#define ABBOTT_VENDOR_ID		0x1a61
#define ABBOTT_STEREO_PLUG_ID		0x3410
#define ABBOTT_PRODUCT_ID		ABBOTT_STEREO_PLUG_ID
#define ABBOTT_STRIP_PORT_ID		0x3420

/* Honeywell vendor and product IDs */
#define HONEYWELL_VENDOR_ID		0x10ac
#define HONEYWELL_HGI80_PRODUCT_ID	0x0102  /* Honeywell HGI80 */

/* Moxa UPORT 11x0 vendor and product IDs */
#define MXU1_VENDOR_ID				0x110a
#define MXU1_1110_PRODUCT_ID			0x1110
#define MXU1_1130_PRODUCT_ID			0x1130
#define MXU1_1150_PRODUCT_ID			0x1150
#define MXU1_1151_PRODUCT_ID			0x1151
#define MXU1_1131_PRODUCT_ID			0x1131

/* Commands */
#define TI_GET_VERSION			0x01
#define TI_GET_PORT_STATUS		0x02
#define TI_GET_PORT_DEV_INFO		0x03
#define TI_GET_CONFIG			0x04
#define TI_SET_CONFIG			0x05
#define TI_OPEN_PORT			0x06
#define TI_CLOSE_PORT			0x07
#define TI_START_PORT			0x08
#define TI_STOP_PORT			0x09
#define TI_TEST_PORT			0x0A
#define TI_PURGE_PORT			0x0B
#define TI_RESET_EXT_DEVICE		0x0C
#define TI_WRITE_DATA			0x80
#define TI_READ_DATA			0x81
#define TI_REQ_TYPE_CLASS		0x82

/* Module identifiers */
#define TI_I2C_PORT			0x01
#define TI_IEEE1284_PORT		0x02
#define TI_UART1_PORT			0x03
#define TI_UART2_PORT			0x04
#define TI_RAM_PORT			0x05

/* Modem status */
#define TI_MSR_DELTA_CTS		0x01
#define TI_MSR_DELTA_DSR		0x02
#define TI_MSR_DELTA_RI			0x04
#define TI_MSR_DELTA_CD			0x08
#define TI_MSR_CTS			0x10
#define TI_MSR_DSR			0x20
#define TI_MSR_RI			0x40
#define TI_MSR_CD			0x80
#define TI_MSR_DELTA_MASK		0x0F
#define TI_MSR_MASK			0xF0

/* Line status */
#define TI_LSR_OVERRUN_ERROR		0x01
#define TI_LSR_PARITY_ERROR		0x02
#define TI_LSR_FRAMING_ERROR		0x04
#define TI_LSR_BREAK			0x08
#define TI_LSR_ERROR			0x0F
#define TI_LSR_RX_FULL			0x10
#define TI_LSR_TX_EMPTY			0x20

/* Line control */
#define TI_LCR_BREAK			0x40

/* Modem control */
#define TI_MCR_LOOP			0x04
#define TI_MCR_DTR			0x10
#define TI_MCR_RTS			0x20

/* Mask settings */
#define TI_UART_ENABLE_RTS_IN		0x0001
#define TI_UART_DISABLE_RTS		0x0002
#define TI_UART_ENABLE_PARITY_CHECKING	0x0008
#define TI_UART_ENABLE_DSR_OUT		0x0010
#define TI_UART_ENABLE_CTS_OUT		0x0020
#define TI_UART_ENABLE_X_OUT		0x0040
#define TI_UART_ENABLE_XA_OUT		0x0080
#define TI_UART_ENABLE_X_IN		0x0100
#define TI_UART_ENABLE_DTR_IN		0x0800
#define TI_UART_DISABLE_DTR		0x1000
#define TI_UART_ENABLE_MS_INTS		0x2000
#define TI_UART_ENABLE_AUTO_START_DMA	0x4000

/* Parity */
#define TI_UART_NO_PARITY		0x00
#define TI_UART_ODD_PARITY		0x01
#define TI_UART_EVEN_PARITY		0x02
#define TI_UART_MARK_PARITY		0x03
#define TI_UART_SPACE_PARITY		0x04

/* Stop bits */
#define TI_UART_1_STOP_BITS		0x00
#define TI_UART_1_5_STOP_BITS		0x01
#define TI_UART_2_STOP_BITS		0x02

/* Bits per character */
#define TI_UART_5_DATA_BITS		0x00
#define TI_UART_6_DATA_BITS		0x01
#define TI_UART_7_DATA_BITS		0x02
#define TI_UART_8_DATA_BITS		0x03

/* 232/485 modes */
#define TI_UART_232			0x00
#define TI_UART_485_RECEIVER_DISABLED	0x01
#define TI_UART_485_RECEIVER_ENABLED	0x02

/* Pipe transfer mode and timeout */
#define TI_PIPE_MODE_CONTINUOUS		0x01
#define TI_PIPE_MODE_MASK		0x03
#define TI_PIPE_TIMEOUT_MASK		0x7C
#define TI_PIPE_TIMEOUT_ENABLE		0x80

/* Config struct */
struct ti_uart_config {
	__be16	wBaudRate;
	__be16	wFlags;
	u8	bDataBits;
	u8	bParity;
	u8	bStopBits;
	char	cXon;
	char	cXoff;
	u8	bUartMode;
} __packed;

/* Get port status */
struct ti_port_status {
	u8 bCmdCode;
	u8 bModuleId;
	u8 bErrorCode;
	u8 bMSR;
	u8 bLSR;
} __packed;

/* Purge modes */
#define TI_PURGE_OUTPUT			0x00
#define TI_PURGE_INPUT			0x80

/* Read/Write data */
#define TI_RW_DATA_ADDR_SFR		0x10
#define TI_RW_DATA_ADDR_IDATA		0x20
#define TI_RW_DATA_ADDR_XDATA		0x30
#define TI_RW_DATA_ADDR_CODE		0x40
#define TI_RW_DATA_ADDR_GPIO		0x50
#define TI_RW_DATA_ADDR_I2C		0x60
#define TI_RW_DATA_ADDR_FLASH		0x70
#define TI_RW_DATA_ADDR_DSP		0x80

#define TI_RW_DATA_UNSPECIFIED		0x00
#define TI_RW_DATA_BYTE			0x01
#define TI_RW_DATA_WORD			0x02
#define TI_RW_DATA_DOUBLE_WORD		0x04

struct ti_write_data_bytes {
	u8	bAddrType;
	u8	bDataType;
	u8	bDataCounter;
	__be16	wBaseAddrHi;
	__be16	wBaseAddrLo;
	u8	bData[0];
} __packed;

struct ti_read_data_request {
	__u8	bAddrType;
	__u8	bDataType;
	__u8	bDataCounter;
	__be16	wBaseAddrHi;
	__be16	wBaseAddrLo;
} __packed;

struct ti_read_data_bytes {
	__u8	bCmdCode;
	__u8	bModuleId;
	__u8	bErrorCode;
	__u8	bData[0];
} __packed;

/* Interrupt struct */
struct ti_interrupt {
	__u8	bICode;
	__u8	bIInfo;
} __packed;

/* Interrupt codes */
#define TI_CODE_HARDWARE_ERROR		0xFF
#define TI_CODE_DATA_ERROR		0x03
#define TI_CODE_MODEM_STATUS		0x04

/* Download firmware max packet size */
#define TI_DOWNLOAD_MAX_PACKET_SIZE	64

/* Firmware image header */
struct ti_firmware_header {
	__le16	wLength;
	u8	bCheckSum;
} __packed;

/* UART addresses */
#define TI_UART1_BASE_ADDR		0xFFA0	/* UART 1 base address */
#define TI_UART2_BASE_ADDR		0xFFB0	/* UART 2 base address */
#define TI_UART_OFFSET_LCR		0x0002	/* UART MCR register offset */
#define TI_UART_OFFSET_MCR		0x0004	/* UART MCR register offset */

#define TI_DRIVER_VERSION	"v0.9"
#define TI_DRIVER_AUTHOR	"Al Borchers <alborchers@steinerpoint.com>"
#define TI_DRIVER_DESC		"TI USB 3410/5052 Serial Driver"

#define TI_FIRMWARE_BUF_SIZE	16284

#define TI_WRITE_BUF_SIZE	1024

#define TI_TRANSFER_TIMEOUT	2

#define TI_DEFAULT_LOW_LATENCY	0
#define TI_DEFAULT_CLOSING_WAIT	4000		/* in .01 secs */

/* supported setserial flags */
#define TI_SET_SERIAL_FLAGS	(ASYNC_LOW_LATENCY)
#define TI_TRANSFER_TIMEOUT	2

#define TI_DEFAULT_CLOSING_WAIT	4000		/* in .01 secs */

/* read urb states */
#define TI_READ_URB_RUNNING	0
#define TI_READ_URB_STOPPING	1
#define TI_READ_URB_STOPPED	2

#define TI_EXTRA_VID_PID_COUNT	5

struct ti_port {
	int			tp_is_open;
	__u8			tp_msr;
	__u8			tp_lsr;
	__u8			tp_shadow_mcr;
	__u8			tp_uart_mode;	/* 232 or 485 modes */
	unsigned int		tp_uart_base_addr;
	int			tp_flags;
	int			tp_closing_wait;/* in .01 secs */
	struct async_icount	tp_icount;
	wait_queue_head_t	tp_msr_wait;	/* wait for msr change */
	wait_queue_head_t	tp_write_wait;
	u8			tp_msr;
	u8			tp_shadow_mcr;
	u8			tp_uart_mode;	/* 232 or 485 modes */
	unsigned int		tp_uart_base_addr;
	struct ti_device	*tp_tdev;
	struct usb_serial_port	*tp_port;
	spinlock_t		tp_lock;
	int			tp_read_urb_state;
	int			tp_write_urb_in_use;
	struct circ_buf		*tp_write_buf;
};

struct ti_device {
	struct mutex		td_open_close_lock;
	int			td_open_port_count;
	struct usb_serial	*td_serial;
	int			td_is_3410;
	bool			td_rs485_only;
};

static int ti_startup(struct usb_serial *serial);
static void ti_shutdown(struct usb_serial *serial);
static int ti_open(struct tty_struct *tty, struct usb_serial_port *port,
		struct file *file);
static void ti_close(struct tty_struct *tty, struct usb_serial_port *port,
		struct file *file);
static void ti_release(struct usb_serial *serial);
static int ti_port_probe(struct usb_serial_port *port);
static int ti_port_remove(struct usb_serial_port *port);
static int ti_open(struct tty_struct *tty, struct usb_serial_port *port);
static void ti_close(struct usb_serial_port *port);
static int ti_write(struct tty_struct *tty, struct usb_serial_port *port,
		const unsigned char *data, int count);
static int ti_write_room(struct tty_struct *tty);
static int ti_chars_in_buffer(struct tty_struct *tty);
static void ti_throttle(struct tty_struct *tty);
static void ti_unthrottle(struct tty_struct *tty);
static int ti_ioctl(struct tty_struct *tty, struct file *file,
		unsigned int cmd, unsigned long arg);
static void ti_set_termios(struct tty_struct *tty,
		struct usb_serial_port *port, struct ktermios *old_termios);
static int ti_tiocmget(struct tty_struct *tty, struct file *file);
static int ti_tiocmset(struct tty_struct *tty, struct file *file,
static bool ti_tx_empty(struct usb_serial_port *port);
static void ti_throttle(struct tty_struct *tty);
static void ti_unthrottle(struct tty_struct *tty);
static int ti_ioctl(struct tty_struct *tty,
		unsigned int cmd, unsigned long arg);
static void ti_set_termios(struct tty_struct *tty,
		struct usb_serial_port *port, struct ktermios *old_termios);
static int ti_tiocmget(struct tty_struct *tty);
static int ti_tiocmset(struct tty_struct *tty,
		unsigned int set, unsigned int clear);
static void ti_break(struct tty_struct *tty, int break_state);
static void ti_interrupt_callback(struct urb *urb);
static void ti_bulk_in_callback(struct urb *urb);
static void ti_bulk_out_callback(struct urb *urb);

static void ti_recv(struct device *dev, struct tty_struct *tty,
	unsigned char *data, int length);
static void ti_send(struct ti_port *tport);
static int ti_set_mcr(struct ti_port *tport, unsigned int mcr);
static int ti_get_lsr(struct ti_port *tport);
static int ti_get_serial_info(struct ti_port *tport,
	struct serial_struct __user *ret_arg);
static int ti_set_serial_info(struct ti_port *tport,
	struct serial_struct __user *new_arg);
static void ti_handle_new_msr(struct ti_port *tport, __u8 msr);

static void ti_drain(struct ti_port *tport, unsigned long timeout, int flush);

static void ti_recv(struct usb_serial_port *port, unsigned char *data,
		int length);
static void ti_send(struct ti_port *tport);
static int ti_set_mcr(struct ti_port *tport, unsigned int mcr);
static int ti_get_lsr(struct ti_port *tport, u8 *lsr);
static int ti_get_serial_info(struct ti_port *tport,
	struct serial_struct __user *ret_arg);
static int ti_set_serial_info(struct tty_struct *tty, struct ti_port *tport,
	struct serial_struct __user *new_arg);
static void ti_handle_new_msr(struct ti_port *tport, u8 msr);

static void ti_stop_read(struct ti_port *tport, struct tty_struct *tty);
static int ti_restart_read(struct ti_port *tport, struct tty_struct *tty);

static int ti_command_out_sync(struct ti_device *tdev, __u8 command,
	__u16 moduleid, __u16 value, __u8 *data, int size);
static int ti_command_in_sync(struct ti_device *tdev, __u8 command,
	__u16 moduleid, __u16 value, __u8 *data, int size);

static int ti_write_byte(struct ti_device *tdev, unsigned long addr,
	__u8 mask, __u8 byte);

static int ti_download_firmware(struct ti_device *tdev, int type);

/* circular buffer */
static struct circ_buf *ti_buf_alloc(void);
static void ti_buf_free(struct circ_buf *cb);
static void ti_buf_clear(struct circ_buf *cb);
static int ti_buf_data_avail(struct circ_buf *cb);
static int ti_buf_space_avail(struct circ_buf *cb);
static int ti_buf_put(struct circ_buf *cb, const char *buf, int count);
static int ti_buf_get(struct circ_buf *cb, char *buf, int count);
static int ti_write_byte(struct usb_serial_port *port, struct ti_device *tdev,
			 unsigned long addr, u8 mask, u8 byte);

static int ti_download_firmware(struct ti_device *tdev);


/* Data */

/* module parameters */
static int debug;
static int low_latency = TI_DEFAULT_LOW_LATENCY;
static int closing_wait = TI_DEFAULT_CLOSING_WAIT;
static ushort vendor_3410[TI_EXTRA_VID_PID_COUNT];
static unsigned int vendor_3410_count;
static ushort product_3410[TI_EXTRA_VID_PID_COUNT];
static unsigned int product_3410_count;
static ushort vendor_5052[TI_EXTRA_VID_PID_COUNT];
static unsigned int vendor_5052_count;
static ushort product_5052[TI_EXTRA_VID_PID_COUNT];
static unsigned int product_5052_count;

/* supported devices */
/* the array dimension is the number of default entries plus */
/* TI_EXTRA_VID_PID_COUNT user defined entries plus 1 terminating */
/* null entry */
static struct usb_device_id ti_id_table_3410[1+TI_EXTRA_VID_PID_COUNT+1] = {
	{ USB_DEVICE(TI_VENDOR_ID, TI_3410_PRODUCT_ID) },
	{ USB_DEVICE(TI_VENDOR_ID, TI_3410_EZ430_ID) },
};

static struct usb_device_id ti_id_table_5052[4+TI_EXTRA_VID_PID_COUNT+1] = {
static int closing_wait = TI_DEFAULT_CLOSING_WAIT;

static const struct usb_device_id ti_id_table_3410[] = {
	{ USB_DEVICE(TI_VENDOR_ID, TI_3410_PRODUCT_ID) },
	{ USB_DEVICE(TI_VENDOR_ID, TI_3410_EZ430_ID) },
	{ USB_DEVICE(MTS_VENDOR_ID, MTS_GSM_NO_FW_PRODUCT_ID) },
	{ USB_DEVICE(MTS_VENDOR_ID, MTS_CDMA_NO_FW_PRODUCT_ID) },
	{ USB_DEVICE(MTS_VENDOR_ID, MTS_CDMA_PRODUCT_ID) },
	{ USB_DEVICE(MTS_VENDOR_ID, MTS_GSM_PRODUCT_ID) },
	{ USB_DEVICE(MTS_VENDOR_ID, MTS_EDGE_PRODUCT_ID) },
	{ USB_DEVICE(MTS_VENDOR_ID, MTS_MT9234MU_PRODUCT_ID) },
	{ USB_DEVICE(MTS_VENDOR_ID, MTS_MT9234ZBA_PRODUCT_ID) },
	{ USB_DEVICE(MTS_VENDOR_ID, MTS_MT9234ZBAOLD_PRODUCT_ID) },
	{ USB_DEVICE(IBM_VENDOR_ID, IBM_4543_PRODUCT_ID) },
	{ USB_DEVICE(IBM_VENDOR_ID, IBM_454B_PRODUCT_ID) },
	{ USB_DEVICE(IBM_VENDOR_ID, IBM_454C_PRODUCT_ID) },
	{ USB_DEVICE(ABBOTT_VENDOR_ID, ABBOTT_STEREO_PLUG_ID) },
	{ USB_DEVICE(ABBOTT_VENDOR_ID, ABBOTT_STRIP_PORT_ID) },
	{ USB_DEVICE(TI_VENDOR_ID, FRI2_PRODUCT_ID) },
	{ USB_DEVICE(HONEYWELL_VENDOR_ID, HONEYWELL_HGI80_PRODUCT_ID) },
	{ USB_DEVICE(MXU1_VENDOR_ID, MXU1_1110_PRODUCT_ID) },
	{ USB_DEVICE(MXU1_VENDOR_ID, MXU1_1130_PRODUCT_ID) },
	{ USB_DEVICE(MXU1_VENDOR_ID, MXU1_1131_PRODUCT_ID) },
	{ USB_DEVICE(MXU1_VENDOR_ID, MXU1_1150_PRODUCT_ID) },
	{ USB_DEVICE(MXU1_VENDOR_ID, MXU1_1151_PRODUCT_ID) },
	{ }	/* terminator */
};

static const struct usb_device_id ti_id_table_5052[] = {
	{ USB_DEVICE(TI_VENDOR_ID, TI_5052_BOOT_PRODUCT_ID) },
	{ USB_DEVICE(TI_VENDOR_ID, TI_5152_BOOT_PRODUCT_ID) },
	{ USB_DEVICE(TI_VENDOR_ID, TI_5052_EEPROM_PRODUCT_ID) },
	{ USB_DEVICE(TI_VENDOR_ID, TI_5052_FIRMWARE_PRODUCT_ID) },
};

static struct usb_device_id ti_id_table_combined[] = {
	{ USB_DEVICE(TI_VENDOR_ID, TI_3410_PRODUCT_ID) },
	{ USB_DEVICE(TI_VENDOR_ID, TI_3410_EZ430_ID) },
	{ }	/* terminator */
	{ }
};

static const struct usb_device_id ti_id_table_combined[] = {
	{ USB_DEVICE(TI_VENDOR_ID, TI_3410_PRODUCT_ID) },
	{ USB_DEVICE(TI_VENDOR_ID, TI_3410_EZ430_ID) },
	{ USB_DEVICE(MTS_VENDOR_ID, MTS_GSM_NO_FW_PRODUCT_ID) },
	{ USB_DEVICE(MTS_VENDOR_ID, MTS_CDMA_NO_FW_PRODUCT_ID) },
	{ USB_DEVICE(MTS_VENDOR_ID, MTS_CDMA_PRODUCT_ID) },
	{ USB_DEVICE(MTS_VENDOR_ID, MTS_GSM_PRODUCT_ID) },
	{ USB_DEVICE(MTS_VENDOR_ID, MTS_EDGE_PRODUCT_ID) },
	{ USB_DEVICE(MTS_VENDOR_ID, MTS_MT9234MU_PRODUCT_ID) },
	{ USB_DEVICE(MTS_VENDOR_ID, MTS_MT9234ZBA_PRODUCT_ID) },
	{ USB_DEVICE(MTS_VENDOR_ID, MTS_MT9234ZBAOLD_PRODUCT_ID) },
	{ USB_DEVICE(TI_VENDOR_ID, TI_5052_BOOT_PRODUCT_ID) },
	{ USB_DEVICE(TI_VENDOR_ID, TI_5152_BOOT_PRODUCT_ID) },
	{ USB_DEVICE(TI_VENDOR_ID, TI_5052_EEPROM_PRODUCT_ID) },
	{ USB_DEVICE(TI_VENDOR_ID, TI_5052_FIRMWARE_PRODUCT_ID) },
	{ }
};

static struct usb_driver ti_usb_driver = {
	.name			= "ti_usb_3410_5052",
	.probe			= usb_serial_probe,
	.disconnect		= usb_serial_disconnect,
	.id_table		= ti_id_table_combined,
	.no_dynamic_id = 	1,
	{ USB_DEVICE(IBM_VENDOR_ID, IBM_4543_PRODUCT_ID) },
	{ USB_DEVICE(IBM_VENDOR_ID, IBM_454B_PRODUCT_ID) },
	{ USB_DEVICE(IBM_VENDOR_ID, IBM_454C_PRODUCT_ID) },
	{ USB_DEVICE(ABBOTT_VENDOR_ID, ABBOTT_PRODUCT_ID) },
	{ USB_DEVICE(ABBOTT_VENDOR_ID, ABBOTT_STRIP_PORT_ID) },
	{ USB_DEVICE(TI_VENDOR_ID, FRI2_PRODUCT_ID) },
	{ USB_DEVICE(HONEYWELL_VENDOR_ID, HONEYWELL_HGI80_PRODUCT_ID) },
	{ USB_DEVICE(MXU1_VENDOR_ID, MXU1_1110_PRODUCT_ID) },
	{ USB_DEVICE(MXU1_VENDOR_ID, MXU1_1130_PRODUCT_ID) },
	{ USB_DEVICE(MXU1_VENDOR_ID, MXU1_1131_PRODUCT_ID) },
	{ USB_DEVICE(MXU1_VENDOR_ID, MXU1_1150_PRODUCT_ID) },
	{ USB_DEVICE(MXU1_VENDOR_ID, MXU1_1151_PRODUCT_ID) },
	{ }	/* terminator */
};

static struct usb_serial_driver ti_1port_device = {
	.driver = {
		.owner		= THIS_MODULE,
		.name		= "ti_usb_3410_5052_1",
	},
	.description		= "TI USB 3410 1 port adapter",
	.usb_driver		= &ti_usb_driver,
	.id_table		= ti_id_table_3410,
	.num_ports		= 1,
	.attach			= ti_startup,
	.shutdown		= ti_shutdown,
	.id_table		= ti_id_table_3410,
	.num_ports		= 1,
	.num_bulk_out		= 1,
	.attach			= ti_startup,
	.release		= ti_release,
	.port_probe		= ti_port_probe,
	.port_remove		= ti_port_remove,
	.open			= ti_open,
	.close			= ti_close,
	.write			= ti_write,
	.write_room		= ti_write_room,
	.chars_in_buffer	= ti_chars_in_buffer,
	.tx_empty		= ti_tx_empty,
	.throttle		= ti_throttle,
	.unthrottle		= ti_unthrottle,
	.ioctl			= ti_ioctl,
	.set_termios		= ti_set_termios,
	.tiocmget		= ti_tiocmget,
	.tiocmset		= ti_tiocmset,
	.tiocmiwait		= usb_serial_generic_tiocmiwait,
	.get_icount		= usb_serial_generic_get_icount,
	.break_ctl		= ti_break,
	.read_int_callback	= ti_interrupt_callback,
	.read_bulk_callback	= ti_bulk_in_callback,
	.write_bulk_callback	= ti_bulk_out_callback,
};

static struct usb_serial_driver ti_2port_device = {
	.driver = {
		.owner		= THIS_MODULE,
		.name		= "ti_usb_3410_5052_2",
	},
	.description		= "TI USB 5052 2 port adapter",
	.usb_driver		= &ti_usb_driver,
	.id_table		= ti_id_table_5052,
	.num_ports		= 2,
	.attach			= ti_startup,
	.shutdown		= ti_shutdown,
	.id_table		= ti_id_table_5052,
	.num_ports		= 2,
	.num_bulk_out		= 1,
	.attach			= ti_startup,
	.release		= ti_release,
	.port_probe		= ti_port_probe,
	.port_remove		= ti_port_remove,
	.open			= ti_open,
	.close			= ti_close,
	.write			= ti_write,
	.write_room		= ti_write_room,
	.chars_in_buffer	= ti_chars_in_buffer,
	.tx_empty		= ti_tx_empty,
	.throttle		= ti_throttle,
	.unthrottle		= ti_unthrottle,
	.ioctl			= ti_ioctl,
	.set_termios		= ti_set_termios,
	.tiocmget		= ti_tiocmget,
	.tiocmset		= ti_tiocmset,
	.tiocmiwait		= usb_serial_generic_tiocmiwait,
	.get_icount		= usb_serial_generic_get_icount,
	.break_ctl		= ti_break,
	.read_int_callback	= ti_interrupt_callback,
	.read_bulk_callback	= ti_bulk_in_callback,
	.write_bulk_callback	= ti_bulk_out_callback,
};

static struct usb_serial_driver * const serial_drivers[] = {
	&ti_1port_device, &ti_2port_device, NULL
};

MODULE_AUTHOR(TI_DRIVER_AUTHOR);
MODULE_DESCRIPTION(TI_DRIVER_DESC);
MODULE_VERSION(TI_DRIVER_VERSION);
MODULE_LICENSE("GPL");

MODULE_FIRMWARE("ti_3410.fw");
MODULE_FIRMWARE("ti_5052.fw");

module_param(debug, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "Enable debugging, 0=no, 1=yes");

module_param(low_latency, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(low_latency,
		"TTY low_latency flag, 0=off, 1=on, default is off");
MODULE_FIRMWARE("mts_cdma.fw");
MODULE_FIRMWARE("mts_gsm.fw");
MODULE_FIRMWARE("mts_edge.fw");
MODULE_FIRMWARE("mts_mt9234mu.fw");
MODULE_FIRMWARE("mts_mt9234zba.fw");
MODULE_FIRMWARE("moxa/moxa-1110.fw");
MODULE_FIRMWARE("moxa/moxa-1130.fw");
MODULE_FIRMWARE("moxa/moxa-1131.fw");
MODULE_FIRMWARE("moxa/moxa-1150.fw");
MODULE_FIRMWARE("moxa/moxa-1151.fw");

module_param(closing_wait, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(closing_wait,
    "Maximum wait for data to drain in close, in .01 secs, default is 4000");

module_param_array(vendor_3410, ushort, &vendor_3410_count, S_IRUGO);
MODULE_PARM_DESC(vendor_3410,
		"Vendor ids for 3410 based devices, 1-5 short integers");
module_param_array(product_3410, ushort, &product_3410_count, S_IRUGO);
MODULE_PARM_DESC(product_3410,
		"Product ids for 3410 based devices, 1-5 short integers");
module_param_array(vendor_5052, ushort, &vendor_5052_count, S_IRUGO);
MODULE_PARM_DESC(vendor_5052,
		"Vendor ids for 5052 based devices, 1-5 short integers");
module_param_array(product_5052, ushort, &product_5052_count, S_IRUGO);
MODULE_PARM_DESC(product_5052,
		"Product ids for 5052 based devices, 1-5 short integers");

MODULE_DEVICE_TABLE(usb, ti_id_table_combined);


/* Functions */

static int __init ti_init(void)
{
	int i, j;
	int ret;

	/* insert extra vendor and product ids */
	j = ARRAY_SIZE(ti_id_table_3410) - TI_EXTRA_VID_PID_COUNT - 1;
	for (i = 0; i < min(vendor_3410_count, product_3410_count); i++, j++) {
		ti_id_table_3410[j].idVendor = vendor_3410[i];
		ti_id_table_3410[j].idProduct = product_3410[i];
		ti_id_table_3410[j].match_flags = USB_DEVICE_ID_MATCH_DEVICE;
	}
	j = ARRAY_SIZE(ti_id_table_5052) - TI_EXTRA_VID_PID_COUNT - 1;
	for (i = 0; i < min(vendor_5052_count, product_5052_count); i++, j++) {
		ti_id_table_5052[j].idVendor = vendor_5052[i];
		ti_id_table_5052[j].idProduct = product_5052[i];
		ti_id_table_5052[j].match_flags = USB_DEVICE_ID_MATCH_DEVICE;
	}

	ret = usb_serial_register(&ti_1port_device);
	if (ret)
		goto failed_1port;
	ret = usb_serial_register(&ti_2port_device);
	if (ret)
		goto failed_2port;

	ret = usb_register(&ti_usb_driver);
	if (ret)
		goto failed_usb;

	info(TI_DRIVER_DESC " " TI_DRIVER_VERSION);

	return 0;

failed_usb:
	usb_serial_deregister(&ti_2port_device);
failed_2port:
	usb_serial_deregister(&ti_1port_device);
failed_1port:
	return ret;
}


static void __exit ti_exit(void)
{
	usb_serial_deregister(&ti_1port_device);
	usb_serial_deregister(&ti_2port_device);
	usb_deregister(&ti_usb_driver);
}


module_init(ti_init);
module_exit(ti_exit);


static int ti_startup(struct usb_serial *serial)
{
	struct ti_device *tdev;
	struct ti_port *tport;
	struct usb_device *dev = serial->dev;
	int status;
	int i;


	dbg("%s - product 0x%4X, num configurations %d, configuration value %d",
	    __func__, le16_to_cpu(dev->descriptor.idProduct),
	    dev->descriptor.bNumConfigurations,
	    dev->actconfig->desc.bConfigurationValue);

	/* create device structure */
	tdev = kzalloc(sizeof(struct ti_device), GFP_KERNEL);
	if (tdev == NULL) {
		dev_err(&dev->dev, "%s - out of memory\n", __func__);
		return -ENOMEM;
	}
MODULE_DEVICE_TABLE(usb, ti_id_table_combined);

module_usb_serial_driver(serial_drivers, ti_id_table_combined);

static int ti_startup(struct usb_serial *serial)
{
	struct ti_device *tdev;
	struct usb_device *dev = serial->dev;
	struct usb_host_interface *cur_altsetting;
	int num_endpoints;
	u16 vid, pid;
	int status;

	dev_dbg(&dev->dev,
		"%s - product 0x%4X, num configurations %d, configuration value %d\n",
		__func__, le16_to_cpu(dev->descriptor.idProduct),
		dev->descriptor.bNumConfigurations,
		dev->actconfig->desc.bConfigurationValue);

	tdev = kzalloc(sizeof(struct ti_device), GFP_KERNEL);
	if (!tdev)
		return -ENOMEM;

	mutex_init(&tdev->td_open_close_lock);
	tdev->td_serial = serial;
	usb_set_serial_data(serial, tdev);

	/* determine device type */
	if (usb_match_id(serial->interface, ti_id_table_3410))
		tdev->td_is_3410 = 1;
	dbg("%s - device type is %s", __func__,
				tdev->td_is_3410 ? "3410" : "5052");

	/* if we have only 1 configuration, download firmware */
	if (dev->descriptor.bNumConfigurations == 1) {
		if (tdev->td_is_3410)
			status = ti_download_firmware(tdev, 3410);
		else
			status = ti_download_firmware(tdev, 5052);
		if (status)
	if (serial->type == &ti_1port_device)
		tdev->td_is_3410 = 1;
	dev_dbg(&dev->dev, "%s - device type is %s\n", __func__,
		tdev->td_is_3410 ? "3410" : "5052");

	vid = le16_to_cpu(dev->descriptor.idVendor);
	pid = le16_to_cpu(dev->descriptor.idProduct);
	if (vid == MXU1_VENDOR_ID) {
		switch (pid) {
		case MXU1_1130_PRODUCT_ID:
		case MXU1_1131_PRODUCT_ID:
			tdev->td_rs485_only = true;
			break;
		}
	}

	cur_altsetting = serial->interface->cur_altsetting;
	num_endpoints = cur_altsetting->desc.bNumEndpoints;

	/* if we have only 1 configuration and 1 endpoint, download firmware */
	if (dev->descriptor.bNumConfigurations == 1 && num_endpoints == 1) {
		status = ti_download_firmware(tdev);

		if (status != 0)
			goto free_tdev;

		/* 3410 must be reset, 5052 resets itself */
		if (tdev->td_is_3410) {
			msleep_interruptible(100);
			usb_reset_device(dev);
		}

		status = -ENODEV;
		goto free_tdev;
	}

	/* the second configuration must be set (in sysfs by hotplug script) */
	if (dev->actconfig->desc.bConfigurationValue == TI_BOOT_CONFIG) {
		status = -ENODEV;
		goto free_tdev;
	}

	/* set up port structures */
	for (i = 0; i < serial->num_ports; ++i) {
		tport = kzalloc(sizeof(struct ti_port), GFP_KERNEL);
		if (tport == NULL) {
			dev_err(&dev->dev, "%s - out of memory\n", __func__);
			status = -ENOMEM;
			goto free_tports;
		}
		spin_lock_init(&tport->tp_lock);
		tport->tp_uart_base_addr = (i == 0 ?
				TI_UART1_BASE_ADDR : TI_UART2_BASE_ADDR);
		tport->tp_flags = low_latency ? ASYNC_LOW_LATENCY : 0;
		tport->tp_closing_wait = closing_wait;
		init_waitqueue_head(&tport->tp_msr_wait);
		init_waitqueue_head(&tport->tp_write_wait);
		tport->tp_write_buf = ti_buf_alloc();
		if (tport->tp_write_buf == NULL) {
			dev_err(&dev->dev, "%s - out of memory\n", __func__);
			kfree(tport);
			status = -ENOMEM;
			goto free_tports;
		}
		tport->tp_port = serial->port[i];
		tport->tp_tdev = tdev;
		usb_set_serial_port_data(serial->port[i], tport);
		tport->tp_uart_mode = 0;	/* default is RS232 */
	}

	return 0;

free_tports:
	for (--i; i >= 0; --i) {
		tport = usb_get_serial_port_data(serial->port[i]);
		ti_buf_free(tport->tp_write_buf);
		kfree(tport);
		usb_set_serial_port_data(serial->port[i], NULL);
	}
	/* the second configuration must be set */
	if (dev->actconfig->desc.bConfigurationValue == TI_BOOT_CONFIG) {
		status = usb_driver_set_configuration(dev, TI_ACTIVE_CONFIG);
		status = status ? status : -ENODEV;
		goto free_tdev;
	}

	if (serial->num_bulk_in < serial->num_ports ||
			serial->num_bulk_out < serial->num_ports) {
		dev_err(&serial->interface->dev, "missing endpoints\n");
		status = -ENODEV;
		goto free_tdev;
	}

	return 0;

free_tdev:
	kfree(tdev);
	usb_set_serial_data(serial, NULL);
	return status;
}


static void ti_shutdown(struct usb_serial *serial)
{
	int i;
	struct ti_device *tdev = usb_get_serial_data(serial);
	struct ti_port *tport;

	dbg("%s", __func__);

	for (i = 0; i < serial->num_ports; ++i) {
		tport = usb_get_serial_port_data(serial->port[i]);
		if (tport) {
			ti_buf_free(tport->tp_write_buf);
			kfree(tport);
			usb_set_serial_port_data(serial->port[i], NULL);
		}
	}

	kfree(tdev);
	usb_set_serial_data(serial, NULL);
}


static int ti_open(struct tty_struct *tty,
			struct usb_serial_port *port, struct file *file)
static void ti_release(struct usb_serial *serial)
{
	struct ti_device *tdev = usb_get_serial_data(serial);

	kfree(tdev);
}

static int ti_port_probe(struct usb_serial_port *port)
{
	struct ti_port *tport;

	tport = kzalloc(sizeof(*tport), GFP_KERNEL);
	if (!tport)
		return -ENOMEM;

	spin_lock_init(&tport->tp_lock);
	if (port == port->serial->port[0])
		tport->tp_uart_base_addr = TI_UART1_BASE_ADDR;
	else
		tport->tp_uart_base_addr = TI_UART2_BASE_ADDR;
	port->port.closing_wait = msecs_to_jiffies(10 * closing_wait);
	tport->tp_port = port;
	tport->tp_tdev = usb_get_serial_data(port->serial);

	if (tport->tp_tdev->td_rs485_only)
		tport->tp_uart_mode = TI_UART_485_RECEIVER_DISABLED;
	else
		tport->tp_uart_mode = TI_UART_232;

	usb_set_serial_port_data(port, tport);

	port->port.drain_delay = 3;

	return 0;
}

static int ti_port_remove(struct usb_serial_port *port)
{
	struct ti_port *tport;

	tport = usb_get_serial_port_data(port);
	kfree(tport);

	return 0;
}

static int ti_open(struct tty_struct *tty, struct usb_serial_port *port)
{
	struct ti_port *tport = usb_get_serial_port_data(port);
	struct ti_device *tdev;
	struct usb_device *dev;
	struct urb *urb;
	int port_number;
	int status;
	u16 open_settings;

	dbg("%s - port %d", __func__, port->number);

	if (tport == NULL)
		return -ENODEV;
	open_settings = (TI_PIPE_MODE_CONTINUOUS |
			 TI_PIPE_TIMEOUT_ENABLE |
			 (TI_TRANSFER_TIMEOUT << 2));

	dev = port->serial->dev;
	tdev = tport->tp_tdev;

	/* only one open on any port on a device at a time */
	if (mutex_lock_interruptible(&tdev->td_open_close_lock))
		return -ERESTARTSYS;

	if (tty)
		tty->low_latency =
				(tport->tp_flags & ASYNC_LOW_LATENCY) ? 1 : 0;

	port_number = port->number - port->serial->minor;

	memset(&(tport->tp_icount), 0x00, sizeof(tport->tp_icount));
	port_number = port->port_number;

	tport->tp_msr = 0;
	tport->tp_shadow_mcr |= (TI_MCR_RTS | TI_MCR_DTR);

	/* start interrupt urb the first time a port is opened on this device */
	if (tdev->td_open_port_count == 0) {
		dbg("%s - start interrupt in urb", __func__);
		urb = tdev->td_serial->port[0]->interrupt_in_urb;
		if (!urb) {
			dev_err(&port->dev, "%s - no interrupt urb\n",
								__func__);
			status = -EINVAL;
			goto release_lock;
		}
		urb->complete = ti_interrupt_callback;
		urb->context = tdev;
		urb->dev = dev;
		status = usb_submit_urb(urb, GFP_KERNEL);
		if (status) {
			dev_err(&port->dev,
				"%s - submit interrupt urb failed, %d\n",
					__func__, status);
		dev_dbg(&port->dev, "%s - start interrupt in urb\n", __func__);
		urb = tdev->td_serial->port[0]->interrupt_in_urb;
		if (!urb) {
			dev_err(&port->dev, "%s - no interrupt urb\n", __func__);
			status = -EINVAL;
			goto release_lock;
		}
		urb->context = tdev;
		status = usb_submit_urb(urb, GFP_KERNEL);
		if (status) {
			dev_err(&port->dev, "%s - submit interrupt urb failed, %d\n", __func__, status);
			goto release_lock;
		}
	}

	if (tty)
		ti_set_termios(tty, port, tty->termios);

	dbg("%s - sending TI_OPEN_PORT", __func__);
		ti_set_termios(tty, port, &tty->termios);

	status = ti_command_out_sync(tdev, TI_OPEN_PORT,
		(__u8)(TI_UART1_PORT + port_number), open_settings, NULL, 0);
	if (status) {
		dev_err(&port->dev, "%s - cannot send open command, %d\n",
							__func__, status);
		goto unlink_int_urb;
	}

	dbg("%s - sending TI_START_PORT", __func__);
			__func__, status);
		goto unlink_int_urb;
	}

	status = ti_command_out_sync(tdev, TI_START_PORT,
		(__u8)(TI_UART1_PORT + port_number), 0, NULL, 0);
	if (status) {
		dev_err(&port->dev, "%s - cannot send start command, %d\n",
							__func__, status);
		goto unlink_int_urb;
	}

	dbg("%s - sending TI_PURGE_PORT", __func__);
	dev_dbg(&port->dev, "%s - sending TI_PURGE_PORT\n", __func__);
	status = ti_command_out_sync(tdev, TI_PURGE_PORT,
		(__u8)(TI_UART1_PORT + port_number), TI_PURGE_INPUT, NULL, 0);
	if (status) {
		dev_err(&port->dev, "%s - cannot clear input buffers, %d\n",
							__func__, status);
		goto unlink_int_urb;
	}
	status = ti_command_out_sync(tdev, TI_PURGE_PORT,
		(__u8)(TI_UART1_PORT + port_number), TI_PURGE_OUTPUT, NULL, 0);
	if (status) {
		dev_err(&port->dev, "%s - cannot clear output buffers, %d\n",
							__func__, status);
		goto unlink_int_urb;
	}

	/* reset the data toggle on the bulk endpoints to work around bug in
	 * host controllers where things get out of sync some times */
	usb_clear_halt(dev, port->write_urb->pipe);
	usb_clear_halt(dev, port->read_urb->pipe);

	if (tty)
		ti_set_termios(tty, port, tty->termios);

	dbg("%s - sending TI_OPEN_PORT (2)", __func__);
		ti_set_termios(tty, port, &tty->termios);

	status = ti_command_out_sync(tdev, TI_OPEN_PORT,
		(__u8)(TI_UART1_PORT + port_number), open_settings, NULL, 0);
	if (status) {
		dev_err(&port->dev, "%s - cannot send open command (2), %d\n",
							__func__, status);
		goto unlink_int_urb;
	}

	dbg("%s - sending TI_START_PORT (2)", __func__);
	dev_dbg(&port->dev, "%s - sending TI_START_PORT (2)\n", __func__);
	status = ti_command_out_sync(tdev, TI_START_PORT,
		(__u8)(TI_UART1_PORT + port_number), 0, NULL, 0);
	if (status) {
		dev_err(&port->dev, "%s - cannot send start command (2), %d\n",
							__func__, status);
		goto unlink_int_urb;
	}

	/* start read urb */
	dbg("%s - start read urb", __func__);
	dev_dbg(&port->dev, "%s - start read urb\n", __func__);
	urb = port->read_urb;
	if (!urb) {
		dev_err(&port->dev, "%s - no read urb\n", __func__);
		status = -EINVAL;
		goto unlink_int_urb;
	}
	tport->tp_read_urb_state = TI_READ_URB_RUNNING;
	urb->complete = ti_bulk_in_callback;
	urb->context = tport;
	urb->dev = dev;
	urb->context = tport;
	status = usb_submit_urb(urb, GFP_KERNEL);
	if (status) {
		dev_err(&port->dev, "%s - submit read urb failed, %d\n",
							__func__, status);
		goto unlink_int_urb;
	}

	tport->tp_is_open = 1;
	++tdev->td_open_port_count;

	goto release_lock;

unlink_int_urb:
	if (tdev->td_open_port_count == 0)
		usb_kill_urb(port->serial->port[0]->interrupt_in_urb);
release_lock:
	mutex_unlock(&tdev->td_open_close_lock);
	dbg("%s - exit %d", __func__, status);
	dev_dbg(&port->dev, "%s - exit %d\n", __func__, status);
	return status;
}


static void ti_close(struct tty_struct *tty, struct usb_serial_port *port,
							struct file *file)
static void ti_close(struct usb_serial_port *port)
{
	struct ti_device *tdev;
	struct ti_port *tport;
	int port_number;
	int status;
	int do_unlock;

	dbg("%s - port %d", __func__, port->number);
	unsigned long flags;

	tdev = usb_get_serial_data(port->serial);
	tport = usb_get_serial_port_data(port);

	tport->tp_is_open = 0;

	ti_drain(tport, (tport->tp_closing_wait*HZ)/100, 1);

	usb_kill_urb(port->read_urb);
	usb_kill_urb(port->write_urb);
	tport->tp_write_urb_in_use = 0;

	port_number = port->number - port->serial->minor;

	dbg("%s - sending TI_CLOSE_PORT", __func__);
	usb_kill_urb(port->read_urb);
	usb_kill_urb(port->write_urb);
	tport->tp_write_urb_in_use = 0;
	spin_lock_irqsave(&tport->tp_lock, flags);
	kfifo_reset_out(&port->write_fifo);
	spin_unlock_irqrestore(&tport->tp_lock, flags);

	port_number = port->port_number;

	status = ti_command_out_sync(tdev, TI_CLOSE_PORT,
		     (__u8)(TI_UART1_PORT + port_number), 0, NULL, 0);
	if (status)
		dev_err(&port->dev,
			"%s - cannot send close port command, %d\n"
							, __func__, status);

	/* if mutex_lock is interrupted, continue anyway */
	do_unlock = !mutex_lock_interruptible(&tdev->td_open_close_lock);
	--tport->tp_tdev->td_open_port_count;
	if (tport->tp_tdev->td_open_port_count <= 0) {
		/* last port is closed, shut down interrupt urb */
		usb_kill_urb(port->serial->port[0]->interrupt_in_urb);
		tport->tp_tdev->td_open_port_count = 0;
	}
	if (do_unlock)
		mutex_unlock(&tdev->td_open_close_lock);

	dbg("%s - exit", __func__);
}


static int ti_write(struct tty_struct *tty, struct usb_serial_port *port,
			const unsigned char *data, int count)
{
	struct ti_port *tport = usb_get_serial_port_data(port);
	unsigned long flags;

	dbg("%s - port %d", __func__, port->number);

	if (count == 0) {
		dbg("%s - write request of 0 bytes", __func__);

	if (count == 0) {
		return 0;
	}

	if (!tport->tp_is_open)
		return -ENODEV;

	spin_lock_irqsave(&tport->tp_lock, flags);
	count = ti_buf_put(tport->tp_write_buf, data, count);
	spin_unlock_irqrestore(&tport->tp_lock, flags);

	count = kfifo_in_locked(&port->write_fifo, data, count,
							&tport->tp_lock);
	ti_send(tport);

	return count;
}


static int ti_write_room(struct tty_struct *tty)
{
	struct usb_serial_port *port = tty->driver_data;
	struct ti_port *tport = usb_get_serial_port_data(port);
	int room = 0;
	unsigned long flags;

	dbg("%s - port %d", __func__, port->number);

	if (tport == NULL)
		return -ENODEV;

	spin_lock_irqsave(&tport->tp_lock, flags);
	room = ti_buf_space_avail(tport->tp_write_buf);
	spin_unlock_irqrestore(&tport->tp_lock, flags);

	dbg("%s - returns %d", __func__, room);
	if (tport == NULL)
		return 0;

	spin_lock_irqsave(&tport->tp_lock, flags);
	room = kfifo_avail(&port->write_fifo);
	spin_unlock_irqrestore(&tport->tp_lock, flags);

	dev_dbg(&port->dev, "%s - returns %d\n", __func__, room);
	return room;
}


static int ti_chars_in_buffer(struct tty_struct *tty)
{
	struct usb_serial_port *port = tty->driver_data;
	struct ti_port *tport = usb_get_serial_port_data(port);
	int chars = 0;
	unsigned long flags;

	dbg("%s - port %d", __func__, port->number);

	if (tport == NULL)
		return -ENODEV;

	spin_lock_irqsave(&tport->tp_lock, flags);
	chars = ti_buf_data_avail(tport->tp_write_buf);
	spin_unlock_irqrestore(&tport->tp_lock, flags);

	dbg("%s - returns %d", __func__, chars);
	return chars;
}

	if (tport == NULL)
		return 0;

	spin_lock_irqsave(&tport->tp_lock, flags);
	chars = kfifo_len(&port->write_fifo);
	spin_unlock_irqrestore(&tport->tp_lock, flags);

	dev_dbg(&port->dev, "%s - returns %d\n", __func__, chars);
	return chars;
}

static bool ti_tx_empty(struct usb_serial_port *port)
{
	struct ti_port *tport = usb_get_serial_port_data(port);
	int ret;
	u8 lsr;

	ret = ti_get_lsr(tport, &lsr);
	if (!ret && !(lsr & TI_LSR_TX_EMPTY))
		return false;

	return true;
}

static void ti_throttle(struct tty_struct *tty)
{
	struct usb_serial_port *port = tty->driver_data;
	struct ti_port *tport = usb_get_serial_port_data(port);

	dbg("%s - port %d", __func__, port->number);

	if (tport == NULL)
		return;

	if (I_IXOFF(tty) || C_CRTSCTS(tty))
		ti_stop_read(tport, tty);

}


static void ti_unthrottle(struct tty_struct *tty)
{
	struct usb_serial_port *port = tty->driver_data;
	struct ti_port *tport = usb_get_serial_port_data(port);
	int status;

	dbg("%s - port %d", __func__, port->number);

	if (tport == NULL)
		return;

	if (I_IXOFF(tty) || C_CRTSCTS(tty)) {
		status = ti_restart_read(tport, tty);
		if (status)
			dev_err(&port->dev, "%s - cannot restart read, %d\n",
							__func__, status);
	}
}


static int ti_ioctl(struct tty_struct *tty, struct file *file,
static int ti_ioctl(struct tty_struct *tty,
	unsigned int cmd, unsigned long arg)
{
	struct usb_serial_port *port = tty->driver_data;
	struct ti_port *tport = usb_get_serial_port_data(port);
	struct async_icount cnow;
	struct async_icount cprev;

	dbg("%s - port %d, cmd = 0x%04X", __func__, port->number, cmd);

	switch (cmd) {
	case TIOCGSERIAL:
		dbg("%s - (%d) TIOCGSERIAL", __func__, port->number);
		return ti_get_serial_info(tport,
				(struct serial_struct __user *)arg);
	case TIOCSSERIAL:
		dbg("%s - (%d) TIOCSSERIAL", __func__, port->number);
		return ti_set_serial_info(tport,
					(struct serial_struct __user *)arg);
	case TIOCMIWAIT:
		dbg("%s - (%d) TIOCMIWAIT", __func__, port->number);
		cprev = tport->tp_icount;
		while (1) {
			interruptible_sleep_on(&tport->tp_msr_wait);
			if (signal_pending(current))
				return -ERESTARTSYS;
			cnow = tport->tp_icount;
			if (cnow.rng == cprev.rng && cnow.dsr == cprev.dsr &&
			    cnow.dcd == cprev.dcd && cnow.cts == cprev.cts)
				return -EIO; /* no change => error */
			if (((arg & TIOCM_RNG) && (cnow.rng != cprev.rng)) ||
			    ((arg & TIOCM_DSR) && (cnow.dsr != cprev.dsr)) ||
			    ((arg & TIOCM_CD)  && (cnow.dcd != cprev.dcd)) ||
			    ((arg & TIOCM_CTS) && (cnow.cts != cprev.cts)))
				return 0;
			cprev = cnow;
		}
		break;
	case TIOCGICOUNT:
		dbg("%s - (%d) TIOCGICOUNT RX=%d, TX=%d",
				__func__, port->number,
				tport->tp_icount.rx, tport->tp_icount.tx);
		if (copy_to_user((void __user *)arg, &tport->tp_icount,
					sizeof(tport->tp_icount)))
			return -EFAULT;
		return 0;
		dev_dbg(&port->dev, "%s - TIOCGSERIAL\n", __func__);
		return ti_get_serial_info(tport,
				(struct serial_struct __user *)arg);
	case TIOCSSERIAL:
		return ti_set_serial_info(tty, tport,
				(struct serial_struct __user *)arg);
	}
	return -ENOIOCTLCMD;
}


static void ti_set_termios(struct tty_struct *tty,
		struct usb_serial_port *port, struct ktermios *old_termios)
{
	struct ti_port *tport = usb_get_serial_port_data(port);
	struct ti_uart_config *config;
	int baud;
	int status;
	int port_number = port->number - port->serial->minor;
	unsigned int mcr;

	dbg("%s - port %d", __func__, port->number);

	cflag = tty->termios->c_cflag;
	iflag = tty->termios->c_iflag;

	dbg("%s - cflag %08x, iflag %08x", __func__, cflag, iflag);
	dbg("%s - old clfag %08x, old iflag %08x", __func__,
				old_termios->c_cflag, old_termios->c_iflag);
	int port_number = port->port_number;
	unsigned int mcr;
	u16 wbaudrate;
	u16 wflags = 0;

	config = kmalloc(sizeof(*config), GFP_KERNEL);
	if (!config) {
		dev_err(&port->dev, "%s - out of memory\n", __func__);
		return;
	}
	if (!config)
		return;

	/* these flags must be set */
	wflags |= TI_UART_ENABLE_MS_INTS;
	wflags |= TI_UART_ENABLE_AUTO_START_DMA;
	config->bUartMode = tport->tp_uart_mode;

	switch (C_CSIZE(tty)) {
	case CS5:
		    config->bDataBits = TI_UART_5_DATA_BITS;
		    break;
	case CS6:
		    config->bDataBits = TI_UART_6_DATA_BITS;
		    break;
	case CS7:
		    config->bDataBits = TI_UART_7_DATA_BITS;
		    break;
	default:
	case CS8:
		    config->bDataBits = TI_UART_8_DATA_BITS;
		    break;
	}

	/* CMSPAR isn't supported by this driver */
	tty->termios->c_cflag &= ~CMSPAR;
	tty->termios.c_cflag &= ~CMSPAR;

	if (C_PARENB(tty)) {
		if (C_PARODD(tty)) {
			wflags |= TI_UART_ENABLE_PARITY_CHECKING;
			config->bParity = TI_UART_ODD_PARITY;
		} else {
			wflags |= TI_UART_ENABLE_PARITY_CHECKING;
			config->bParity = TI_UART_EVEN_PARITY;
		}
	} else {
		wflags &= ~TI_UART_ENABLE_PARITY_CHECKING;
		config->bParity = TI_UART_NO_PARITY;
	}

	if (C_CSTOPB(tty))
		config->bStopBits = TI_UART_2_STOP_BITS;
	else
		config->bStopBits = TI_UART_1_STOP_BITS;

	if (C_CRTSCTS(tty)) {
		/* RTS flow control must be off to drop RTS for baud rate B0 */
		if ((C_BAUD(tty)) != B0)
			wflags |= TI_UART_ENABLE_RTS_IN;
		wflags |= TI_UART_ENABLE_CTS_OUT;
	} else {
		tty->hw_stopped = 0;
		ti_restart_read(tport, tty);
	}

	if (I_IXOFF(tty) || I_IXON(tty)) {
		config->cXon  = START_CHAR(tty);
		config->cXoff = STOP_CHAR(tty);

		if (I_IXOFF(tty))
			wflags |= TI_UART_ENABLE_X_IN;
		else
			ti_restart_read(tport, tty);

		if (I_IXON(tty))
			wflags |= TI_UART_ENABLE_X_OUT;
	}

	baud = tty_get_baud_rate(tty);
	if (!baud)
		baud = 9600;
	if (tport->tp_tdev->td_is_3410)
		wbaudrate = (923077 + baud/2) / baud;
	else
		wbaudrate = (461538 + baud/2) / baud;

	/* FIXME: Should calculate resulting baud here and report it back */
	if ((C_BAUD(tty)) != B0)
		tty_encode_baud_rate(tty, baud, baud);

	dbg("%s - BaudRate=%d, wBaudRate=%d, wFlags=0x%04X, bDataBits=%d, bParity=%d, bStopBits=%d, cXon=%d, cXoff=%d, bUartMode=%d",
	__func__, baud, config->wBaudRate, config->wFlags, config->bDataBits, config->bParity, config->bStopBits, config->cXon, config->cXoff, config->bUartMode);
	dev_dbg(&port->dev,
		"%s - BaudRate=%d, wBaudRate=%d, wFlags=0x%04X, bDataBits=%d, bParity=%d, bStopBits=%d, cXon=%d, cXoff=%d, bUartMode=%d\n",
		__func__, baud, wbaudrate, wflags,
		config->bDataBits, config->bParity, config->bStopBits,
		config->cXon, config->cXoff, config->bUartMode);

	config->wBaudRate = cpu_to_be16(wbaudrate);
	config->wFlags = cpu_to_be16(wflags);

	status = ti_command_out_sync(tport->tp_tdev, TI_SET_CONFIG,
		(__u8)(TI_UART1_PORT + port_number), 0, (__u8 *)config,
		sizeof(*config));
	if (status)
		dev_err(&port->dev, "%s - cannot set config on port %d, %d\n",
					__func__, port_number, status);

	/* SET_CONFIG asserts RTS and DTR, reset them correctly */
	mcr = tport->tp_shadow_mcr;
	/* if baud rate is B0, clear RTS and DTR */
	if (C_BAUD(tty) == B0)
		mcr &= ~(TI_MCR_DTR | TI_MCR_RTS);
	status = ti_set_mcr(tport, mcr);
	if (status)
		dev_err(&port->dev,
			"%s - cannot set modem control on port %d, %d\n",
						__func__, port_number, status);

	kfree(config);
}


static int ti_tiocmget(struct tty_struct *tty, struct file *file)
static int ti_tiocmget(struct tty_struct *tty)
{
	struct usb_serial_port *port = tty->driver_data;
	struct ti_port *tport = usb_get_serial_port_data(port);
	unsigned int result;
	unsigned int msr;
	unsigned int mcr;
	unsigned long flags;

	dbg("%s - port %d", __func__, port->number);

	if (tport == NULL)
		return -ENODEV;

	spin_lock_irqsave(&tport->tp_lock, flags);
	msr = tport->tp_msr;
	mcr = tport->tp_shadow_mcr;
	spin_unlock_irqrestore(&tport->tp_lock, flags);

	result = ((mcr & TI_MCR_DTR) ? TIOCM_DTR : 0)
		| ((mcr & TI_MCR_RTS) ? TIOCM_RTS : 0)
		| ((mcr & TI_MCR_LOOP) ? TIOCM_LOOP : 0)
		| ((msr & TI_MSR_CTS) ? TIOCM_CTS : 0)
		| ((msr & TI_MSR_CD) ? TIOCM_CAR : 0)
		| ((msr & TI_MSR_RI) ? TIOCM_RI : 0)
		| ((msr & TI_MSR_DSR) ? TIOCM_DSR : 0);

	dbg("%s - 0x%04X", __func__, result);
	dev_dbg(&port->dev, "%s - 0x%04X\n", __func__, result);

	return result;
}


static int ti_tiocmset(struct tty_struct *tty, struct file *file,
	unsigned int set, unsigned int clear)
static int ti_tiocmset(struct tty_struct *tty,
				unsigned int set, unsigned int clear)
{
	struct usb_serial_port *port = tty->driver_data;
	struct ti_port *tport = usb_get_serial_port_data(port);
	unsigned int mcr;
	unsigned long flags;

	dbg("%s - port %d", __func__, port->number);

	if (tport == NULL)
		return -ENODEV;

	spin_lock_irqsave(&tport->tp_lock, flags);
	mcr = tport->tp_shadow_mcr;

	if (set & TIOCM_RTS)
		mcr |= TI_MCR_RTS;
	if (set & TIOCM_DTR)
		mcr |= TI_MCR_DTR;
	if (set & TIOCM_LOOP)
		mcr |= TI_MCR_LOOP;

	if (clear & TIOCM_RTS)
		mcr &= ~TI_MCR_RTS;
	if (clear & TIOCM_DTR)
		mcr &= ~TI_MCR_DTR;
	if (clear & TIOCM_LOOP)
		mcr &= ~TI_MCR_LOOP;
	spin_unlock_irqrestore(&tport->tp_lock, flags);

	return ti_set_mcr(tport, mcr);
}


static void ti_break(struct tty_struct *tty, int break_state)
{
	struct usb_serial_port *port = tty->driver_data;
	struct ti_port *tport = usb_get_serial_port_data(port);
	int status;

	dbg("%s - state = %d", __func__, break_state);
	dev_dbg(&port->dev, "%s - state = %d\n", __func__, break_state);

	if (tport == NULL)
		return;

	ti_drain(tport, (tport->tp_closing_wait*HZ)/100, 0);

	status = ti_write_byte(tport->tp_tdev,
	status = ti_write_byte(port, tport->tp_tdev,
		tport->tp_uart_base_addr + TI_UART_OFFSET_LCR,
		TI_LCR_BREAK, break_state == -1 ? TI_LCR_BREAK : 0);

	if (status)
		dbg("%s - error setting break, %d", __func__, status);
		dev_dbg(&port->dev, "%s - error setting break, %d\n", __func__, status);
}

static int ti_get_port_from_code(unsigned char code)
{
	return (code >> 6) & 0x01;
}

static int ti_get_func_from_code(unsigned char code)
{
	return code & 0x0f;
}

static void ti_interrupt_callback(struct urb *urb)
{
	struct ti_device *tdev = urb->context;
	struct usb_serial_port *port;
	struct usb_serial *serial = tdev->td_serial;
	struct ti_port *tport;
	struct device *dev = &urb->dev->dev;
	unsigned char *data = urb->transfer_buffer;
	int length = urb->actual_length;
	int port_number;
	int function;
	int status = urb->status;
	int retval;
	u8 msr;

	dbg("%s", __func__);

	switch (status) {
	case 0:
		break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		dbg("%s - urb shutting down, %d", __func__, status);
		tdev->td_urb_error = 1;
		return;
	default:
		dev_err(dev, "%s - nonzero urb status, %d\n",
			__func__, status);
		dev_dbg(dev, "%s - urb shutting down, %d\n", __func__, status);
		return;
	default:
		dev_err(dev, "%s - nonzero urb status, %d\n", __func__, status);
		goto exit;
	}

	if (length != 2) {
		dbg("%s - bad packet size, %d", __func__, length);
		dev_dbg(dev, "%s - bad packet size, %d\n", __func__, length);
		goto exit;
	}

	if (data[0] == TI_CODE_HARDWARE_ERROR) {
		dev_err(dev, "%s - hardware error, %d\n", __func__, data[1]);
		goto exit;
	}

	port_number = ti_get_port_from_code(data[0]);
	function = ti_get_func_from_code(data[0]);

	dbg("%s - port_number %d, function %d, data 0x%02X",
				__func__, port_number, function, data[1]);
	dev_dbg(dev, "%s - port_number %d, function %d, data 0x%02X\n",
		__func__, port_number, function, data[1]);

	if (port_number >= serial->num_ports) {
		dev_err(dev, "%s - bad port number, %d\n",
						__func__, port_number);
		goto exit;
	}

	port = serial->port[port_number];

	tport = usb_get_serial_port_data(port);
	if (!tport)
		goto exit;

	switch (function) {
	case TI_CODE_DATA_ERROR:
		dev_err(dev, "%s - DATA ERROR, port %d, data 0x%02X\n",
					__func__, port_number, data[1]);
			__func__, port_number, data[1]);
		break;

	case TI_CODE_MODEM_STATUS:
		msr = data[1];
		dbg("%s - port %d, msr 0x%02X", __func__, port_number, msr);
		dev_dbg(dev, "%s - port %d, msr 0x%02X\n", __func__, port_number, msr);
		ti_handle_new_msr(tport, msr);
		break;

	default:
		dev_err(dev, "%s - unknown interrupt code, 0x%02X\n",
							__func__, data[1]);
		break;
	}

exit:
	retval = usb_submit_urb(urb, GFP_ATOMIC);
	if (retval)
		dev_err(dev, "%s - resubmit interrupt urb failed, %d\n",
			__func__, retval);
}


static void ti_bulk_in_callback(struct urb *urb)
{
	struct ti_port *tport = urb->context;
	struct usb_serial_port *port = tport->tp_port;
	struct device *dev = &urb->dev->dev;
	int status = urb->status;
	unsigned long flags;
	int retval = 0;

	dbg("%s", __func__);

	switch (status) {
	case 0:
		break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		dbg("%s - urb shutting down, %d", __func__, status);
		tport->tp_tdev->td_urb_error = 1;
		wake_up_interruptible(&tport->tp_write_wait);
		dev_dbg(dev, "%s - urb shutting down, %d\n", __func__, status);
		return;
	default:
		dev_err(dev, "%s - nonzero urb status, %d\n",
			__func__, status);
		tport->tp_tdev->td_urb_error = 1;
		wake_up_interruptible(&tport->tp_write_wait);
	}

	if (status == -EPIPE)
		goto exit;

	if (status) {
		dev_err(dev, "%s - stopping read!\n", __func__);
		return;
	}

	if (port->port.tty && urb->actual_length) {
		usb_serial_debug_data(debug, dev, __func__,
			urb->actual_length, urb->transfer_buffer);

		if (!tport->tp_is_open)
			dbg("%s - port closed, dropping data", __func__);
		else
			ti_recv(&urb->dev->dev, port->port.tty,
						urb->transfer_buffer,
						urb->actual_length);

		spin_lock(&tport->tp_lock);
		tport->tp_icount.rx += urb->actual_length;
	if (urb->actual_length) {
		usb_serial_debug_data(dev, __func__, urb->actual_length,
				      urb->transfer_buffer);

		if (!tport->tp_is_open)
			dev_dbg(dev, "%s - port closed, dropping data\n",
				__func__);
		else
			ti_recv(port, urb->transfer_buffer, urb->actual_length);
		spin_lock_irqsave(&tport->tp_lock, flags);
		port->icount.rx += urb->actual_length;
		spin_unlock_irqrestore(&tport->tp_lock, flags);
	}

exit:
	/* continue to read unless stopping */
	spin_lock(&tport->tp_lock);
	if (tport->tp_read_urb_state == TI_READ_URB_RUNNING) {
		urb->dev = port->serial->dev;
		retval = usb_submit_urb(urb, GFP_ATOMIC);
	} else if (tport->tp_read_urb_state == TI_READ_URB_STOPPING) {
		tport->tp_read_urb_state = TI_READ_URB_STOPPED;
	}
	spin_lock_irqsave(&tport->tp_lock, flags);
	if (tport->tp_read_urb_state == TI_READ_URB_RUNNING)
		retval = usb_submit_urb(urb, GFP_ATOMIC);
	else if (tport->tp_read_urb_state == TI_READ_URB_STOPPING)
		tport->tp_read_urb_state = TI_READ_URB_STOPPED;

	spin_unlock_irqrestore(&tport->tp_lock, flags);
	if (retval)
		dev_err(dev, "%s - resubmit read urb failed, %d\n",
			__func__, retval);
}


static void ti_bulk_out_callback(struct urb *urb)
{
	struct ti_port *tport = urb->context;
	struct usb_serial_port *port = tport->tp_port;
	struct device *dev = &urb->dev->dev;
	int status = urb->status;

	dbg("%s - port %d", __func__, port->number);

	int status = urb->status;

	tport->tp_write_urb_in_use = 0;

	switch (status) {
	case 0:
		break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		dbg("%s - urb shutting down, %d", __func__, status);
		tport->tp_tdev->td_urb_error = 1;
		wake_up_interruptible(&tport->tp_write_wait);
		return;
	default:
		dev_err(dev, "%s - nonzero urb status, %d\n",
			__func__, status);
		tport->tp_tdev->td_urb_error = 1;
		wake_up_interruptible(&tport->tp_write_wait);
		dev_dbg(&port->dev, "%s - urb shutting down, %d\n", __func__, status);
		return;
	default:
		dev_err_console(port, "%s - nonzero urb status, %d\n",
			__func__, status);
	}

	/* send any buffered data */
	ti_send(tport);
}


static void ti_recv(struct device *dev, struct tty_struct *tty,
	unsigned char *data, int length)
static void ti_recv(struct usb_serial_port *port, unsigned char *data,
		int length)
{
	int cnt;

	do {
		cnt = tty_buffer_request_room(tty, length);
		if (cnt < length) {
			dev_err(dev, "%s - dropping data, %d bytes lost\n",
		cnt = tty_insert_flip_string(&port->port, data, length);
		if (cnt < length) {
			dev_err(&port->dev, "%s - dropping data, %d bytes lost\n",
						__func__, length - cnt);
			if (cnt == 0)
				break;
		}
		tty_insert_flip_string(tty, data, cnt);
		tty_flip_buffer_push(tty);
		data += cnt;
		length -= cnt;
	} while (length > 0);

		tty_flip_buffer_push(&port->port);
		data += cnt;
		length -= cnt;
	} while (length > 0);
}


static void ti_send(struct ti_port *tport)
{
	int count, result;
	struct usb_serial_port *port = tport->tp_port;
	struct tty_struct *tty = port->port.tty;	/* FIXME */
	unsigned long flags;


	dbg("%s - port %d", __func__, port->number);

	spin_lock_irqsave(&tport->tp_lock, flags);

	if (tport->tp_write_urb_in_use) {
		spin_unlock_irqrestore(&tport->tp_lock, flags);
		return;
	}

	count = ti_buf_get(tport->tp_write_buf,
				port->write_urb->transfer_buffer,
				port->bulk_out_size);

	if (count == 0) {
		spin_unlock_irqrestore(&tport->tp_lock, flags);
		return;
	}
	unsigned long flags;

	spin_lock_irqsave(&tport->tp_lock, flags);

	if (tport->tp_write_urb_in_use)
		goto unlock;

	count = kfifo_out(&port->write_fifo,
				port->write_urb->transfer_buffer,
				port->bulk_out_size);

	if (count == 0)
		goto unlock;

	tport->tp_write_urb_in_use = 1;

	spin_unlock_irqrestore(&tport->tp_lock, flags);

	usb_serial_debug_data(debug, &port->dev, __func__, count,
					port->write_urb->transfer_buffer);
	usb_serial_debug_data(&port->dev, __func__, count,
			      port->write_urb->transfer_buffer);

	usb_fill_bulk_urb(port->write_urb, port->serial->dev,
			   usb_sndbulkpipe(port->serial->dev,
					    port->bulk_out_endpointAddress),
			   port->write_urb->transfer_buffer, count,
			   ti_bulk_out_callback, tport);

	result = usb_submit_urb(port->write_urb, GFP_ATOMIC);
	if (result) {
		dev_err(&port->dev, "%s - submit write urb failed, %d\n",
		dev_err_console(port, "%s - submit write urb failed, %d\n",
							__func__, result);
		tport->tp_write_urb_in_use = 0;
		/* TODO: reschedule ti_send */
	} else {
		spin_lock_irqsave(&tport->tp_lock, flags);
		tport->tp_icount.tx += count;
		port->icount.tx += count;
		spin_unlock_irqrestore(&tport->tp_lock, flags);
	}

	/* more room in the buffer for new writes, wakeup */
	if (tty)
		tty_wakeup(tty);
	wake_up_interruptible(&tport->tp_write_wait);
	tty_port_tty_wakeup(&port->port);

	return;
unlock:
	spin_unlock_irqrestore(&tport->tp_lock, flags);
	return;
}


static int ti_set_mcr(struct ti_port *tport, unsigned int mcr)
{
	unsigned long flags;
	int status;

	status = ti_write_byte(tport->tp_tdev,
	status = ti_write_byte(tport->tp_port, tport->tp_tdev,
		tport->tp_uart_base_addr + TI_UART_OFFSET_MCR,
		TI_MCR_RTS | TI_MCR_DTR | TI_MCR_LOOP, mcr);

	spin_lock_irqsave(&tport->tp_lock, flags);
	if (!status)
		tport->tp_shadow_mcr = mcr;
	spin_unlock_irqrestore(&tport->tp_lock, flags);

	return status;
}


static int ti_get_lsr(struct ti_port *tport)
static int ti_get_lsr(struct ti_port *tport, u8 *lsr)
{
	int size, status;
	struct ti_device *tdev = tport->tp_tdev;
	struct usb_serial_port *port = tport->tp_port;
	int port_number = port->number - port->serial->minor;
	struct ti_port_status *data;

	dbg("%s - port %d", __func__, port->number);

	size = sizeof(struct ti_port_status);
	data = kmalloc(size, GFP_KERNEL);
	if (!data) {
		dev_err(&port->dev, "%s - out of memory\n", __func__);
		return -ENOMEM;
	}
	int port_number = port->port_number;
	struct ti_port_status *data;

	size = sizeof(struct ti_port_status);
	data = kmalloc(size, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	status = ti_command_in_sync(tdev, TI_GET_PORT_STATUS,
		(__u8)(TI_UART1_PORT+port_number), 0, (__u8 *)data, size);
	if (status) {
		dev_err(&port->dev,
			"%s - get port status command failed, %d\n",
							__func__, status);
		goto free_data;
	}

	dbg("%s - lsr 0x%02X", __func__, data->bLSR);

	tport->tp_lsr = data->bLSR;
	dev_dbg(&port->dev, "%s - lsr 0x%02X\n", __func__, data->bLSR);

	*lsr = data->bLSR;

free_data:
	kfree(data);
	return status;
}


static int ti_get_serial_info(struct ti_port *tport,
	struct serial_struct __user *ret_arg)
{
	struct usb_serial_port *port = tport->tp_port;
	struct serial_struct ret_serial;
	unsigned cwait;

	if (!ret_arg)
		return -EFAULT;

	memset(&ret_serial, 0, sizeof(ret_serial));

	ret_serial.type = PORT_16550A;
	ret_serial.line = port->serial->minor;
	ret_serial.port = port->number - port->serial->minor;
	ret_serial.flags = tport->tp_flags;
	ret_serial.xmit_fifo_size = TI_WRITE_BUF_SIZE;
	ret_serial.baud_base = tport->tp_tdev->td_is_3410 ? 921600 : 460800;
	ret_serial.closing_wait = tport->tp_closing_wait;
	cwait = port->port.closing_wait;
	if (cwait != ASYNC_CLOSING_WAIT_NONE)
		cwait = jiffies_to_msecs(cwait) / 10;

	memset(&ret_serial, 0, sizeof(ret_serial));

	ret_serial.type = PORT_16550A;
	ret_serial.line = port->minor;
	ret_serial.port = port->port_number;
	ret_serial.xmit_fifo_size = kfifo_size(&port->write_fifo);
	ret_serial.baud_base = tport->tp_tdev->td_is_3410 ? 921600 : 460800;
	ret_serial.closing_wait = cwait;

	if (copy_to_user(ret_arg, &ret_serial, sizeof(*ret_arg)))
		return -EFAULT;

	return 0;
}


static int ti_set_serial_info(struct ti_port *tport,
	struct serial_struct __user *new_arg)
{
	struct usb_serial_port *port = tport->tp_port;
	struct serial_struct new_serial;
static int ti_set_serial_info(struct tty_struct *tty, struct ti_port *tport,
	struct serial_struct __user *new_arg)
{
	struct serial_struct new_serial;
	unsigned cwait;

	if (copy_from_user(&new_serial, new_arg, sizeof(new_serial)))
		return -EFAULT;

	tport->tp_flags = new_serial.flags & TI_SET_SERIAL_FLAGS;
	/* FIXME */
	if (port->port.tty)
		port->port.tty->low_latency =
			(tport->tp_flags & ASYNC_LOW_LATENCY) ? 1 : 0;
	tport->tp_closing_wait = new_serial.closing_wait;
	cwait = new_serial.closing_wait;
	if (cwait != ASYNC_CLOSING_WAIT_NONE)
		cwait = msecs_to_jiffies(10 * new_serial.closing_wait);

	tport->tp_port->port.closing_wait = cwait;

	return 0;
}


static void ti_handle_new_msr(struct ti_port *tport, u8 msr)
{
	struct async_icount *icount;
	struct tty_struct *tty;
	unsigned long flags;

	dbg("%s - msr 0x%02X", __func__, msr);

	if (msr & TI_MSR_DELTA_MASK) {
		spin_lock_irqsave(&tport->tp_lock, flags);
		icount = &tport->tp_icount;
	dev_dbg(&tport->tp_port->dev, "%s - msr 0x%02X\n", __func__, msr);

	if (msr & TI_MSR_DELTA_MASK) {
		spin_lock_irqsave(&tport->tp_lock, flags);
		icount = &tport->tp_port->icount;
		if (msr & TI_MSR_DELTA_CTS)
			icount->cts++;
		if (msr & TI_MSR_DELTA_DSR)
			icount->dsr++;
		if (msr & TI_MSR_DELTA_CD)
			icount->dcd++;
		if (msr & TI_MSR_DELTA_RI)
			icount->rng++;
		wake_up_interruptible(&tport->tp_msr_wait);
		wake_up_interruptible(&tport->tp_port->port.delta_msr_wait);
		spin_unlock_irqrestore(&tport->tp_lock, flags);
	}

	tport->tp_msr = msr & TI_MSR_MASK;

	/* handle CTS flow control */
	tty = tport->tp_port->port.tty;
	if (tty && C_CRTSCTS(tty)) {
		if (msr & TI_MSR_CTS) {
			tty->hw_stopped = 0;
			tty_wakeup(tty);
		} else {
			tty->hw_stopped = 1;
		}
	}
}


static void ti_drain(struct ti_port *tport, unsigned long timeout, int flush)
{
	struct ti_device *tdev = tport->tp_tdev;
	struct usb_serial_port *port = tport->tp_port;
	wait_queue_t wait;

	dbg("%s - port %d", __func__, port->number);

	spin_lock_irq(&tport->tp_lock);

	/* wait for data to drain from the buffer */
	tdev->td_urb_error = 0;
	init_waitqueue_entry(&wait, current);
	add_wait_queue(&tport->tp_write_wait, &wait);
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (ti_buf_data_avail(tport->tp_write_buf) == 0
		|| timeout == 0 || signal_pending(current)
		|| tdev->td_urb_error
		|| port->serial->disconnected)  /* disconnect */
			break;
		spin_unlock_irq(&tport->tp_lock);
		timeout = schedule_timeout(timeout);
		spin_lock_irq(&tport->tp_lock);
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&tport->tp_write_wait, &wait);

	/* flush any remaining data in the buffer */
	if (flush)
		ti_buf_clear(tport->tp_write_buf);

	spin_unlock_irq(&tport->tp_lock);

	mutex_lock(&port->serial->disc_mutex);
	/* wait for data to drain from the device */
	/* wait for empty tx register, plus 20 ms */
	timeout += jiffies;
	tport->tp_lsr &= ~TI_LSR_TX_EMPTY;
	while ((long)(jiffies - timeout) < 0 && !signal_pending(current)
	&& !(tport->tp_lsr&TI_LSR_TX_EMPTY) && !tdev->td_urb_error
	&& !port->serial->disconnected) {
		if (ti_get_lsr(tport))
			break;
		mutex_unlock(&port->serial->disc_mutex);
		msleep_interruptible(20);
		mutex_lock(&port->serial->disc_mutex);
	}
	mutex_unlock(&port->serial->disc_mutex);
	tty = tty_port_tty_get(&tport->tp_port->port);
	if (tty && C_CRTSCTS(tty)) {
		if (msr & TI_MSR_CTS)
			tty_wakeup(tty);
	}
	tty_kref_put(tty);
}


static void ti_stop_read(struct ti_port *tport, struct tty_struct *tty)
{
	unsigned long flags;

	spin_lock_irqsave(&tport->tp_lock, flags);

	if (tport->tp_read_urb_state == TI_READ_URB_RUNNING)
		tport->tp_read_urb_state = TI_READ_URB_STOPPING;

	spin_unlock_irqrestore(&tport->tp_lock, flags);
}


static int ti_restart_read(struct ti_port *tport, struct tty_struct *tty)
{
	struct urb *urb;
	int status = 0;
	unsigned long flags;

	spin_lock_irqsave(&tport->tp_lock, flags);

	if (tport->tp_read_urb_state == TI_READ_URB_STOPPED) {
		tport->tp_read_urb_state = TI_READ_URB_RUNNING;
		urb = tport->tp_port->read_urb;
		spin_unlock_irqrestore(&tport->tp_lock, flags);
		urb->complete = ti_bulk_in_callback;
		urb->context = tport;
		urb->dev = tport->tp_port->serial->dev;
		urb->context = tport;
		status = usb_submit_urb(urb, GFP_KERNEL);
	} else  {
		tport->tp_read_urb_state = TI_READ_URB_RUNNING;
		spin_unlock_irqrestore(&tport->tp_lock, flags);
	}

	return status;
}


static int ti_command_out_sync(struct ti_device *tdev, __u8 command,
	__u16 moduleid, __u16 value, __u8 *data, int size)
{
	int status;

	status = usb_control_msg(tdev->td_serial->dev,
		usb_sndctrlpipe(tdev->td_serial->dev, 0), command,
		(USB_TYPE_VENDOR | USB_RECIP_DEVICE | USB_DIR_OUT),
		value, moduleid, data, size, 1000);

	if (status < 0)
		return status;

	return 0;
}


static int ti_command_in_sync(struct ti_device *tdev, __u8 command,
	__u16 moduleid, __u16 value, __u8 *data, int size)
{
	int status;

	status = usb_control_msg(tdev->td_serial->dev,
		usb_rcvctrlpipe(tdev->td_serial->dev, 0), command,
		(USB_TYPE_VENDOR | USB_RECIP_DEVICE | USB_DIR_IN),
		value, moduleid, data, size, 1000);

	if (status == size)
		status = 0;
	else if (status >= 0)
		status = -ECOMM;

	return status;
}


static int ti_write_byte(struct ti_device *tdev, unsigned long addr,
	__u8 mask, __u8 byte)
static int ti_write_byte(struct usb_serial_port *port,
			 struct ti_device *tdev, unsigned long addr,
			 u8 mask, u8 byte)
{
	int status;
	unsigned int size;
	struct ti_write_data_bytes *data;
	struct device *dev = &tdev->td_serial->dev->dev;

	dbg("%s - addr 0x%08lX, mask 0x%02X, byte 0x%02X",
					__func__, addr, mask, byte);

	size = sizeof(struct ti_write_data_bytes) + 2;
	data = kmalloc(size, GFP_KERNEL);
	if (!data) {
		dev_err(dev, "%s - out of memory\n", __func__);
		return -ENOMEM;
	}

	dev_dbg(&port->dev, "%s - addr 0x%08lX, mask 0x%02X, byte 0x%02X\n", __func__,
		addr, mask, byte);

	size = sizeof(struct ti_write_data_bytes) + 2;
	data = kmalloc(size, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->bAddrType = TI_RW_DATA_ADDR_XDATA;
	data->bDataType = TI_RW_DATA_BYTE;
	data->bDataCounter = 1;
	data->wBaseAddrHi = cpu_to_be16(addr>>16);
	data->wBaseAddrLo = cpu_to_be16(addr);
	data->bData[0] = mask;
	data->bData[1] = byte;

	status = ti_command_out_sync(tdev, TI_WRITE_DATA, TI_RAM_PORT, 0,
		(__u8 *)data, size);

	if (status < 0)
		dev_err(dev, "%s - failed, %d\n", __func__, status);
		dev_err(&port->dev, "%s - failed, %d\n", __func__, status);

	kfree(data);

	return status;
}

static int ti_do_download(struct usb_device *dev, int pipe,
						u8 *buffer, int size)
{
	int pos;
	u8 cs = 0;
	int done;
	struct ti_firmware_header *header;
	int status;
	int status = 0;
	int len;

	for (pos = sizeof(struct ti_firmware_header); pos < size; pos++)
		cs = (u8)(cs + buffer[pos]);

	header = (struct ti_firmware_header *)buffer;
	header->wLength = cpu_to_le16(size - sizeof(*header));
	header->bCheckSum = cs;

	dbg("%s - downloading firmware", __func__);
	dev_dbg(&dev->dev, "%s - downloading firmware\n", __func__);
	for (pos = 0; pos < size; pos += done) {
		len = min(size - pos, TI_DOWNLOAD_MAX_PACKET_SIZE);
		status = usb_bulk_msg(dev, pipe, buffer + pos, len,
								&done, 1000);
		if (status)
			break;
	}
	return status;
}

static int ti_download_firmware(struct ti_device *tdev, int type)
{
	int status = -ENOMEM;
static int ti_download_firmware(struct ti_device *tdev)
{
	int status;
	int buffer_size;
	u8 *buffer;
	struct usb_device *dev = tdev->td_serial->dev;
	unsigned int pipe = usb_sndbulkpipe(dev,
		tdev->td_serial->port[0]->bulk_out_endpointAddress);
	const struct firmware *fw_p;
	char buf[32];
	sprintf(buf, "ti_usb-%d.bin", type);

	if (request_firmware(&fw_p, buf, &dev->dev)) {

	if (le16_to_cpu(dev->descriptor.idVendor) == MXU1_VENDOR_ID) {
		snprintf(buf,
			sizeof(buf),
			"moxa/moxa-%04x.fw",
			le16_to_cpu(dev->descriptor.idProduct));

		status = request_firmware(&fw_p, buf, &dev->dev);
		goto check_firmware;
	}

	/* try ID specific firmware first, then try generic firmware */
	sprintf(buf, "ti_usb-v%04x-p%04x.fw",
			le16_to_cpu(dev->descriptor.idVendor),
			le16_to_cpu(dev->descriptor.idProduct));
	status = request_firmware(&fw_p, buf, &dev->dev);

	if (status != 0) {
		buf[0] = '\0';
		if (le16_to_cpu(dev->descriptor.idVendor) == MTS_VENDOR_ID) {
			switch (le16_to_cpu(dev->descriptor.idProduct)) {
			case MTS_CDMA_PRODUCT_ID:
				strcpy(buf, "mts_cdma.fw");
				break;
			case MTS_GSM_PRODUCT_ID:
				strcpy(buf, "mts_gsm.fw");
				break;
			case MTS_EDGE_PRODUCT_ID:
				strcpy(buf, "mts_edge.fw");
				break;
			case MTS_MT9234MU_PRODUCT_ID:
				strcpy(buf, "mts_mt9234mu.fw");
				break;
			case MTS_MT9234ZBA_PRODUCT_ID:
				strcpy(buf, "mts_mt9234zba.fw");
				break;
			case MTS_MT9234ZBAOLD_PRODUCT_ID:
				strcpy(buf, "mts_mt9234zba.fw");
				break;			}
		}
		if (buf[0] == '\0') {
			if (tdev->td_is_3410)
				strcpy(buf, "ti_3410.fw");
			else
				strcpy(buf, "ti_5052.fw");
		}
		status = request_firmware(&fw_p, buf, &dev->dev);
	}

check_firmware:
	if (status) {
		dev_err(&dev->dev, "%s - firmware not found\n", __func__);
		return -ENOENT;
	}
	if (fw_p->size > TI_FIRMWARE_BUF_SIZE) {
		dev_err(&dev->dev, "%s - firmware too large\n", __func__);
		dev_err(&dev->dev, "%s - firmware too large %zu\n", __func__, fw_p->size);
		release_firmware(fw_p);
		return -ENOENT;
	}

	buffer_size = TI_FIRMWARE_BUF_SIZE + sizeof(struct ti_firmware_header);
	buffer = kmalloc(buffer_size, GFP_KERNEL);
	if (buffer) {
		memcpy(buffer, fw_p->data, fw_p->size);
		memset(buffer + fw_p->size, 0xff, buffer_size - fw_p->size);
		status = ti_do_download(dev, pipe, buffer, fw_p->size);
		kfree(buffer);
	} else {
		status = -ENOMEM;
	}
	release_firmware(fw_p);
	if (status) {
		dev_err(&dev->dev, "%s - error downloading firmware, %d\n",
							__func__, status);
		return status;
	}

	dbg("%s - download successful", __func__);

	return 0;
}


/* Circular Buffer Functions */

/*
 * ti_buf_alloc
 *
 * Allocate a circular buffer and all associated memory.
 */

static struct circ_buf *ti_buf_alloc(void)
{
	struct circ_buf *cb;

	cb = kmalloc(sizeof(struct circ_buf), GFP_KERNEL);
	if (cb == NULL)
		return NULL;

	cb->buf = kmalloc(TI_WRITE_BUF_SIZE, GFP_KERNEL);
	if (cb->buf == NULL) {
		kfree(cb);
		return NULL;
	}

	ti_buf_clear(cb);

	return cb;
}


/*
 * ti_buf_free
 *
 * Free the buffer and all associated memory.
 */

static void ti_buf_free(struct circ_buf *cb)
{
	kfree(cb->buf);
	kfree(cb);
}


/*
 * ti_buf_clear
 *
 * Clear out all data in the circular buffer.
 */

static void ti_buf_clear(struct circ_buf *cb)
{
	cb->head = cb->tail = 0;
}


/*
 * ti_buf_data_avail
 *
 * Return the number of bytes of data available in the circular
 * buffer.
 */

static int ti_buf_data_avail(struct circ_buf *cb)
{
	return CIRC_CNT(cb->head, cb->tail, TI_WRITE_BUF_SIZE);
}


/*
 * ti_buf_space_avail
 *
 * Return the number of bytes of space available in the circular
 * buffer.
 */

static int ti_buf_space_avail(struct circ_buf *cb)
{
	return CIRC_SPACE(cb->head, cb->tail, TI_WRITE_BUF_SIZE);
}


/*
 * ti_buf_put
 *
 * Copy data data from a user buffer and put it into the circular buffer.
 * Restrict to the amount of space available.
 *
 * Return the number of bytes copied.
 */

static int ti_buf_put(struct circ_buf *cb, const char *buf, int count)
{
	int c, ret = 0;

	while (1) {
		c = CIRC_SPACE_TO_END(cb->head, cb->tail, TI_WRITE_BUF_SIZE);
		if (count < c)
			c = count;
		if (c <= 0)
			break;
		memcpy(cb->buf + cb->head, buf, c);
		cb->head = (cb->head + c) & (TI_WRITE_BUF_SIZE-1);
		buf += c;
		count -= c;
		ret += c;
	}

	return ret;
}


/*
 * ti_buf_get
 *
 * Get data from the circular buffer and copy to the given buffer.
 * Restrict to the amount of data available.
 *
 * Return the number of bytes copied.
 */

static int ti_buf_get(struct circ_buf *cb, char *buf, int count)
{
	int c, ret = 0;

	while (1) {
		c = CIRC_CNT_TO_END(cb->head, cb->tail, TI_WRITE_BUF_SIZE);
		if (count < c)
			c = count;
		if (c <= 0)
			break;
		memcpy(buf, cb->buf + cb->tail, c);
		cb->tail = (cb->tail + c) & (TI_WRITE_BUF_SIZE-1);
		buf += c;
		count -= c;
		ret += c;
	}

	return ret;
}
	dev_dbg(&dev->dev, "%s - download successful\n", __func__);

	return 0;
}
