/*
    v4l2 common internal API header

    This header contains internal shared ioctl definitions for use by the
    internal low-level v4l2 drivers.
    Each ioctl begins with VIDIOC_INT_ to clearly mark that it is an internal
    define,

    Copyright (C) 2005  Hans Verkuil <hverkuil@xs4all.nl>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef V4L2_COMMON_H_
#define V4L2_COMMON_H_

#include <media/v4l2-dev.h>

/* Common printk constructs for v4l-i2c drivers. These macros create a unique
   prefix consisting of the driver name, the adapter number and the i2c
   address. */
#define v4l_printk(level, name, adapter, addr, fmt, arg...) \
	printk(level "%s %d-%04x: " fmt, name, i2c_adapter_id(adapter), addr , ## arg)

#define v4l_client_printk(level, client, fmt, arg...)			    \
	v4l_printk(level, (client)->driver->driver.name, (client)->adapter, \
	v4l_printk(level, (client)->dev.driver->name, (client)->adapter, \
		   (client)->addr, fmt , ## arg)

#define v4l_err(client, fmt, arg...) \
	v4l_client_printk(KERN_ERR, client, fmt , ## arg)

#define v4l_warn(client, fmt, arg...) \
	v4l_client_printk(KERN_WARNING, client, fmt , ## arg)

#define v4l_info(client, fmt, arg...) \
	v4l_client_printk(KERN_INFO, client, fmt , ## arg)

/* These three macros assume that the debug level is set with a module
   parameter called 'debug'. */
#define v4l_dbg(level, debug, client, fmt, arg...)			     \
	do {								     \
		if (debug >= (level))					     \
			v4l_client_printk(KERN_DEBUG, client, fmt , ## arg); \
	} while (0)

/* Add a version of v4l_dbg to be used on drivers using dev_foo() macros */
#define dev_dbg_lvl(__dev, __level, __debug, __fmt, __arg...)		\
	do {								\
		if (__debug >= (__level))				\
			dev_printk(KERN_DEBUG, __dev, __fmt, ##__arg);	\
	} while (0)

/* ------------------------------------------------------------------------- */

/* Priority helper functions */

struct v4l2_prio_state {
	atomic_t prios[4];
};
int v4l2_prio_init(struct v4l2_prio_state *global);
int v4l2_prio_change(struct v4l2_prio_state *global, enum v4l2_priority *local,
		     enum v4l2_priority new);
int v4l2_prio_open(struct v4l2_prio_state *global, enum v4l2_priority *local);
int v4l2_prio_close(struct v4l2_prio_state *global, enum v4l2_priority *local);
enum v4l2_priority v4l2_prio_max(struct v4l2_prio_state *global);
int v4l2_prio_check(struct v4l2_prio_state *global, enum v4l2_priority *local);

/* ------------------------------------------------------------------------- */

/* Control helper functions */

int v4l2_ctrl_check(struct v4l2_ext_control *ctrl, struct v4l2_queryctrl *qctrl,
		const char **menu_items);
const char **v4l2_ctrl_get_menu(u32 id);
int v4l2_ctrl_query_fill(struct v4l2_queryctrl *qctrl, s32 min, s32 max, s32 step, s32 def);
int v4l2_ctrl_query_fill_std(struct v4l2_queryctrl *qctrl);
int v4l2_ctrl_query_menu(struct v4l2_querymenu *qmenu,
		struct v4l2_queryctrl *qctrl, const char **menu_items);
u32 v4l2_ctrl_next(const u32 * const *ctrl_classes, u32 id);

/* ------------------------------------------------------------------------- */

/* Register/chip ident helper function */

struct i2c_client; /* forward reference */
int v4l2_chip_match_i2c_client(struct i2c_client *c, u32 id_type, u32 chip_id);
int v4l2_chip_ident_i2c_client(struct i2c_client *c, struct v4l2_chip_ident *chip,
		u32 ident, u32 revision);
int v4l2_chip_match_host(u32 id_type, u32 chip_id);

/* ------------------------------------------------------------------------- */

/* Helper function for I2C legacy drivers */
/* These printk constructs can be used with v4l2_device and v4l2_subdev */
#define v4l2_printk(level, dev, fmt, arg...) \
	printk(level "%s: " fmt, (dev)->name , ## arg)

#define v4l2_err(dev, fmt, arg...) \
	v4l2_printk(KERN_ERR, dev, fmt , ## arg)

#define v4l2_warn(dev, fmt, arg...) \
	v4l2_printk(KERN_WARNING, dev, fmt , ## arg)

#define v4l2_info(dev, fmt, arg...) \
	v4l2_printk(KERN_INFO, dev, fmt , ## arg)

/* These three macros assume that the debug level is set with a module
   parameter called 'debug'. */
#define v4l2_dbg(level, debug, dev, fmt, arg...)			\
	do {								\
		if (debug >= (level))					\
			v4l2_printk(KERN_DEBUG, dev, fmt , ## arg);	\
	} while (0)

/**
 * v4l2_ctrl_query_fill- Fill in a struct v4l2_queryctrl
 *
 * @qctrl: pointer to the &struct v4l2_queryctrl to be filled
 * @min: minimum value for the control
 * @max: maximum value for the control
 * @step: control step
 * @def: default value for the control
 *
 * Fills the &struct v4l2_queryctrl fields for the query control.
 *
 * .. note::
 *
 *    This function assumes that the @qctrl->id field is filled.
 *
 * Returns -EINVAL if the control is not known by the V4L2 core, 0 on success.
 */

int v4l2_ctrl_query_fill(struct v4l2_queryctrl *qctrl,
			 s32 min, s32 max, s32 step, s32 def);

/* ------------------------------------------------------------------------- */

/* I2C Helper functions */

struct i2c_driver;
struct i2c_adapter;
struct i2c_client;
struct i2c_device_id;

int v4l2_i2c_attach(struct i2c_adapter *adapter, int address, struct i2c_driver *driver,
		const char *name,
		int (*probe)(struct i2c_client *, const struct i2c_device_id *));

/* ------------------------------------------------------------------------- */

/* Internal ioctls */

/* VIDIOC_INT_DECODE_VBI_LINE */
struct v4l2_decode_vbi_line {
	u32 is_second_field;	/* Set to 0 for the first (odd) field,
				   set to 1 for the second (even) field. */
	u8 *p; 			/* Pointer to the sliced VBI data from the decoder.
				   On exit points to the start of the payload. */
	u32 line;		/* Line number of the sliced VBI data (1-23) */
	u32 type;		/* VBI service type (V4L2_SLICED_*). 0 if no service found */
};

struct v4l2_device;
struct v4l2_subdev;
struct v4l2_subdev_ops;

/**
 * v4l2_i2c_new_subdev - Load an i2c module and return an initialized
 *	&struct v4l2_subdev.
 *
 * @v4l2_dev: pointer to &struct v4l2_device
 * @adapter: pointer to struct i2c_adapter
 * @client_type:  name of the chip that's on the adapter.
 * @addr: I2C address. If zero, it will use @probe_addrs
 * @probe_addrs: array with a list of address. The last entry at such
 *	array should be %I2C_CLIENT_END.
 *
 * returns a &struct v4l2_subdev pointer.
 */
struct v4l2_subdev *v4l2_i2c_new_subdev(struct v4l2_device *v4l2_dev,
		struct i2c_adapter *adapter, const char *client_type,
		u8 addr, const unsigned short *probe_addrs);

struct i2c_board_info;

/**
 * v4l2_i2c_new_subdev_board - Load an i2c module and return an initialized
 *	&struct v4l2_subdev.
 *
 * @v4l2_dev: pointer to &struct v4l2_device
 * @adapter: pointer to struct i2c_adapter
 * @info: pointer to struct i2c_board_info used to replace the irq,
 *	 platform_data and addr arguments.
 * @probe_addrs: array with a list of address. The last entry at such
 *	array should be %I2C_CLIENT_END.
 *
 * returns a &struct v4l2_subdev pointer.
 */
struct v4l2_subdev *v4l2_i2c_new_subdev_board(struct v4l2_device *v4l2_dev,
		struct i2c_adapter *adapter, struct i2c_board_info *info,
		const unsigned short *probe_addrs);

/**
 * v4l2_i2c_subdev_init - Initializes a &struct v4l2_subdev with data from
 *	an i2c_client struct.
 *
 * @sd: pointer to &struct v4l2_subdev
 * @client: pointer to struct i2c_client
 * @ops: pointer to &struct v4l2_subdev_ops
 */
void v4l2_i2c_subdev_init(struct v4l2_subdev *sd, struct i2c_client *client,
		const struct v4l2_subdev_ops *ops);

/**
 * v4l2_i2c_subdev_addr - returns i2c client address of &struct v4l2_subdev.
 *
 * @sd: pointer to &struct v4l2_subdev
 *
 * Returns the address of an I2C sub-device
 */
unsigned short v4l2_i2c_subdev_addr(struct v4l2_subdev *sd);

/**
 * enum v4l2_i2c_tuner_type - specifies the range of tuner address that
 *	should be used when seeking for I2C devices.
 *
 * @ADDRS_RADIO:		Radio tuner addresses.
 *				Represent the following I2C addresses:
 *				0x10 (if compiled with tea5761 support)
 *				and 0x60.
 * @ADDRS_DEMOD:		Demod tuner addresses.
 *				Represent the following I2C addresses:
 *				0x42, 0x43, 0x4a and 0x4b.
 * @ADDRS_TV:			TV tuner addresses.
 *				Represent the following I2C addresses:
 *				0x42, 0x43, 0x4a, 0x4b, 0x60, 0x61, 0x62,
 *				0x63 and 0x64.
 * @ADDRS_TV_WITH_DEMOD:	TV tuner addresses if demod is present, this
 *				excludes addresses used by the demodulator
 *				from the list of candidates.
 *				Represent the following I2C addresses:
 *				0x60, 0x61, 0x62, 0x63 and 0x64.
 *
 * NOTE: All I2C addresses above use the 7-bit notation.
 */
enum v4l2_i2c_tuner_type {
	ADDRS_RADIO,
	ADDRS_DEMOD,
	ADDRS_TV,
	ADDRS_TV_WITH_DEMOD,
};
/**
 * v4l2_i2c_tuner_addrs - Return a list of I2C tuner addresses to probe.
 *
 * @type: type of the tuner to seek, as defined by
 *	  &enum v4l2_i2c_tuner_type.
 *
 * NOTE: Use only if the tuner addresses are unknown.
 */
const unsigned short *v4l2_i2c_tuner_addrs(enum v4l2_i2c_tuner_type type);

/* ------------------------------------------------------------------------- */

/* SPI Helper functions */
#if defined(CONFIG_SPI)

#include <linux/spi/spi.h>

struct spi_device;

/**
 *  v4l2_spi_new_subdev - Load an spi module and return an initialized
 *	&struct v4l2_subdev.
 *
 *
 * @v4l2_dev: pointer to &struct v4l2_device.
 * @master: pointer to struct spi_master.
 * @info: pointer to struct spi_board_info.
 *
 * returns a &struct v4l2_subdev pointer.
 */
struct v4l2_subdev *v4l2_spi_new_subdev(struct v4l2_device *v4l2_dev,
		struct spi_master *master, struct spi_board_info *info);

/**
 * v4l2_spi_subdev_init - Initialize a v4l2_subdev with data from an
 *	spi_device struct.
 *
 * @sd: pointer to &struct v4l2_subdev
 * @spi: pointer to struct spi_device.
 * @ops: pointer to &struct v4l2_subdev_ops
 */
void v4l2_spi_subdev_init(struct v4l2_subdev *sd, struct spi_device *spi,
		const struct v4l2_subdev_ops *ops);
#endif

/* ------------------------------------------------------------------------- */

/*
 * FIXME: these remaining ioctls/structs should be removed as well, but they
 * are still used in tuner-simple.c (TUNER_SET_CONFIG) and cx18/ivtv (RESET).
 * To remove these ioctls some more cleanup is needed in those modules.
 *
 * It doesn't make much sense on documenting them, as what we really want is
 * to get rid of them.
 */

/* s_config */
struct v4l2_priv_tun_config {
	int tuner;
	void *priv;
};

/* audio ioctls */

/* v4l device was opened in Radio mode, to be replaced by VIDIOC_INT_S_TUNER_MODE */
#define AUDC_SET_RADIO        _IO('d',88)

/* tuner ioctls */

/* Sets tuner type and its I2C addr */
#define TUNER_SET_TYPE_ADDR          _IOW('d', 90, int)

/* Puts tuner on powersaving state, disabling it, except for i2c. To be replaced
   by VIDIOC_INT_S_STANDBY. */
#define TUNER_SET_STANDBY            _IOW('d', 91, int)

/* Sets tda9887 specific stuff, like port1, port2 and qss */
#define TUNER_SET_CONFIG           _IOW('d', 92, struct v4l2_priv_tun_config)

/* Switch the tuner to a specific tuner mode. Replacement of AUDC_SET_RADIO */
#define VIDIOC_INT_S_TUNER_MODE	     _IOW('d', 93, enum v4l2_tuner_type)

/* Generic standby command. Passing -1 (all bits set to 1) will put the whole
   chip into standby mode, value 0 will make the chip fully active. Specific
   bits can be used by certain chips to enable/disable specific subsystems.
   Replacement of TUNER_SET_STANDBY. */
#define VIDIOC_INT_S_STANDBY 	     _IOW('d', 94, u32)

/* 100, 101 used by  VIDIOC_DBG_[SG]_REGISTER */

/* Generic reset command. The argument selects which subsystems to reset.
   Passing 0 will always reset the whole chip. */
#define VIDIOC_INT_RESET            	_IOW ('d', 102, u32)

/* Set the frequency (in Hz) of the audio clock output.
   Used to slave an audio processor to the video decoder, ensuring that audio
   and video remain synchronized.
   Usual values for the frequency are 48000, 44100 or 32000 Hz.
   If the frequency is not supported, then -EINVAL is returned. */
#define VIDIOC_INT_AUDIO_CLOCK_FREQ 	_IOW ('d', 103, u32)

/* Video decoders that support sliced VBI need to implement this ioctl.
   Field p of the v4l2_sliced_vbi_line struct is set to the start of the VBI
   data that was generated by the decoder. The driver then parses the sliced
   VBI data and sets the other fields in the struct accordingly. The pointer p
   is updated to point to the start of the payload which can be copied
   verbatim into the data field of the v4l2_sliced_vbi_data struct. If no
   valid VBI data was found, then the type field is set to 0 on return. */
#define VIDIOC_INT_DECODE_VBI_LINE  	_IOWR('d', 104, struct v4l2_decode_vbi_line)

/* Used to generate VBI signals on a video signal. v4l2_sliced_vbi_data is
   filled with the data packets that should be output. Note that if you set
   the line field to 0, then that VBI signal is disabled. If no
   valid VBI data was found, then the type field is set to 0 on return. */
#define VIDIOC_INT_S_VBI_DATA 		_IOW ('d', 105, struct v4l2_sliced_vbi_data)

/* Used to obtain the sliced VBI packet from a readback register. Not all
   video decoders support this. If no data is available because the readback
   register contains invalid or erroneous data -EIO is returned. Note that
   you must fill in the 'id' member and the 'field' member (to determine
   whether CC data from the first or second field should be obtained). */
#define VIDIOC_INT_G_VBI_DATA 		_IOWR('d', 106, struct v4l2_sliced_vbi_data)

/* Sets I2S speed in bps. This is used to provide a standard way to select I2S
   clock used by driving digital audio streams at some board designs.
   Usual values for the frequency are 1024000 and 2048000.
   If the frequency is not supported, then -EINVAL is returned. */
#define VIDIOC_INT_I2S_CLOCK_FREQ 	_IOW ('d', 108, u32)

/* Routing definition, device dependent. It specifies which inputs (if any)
   should be routed to which outputs (if any). */
#define TUNER_SET_CONFIG           _IOW('d', 92, struct v4l2_priv_tun_config)

#define VIDIOC_INT_RESET		_IOW ('d', 102, u32)

/* These internal commands should be used to define the inputs and outputs
   of an audio/video chip. They will replace the v4l2 API commands
   VIDIOC_S/G_INPUT, VIDIOC_S/G_OUTPUT, VIDIOC_S/G_AUDIO and VIDIOC_S/G_AUDOUT
   that are meant to be used by the user.
   The internal commands should be used to switch inputs/outputs
   because only the driver knows how to map a 'Television' input to the precise
   input/output routing of an A/D converter, or a DSP, or a video digitizer.
   These four commands should only be sent directly to an i2c device, they
   should not be broadcast as the routing is very device specific. */
#define	VIDIOC_INT_S_AUDIO_ROUTING	_IOW ('d', 109, struct v4l2_routing)
#define	VIDIOC_INT_G_AUDIO_ROUTING	_IOR ('d', 110, struct v4l2_routing)
#define	VIDIOC_INT_S_VIDEO_ROUTING	_IOW ('d', 111, struct v4l2_routing)
#define	VIDIOC_INT_G_VIDEO_ROUTING	_IOR ('d', 112, struct v4l2_routing)

struct v4l2_crystal_freq {
	u32 freq;	/* frequency in Hz of the crystal */
	u32 flags; 	/* device specific flags */
};

/* Sets the frequency of the crystal used to generate the clocks.
   An extra flags field allows device specific configuration regarding
   clock frequency dividers, etc. If not used, then set flags to 0.
   If the frequency is not supported, then -EINVAL is returned. */
#define VIDIOC_INT_S_CRYSTAL_FREQ 	_IOW ('d', 113, struct v4l2_crystal_freq)

/* Initialize the sensor registors to some sort of reasonable
   default values. */
#define VIDIOC_INT_INIT			_IOW ('d', 114, u32)

/* Set v4l2_std_id for video OUTPUT devices. This is ignored by
   video input devices. */
#define VIDIOC_INT_S_STD_OUTPUT		_IOW  ('d', 115, v4l2_std_id)

/* Get v4l2_std_id for video OUTPUT devices. This is ignored by
   video input devices. */
#define VIDIOC_INT_G_STD_OUTPUT		_IOW  ('d', 116, v4l2_std_id)
/* ------------------------------------------------------------------------- */

/* Miscellaneous helper functions */

/**
 * v4l_bound_align_image - adjust video dimensions according to
 *	a given constraints.
 *
 * @width:	pointer to width that will be adjusted if needed.
 * @wmin:	minimum width.
 * @wmax:	maximum width.
 * @walign:	least significant bit on width.
 * @height:	pointer to height that will be adjusted if needed.
 * @hmin:	minimum height.
 * @hmax:	maximum height.
 * @halign:	least significant bit on width.
 * @salign:	least significant bit for the image size (e. g.
 *		:math:`width * height`).
 *
 * Clip an image to have @width between @wmin and @wmax, and @height between
 * @hmin and @hmax, inclusive.
 *
 * Additionally, the @width will be a multiple of :math:`2^{walign}`,
 * the @height will be a multiple of :math:`2^{halign}`, and the overall
 * size :math:`width * height` will be a multiple of :math:`2^{salign}`.
 *
 * .. note::
 *
 *    #. The clipping rectangle may be shrunk or enlarged to fit the alignment
 *       constraints.
 *    #. @wmax must not be smaller than @wmin.
 *    #. @hmax must not be smaller than @hmin.
 *    #. The alignments must not be so high there are no possible image
 *       sizes within the allowed bounds.
 *    #. @wmin and @hmin must be at least 1 (don't use 0).
 *    #. For @walign, @halign and @salign, if you don't care about a certain
 *       alignment, specify ``0``, as :math:`2^0 = 1` and one byte alignment
 *       is equivalent to no alignment.
 *    #. If you only want to adjust downward, specify a maximum that's the
 *       same as the initial value.
 */
void v4l_bound_align_image(unsigned int *width, unsigned int wmin,
			   unsigned int wmax, unsigned int walign,
			   unsigned int *height, unsigned int hmin,
			   unsigned int hmax, unsigned int halign,
			   unsigned int salign);

/**
 * v4l2_find_nearest_size - Find the nearest size among a discrete
 *	set of resolutions contained in an array of a driver specific struct.
 *
 * @array: a driver specific array of image sizes
 * @array_size: the length of the driver specific array of image sizes
 * @width_field: the name of the width field in the driver specific struct
 * @height_field: the name of the height field in the driver specific struct
 * @width: desired width.
 * @height: desired height.
 *
 * Finds the closest resolution to minimize the width and height differences
 * between what requested and the supported resolutions. The size of the width
 * and height fields in the driver specific must equal to that of u32, i.e. four
 * bytes.
 *
 * Returns the best match or NULL if the length of the array is zero.
 */
#define v4l2_find_nearest_size(array, array_size, width_field, height_field, \
			       width, height)				\
	({								\
		BUILD_BUG_ON(sizeof((array)->width_field) != sizeof(u32) || \
			     sizeof((array)->height_field) != sizeof(u32)); \
		(typeof(&(array)[0]))__v4l2_find_nearest_size(		\
			(array), array_size, sizeof(*(array)),		\
			offsetof(typeof(*(array)), width_field),	\
			offsetof(typeof(*(array)), height_field),	\
			width, height);					\
	})
const void *
__v4l2_find_nearest_size(const void *array, size_t array_size,
			 size_t entry_size, size_t width_offset,
			 size_t height_offset, s32 width, s32 height);

/**
 * v4l2_get_timestamp - helper routine to get a timestamp to be used when
 *	filling streaming metadata. Internally, it uses ktime_get_ts(),
 *	which is the recommended way to get it.
 *
 * @tv: pointer to &struct timeval to be filled.
 */
void v4l2_get_timestamp(struct timeval *tv);

/**
 * v4l2_g_parm_cap - helper routine for vidioc_g_parm to fill this in by
 *      calling the g_frame_interval op of the given subdev. It only works
 *      for V4L2_BUF_TYPE_VIDEO_CAPTURE(_MPLANE), hence the _cap in the
 *      function name.
 *
 * @vdev: the struct video_device pointer. Used to determine the device caps.
 * @sd: the sub-device pointer.
 * @a: the VIDIOC_G_PARM argument.
 */
int v4l2_g_parm_cap(struct video_device *vdev,
		    struct v4l2_subdev *sd, struct v4l2_streamparm *a);

/**
 * v4l2_s_parm_cap - helper routine for vidioc_s_parm to fill this in by
 *      calling the s_frame_interval op of the given subdev. It only works
 *      for V4L2_BUF_TYPE_VIDEO_CAPTURE(_MPLANE), hence the _cap in the
 *      function name.
 *
 * @vdev: the struct video_device pointer. Used to determine the device caps.
 * @sd: the sub-device pointer.
 * @a: the VIDIOC_S_PARM argument.
 */
int v4l2_s_parm_cap(struct video_device *vdev,
		    struct v4l2_subdev *sd, struct v4l2_streamparm *a);

#endif /* V4L2_COMMON_H_ */
