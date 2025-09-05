/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ethtool.h: Defines for Linux ethtool.
 *
 * Copyright (C) 1998 David S. Miller (davem@redhat.com)
 * Copyright 2001 Jeff Garzik <jgarzik@pobox.com>
 * Portions Copyright 2001 Sun Microsystems (thockin@sun.com)
 * Portions Copyright 2002 Intel (eli.kupermann@intel.com,
 *                                christopher.leech@intel.com,
 *                                scott.feldman@intel.com)
 */

#ifndef _LINUX_ETHTOOL_H
#define _LINUX_ETHTOOL_H

#include <linux/types.h>

/* This should work for both 32 and 64 bit userland. */
struct ethtool_cmd {
	__u32	cmd;
	__u32	supported;	/* Features this interface supports */
	__u32	advertising;	/* Features this interface advertises */
	__u16	speed;		/* The forced speed, 10Mb, 100Mb, gigabit */
	__u8	duplex;		/* Duplex, half or full */
	__u8	port;		/* Which connector port */
	__u8	phy_address;
	__u8	transceiver;	/* Which transceiver to use */
	__u8	autoneg;	/* Enable or disable autonegotiation */
	__u32	maxtxpkt;	/* Tx pkts before generating tx int */
	__u32	maxrxpkt;	/* Rx pkts before generating rx int */
	__u16	speed_hi;
	__u16	reserved2;
	__u32	reserved[3];
};

static inline void ethtool_cmd_speed_set(struct ethtool_cmd *ep,
						__u32 speed)
{

	ep->speed = (__u16)speed;
	ep->speed_hi = (__u16)(speed >> 16);
}

static inline __u32 ethtool_cmd_speed(struct ethtool_cmd *ep)
{
	return (ep->speed_hi << 16) | ep->speed;
}

#define ETHTOOL_BUSINFO_LEN	32
/* these strings are set to whatever the driver author decides... */
struct ethtool_drvinfo {
	__u32	cmd;
	char	driver[32];	/* driver short name, "tulip", "eepro100" */
	char	version[32];	/* driver version string */
	char	fw_version[32];	/* firmware version string, if applicable */
	char	bus_info[ETHTOOL_BUSINFO_LEN];	/* Bus info for this IF. */
				/* For PCI devices, use pci_name(pci_dev). */
	char	reserved1[32];
	char	reserved2[12];
	__u32	n_priv_flags;	/* number of flags valid in ETHTOOL_GPFLAGS */
	__u32	n_stats;	/* number of u64's from ETHTOOL_GSTATS */
	__u32	testinfo_len;
	__u32	eedump_len;	/* Size of data from ETHTOOL_GEEPROM (bytes) */
	__u32	regdump_len;	/* Size of data from ETHTOOL_GREGS (bytes) */
};

#define SOPASS_MAX	6
/* wake-on-lan settings */
struct ethtool_wolinfo {
	__u32	cmd;
	__u32	supported;
	__u32	wolopts;
	__u8	sopass[SOPASS_MAX]; /* SecureOn(tm) password */
};

/* for passing single values */
struct ethtool_value {
	__u32	cmd;
	__u32	data;
};

/* for passing big chunks of data */
struct ethtool_regs {
	__u32	cmd;
	__u32	version; /* driver-specific, indicates different chips/revs */
	__u32	len; /* bytes */
	__u8	data[0];
};

/* for passing EEPROM chunks */
struct ethtool_eeprom {
	__u32	cmd;
	__u32	magic;
	__u32	offset; /* in bytes */
	__u32	len; /* in bytes */
	__u8	data[0];
};

/* for configuring coalescing parameters of chip */
struct ethtool_coalesce {
	__u32	cmd;	/* ETHTOOL_{G,S}COALESCE */

	/* How many usecs to delay an RX interrupt after
	 * a packet arrives.  If 0, only rx_max_coalesced_frames
	 * is used.
	 */
	__u32	rx_coalesce_usecs;

	/* How many packets to delay an RX interrupt after
	 * a packet arrives.  If 0, only rx_coalesce_usecs is
	 * used.  It is illegal to set both usecs and max frames
	 * to zero as this would cause RX interrupts to never be
	 * generated.
	 */
	__u32	rx_max_coalesced_frames;

	/* Same as above two parameters, except that these values
	 * apply while an IRQ is being serviced by the host.  Not
	 * all cards support this feature and the values are ignored
	 * in that case.
	 */
	__u32	rx_coalesce_usecs_irq;
	__u32	rx_max_coalesced_frames_irq;

	/* How many usecs to delay a TX interrupt after
	 * a packet is sent.  If 0, only tx_max_coalesced_frames
	 * is used.
	 */
	__u32	tx_coalesce_usecs;

	/* How many packets to delay a TX interrupt after
	 * a packet is sent.  If 0, only tx_coalesce_usecs is
	 * used.  It is illegal to set both usecs and max frames
	 * to zero as this would cause TX interrupts to never be
	 * generated.
	 */
	__u32	tx_max_coalesced_frames;

	/* Same as above two parameters, except that these values
	 * apply while an IRQ is being serviced by the host.  Not
	 * all cards support this feature and the values are ignored
	 * in that case.
	 */
	__u32	tx_coalesce_usecs_irq;
	__u32	tx_max_coalesced_frames_irq;

	/* How many usecs to delay in-memory statistics
	 * block updates.  Some drivers do not have an in-memory
	 * statistic block, and in such cases this value is ignored.
	 * This value must not be zero.
	 */
	__u32	stats_block_coalesce_usecs;

	/* Adaptive RX/TX coalescing is an algorithm implemented by
	 * some drivers to improve latency under low packet rates and
	 * improve throughput under high packet rates.  Some drivers
	 * only implement one of RX or TX adaptive coalescing.  Anything
	 * not implemented by the driver causes these values to be
	 * silently ignored.
	 */
	__u32	use_adaptive_rx_coalesce;
	__u32	use_adaptive_tx_coalesce;

	/* When the packet rate (measured in packets per second)
	 * is below pkt_rate_low, the {rx,tx}_*_low parameters are
	 * used.
	 */
	__u32	pkt_rate_low;
	__u32	rx_coalesce_usecs_low;
	__u32	rx_max_coalesced_frames_low;
	__u32	tx_coalesce_usecs_low;
	__u32	tx_max_coalesced_frames_low;

	/* When the packet rate is below pkt_rate_high but above
	 * pkt_rate_low (both measured in packets per second) the
	 * normal {rx,tx}_* coalescing parameters are used.
	 */

	/* When the packet rate is (measured in packets per second)
	 * is above pkt_rate_high, the {rx,tx}_*_high parameters are
	 * used.
	 */
	__u32	pkt_rate_high;
	__u32	rx_coalesce_usecs_high;
	__u32	rx_max_coalesced_frames_high;
	__u32	tx_coalesce_usecs_high;
	__u32	tx_max_coalesced_frames_high;

	/* How often to do adaptive coalescing packet rate sampling,
	 * measured in seconds.  Must not be zero.
	 */
	__u32	rate_sample_interval;
};

/* for configuring RX/TX ring parameters */
struct ethtool_ringparam {
	__u32	cmd;	/* ETHTOOL_{G,S}RINGPARAM */

	/* Read only attributes.  These indicate the maximum number
	 * of pending RX/TX ring entries the driver will allow the
	 * user to set.
	 */
	__u32	rx_max_pending;
	__u32	rx_mini_max_pending;
	__u32	rx_jumbo_max_pending;
	__u32	tx_max_pending;

	/* Values changeable by the user.  The valid values are
	 * in the range 1 to the "*_max_pending" counterpart above.
	 */
	__u32	rx_pending;
	__u32	rx_mini_pending;
	__u32	rx_jumbo_pending;
	__u32	tx_pending;
};

/* for configuring link flow control parameters */
struct ethtool_pauseparam {
	__u32	cmd;	/* ETHTOOL_{G,S}PAUSEPARAM */

	/* If the link is being auto-negotiated (via ethtool_cmd.autoneg
	 * being true) the user may set 'autonet' here non-zero to have the
	 * pause parameters be auto-negotiated too.  In such a case, the
	 * {rx,tx}_pause values below determine what capabilities are
	 * advertised.
	 *
	 * If 'autoneg' is zero or the link is not being auto-negotiated,
	 * then {rx,tx}_pause force the driver to use/not-use pause
	 * flow control.
	 */
	__u32	autoneg;
	__u32	rx_pause;
	__u32	tx_pause;
};

#define ETH_GSTRING_LEN		32
enum ethtool_stringset {
	ETH_SS_TEST		= 0,
	ETH_SS_STATS,
	ETH_SS_PRIV_FLAGS,
};

/* for passing string sets for data tagging */
struct ethtool_gstrings {
	__u32	cmd;		/* ETHTOOL_GSTRINGS */
	__u32	string_set;	/* string set id e.c. ETH_SS_TEST, etc*/
	__u32	len;		/* number of strings in the string set */
	__u8	data[0];
};

enum ethtool_test_flags {
	ETH_TEST_FL_OFFLINE	= (1 << 0),	/* online / offline */
	ETH_TEST_FL_FAILED	= (1 << 1),	/* test passed / failed */
};

/* for requesting NIC test and getting results*/
struct ethtool_test {
	__u32	cmd;		/* ETHTOOL_TEST */
	__u32	flags;		/* ETH_TEST_FL_xxx */
	__u32	reserved;
	__u32	len;		/* result length, in number of u64 elements */
	__u64	data[0];
};

/* for dumping NIC-specific statistics */
struct ethtool_stats {
	__u32	cmd;		/* ETHTOOL_GSTATS */
	__u32	n_stats;	/* number of u64's being returned */
	__u64	data[0];
};

struct ethtool_perm_addr {
	__u32	cmd;		/* ETHTOOL_GPERMADDR */
	__u32	size;
	__u8	data[0];
};

/* boolean flags controlling per-interface behavior characteristics.
 * When reading, the flag indicates whether or not a certain behavior
 * is enabled/present.  When writing, the flag indicates whether
 * or not the driver should turn on (set) or off (clear) a behavior.
 *
 * Some behaviors may read-only (unconditionally absent or present).
 * If such is the case, return EINVAL in the set-flags operation if the
 * flag differs from the read-only value.
 */
enum ethtool_flags {
	ETH_FLAG_LRO		= (1 << 15),	/* LRO is enabled */
};

struct ethtool_rxnfc {
	__u32		cmd;
	__u32		flow_type;
	__u64		data;
};

#ifdef __KERNEL__
 * Portions Copyright (C) Sun Microsystems 2008
 */
#ifndef _LINUX_ETHTOOL_H
#define _LINUX_ETHTOOL_H

#include <linux/bitmap.h>
#include <linux/compat.h>
#include <uapi/linux/ethtool.h>

#ifdef CONFIG_COMPAT

struct compat_ethtool_rx_flow_spec {
	u32		flow_type;
	union ethtool_flow_union h_u;
	struct ethtool_flow_ext h_ext;
	union ethtool_flow_union m_u;
	struct ethtool_flow_ext m_ext;
	compat_u64	ring_cookie;
	u32		location;
};

struct compat_ethtool_rxnfc {
	u32				cmd;
	u32				flow_type;
	compat_u64			data;
	struct compat_ethtool_rx_flow_spec fs;
	u32				rule_cnt;
	u32				rule_locs[0];
};

#endif /* CONFIG_COMPAT */

#include <linux/rculist.h>

/**
 * enum ethtool_phys_id_state - indicator state for physical identification
 * @ETHTOOL_ID_INACTIVE: Physical ID indicator should be deactivated
 * @ETHTOOL_ID_ACTIVE: Physical ID indicator should be activated
 * @ETHTOOL_ID_ON: LED should be turned on (used iff %ETHTOOL_ID_ACTIVE
 *	is not supported)
 * @ETHTOOL_ID_OFF: LED should be turned off (used iff %ETHTOOL_ID_ACTIVE
 *	is not supported)
 */
enum ethtool_phys_id_state {
	ETHTOOL_ID_INACTIVE,
	ETHTOOL_ID_ACTIVE,
	ETHTOOL_ID_ON,
	ETHTOOL_ID_OFF
};

enum {
	ETH_RSS_HASH_TOP_BIT, /* Configurable RSS hash function - Toeplitz */
	ETH_RSS_HASH_XOR_BIT, /* Configurable RSS hash function - Xor */
	ETH_RSS_HASH_CRC32_BIT, /* Configurable RSS hash function - Crc32 */

	/*
	 * Add your fresh new hash function bits above and remember to update
	 * rss_hash_func_strings[] in ethtool.c
	 */
	ETH_RSS_HASH_FUNCS_COUNT
};

#define __ETH_RSS_HASH_BIT(bit)	((u32)1 << (bit))
#define __ETH_RSS_HASH(name)	__ETH_RSS_HASH_BIT(ETH_RSS_HASH_##name##_BIT)

#define ETH_RSS_HASH_TOP	__ETH_RSS_HASH(TOP)
#define ETH_RSS_HASH_XOR	__ETH_RSS_HASH(XOR)
#define ETH_RSS_HASH_CRC32	__ETH_RSS_HASH(CRC32)

#define ETH_RSS_HASH_UNKNOWN	0
#define ETH_RSS_HASH_NO_CHANGE	0

struct net_device;

/* Some generic methods drivers may use in their ethtool_ops */
u32 ethtool_op_get_link(struct net_device *dev);
u32 ethtool_op_get_tx_csum(struct net_device *dev);
int ethtool_op_set_tx_csum(struct net_device *dev, u32 data);
int ethtool_op_set_tx_hw_csum(struct net_device *dev, u32 data);
int ethtool_op_set_tx_ipv6_csum(struct net_device *dev, u32 data);
u32 ethtool_op_get_sg(struct net_device *dev);
int ethtool_op_set_sg(struct net_device *dev, u32 data);
u32 ethtool_op_get_tso(struct net_device *dev);
int ethtool_op_set_tso(struct net_device *dev, u32 data);
u32 ethtool_op_get_ufo(struct net_device *dev);
int ethtool_op_set_ufo(struct net_device *dev, u32 data);
u32 ethtool_op_get_flags(struct net_device *dev);
int ethtool_op_set_flags(struct net_device *dev, u32 data);

/**
 * &ethtool_ops - Alter and report network device settings
 * get_settings: Get device-specific settings
 * set_settings: Set device-specific settings
 * get_drvinfo: Report driver information
 * get_regs: Get device registers
 * get_wol: Report whether Wake-on-Lan is enabled
 * set_wol: Turn Wake-on-Lan on or off
 * get_msglevel: Report driver message level
 * set_msglevel: Set driver message level
 * nway_reset: Restart autonegotiation
 * get_link: Get link status
 * get_eeprom: Read data from the device EEPROM
 * set_eeprom: Write data to the device EEPROM
 * get_coalesce: Get interrupt coalescing parameters
 * set_coalesce: Set interrupt coalescing parameters
 * get_ringparam: Report ring sizes
 * set_ringparam: Set ring sizes
 * get_pauseparam: Report pause parameters
 * set_pauseparam: Set pause parameters
 * get_rx_csum: Report whether receive checksums are turned on or off
 * set_rx_csum: Turn receive checksum on or off
 * get_tx_csum: Report whether transmit checksums are turned on or off
 * set_tx_csum: Turn transmit checksums on or off
 * get_sg: Report whether scatter-gather is enabled
 * set_sg: Turn scatter-gather on or off
 * get_tso: Report whether TCP segmentation offload is enabled
 * set_tso: Turn TCP segmentation offload on or off
 * get_ufo: Report whether UDP fragmentation offload is enabled
 * set_ufo: Turn UDP fragmentation offload on or off
 * self_test: Run specified self-tests
 * get_strings: Return a set of strings that describe the requested objects 
 * phys_id: Identify the device
 * get_stats: Return statistics about the device
 * get_flags: get 32-bit flags bitmap
 * set_flags: set 32-bit flags bitmap
 * 
 * Description:
 *
 * get_settings:
 *	@get_settings is passed an &ethtool_cmd to fill in.  It returns
 *	an negative errno or zero.
 *
 * set_settings:
 *	@set_settings is passed an &ethtool_cmd and should attempt to set
 *	all the settings this device supports.  It may return an error value
 *	if something goes wrong (otherwise 0).
 *
 * get_eeprom:
int ethtool_op_get_ts_info(struct net_device *dev, struct ethtool_ts_info *eti);

/**
 * ethtool_rxfh_indir_default - get default value for RX flow hash indirection
 * @index: Index in RX flow hash indirection table
 * @n_rx_rings: Number of RX rings to use
 *
 * This function provides the default policy for RX flow hash indirection.
 */
static inline u32 ethtool_rxfh_indir_default(u32 index, u32 n_rx_rings)
{
	return index % n_rx_rings;
}

/* number of link mode bits/ulongs handled internally by kernel */
#define __ETHTOOL_LINK_MODE_MASK_NBITS			\
	(__ETHTOOL_LINK_MODE_LAST + 1)

/* declare a link mode bitmap */
#define __ETHTOOL_DECLARE_LINK_MODE_MASK(name)		\
	DECLARE_BITMAP(name, __ETHTOOL_LINK_MODE_MASK_NBITS)

/* drivers must ignore base.cmd and base.link_mode_masks_nwords
 * fields, but they are allowed to overwrite them (will be ignored).
 */
struct ethtool_link_ksettings {
	struct ethtool_link_settings base;
	struct {
		__ETHTOOL_DECLARE_LINK_MODE_MASK(supported);
		__ETHTOOL_DECLARE_LINK_MODE_MASK(advertising);
		__ETHTOOL_DECLARE_LINK_MODE_MASK(lp_advertising);
	} link_modes;
};

/**
 * ethtool_link_ksettings_zero_link_mode - clear link_ksettings link mode mask
 *   @ptr : pointer to struct ethtool_link_ksettings
 *   @name : one of supported/advertising/lp_advertising
 */
#define ethtool_link_ksettings_zero_link_mode(ptr, name)		\
	bitmap_zero((ptr)->link_modes.name, __ETHTOOL_LINK_MODE_MASK_NBITS)

/**
 * ethtool_link_ksettings_add_link_mode - set bit in link_ksettings
 * link mode mask
 *   @ptr : pointer to struct ethtool_link_ksettings
 *   @name : one of supported/advertising/lp_advertising
 *   @mode : one of the ETHTOOL_LINK_MODE_*_BIT
 * (not atomic, no bound checking)
 */
#define ethtool_link_ksettings_add_link_mode(ptr, name, mode)		\
	__set_bit(ETHTOOL_LINK_MODE_ ## mode ## _BIT, (ptr)->link_modes.name)

/**
 * ethtool_link_ksettings_del_link_mode - clear bit in link_ksettings
 * link mode mask
 *   @ptr : pointer to struct ethtool_link_ksettings
 *   @name : one of supported/advertising/lp_advertising
 *   @mode : one of the ETHTOOL_LINK_MODE_*_BIT
 * (not atomic, no bound checking)
 */
#define ethtool_link_ksettings_del_link_mode(ptr, name, mode)		\
	__clear_bit(ETHTOOL_LINK_MODE_ ## mode ## _BIT, (ptr)->link_modes.name)

/**
 * ethtool_link_ksettings_test_link_mode - test bit in ksettings link mode mask
 *   @ptr : pointer to struct ethtool_link_ksettings
 *   @name : one of supported/advertising/lp_advertising
 *   @mode : one of the ETHTOOL_LINK_MODE_*_BIT
 * (not atomic, no bound checking)
 *
 * Returns true/false.
 */
#define ethtool_link_ksettings_test_link_mode(ptr, name, mode)		\
	test_bit(ETHTOOL_LINK_MODE_ ## mode ## _BIT, (ptr)->link_modes.name)

extern int
__ethtool_get_link_ksettings(struct net_device *dev,
			     struct ethtool_link_ksettings *link_ksettings);

void ethtool_convert_legacy_u32_to_link_mode(unsigned long *dst,
					     u32 legacy_u32);

/* return false if src had higher bits set. lower bits always updated. */
bool ethtool_convert_link_mode_to_legacy_u32(u32 *legacy_u32,
				     const unsigned long *src);

/**
 * struct ethtool_ops - optional netdev operations
 * @get_settings: DEPRECATED, use %get_link_ksettings/%set_link_ksettings
 *	API. Get various device settings including Ethernet link
 *	settings. The @cmd parameter is expected to have been cleared
 *	before get_settings is called. Returns a negative error code
 *	or zero.
 * @set_settings: DEPRECATED, use %get_link_ksettings/%set_link_ksettings
 *	API. Set various device settings including Ethernet link
 *	settings.  Returns a negative error code or zero.
 * @get_drvinfo: Report driver/device information.  Should only set the
 *	@driver, @version, @fw_version and @bus_info fields.  If not
 *	implemented, the @driver and @bus_info fields will be filled in
 *	according to the netdev's parent device.
 * @get_regs_len: Get buffer length required for @get_regs
 * @get_regs: Get device registers
 * @get_wol: Report whether Wake-on-Lan is enabled
 * @set_wol: Turn Wake-on-Lan on or off.  Returns a negative error code
 *	or zero.
 * @get_msglevel: Report driver message level.  This should be the value
 *	of the @msg_enable field used by netif logging functions.
 * @set_msglevel: Set driver message level
 * @nway_reset: Restart autonegotiation.  Returns a negative error code
 *	or zero.
 * @get_link: Report whether physical link is up.  Will only be called if
 *	the netdev is up.  Should usually be set to ethtool_op_get_link(),
 *	which uses netif_carrier_ok().
 * @get_eeprom: Read data from the device EEPROM.
 *	Should fill in the magic field.  Don't need to check len for zero
 *	or wraparound.  Fill in the data argument with the eeprom values
 *	from offset to offset + len.  Update len to the amount read.
 *	Returns an error or zero.
 *
 * set_eeprom:
 *	Should validate the magic field.  Don't need to check len for zero
 *	or wraparound.  Update len to the amount written.  Returns an error
 *	or zero.
 * @set_eeprom: Write data to the device EEPROM.
 *	Should validate the magic field.  Don't need to check len for zero
 *	or wraparound.  Update len to the amount written.  Returns an error
 *	or zero.
 * @get_coalesce: Get interrupt coalescing parameters.  Returns a negative
 *	error code or zero.
 * @set_coalesce: Set interrupt coalescing parameters.  Returns a negative
 *	error code or zero.
 * @get_ringparam: Report ring sizes
 * @set_ringparam: Set ring sizes.  Returns a negative error code or zero.
 * @get_pauseparam: Report pause parameters
 * @set_pauseparam: Set pause parameters.  Returns a negative error code
 *	or zero.
 * @self_test: Run specified self-tests
 * @get_strings: Return a set of strings that describe the requested objects
 * @set_phys_id: Identify the physical devices, e.g. by flashing an LED
 *	attached to it.  The implementation may update the indicator
 *	asynchronously or synchronously, but in either case it must return
 *	quickly.  It is initially called with the argument %ETHTOOL_ID_ACTIVE,
 *	and must either activate asynchronous updates and return zero, return
 *	a negative error or return a positive frequency for synchronous
 *	indication (e.g. 1 for one on/off cycle per second).  If it returns
 *	a frequency then it will be called again at intervals with the
 *	argument %ETHTOOL_ID_ON or %ETHTOOL_ID_OFF and should set the state of
 *	the indicator accordingly.  Finally, it is called with the argument
 *	%ETHTOOL_ID_INACTIVE and must deactivate the indicator.  Returns a
 *	negative error code or zero.
 * @get_ethtool_stats: Return extended statistics about the device.
 *	This is only useful if the device maintains statistics not
 *	included in &struct rtnl_link_stats64.
 * @begin: Function to be called before any other operation.  Returns a
 *	negative error code or zero.
 * @complete: Function to be called after any other operation except
 *	@begin.  Will be called even if the other operation failed.
 * @get_priv_flags: Report driver-specific feature flags.
 * @set_priv_flags: Set driver-specific feature flags.  Returns a negative
 *	error code or zero.
 * @get_sset_count: Get number of strings that @get_strings will write.
 * @get_rxnfc: Get RX flow classification rules.  Returns a negative
 *	error code or zero.
 * @set_rxnfc: Set RX flow classification rules.  Returns a negative
 *	error code or zero.
 * @flash_device: Write a firmware image to device's flash memory.
 *	Returns a negative error code or zero.
 * @reset: Reset (part of) the device, as specified by a bitmask of
 *	flags from &enum ethtool_reset_flags.  Returns a negative
 *	error code or zero.
 * @get_rxfh_key_size: Get the size of the RX flow hash key.
 *	Returns zero if not supported for this specific device.
 * @get_rxfh_indir_size: Get the size of the RX flow hash indirection table.
 *	Returns zero if not supported for this specific device.
 * @get_rxfh: Get the contents of the RX flow hash indirection table, hash key
 *	and/or hash function.
 *	Returns a negative error code or zero.
 * @set_rxfh: Set the contents of the RX flow hash indirection table, hash
 *	key, and/or hash function.  Arguments which are set to %NULL or zero
 *	will remain unchanged.
 *	Returns a negative error code or zero. An error code must be returned
 *	if at least one unsupported change was requested.
 * @get_channels: Get number of channels.
 * @set_channels: Set number of channels.  Returns a negative error code or
 *	zero.
 * @get_dump_flag: Get dump flag indicating current dump length, version,
 * 		   and flag of the device.
 * @get_dump_data: Get dump data.
 * @set_dump: Set dump specific flags to the device.
 * @get_ts_info: Get the time stamping and PTP hardware clock capabilities.
 *	Drivers supporting transmit time stamps in software should set this to
 *	ethtool_op_get_ts_info().
 * @get_module_info: Get the size and type of the eeprom contained within
 *	a plug-in module.
 * @get_module_eeprom: Get the eeprom information from the plug-in module
 * @get_eee: Get Energy-Efficient (EEE) supported and status.
 * @set_eee: Set EEE status (enable/disable) as well as LPI timers.
 * @get_per_queue_coalesce: Get interrupt coalescing parameters per queue.
 *	It must check that the given queue number is valid. If neither a RX nor
 *	a TX queue has this number, return -EINVAL. If only a RX queue or a TX
 *	queue has this number, set the inapplicable fields to ~0 and return 0.
 *	Returns a negative error code or zero.
 * @set_per_queue_coalesce: Set interrupt coalescing parameters per queue.
 *	It must check that the given queue number is valid. If neither a RX nor
 *	a TX queue has this number, return -EINVAL. If only a RX queue or a TX
 *	queue has this number, ignore the inapplicable fields.
 *	Returns a negative error code or zero.
 * @get_link_ksettings: When defined, takes precedence over the
 *	%get_settings method. Get various device settings
 *	including Ethernet link settings. The %cmd and
 *	%link_mode_masks_nwords fields should be ignored (use
 *	%__ETHTOOL_LINK_MODE_MASK_NBITS instead of the latter), any
 *	change to them will be overwritten by kernel. Returns a
 *	negative error code or zero.
 * @set_link_ksettings: When defined, takes precedence over the
 *	%set_settings method. Set various device settings including
 *	Ethernet link settings. The %cmd and %link_mode_masks_nwords
 *	fields should be ignored (use %__ETHTOOL_LINK_MODE_MASK_NBITS
 *	instead of the latter), any change to them will be overwritten
 *	by kernel. Returns a negative error code or zero.
 *
 * All operations are optional (i.e. the function pointer may be set
 * to %NULL) and callers must take this into account.  Callers must
 * hold the RTNL lock.
 *
 * See the structures used by these operations for further documentation.
 * Note that for all operations using a structure ending with a zero-
 * length array, the array is allocated separately in the kernel and
 * is passed to the driver as an additional parameter.
 *
 * See &struct net_device and &struct net_device_ops for documentation
 * of the generic netdev features interface.
 */
struct ethtool_ops {
	int	(*get_settings)(struct net_device *, struct ethtool_cmd *);
	int	(*set_settings)(struct net_device *, struct ethtool_cmd *);
	void	(*get_drvinfo)(struct net_device *, struct ethtool_drvinfo *);
	int	(*get_regs_len)(struct net_device *);
	void	(*get_regs)(struct net_device *, struct ethtool_regs *, void *);
	void	(*get_wol)(struct net_device *, struct ethtool_wolinfo *);
	int	(*set_wol)(struct net_device *, struct ethtool_wolinfo *);
	u32	(*get_msglevel)(struct net_device *);
	void	(*set_msglevel)(struct net_device *, u32);
	int	(*nway_reset)(struct net_device *);
	u32	(*get_link)(struct net_device *);
	int	(*get_eeprom_len)(struct net_device *);
	int	(*get_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int	(*set_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int	(*get_coalesce)(struct net_device *, struct ethtool_coalesce *);
	int	(*set_coalesce)(struct net_device *, struct ethtool_coalesce *);
	void	(*get_ringparam)(struct net_device *, struct ethtool_ringparam *);
	int	(*set_ringparam)(struct net_device *, struct ethtool_ringparam *);
	void	(*get_pauseparam)(struct net_device *, struct ethtool_pauseparam*);
	int	(*set_pauseparam)(struct net_device *, struct ethtool_pauseparam*);
	u32	(*get_rx_csum)(struct net_device *);
	int	(*set_rx_csum)(struct net_device *, u32);
	u32	(*get_tx_csum)(struct net_device *);
	int	(*set_tx_csum)(struct net_device *, u32);
	u32	(*get_sg)(struct net_device *);
	int	(*set_sg)(struct net_device *, u32);
	u32	(*get_tso)(struct net_device *);
	int	(*set_tso)(struct net_device *, u32);
	void	(*self_test)(struct net_device *, struct ethtool_test *, u64 *);
	void	(*get_strings)(struct net_device *, u32 stringset, u8 *);
	int	(*phys_id)(struct net_device *, u32);
	void	(*get_ethtool_stats)(struct net_device *, struct ethtool_stats *, u64 *);
	int	(*begin)(struct net_device *);
	void	(*complete)(struct net_device *);
	u32     (*get_ufo)(struct net_device *);
	int     (*set_ufo)(struct net_device *, u32);
	u32     (*get_flags)(struct net_device *);
	int     (*set_flags)(struct net_device *, u32);
	u32     (*get_priv_flags)(struct net_device *);
	int     (*set_priv_flags)(struct net_device *, u32);
	int	(*get_sset_count)(struct net_device *, int);

	/* the following hooks are obsolete */
	int	(*self_test_count)(struct net_device *);/* use get_sset_count */
	int	(*get_stats_count)(struct net_device *);/* use get_sset_count */
	int	(*get_rxhash)(struct net_device *, struct ethtool_rxnfc *);
	int	(*set_rxhash)(struct net_device *, struct ethtool_rxnfc *);
};
#endif /* __KERNEL__ */

/* CMDs currently supported */
#define ETHTOOL_GSET		0x00000001 /* Get settings. */
#define ETHTOOL_SSET		0x00000002 /* Set settings. */
#define ETHTOOL_GDRVINFO	0x00000003 /* Get driver info. */
#define ETHTOOL_GREGS		0x00000004 /* Get NIC registers. */
#define ETHTOOL_GWOL		0x00000005 /* Get wake-on-lan options. */
#define ETHTOOL_SWOL		0x00000006 /* Set wake-on-lan options. */
#define ETHTOOL_GMSGLVL		0x00000007 /* Get driver message level */
#define ETHTOOL_SMSGLVL		0x00000008 /* Set driver msg level. */
#define ETHTOOL_NWAY_RST	0x00000009 /* Restart autonegotiation. */
#define ETHTOOL_GLINK		0x0000000a /* Get link status (ethtool_value) */
#define ETHTOOL_GEEPROM		0x0000000b /* Get EEPROM data */
#define ETHTOOL_SEEPROM		0x0000000c /* Set EEPROM data. */
#define ETHTOOL_GCOALESCE	0x0000000e /* Get coalesce config */
#define ETHTOOL_SCOALESCE	0x0000000f /* Set coalesce config. */
#define ETHTOOL_GRINGPARAM	0x00000010 /* Get ring parameters */
#define ETHTOOL_SRINGPARAM	0x00000011 /* Set ring parameters. */
#define ETHTOOL_GPAUSEPARAM	0x00000012 /* Get pause parameters */
#define ETHTOOL_SPAUSEPARAM	0x00000013 /* Set pause parameters. */
#define ETHTOOL_GRXCSUM		0x00000014 /* Get RX hw csum enable (ethtool_value) */
#define ETHTOOL_SRXCSUM		0x00000015 /* Set RX hw csum enable (ethtool_value) */
#define ETHTOOL_GTXCSUM		0x00000016 /* Get TX hw csum enable (ethtool_value) */
#define ETHTOOL_STXCSUM		0x00000017 /* Set TX hw csum enable (ethtool_value) */
#define ETHTOOL_GSG		0x00000018 /* Get scatter-gather enable
					    * (ethtool_value) */
#define ETHTOOL_SSG		0x00000019 /* Set scatter-gather enable
					    * (ethtool_value). */
#define ETHTOOL_TEST		0x0000001a /* execute NIC self-test. */
#define ETHTOOL_GSTRINGS	0x0000001b /* get specified string set */
#define ETHTOOL_PHYS_ID		0x0000001c /* identify the NIC */
#define ETHTOOL_GSTATS		0x0000001d /* get NIC-specific statistics */
#define ETHTOOL_GTSO		0x0000001e /* Get TSO enable (ethtool_value) */
#define ETHTOOL_STSO		0x0000001f /* Set TSO enable (ethtool_value) */
#define ETHTOOL_GPERMADDR	0x00000020 /* Get permanent hardware address */
#define ETHTOOL_GUFO		0x00000021 /* Get UFO enable (ethtool_value) */
#define ETHTOOL_SUFO		0x00000022 /* Set UFO enable (ethtool_value) */
#define ETHTOOL_GGSO		0x00000023 /* Get GSO enable (ethtool_value) */
#define ETHTOOL_SGSO		0x00000024 /* Set GSO enable (ethtool_value) */
#define ETHTOOL_GFLAGS		0x00000025 /* Get flags bitmap(ethtool_value) */
#define ETHTOOL_SFLAGS		0x00000026 /* Set flags bitmap(ethtool_value) */
#define ETHTOOL_GPFLAGS		0x00000027 /* Get driver-private flags bitmap */
#define ETHTOOL_SPFLAGS		0x00000028 /* Set driver-private flags bitmap */

#define	ETHTOOL_GRXFH		0x00000029 /* Get RX flow hash configuration */
#define	ETHTOOL_SRXFH		0x0000002a /* Set RX flow hash configuration */

/* compatibility with older code */
#define SPARC_ETH_GSET		ETHTOOL_GSET
#define SPARC_ETH_SSET		ETHTOOL_SSET

/* Indicates what features are supported by the interface. */
#define SUPPORTED_10baseT_Half		(1 << 0)
#define SUPPORTED_10baseT_Full		(1 << 1)
#define SUPPORTED_100baseT_Half		(1 << 2)
#define SUPPORTED_100baseT_Full		(1 << 3)
#define SUPPORTED_1000baseT_Half	(1 << 4)
#define SUPPORTED_1000baseT_Full	(1 << 5)
#define SUPPORTED_Autoneg		(1 << 6)
#define SUPPORTED_TP			(1 << 7)
#define SUPPORTED_AUI			(1 << 8)
#define SUPPORTED_MII			(1 << 9)
#define SUPPORTED_FIBRE			(1 << 10)
#define SUPPORTED_BNC			(1 << 11)
#define SUPPORTED_10000baseT_Full	(1 << 12)
#define SUPPORTED_Pause			(1 << 13)
#define SUPPORTED_Asym_Pause		(1 << 14)
#define SUPPORTED_2500baseX_Full	(1 << 15)

/* Indicates what features are advertised by the interface. */
#define ADVERTISED_10baseT_Half		(1 << 0)
#define ADVERTISED_10baseT_Full		(1 << 1)
#define ADVERTISED_100baseT_Half	(1 << 2)
#define ADVERTISED_100baseT_Full	(1 << 3)
#define ADVERTISED_1000baseT_Half	(1 << 4)
#define ADVERTISED_1000baseT_Full	(1 << 5)
#define ADVERTISED_Autoneg		(1 << 6)
#define ADVERTISED_TP			(1 << 7)
#define ADVERTISED_AUI			(1 << 8)
#define ADVERTISED_MII			(1 << 9)
#define ADVERTISED_FIBRE		(1 << 10)
#define ADVERTISED_BNC			(1 << 11)
#define ADVERTISED_10000baseT_Full	(1 << 12)
#define ADVERTISED_Pause		(1 << 13)
#define ADVERTISED_Asym_Pause		(1 << 14)
#define ADVERTISED_2500baseX_Full	(1 << 15)

/* The following are all involved in forcing a particular link
 * mode for the device for setting things.  When getting the
 * devices settings, these indicate the current mode and whether
 * it was foced up into this mode or autonegotiated.
 */

/* The forced speed, 10Mb, 100Mb, gigabit, 2.5Gb, 10GbE. */
#define SPEED_10		10
#define SPEED_100		100
#define SPEED_1000		1000
#define SPEED_2500		2500
#define SPEED_10000		10000

/* Duplex, half or full. */
#define DUPLEX_HALF		0x00
#define DUPLEX_FULL		0x01

/* Which connector port. */
#define PORT_TP			0x00
#define PORT_AUI		0x01
#define PORT_MII		0x02
#define PORT_FIBRE		0x03
#define PORT_BNC		0x04

/* Which transceiver to use. */
#define XCVR_INTERNAL		0x00
#define XCVR_EXTERNAL		0x01
#define XCVR_DUMMY1		0x02
#define XCVR_DUMMY2		0x03
#define XCVR_DUMMY3		0x04

/* Enable or disable autonegotiation.  If this is set to enable,
 * the forced link modes above are completely ignored.
 */
#define AUTONEG_DISABLE		0x00
#define AUTONEG_ENABLE		0x01

/* Wake-On-Lan options. */
#define WAKE_PHY		(1 << 0)
#define WAKE_UCAST		(1 << 1)
#define WAKE_MCAST		(1 << 2)
#define WAKE_BCAST		(1 << 3)
#define WAKE_ARP		(1 << 4)
#define WAKE_MAGIC		(1 << 5)
#define WAKE_MAGICSECURE	(1 << 6) /* only meaningful if WAKE_MAGIC */

/* L3-L4 network traffic flow types */
#define	TCP_V4_FLOW	0x01
#define	UDP_V4_FLOW	0x02
#define	SCTP_V4_FLOW	0x03
#define	AH_ESP_V4_FLOW	0x04
#define	TCP_V6_FLOW	0x05
#define	UDP_V6_FLOW	0x06
#define	SCTP_V6_FLOW	0x07
#define	AH_ESP_V6_FLOW	0x08

/* L3-L4 network traffic flow hash options */
#define	RXH_DEV_PORT	(1 << 0)
#define	RXH_L2DA	(1 << 1)
#define	RXH_VLAN	(1 << 2)
#define	RXH_L3_PROTO	(1 << 3)
#define	RXH_IP_SRC	(1 << 4)
#define	RXH_IP_DST	(1 << 5)
#define	RXH_L4_B_0_1	(1 << 6) /* src port in case of TCP/UDP/SCTP */
#define	RXH_L4_B_2_3	(1 << 7) /* dst port in case of TCP/UDP/SCTP */
#define	RXH_DISCARD	(1 << 31)


	int	(*get_eeprom)(struct net_device *,
			      struct ethtool_eeprom *, u8 *);
	int	(*set_eeprom)(struct net_device *,
			      struct ethtool_eeprom *, u8 *);
	int	(*get_coalesce)(struct net_device *, struct ethtool_coalesce *);
	int	(*set_coalesce)(struct net_device *, struct ethtool_coalesce *);
	void	(*get_ringparam)(struct net_device *,
				 struct ethtool_ringparam *);
	int	(*set_ringparam)(struct net_device *,
				 struct ethtool_ringparam *);
	void	(*get_pauseparam)(struct net_device *,
				  struct ethtool_pauseparam*);
	int	(*set_pauseparam)(struct net_device *,
				  struct ethtool_pauseparam*);
	void	(*self_test)(struct net_device *, struct ethtool_test *, u64 *);
	void	(*get_strings)(struct net_device *, u32 stringset, u8 *);
	int	(*set_phys_id)(struct net_device *, enum ethtool_phys_id_state);
	void	(*get_ethtool_stats)(struct net_device *,
				     struct ethtool_stats *, u64 *);
	int	(*begin)(struct net_device *);
	void	(*complete)(struct net_device *);
	u32	(*get_priv_flags)(struct net_device *);
	int	(*set_priv_flags)(struct net_device *, u32);
	int	(*get_sset_count)(struct net_device *, int);
	int	(*get_rxnfc)(struct net_device *,
			     struct ethtool_rxnfc *, u32 *rule_locs);
	int	(*set_rxnfc)(struct net_device *, struct ethtool_rxnfc *);
	int	(*flash_device)(struct net_device *, struct ethtool_flash *);
	int	(*reset)(struct net_device *, u32 *);
	u32	(*get_rxfh_key_size)(struct net_device *);
	u32	(*get_rxfh_indir_size)(struct net_device *);
	int	(*get_rxfh)(struct net_device *, u32 *indir, u8 *key,
			    u8 *hfunc);
	int	(*set_rxfh)(struct net_device *, const u32 *indir,
			    const u8 *key, const u8 hfunc);
	void	(*get_channels)(struct net_device *, struct ethtool_channels *);
	int	(*set_channels)(struct net_device *, struct ethtool_channels *);
	int	(*get_dump_flag)(struct net_device *, struct ethtool_dump *);
	int	(*get_dump_data)(struct net_device *,
				 struct ethtool_dump *, void *);
	int	(*set_dump)(struct net_device *, struct ethtool_dump *);
	int	(*get_ts_info)(struct net_device *, struct ethtool_ts_info *);
	int     (*get_module_info)(struct net_device *,
				   struct ethtool_modinfo *);
	int     (*get_module_eeprom)(struct net_device *,
				     struct ethtool_eeprom *, u8 *);
	int	(*get_eee)(struct net_device *, struct ethtool_eee *);
	int	(*set_eee)(struct net_device *, struct ethtool_eee *);
	int	(*get_tunable)(struct net_device *,
			       const struct ethtool_tunable *, void *);
	int	(*set_tunable)(struct net_device *,
			       const struct ethtool_tunable *, const void *);
	int	(*get_per_queue_coalesce)(struct net_device *, u32,
					  struct ethtool_coalesce *);
	int	(*set_per_queue_coalesce)(struct net_device *, u32,
					  struct ethtool_coalesce *);
	int	(*get_link_ksettings)(struct net_device *,
				      struct ethtool_link_ksettings *);
	int	(*set_link_ksettings)(struct net_device *,
				      const struct ethtool_link_ksettings *);
	int	(*get_fecparam)(struct net_device *,
				      struct ethtool_fecparam *);
	int	(*set_fecparam)(struct net_device *,
				      struct ethtool_fecparam *);
};
#endif /* _LINUX_ETHTOOL_H */
