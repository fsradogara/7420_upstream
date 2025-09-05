/*
 * Copyright (c) 2007 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/kernel.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>

#include "ipoib.h"

struct ipoib_stats {
	char stat_string[ETH_GSTRING_LEN];
	int stat_offset;
};

#define IPOIB_NETDEV_STAT(m) { \
		.stat_string = #m, \
		.stat_offset = offsetof(struct rtnl_link_stats64, m) }

static const struct ipoib_stats ipoib_gstrings_stats[] = {
	IPOIB_NETDEV_STAT(rx_packets),
	IPOIB_NETDEV_STAT(tx_packets),
	IPOIB_NETDEV_STAT(rx_bytes),
	IPOIB_NETDEV_STAT(tx_bytes),
	IPOIB_NETDEV_STAT(tx_errors),
	IPOIB_NETDEV_STAT(rx_dropped),
	IPOIB_NETDEV_STAT(tx_dropped),
	IPOIB_NETDEV_STAT(multicast),
};

#define IPOIB_GLOBAL_STATS_LEN	ARRAY_SIZE(ipoib_gstrings_stats)

static void ipoib_get_drvinfo(struct net_device *netdev,
			      struct ethtool_drvinfo *drvinfo)
{
	strncpy(drvinfo->driver, "ipoib", sizeof(drvinfo->driver) - 1);
	struct ipoib_dev_priv *priv = netdev_priv(netdev);
	struct ib_device_attr *attr;
	struct ipoib_dev_priv *priv = ipoib_priv(netdev);

	ib_get_device_fw_str(priv->ca, drvinfo->fw_version);

	strlcpy(drvinfo->bus_info, dev_name(priv->ca->dev.parent),
		sizeof(drvinfo->bus_info));

	strlcpy(drvinfo->version, ipoib_driver_version,
		sizeof(drvinfo->version));

	strlcpy(drvinfo->driver, "ib_ipoib", sizeof(drvinfo->driver));
}

static int ipoib_get_coalesce(struct net_device *dev,
			      struct ethtool_coalesce *coal)
{
	struct ipoib_dev_priv *priv = ipoib_priv(dev);

	coal->rx_coalesce_usecs = priv->ethtool.coalesce_usecs;
	coal->tx_coalesce_usecs = priv->ethtool.coalesce_usecs;
	coal->rx_max_coalesced_frames = priv->ethtool.max_coalesced_frames;
	coal->tx_max_coalesced_frames = priv->ethtool.max_coalesced_frames;
	coal->rx_max_coalesced_frames = priv->ethtool.max_coalesced_frames;

	return 0;
}

static int ipoib_set_coalesce(struct net_device *dev,
			      struct ethtool_coalesce *coal)
{
	struct ipoib_dev_priv *priv = ipoib_priv(dev);
	int ret;

	/*
	 * Since IPoIB uses a single CQ for both rx and tx, we assume
	 * that rx params dictate the configuration.  These values are
	 * saved in the private data and returned when ipoib_get_coalesce()
	 * is called.
	 * These values are saved in the private data and returned
	 * when ipoib_get_coalesce() is called
	 */
	if (coal->rx_coalesce_usecs       > 0xffff ||
	    coal->rx_max_coalesced_frames > 0xffff)
		return -EINVAL;

	ret = ib_modify_cq(priv->recv_cq, coal->rx_max_coalesced_frames,
			   coal->rx_coalesce_usecs);
	if (ret && ret != -ENOSYS) {
		ipoib_warn(priv, "failed modifying CQ (%d)\n", ret);
		return ret;
	}

	coal->tx_coalesce_usecs       = coal->rx_coalesce_usecs;
	coal->tx_max_coalesced_frames = coal->rx_max_coalesced_frames;
	priv->ethtool.coalesce_usecs       = coal->rx_coalesce_usecs;
	priv->ethtool.max_coalesced_frames = coal->rx_max_coalesced_frames;

	return 0;
}
static void ipoib_get_ethtool_stats(struct net_device *dev,
				    struct ethtool_stats __always_unused *stats,
				    u64 *data)
{
	int i;
	struct net_device_stats *net_stats = &dev->stats;
	u8 *p = (u8 *)net_stats;

	for (i = 0; i < IPOIB_GLOBAL_STATS_LEN; i++)
		data[i] = *(u64 *)(p + ipoib_gstrings_stats[i].stat_offset);

}
static void ipoib_get_strings(struct net_device __always_unused *dev,
			      u32 stringset, u8 *data)
{
	u8 *p = data;
	int i;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < IPOIB_GLOBAL_STATS_LEN; i++) {
			memcpy(p, ipoib_gstrings_stats[i].stat_string,
				ETH_GSTRING_LEN);
			p += ETH_GSTRING_LEN;
		}
		break;
	case ETH_SS_TEST:
	default:
		break;
	}
}
static int ipoib_get_sset_count(struct net_device __always_unused *dev,
				 int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return IPOIB_GLOBAL_STATS_LEN;
	case ETH_SS_TEST:
	default:
		break;
	}
	return -EOPNOTSUPP;
}

/* Return lane speed in unit of 1e6 bit/sec */
static inline int ib_speed_enum_to_int(int speed)
{
	switch (speed) {
	case IB_SPEED_SDR:
		return SPEED_2500;
	case IB_SPEED_DDR:
		return SPEED_5000;
	case IB_SPEED_QDR:
	case IB_SPEED_FDR10:
		return SPEED_10000;
	case IB_SPEED_FDR:
		return SPEED_14000;
	case IB_SPEED_EDR:
		return SPEED_25000;
	}

	return SPEED_UNKNOWN;
}

static int ipoib_get_link_ksettings(struct net_device *netdev,
				    struct ethtool_link_ksettings *cmd)
{
	struct ipoib_dev_priv *priv = ipoib_priv(netdev);
	struct ib_port_attr attr;
	int ret, speed, width;

	if (!netif_carrier_ok(netdev)) {
		cmd->base.speed = SPEED_UNKNOWN;
		cmd->base.duplex = DUPLEX_UNKNOWN;
		return 0;
	}

	ret = ib_query_port(priv->ca, priv->port, &attr);
	if (ret < 0)
		return -EINVAL;

	speed = ib_speed_enum_to_int(attr.active_speed);
	width = ib_width_enum_to_int(attr.active_width);

	if (speed < 0 || width < 0)
		return -EINVAL;

	/* Except the following are set, the other members of
	 * the struct ethtool_link_settings are initialized to
	 * zero in the function __ethtool_get_link_ksettings.
	 */
	cmd->base.speed		 = speed * width;
	cmd->base.duplex	 = DUPLEX_FULL;

	cmd->base.phy_address	 = 0xFF;

	cmd->base.autoneg	 = AUTONEG_ENABLE;
	cmd->base.port		 = PORT_OTHER;

	return 0;
}

static const char ipoib_stats_keys[][ETH_GSTRING_LEN] = {
	"LRO aggregated", "LRO flushed",
	"LRO avg aggr", "LRO no desc"
};

static void ipoib_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	switch (stringset) {
	case ETH_SS_STATS:
		memcpy(data, *ipoib_stats_keys,	sizeof(ipoib_stats_keys));
		break;
	}
}

static int ipoib_get_sset_count(struct net_device *dev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return ARRAY_SIZE(ipoib_stats_keys);
	default:
		return -EOPNOTSUPP;
	}
}

static void ipoib_get_ethtool_stats(struct net_device *dev,
				struct ethtool_stats *stats, uint64_t *data)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	int index = 0;

	/* Get LRO statistics */
	data[index++] = priv->lro.lro_mgr.stats.aggregated;
	data[index++] = priv->lro.lro_mgr.stats.flushed;
	if (priv->lro.lro_mgr.stats.flushed)
		data[index++] = priv->lro.lro_mgr.stats.aggregated /
				priv->lro.lro_mgr.stats.flushed;
	else
		data[index++] = 0;
	data[index++] = priv->lro.lro_mgr.stats.no_desc;
}

static const struct ethtool_ops ipoib_ethtool_ops = {
	.get_drvinfo		= ipoib_get_drvinfo,
	.get_tso		= ethtool_op_get_tso,
	.get_coalesce		= ipoib_get_coalesce,
	.set_coalesce		= ipoib_set_coalesce,
	.get_flags		= ethtool_op_get_flags,
	.set_flags		= ethtool_op_set_flags,
	.get_strings		= ipoib_get_strings,
	.get_sset_count		= ipoib_get_sset_count,
	.get_ethtool_stats	= ipoib_get_ethtool_stats,
static const struct ethtool_ops ipoib_ethtool_ops = {
	.get_link_ksettings	= ipoib_get_link_ksettings,
	.get_drvinfo		= ipoib_get_drvinfo,
	.get_coalesce		= ipoib_get_coalesce,
	.set_coalesce		= ipoib_set_coalesce,
	.get_strings		= ipoib_get_strings,
	.get_ethtool_stats	= ipoib_get_ethtool_stats,
	.get_sset_count		= ipoib_get_sset_count,
};

void ipoib_set_ethtool_ops(struct net_device *dev)
{
	SET_ETHTOOL_OPS(dev, &ipoib_ethtool_ops);
	dev->ethtool_ops = &ipoib_ethtool_ops;
}
