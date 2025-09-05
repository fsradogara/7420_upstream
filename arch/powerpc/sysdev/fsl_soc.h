/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PPC_FSL_SOC_H
#define __PPC_FSL_SOC_H
#ifdef __KERNEL__

#include <asm/mmu.h>

extern phys_addr_t get_immrbase(void);
extern u32 get_brgfreq(void);
extern u32 get_baudrate(void);
struct spi_device;

extern phys_addr_t get_immrbase(void);
#if defined(CONFIG_CPM) || defined(CONFIG_QUICC_ENGINE)
extern u32 get_brgfreq(void);
extern u32 get_baudrate(void);
#else
static inline u32 get_brgfreq(void) { return -1; }
static inline u32 get_baudrate(void) { return -1; }
#endif
extern u32 fsl_get_sys_freq(void);

struct spi_board_info;
struct device_node;

extern int fsl_spi_init(struct spi_board_info *board_infos,
			unsigned int num_board_infos,
			void (*activate_cs)(u8 cs, u8 polarity),
			void (*deactivate_cs)(u8 cs, u8 polarity));

extern void fsl_rstcr_restart(char *cmd);

#if defined(CONFIG_FB_FSL_DIU) || defined(CONFIG_FB_FSL_DIU_MODULE)
#include <linux/bootmem.h>
#include <asm/rheap.h>
struct platform_diu_data_ops {
	rh_block_t diu_rh_block[16];
	rh_info_t diu_rh_info;
	unsigned long diu_size;
	void *diu_mem;

	unsigned int (*get_pixel_format) (unsigned int bits_per_pixel,
		int monitor_port);
	void (*set_gamma_table) (int monitor_port, char *gamma_table_base);
	void (*set_monitor_port) (int monitor_port);
	void (*set_pixel_clock) (unsigned int pixclock);
	ssize_t (*show_monitor_port) (int monitor_port, char *buf);
	int (*set_sysfs_monitor_port) (int val);
};

extern struct platform_diu_data_ops diu_ops;
int __init preallocate_diu_videomemory(void);
#endif
extern void fsl_rstcr_restart(char *cmd);

/* The different ports that the DIU can be connected to */
enum fsl_diu_monitor_port {
	FSL_DIU_PORT_DVI,	/* DVI */
	FSL_DIU_PORT_LVDS,	/* Single-link LVDS */
	FSL_DIU_PORT_DLVDS	/* Dual-link LVDS */
};

struct platform_diu_data_ops {
	u32 (*get_pixel_format)(enum fsl_diu_monitor_port port,
		unsigned int bpp);
	void (*set_gamma_table)(enum fsl_diu_monitor_port port,
		char *gamma_table_base);
	void (*set_monitor_port)(enum fsl_diu_monitor_port port);
	void (*set_pixel_clock)(unsigned int pixclock);
	enum fsl_diu_monitor_port (*valid_monitor_port)
		(enum fsl_diu_monitor_port port);
	void (*release_bootmem)(void);
};

extern struct platform_diu_data_ops diu_ops;

void __noreturn fsl_hv_restart(char *cmd);
void __noreturn fsl_hv_halt(void);

#endif
#endif
