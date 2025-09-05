/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_CPU_H

#define ARCH_X86_CPU_H

struct cpu_model_info {
	int vendor;
	int family;
	char *model_names[16];
};

/* attempt to consolidate cpu attributes */
struct cpu_dev {
	char	* c_vendor;

	/* some have two possibilities for cpuid string */
	char	* c_ident[2];	

	struct		cpu_model_info c_models[4];

	void            (*c_early_init)(struct cpuinfo_x86 *c);
	void		(*c_init)(struct cpuinfo_x86 * c);
	void		(*c_identify)(struct cpuinfo_x86 * c);
	unsigned int	(*c_size_cache)(struct cpuinfo_x86 * c, unsigned int size);
};

extern struct cpu_dev * cpu_devs [X86_VENDOR_NUM];

struct cpu_vendor_dev {
	int vendor;
	struct cpu_dev *cpu_dev;
};

#define cpu_vendor_dev_register(cpu_vendor_id, cpu_dev) \
	static struct cpu_vendor_dev __cpu_vendor_dev_##cpu_vendor_id __used \
	__attribute__((__section__(".x86cpuvendor.init"))) = \
	{ cpu_vendor_id, cpu_dev }

extern struct cpu_vendor_dev __x86cpuvendor_start[], __x86cpuvendor_end[];

extern int get_model_name(struct cpuinfo_x86 *c);
extern void display_cacheinfo(struct cpuinfo_x86 *c);

#endif
#define ARCH_X86_CPU_H

/* attempt to consolidate cpu attributes */
struct cpu_dev {
	const char	*c_vendor;

	/* some have two possibilities for cpuid string */
	const char	*c_ident[2];

	void            (*c_early_init)(struct cpuinfo_x86 *);
	void		(*c_bsp_init)(struct cpuinfo_x86 *);
	void		(*c_init)(struct cpuinfo_x86 *);
	void		(*c_identify)(struct cpuinfo_x86 *);
	void		(*c_detect_tlb)(struct cpuinfo_x86 *);
	void		(*c_bsp_resume)(struct cpuinfo_x86 *);
	int		c_x86_vendor;
#ifdef CONFIG_X86_32
	/* Optional vendor specific routine to obtain the cache size. */
	unsigned int	(*legacy_cache_size)(struct cpuinfo_x86 *,
					     unsigned int);

	/* Family/stepping-based lookup table for model names. */
	struct legacy_cpu_model_info {
		int		family;
		const char	*model_names[16];
	}		legacy_models[5];
#endif
};

struct _tlb_table {
	unsigned char descriptor;
	char tlb_type;
	unsigned int entries;
	/* unsigned int ways; */
	char info[128];
};

#define cpu_dev_register(cpu_devX) \
	static const struct cpu_dev *const __cpu_dev_##cpu_devX __used \
	__attribute__((__section__(".x86_cpu_dev.init"))) = \
	&cpu_devX;

extern const struct cpu_dev *const __x86_cpu_dev_start[],
			    *const __x86_cpu_dev_end[];

extern void get_cpu_cap(struct cpuinfo_x86 *c);
extern void cpu_detect_cache_sizes(struct cpuinfo_x86 *c);
extern int detect_extended_topology_early(struct cpuinfo_x86 *c);
extern int detect_ht_early(struct cpuinfo_x86 *c);

unsigned int aperfmperf_get_khz(int cpu);

extern void x86_spec_ctrl_setup_ap(void);

#endif /* ARCH_X86_CPU_H */
