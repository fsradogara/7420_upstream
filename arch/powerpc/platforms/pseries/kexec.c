/*
 *  Copyright 2006 Michael Ellerman, IBM Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/interrupt.h>

#include <asm/machdep.h>
#include <asm/page.h>
#include <asm/firmware.h>
#include <asm/kexec.h>
#include <asm/mpic.h>
#include <asm/smp.h>

#include "pseries.h"
#include "xics.h"
#include "plpar_wrappers.h"
#include <asm/xics.h>
#include <asm/xive.h>
#include <asm/smp.h>
#include <asm/plpar_wrappers.h>

#include "pseries.h"

void pseries_kexec_cpu_down(int crash_shutdown, int secondary)
{
	/*
	 * Don't risk a hypervisor call if we're crashing
	 * XXX: Why? The hypervisor is not crashing. It might be better
	 * to at least attempt unregister to avoid the hypervisor stepping
	 * on our memory.
	 */
	if (firmware_has_feature(FW_FEATURE_SPLPAR) && !crash_shutdown) {
		unsigned long addr;

		addr = __pa(get_slb_shadow());
		if (unregister_slb_shadow(hard_smp_processor_id(), addr))
			printk("SLB shadow buffer deregistration of "
			       "cpu %u (hw_cpu_id %d) failed\n",
			       smp_processor_id(),
			       hard_smp_processor_id());

		addr = __pa(get_lppaca());
		if (unregister_vpa(hard_smp_processor_id(), addr)) {
			printk("VPA deregistration of cpu %u (hw_cpu_id %d) "
					"failed\n", smp_processor_id(),
					hard_smp_processor_id());
		int ret;
		int cpu = smp_processor_id();
		int hwcpu = hard_smp_processor_id();

		if (get_lppaca()->dtl_enable_mask) {
			ret = unregister_dtl(hwcpu);
			if (ret) {
				pr_err("WARNING: DTL deregistration for cpu "
				       "%d (hw %d) failed with %d\n",
				       cpu, hwcpu, ret);
			}
		}

		ret = unregister_slb_shadow(hwcpu);
		if (ret) {
			pr_err("WARNING: SLB shadow buffer deregistration "
			       "for cpu %d (hw %d) failed with %d\n",
			       cpu, hwcpu, ret);
		}

		ret = unregister_vpa(hwcpu);
		if (ret) {
			pr_err("WARNING: VPA deregistration for cpu %d "
			       "(hw %d) failed with %d\n", cpu, hwcpu, ret);
		}
	}

	if (xive_enabled()) {
		xive_teardown_cpu();

		if (!secondary)
			xive_shutdown();
	} else
		xics_kexec_teardown_cpu(secondary);
}

static int __init pseries_kexec_setup(void)
{
	ppc_md.machine_kexec = default_machine_kexec;
	ppc_md.machine_kexec_prepare = default_machine_kexec_prepare;
	ppc_md.machine_crash_shutdown = default_machine_crash_shutdown;

	return 0;
}
machine_device_initcall(pseries, pseries_kexec_setup);
