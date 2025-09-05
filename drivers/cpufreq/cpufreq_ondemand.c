/*
 *  drivers/cpufreq/cpufreq_ondemand.c
 *
 *  Copyright (C)  2001 Russell King
 *            (C)  2003 Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>.
 *                      Jun Nakajima <jun.nakajima@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/cpufreq.h>
#include <linux/cpu.h>
#include <linux/jiffies.h>
#include <linux/kernel_stat.h>
#include <linux/mutex.h>

/*
 * dbs is used in this file as a shortform for demandbased switching
 * It helps to keep variable names smaller, simpler
 */

#define DEF_FREQUENCY_UP_THRESHOLD		(80)
#define MIN_FREQUENCY_UP_THRESHOLD		(11)
#define MAX_FREQUENCY_UP_THRESHOLD		(100)

/*
 * The polling frequency of this governor depends on the capability of
 * the processor. Default polling frequency is 1000 times the transition
 * latency of the processor. The governor will work on any processor with
 * transition latency <= 10mS, using appropriate sampling
 * rate.
 * For CPUs with transition latency > 10mS (mostly drivers with CPUFREQ_ETERNAL)
 * this governor will not work.
 * All times here are in uS.
 */
static unsigned int def_sampling_rate;
#define MIN_SAMPLING_RATE_RATIO			(2)
/* for correct statistics, we need at least 10 ticks between each measure */
#define MIN_STAT_SAMPLING_RATE 			\
			(MIN_SAMPLING_RATE_RATIO * jiffies_to_usecs(10))
#define MIN_SAMPLING_RATE			\
			(def_sampling_rate / MIN_SAMPLING_RATE_RATIO)
#define MAX_SAMPLING_RATE			(500 * def_sampling_rate)
#define DEF_SAMPLING_RATE_LATENCY_MULTIPLIER	(1000)
#define TRANSITION_LATENCY_LIMIT		(10 * 1000 * 1000)

static void do_dbs_timer(struct work_struct *work);

/* Sampling types */
enum {DBS_NORMAL_SAMPLE, DBS_SUB_SAMPLE};

struct cpu_dbs_info_s {
	cputime64_t prev_cpu_idle;
	cputime64_t prev_cpu_wall;
	struct cpufreq_policy *cur_policy;
 	struct delayed_work work;
	struct cpufreq_frequency_table *freq_table;
	unsigned int freq_lo;
	unsigned int freq_lo_jiffies;
	unsigned int freq_hi_jiffies;
	int cpu;
	unsigned int enable:1,
	             sample_type:1;
};
static DEFINE_PER_CPU(struct cpu_dbs_info_s, cpu_dbs_info);

static unsigned int dbs_enable;	/* number of CPUs using this policy */

/*
 * DEADLOCK ALERT! There is a ordering requirement between cpu_hotplug
 * lock and dbs_mutex. cpu_hotplug lock should always be held before
 * dbs_mutex. If any function that can potentially take cpu_hotplug lock
 * (like __cpufreq_driver_target()) is being called with dbs_mutex taken, then
 * cpu_hotplug lock should be taken before that. Note that cpu_hotplug lock
 * is recursive for the same process. -Venki
 */
static DEFINE_MUTEX(dbs_mutex);

static struct workqueue_struct	*kondemand_wq;

static struct dbs_tuners {
	unsigned int sampling_rate;
	unsigned int up_threshold;
	unsigned int ignore_nice;
	unsigned int powersave_bias;
} dbs_tuners_ins = {
	.up_threshold = DEF_FREQUENCY_UP_THRESHOLD,
	.ignore_nice = 0,
	.powersave_bias = 0,
};

static inline cputime64_t get_cpu_idle_time(unsigned int cpu)
{
	cputime64_t idle_time;
	cputime64_t cur_jiffies;
	cputime64_t busy_time;

	cur_jiffies = jiffies64_to_cputime64(get_jiffies_64());
	busy_time = cputime64_add(kstat_cpu(cpu).cpustat.user,
			kstat_cpu(cpu).cpustat.system);

	busy_time = cputime64_add(busy_time, kstat_cpu(cpu).cpustat.irq);
	busy_time = cputime64_add(busy_time, kstat_cpu(cpu).cpustat.softirq);
	busy_time = cputime64_add(busy_time, kstat_cpu(cpu).cpustat.steal);

	if (!dbs_tuners_ins.ignore_nice) {
		busy_time = cputime64_add(busy_time,
				kstat_cpu(cpu).cpustat.nice);
	}

	idle_time = cputime64_sub(cur_jiffies, busy_time);
	return idle_time;
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cpu.h>
#include <linux/percpu-defs.h>
#include <linux/slab.h>
#include <linux/tick.h>
#include <linux/sched/cpufreq.h>

#include "cpufreq_ondemand.h"

/* On-demand governor macros */
#define DEF_FREQUENCY_UP_THRESHOLD		(80)
#define DEF_SAMPLING_DOWN_FACTOR		(1)
#define MAX_SAMPLING_DOWN_FACTOR		(100000)
#define MICRO_FREQUENCY_UP_THRESHOLD		(95)
#define MICRO_FREQUENCY_MIN_SAMPLE_RATE		(10000)
#define MIN_FREQUENCY_UP_THRESHOLD		(1)
#define MAX_FREQUENCY_UP_THRESHOLD		(100)

static struct od_ops od_ops;

static unsigned int default_powersave_bias;

/*
 * Not all CPUs want IO time to be accounted as busy; this depends on how
 * efficient idling at a higher frequency/voltage is.
 * Pavel Machek says this is not so for various generations of AMD and old
 * Intel systems.
 * Mike Chan (android.com) claims this is also not true for ARM.
 * Because of this, whitelist specific known (series) of CPUs by default, and
 * leave all others up to the user.
 */
static int should_io_be_busy(void)
{
#if defined(CONFIG_X86)
	/*
	 * For Intel, Core 2 (model 15) and later have an efficient idle.
	 */
	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL &&
			boot_cpu_data.x86 == 6 &&
			boot_cpu_data.x86_model >= 15)
		return 1;
#endif
	return 0;
}

/*
 * Find right freq to be set now with powersave_bias on.
 * Returns the freq_hi to be used right now and will set freq_hi_delay_us,
 * freq_lo, and freq_lo_delay_us in percpu area for averaging freqs.
 */
static unsigned int powersave_bias_target(struct cpufreq_policy *policy,
					  unsigned int freq_next,
					  unsigned int relation)
static unsigned int generic_powersave_bias_target(struct cpufreq_policy *policy,
		unsigned int freq_next, unsigned int relation)
{
	unsigned int freq_req, freq_reduc, freq_avg;
	unsigned int freq_hi, freq_lo;
	unsigned int index = 0;
	unsigned int jiffies_total, jiffies_hi, jiffies_lo;
	struct cpu_dbs_info_s *dbs_info = &per_cpu(cpu_dbs_info, policy->cpu);
	struct od_cpu_dbs_info_s *dbs_info = &per_cpu(od_cpu_dbs_info,
						   policy->cpu);
	struct dbs_data *dbs_data = policy->governor_data;
	unsigned int index;
	unsigned int delay_hi_us;
	struct policy_dbs_info *policy_dbs = policy->governor_data;
	struct od_policy_dbs_info *dbs_info = to_dbs_info(policy_dbs);
	struct dbs_data *dbs_data = policy_dbs->dbs_data;
	struct od_dbs_tuners *od_tuners = dbs_data->tuners;
	struct cpufreq_frequency_table *freq_table = policy->freq_table;

	if (!freq_table) {
		dbs_info->freq_lo = 0;
		dbs_info->freq_lo_delay_us = 0;
		return freq_next;
	}

	cpufreq_frequency_table_target(policy, dbs_info->freq_table, freq_next,
			relation, &index);
	freq_req = dbs_info->freq_table[index].frequency;
	freq_reduc = freq_req * dbs_tuners_ins.powersave_bias / 1000;
	index = cpufreq_frequency_table_target(policy, freq_next, relation);
	freq_req = freq_table[index].frequency;
	freq_reduc = freq_req * od_tuners->powersave_bias / 1000;
	freq_avg = freq_req - freq_reduc;

	/* Find freq bounds for freq_avg in freq_table */
	index = cpufreq_table_find_index_h(policy, freq_avg);
	freq_lo = freq_table[index].frequency;
	index = cpufreq_table_find_index_l(policy, freq_avg);
	freq_hi = freq_table[index].frequency;

	/* Find out how long we have to be in hi and lo freqs */
	if (freq_hi == freq_lo) {
		dbs_info->freq_lo = 0;
		dbs_info->freq_lo_delay_us = 0;
		return freq_lo;
	}
	jiffies_total = usecs_to_jiffies(dbs_tuners_ins.sampling_rate);
	jiffies_total = usecs_to_jiffies(od_tuners->sampling_rate);
	jiffies_hi = (freq_avg - freq_lo) * jiffies_total;
	jiffies_hi += ((freq_hi - freq_lo) / 2);
	jiffies_hi /= (freq_hi - freq_lo);
	jiffies_lo = jiffies_total - jiffies_hi;
	delay_hi_us = (freq_avg - freq_lo) * dbs_data->sampling_rate;
	delay_hi_us += (freq_hi - freq_lo) / 2;
	delay_hi_us /= freq_hi - freq_lo;
	dbs_info->freq_hi_delay_us = delay_hi_us;
	dbs_info->freq_lo = freq_lo;
	dbs_info->freq_lo_delay_us = dbs_data->sampling_rate - delay_hi_us;
	return freq_hi;
}

static void ondemand_powersave_bias_init(struct cpufreq_policy *policy)
{
	int i;
	for_each_online_cpu(i) {
		struct cpu_dbs_info_s *dbs_info = &per_cpu(cpu_dbs_info, i);
		dbs_info->freq_table = cpufreq_frequency_get_table(i);
		dbs_info->freq_lo = 0;
	}
}

/************************** sysfs interface ************************/
static ssize_t show_sampling_rate_max(struct cpufreq_policy *policy, char *buf)
{
	return sprintf (buf, "%u\n", MAX_SAMPLING_RATE);
}

static ssize_t show_sampling_rate_min(struct cpufreq_policy *policy, char *buf)
{
	return sprintf (buf, "%u\n", MIN_SAMPLING_RATE);
}

#define define_one_ro(_name)		\
static struct freq_attr _name =		\
__ATTR(_name, 0444, show_##_name, NULL)

define_one_ro(sampling_rate_max);
define_one_ro(sampling_rate_min);

/* cpufreq_ondemand Governor Tunables */
#define show_one(file_name, object)					\
static ssize_t show_##file_name						\
(struct cpufreq_policy *unused, char *buf)				\
{									\
	return sprintf(buf, "%u\n", dbs_tuners_ins.object);		\
}
show_one(sampling_rate, sampling_rate);
show_one(up_threshold, up_threshold);
show_one(ignore_nice_load, ignore_nice);
show_one(powersave_bias, powersave_bias);

static ssize_t store_sampling_rate(struct cpufreq_policy *unused,
		const char *buf, size_t count)
		ondemand_powersave_bias_init_cpu(i);
	}
	struct od_policy_dbs_info *dbs_info = to_dbs_info(policy->governor_data);

	dbs_info->freq_lo = 0;
}

static void dbs_freq_increase(struct cpufreq_policy *policy, unsigned int freq)
{
	struct policy_dbs_info *policy_dbs = policy->governor_data;
	struct dbs_data *dbs_data = policy_dbs->dbs_data;
	struct od_dbs_tuners *od_tuners = dbs_data->tuners;

	if (od_tuners->powersave_bias)
		freq = od_ops.powersave_bias_target(policy, freq,
				CPUFREQ_RELATION_H);
	else if (policy->cur == policy->max)
		return;

	__cpufreq_driver_target(policy, freq, od_tuners->powersave_bias ?
			CPUFREQ_RELATION_L : CPUFREQ_RELATION_H);
}

/*
 * Every sampling_rate, we check, if current idle time is less than 20%
 * (default), then we try to increase frequency. Else, we adjust the frequency
 * proportional to load.
 */
static void od_update(struct cpufreq_policy *policy)
{
	struct policy_dbs_info *policy_dbs = policy->governor_data;
	struct od_policy_dbs_info *dbs_info = to_dbs_info(policy_dbs);
	struct dbs_data *dbs_data = policy_dbs->dbs_data;
	struct od_dbs_tuners *od_tuners = dbs_data->tuners;
	unsigned int load = dbs_update(policy);

	dbs_info->freq_lo = 0;

	/* Check for frequency increase */
	if (load > dbs_data->up_threshold) {
		/* If switching to max speed, apply sampling_down_factor */
		if (policy->cur < policy->max)
			policy_dbs->rate_mult = dbs_data->sampling_down_factor;
		dbs_freq_increase(policy, policy->max);
	} else {
		/* Calculate the next frequency proportional to load */
		unsigned int freq_next, min_f, max_f;

		min_f = policy->cpuinfo.min_freq;
		max_f = policy->cpuinfo.max_freq;
		freq_next = min_f + load * (max_f - min_f) / 100;

		/* No longer fully busy, reset rate_mult */
		policy_dbs->rate_mult = 1;

		if (od_tuners->powersave_bias)
			freq_next = od_ops.powersave_bias_target(policy,
								 freq_next,
								 CPUFREQ_RELATION_L);

		__cpufreq_driver_target(policy, freq_next, CPUFREQ_RELATION_C);
	}
}

static unsigned int od_dbs_update(struct cpufreq_policy *policy)
{
	struct policy_dbs_info *policy_dbs = policy->governor_data;
	struct dbs_data *dbs_data = policy_dbs->dbs_data;
	struct od_policy_dbs_info *dbs_info = to_dbs_info(policy_dbs);
	int sample_type = dbs_info->sample_type;

	/* Common NORMAL_SAMPLE setup */
	dbs_info->sample_type = OD_NORMAL_SAMPLE;
	/*
	 * OD_SUB_SAMPLE doesn't make sense if sample_delay_ns is 0, so ignore
	 * it then.
	 */
	if (sample_type == OD_SUB_SAMPLE && policy_dbs->sample_delay_ns > 0) {
		__cpufreq_driver_target(policy, dbs_info->freq_lo,
					CPUFREQ_RELATION_H);
		return dbs_info->freq_lo_delay_us;
	}

	od_update(policy);

	if (dbs_info->freq_lo) {
		/* Setup SUB_SAMPLE */
		dbs_info->sample_type = OD_SUB_SAMPLE;
		return dbs_info->freq_hi_delay_us;
	}

	return dbs_data->sampling_rate * policy_dbs->rate_mult;
}

/************************** sysfs interface ************************/
static struct dbs_governor od_dbs_gov;

static ssize_t store_io_is_busy(struct gov_attr_set *attr_set, const char *buf,
				size_t count)
{
	struct dbs_data *dbs_data = to_dbs_data(attr_set);
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	mutex_lock(&dbs_mutex);
	if (ret != 1 || input > MAX_SAMPLING_RATE
		     || input < MIN_SAMPLING_RATE) {
		mutex_unlock(&dbs_mutex);
		return -EINVAL;
	}

	dbs_tuners_ins.sampling_rate = input;
	mutex_unlock(&dbs_mutex);

	return count;
}

static ssize_t store_up_threshold(struct cpufreq_policy *unused,
		const char *buf, size_t count)
{
	if (ret != 1)
		return -EINVAL;

	update_sampling_rate(dbs_data, input);
	return count;
}

static ssize_t store_io_is_busy(struct dbs_data *dbs_data, const char *buf,
		size_t count)
{
	struct od_dbs_tuners *od_tuners = dbs_data->tuners;
	unsigned int input;
	int ret;
	unsigned int j;

	ret = sscanf(buf, "%u", &input);
	if (ret != 1)
		return -EINVAL;
	dbs_data->io_is_busy = !!input;

	/* we need to re-evaluate prev_cpu_idle */
	gov_update_cpu_data(dbs_data);

	return count;
}

static ssize_t store_up_threshold(struct gov_attr_set *attr_set,
				  const char *buf, size_t count)
{
	struct dbs_data *dbs_data = to_dbs_data(attr_set);
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	mutex_lock(&dbs_mutex);
	if (ret != 1 || input > MAX_FREQUENCY_UP_THRESHOLD ||
			input < MIN_FREQUENCY_UP_THRESHOLD) {
		mutex_unlock(&dbs_mutex);
		return -EINVAL;
	}

	dbs_tuners_ins.up_threshold = input;
	mutex_unlock(&dbs_mutex);

	return count;
}

static ssize_t store_ignore_nice_load(struct cpufreq_policy *policy,
		const char *buf, size_t count)
{
	if (ret != 1 || input > MAX_FREQUENCY_UP_THRESHOLD ||
			input < MIN_FREQUENCY_UP_THRESHOLD) {
		return -EINVAL;
	}

	dbs_data->up_threshold = input;
	return count;
}

static ssize_t store_sampling_down_factor(struct gov_attr_set *attr_set,
					  const char *buf, size_t count)
{
	struct dbs_data *dbs_data = to_dbs_data(attr_set);
	struct policy_dbs_info *policy_dbs;
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1 || input > MAX_SAMPLING_DOWN_FACTOR || input < 1)
		return -EINVAL;

	dbs_data->sampling_down_factor = input;

	/* Reset down sampling multiplier in case it was active */
	list_for_each_entry(policy_dbs, &attr_set->policy_list, list) {
		/*
		 * Doing this without locking might lead to using different
		 * rate_mult values in od_update() and od_dbs_update().
		 */
		mutex_lock(&policy_dbs->update_mutex);
		policy_dbs->rate_mult = 1;
		mutex_unlock(&policy_dbs->update_mutex);
	}

	return count;
}

static ssize_t store_ignore_nice_load(struct gov_attr_set *attr_set,
				      const char *buf, size_t count)
{
	struct dbs_data *dbs_data = to_dbs_data(attr_set);
	unsigned int input;
	int ret;

	ret = sscanf(buf, "%u", &input);
	if ( ret != 1 )
		return -EINVAL;

	if ( input > 1 )
		input = 1;

	mutex_lock(&dbs_mutex);
	if ( input == dbs_tuners_ins.ignore_nice ) { /* nothing to do */
		mutex_unlock(&dbs_mutex);
		return count;
	}
	dbs_tuners_ins.ignore_nice = input;

	/* we need to re-evaluate prev_cpu_idle */
	for_each_online_cpu(j) {
		struct cpu_dbs_info_s *dbs_info;
		dbs_info = &per_cpu(cpu_dbs_info, j);
		dbs_info->prev_cpu_idle = get_cpu_idle_time(j);
		dbs_info->prev_cpu_wall = get_jiffies_64();
	}
	mutex_unlock(&dbs_mutex);

	return count;
}

static ssize_t store_powersave_bias(struct cpufreq_policy *unused,
		const char *buf, size_t count)
{
	if (ret != 1)
		return -EINVAL;

	if (input > 1)
		input = 1;

	if (input == dbs_data->ignore_nice_load) { /* nothing to do */
		return count;
	}
	dbs_data->ignore_nice_load = input;

	/* we need to re-evaluate prev_cpu_idle */
	gov_update_cpu_data(dbs_data);

	return count;
}

static ssize_t store_powersave_bias(struct gov_attr_set *attr_set,
				    const char *buf, size_t count)
{
	struct dbs_data *dbs_data = to_dbs_data(attr_set);
	struct od_dbs_tuners *od_tuners = dbs_data->tuners;
	struct policy_dbs_info *policy_dbs;
	unsigned int input;
	int ret;
	ret = sscanf(buf, "%u", &input);

	if (ret != 1)
		return -EINVAL;

	if (input > 1000)
		input = 1000;

	mutex_lock(&dbs_mutex);
	dbs_tuners_ins.powersave_bias = input;
	ondemand_powersave_bias_init();
	mutex_unlock(&dbs_mutex);

	return count;
}

#define define_one_rw(_name) \
static struct freq_attr _name = \
__ATTR(_name, 0644, show_##_name, store_##_name)

define_one_rw(sampling_rate);
define_one_rw(up_threshold);
define_one_rw(ignore_nice_load);
define_one_rw(powersave_bias);

static struct attribute * dbs_attributes[] = {
	&sampling_rate_max.attr,
	&sampling_rate_min.attr,
	&sampling_rate.attr,
	&up_threshold.attr,
	&ignore_nice_load.attr,
	&powersave_bias.attr,
	NULL
};

static struct attribute_group dbs_attr_group = {
	.attrs = dbs_attributes,
	od_tuners->powersave_bias = input;

	list_for_each_entry(policy_dbs, &attr_set->policy_list, list)
		ondemand_powersave_bias_init(policy_dbs->policy);

	return count;
}

gov_show_one_common(sampling_rate);
gov_show_one_common(up_threshold);
gov_show_one_common(sampling_down_factor);
gov_show_one_common(ignore_nice_load);
gov_show_one_common(io_is_busy);
gov_show_one(od, powersave_bias);

gov_attr_rw(sampling_rate);
gov_attr_rw(io_is_busy);
gov_attr_rw(up_threshold);
gov_attr_rw(sampling_down_factor);
gov_attr_rw(ignore_nice_load);
gov_attr_rw(powersave_bias);

static struct attribute *od_attributes[] = {
	&sampling_rate.attr,
	&up_threshold.attr,
	&sampling_down_factor.attr,
	&ignore_nice_load.attr,
	&powersave_bias.attr,
	&io_is_busy.attr,
	NULL
};

/************************** sysfs end ************************/

static void dbs_check_cpu(struct cpu_dbs_info_s *this_dbs_info)
{
	unsigned int idle_ticks, total_ticks;
	unsigned int load = 0;
	cputime64_t cur_jiffies;

	struct cpufreq_policy *policy;
	unsigned int j;

	if (!this_dbs_info->enable)
		return;

	this_dbs_info->freq_lo = 0;
	policy = this_dbs_info->cur_policy;
	cur_jiffies = jiffies64_to_cputime64(get_jiffies_64());
	total_ticks = (unsigned int) cputime64_sub(cur_jiffies,
			this_dbs_info->prev_cpu_wall);
	this_dbs_info->prev_cpu_wall = get_jiffies_64();

	if (!total_ticks)
		return;
	/*
	 * Every sampling_rate, we check, if current idle time is less
	 * than 20% (default), then we try to increase frequency
	 * Every sampling_rate, we look for a the lowest
	 * frequency which can sustain the load while keeping idle time over
	 * 30%. If such a frequency exist, we try to decrease to this frequency.
	 *
	 * Any frequency increase takes it to the maximum frequency.
	 * Frequency reduction happens at minimum steps of
	 * 5% (default) of current frequency
	 */

	/* Get Idle Time */
	idle_ticks = UINT_MAX;
	for_each_cpu_mask_nr(j, policy->cpus) {
		cputime64_t total_idle_ticks;
		unsigned int tmp_idle_ticks;
		struct cpu_dbs_info_s *j_dbs_info;

		j_dbs_info = &per_cpu(cpu_dbs_info, j);
		total_idle_ticks = get_cpu_idle_time(j);
		tmp_idle_ticks = (unsigned int) cputime64_sub(total_idle_ticks,
				j_dbs_info->prev_cpu_idle);
		j_dbs_info->prev_cpu_idle = total_idle_ticks;

		if (tmp_idle_ticks < idle_ticks)
			idle_ticks = tmp_idle_ticks;
	}
	if (likely(total_ticks > idle_ticks))
		load = (100 * (total_ticks - idle_ticks)) / total_ticks;

	/* Check for frequency increase */
	if (load > dbs_tuners_ins.up_threshold) {
		/* if we are already at full speed then break out early */
		if (!dbs_tuners_ins.powersave_bias) {
			if (policy->cur == policy->max)
				return;

			__cpufreq_driver_target(policy, policy->max,
				CPUFREQ_RELATION_H);
		} else {
			int freq = powersave_bias_target(policy, policy->max,
					CPUFREQ_RELATION_H);
			__cpufreq_driver_target(policy, freq,
				CPUFREQ_RELATION_L);
		}
		return;
	}

	/* Check for frequency decrease */
	/* if we cannot reduce the frequency anymore, break out early */
	if (policy->cur == policy->min)
		return;

	/*
	 * The optimal frequency is the frequency that is the lowest that
	 * can support the current CPU usage without triggering the up
	 * policy. To be safe, we focus 10 points under the threshold.
	 */
	if (load < (dbs_tuners_ins.up_threshold - 10)) {
		unsigned int freq_next, freq_cur;

		freq_cur = __cpufreq_driver_getavg(policy);
		if (!freq_cur)
			freq_cur = policy->cur;

		freq_next = (freq_cur * load) /
			(dbs_tuners_ins.up_threshold - 10);

		if (!dbs_tuners_ins.powersave_bias) {
			__cpufreq_driver_target(policy, freq_next,
					CPUFREQ_RELATION_L);
		} else {
			int freq = powersave_bias_target(policy, freq_next,
					CPUFREQ_RELATION_L);
			__cpufreq_driver_target(policy, freq,
				CPUFREQ_RELATION_L);
		}
	}
}

static void do_dbs_timer(struct work_struct *work)
{
	struct cpu_dbs_info_s *dbs_info =
		container_of(work, struct cpu_dbs_info_s, work.work);
	unsigned int cpu = dbs_info->cpu;
	int sample_type = dbs_info->sample_type;

	/* We want all CPUs to do sampling nearly on same jiffy */
	int delay = usecs_to_jiffies(dbs_tuners_ins.sampling_rate);

	delay -= jiffies % delay;

	if (lock_policy_rwsem_write(cpu) < 0)
		return;

	if (!dbs_info->enable) {
		unlock_policy_rwsem_write(cpu);
		return;
	}

	/* Common NORMAL_SAMPLE setup */
	dbs_info->sample_type = DBS_NORMAL_SAMPLE;
	if (!dbs_tuners_ins.powersave_bias ||
	    sample_type == DBS_NORMAL_SAMPLE) {
		dbs_check_cpu(dbs_info);
		if (dbs_info->freq_lo) {
			/* Setup timer for SUB_SAMPLE */
			dbs_info->sample_type = DBS_SUB_SAMPLE;
			delay = dbs_info->freq_hi_jiffies;
		}
	} else {
		__cpufreq_driver_target(dbs_info->cur_policy,
	                        	dbs_info->freq_lo,
	                        	CPUFREQ_RELATION_H);
	}
	queue_delayed_work_on(cpu, kondemand_wq, &dbs_info->work, delay);
	unlock_policy_rwsem_write(cpu);
}

static inline void dbs_timer_init(struct cpu_dbs_info_s *dbs_info)
{
	/* We want all CPUs to do sampling nearly on same jiffy */
	int delay = usecs_to_jiffies(dbs_tuners_ins.sampling_rate);
	delay -= jiffies % delay;

	dbs_info->enable = 1;
	ondemand_powersave_bias_init();
	dbs_info->sample_type = DBS_NORMAL_SAMPLE;
	INIT_DELAYED_WORK_DEFERRABLE(&dbs_info->work, do_dbs_timer);
	queue_delayed_work_on(dbs_info->cpu, kondemand_wq, &dbs_info->work,
	                      delay);
}

static inline void dbs_timer_exit(struct cpu_dbs_info_s *dbs_info)
{
	dbs_info->enable = 0;
	cancel_delayed_work(&dbs_info->work);
}

static int cpufreq_governor_dbs(struct cpufreq_policy *policy,
				   unsigned int event)
{
	unsigned int cpu = policy->cpu;
	struct cpu_dbs_info_s *this_dbs_info;
	unsigned int j;
	int rc;

	this_dbs_info = &per_cpu(cpu_dbs_info, cpu);

	switch (event) {
	case CPUFREQ_GOV_START:
		if ((!cpu_online(cpu)) || (!policy->cur))
			return -EINVAL;

		if (this_dbs_info->enable) /* Already enabled */
			break;

		mutex_lock(&dbs_mutex);
		dbs_enable++;

		rc = sysfs_create_group(&policy->kobj, &dbs_attr_group);
		if (rc) {
			dbs_enable--;
			mutex_unlock(&dbs_mutex);
			return rc;
		}

		for_each_cpu_mask_nr(j, policy->cpus) {
			struct cpu_dbs_info_s *j_dbs_info;
			j_dbs_info = &per_cpu(cpu_dbs_info, j);
			j_dbs_info->cur_policy = policy;

			j_dbs_info->prev_cpu_idle = get_cpu_idle_time(j);
			j_dbs_info->prev_cpu_wall = get_jiffies_64();
		}
		this_dbs_info->cpu = cpu;
		/*
		 * Start the timerschedule work, when this governor
		 * is used for first time
		 */
		if (dbs_enable == 1) {
			unsigned int latency;
			/* policy latency is in nS. Convert it to uS first */
			latency = policy->cpuinfo.transition_latency / 1000;
			if (latency == 0)
				latency = 1;

			def_sampling_rate = latency *
					DEF_SAMPLING_RATE_LATENCY_MULTIPLIER;

			if (def_sampling_rate < MIN_STAT_SAMPLING_RATE)
				def_sampling_rate = MIN_STAT_SAMPLING_RATE;

			dbs_tuners_ins.sampling_rate = def_sampling_rate;
		}
		dbs_timer_init(this_dbs_info);

		mutex_unlock(&dbs_mutex);
		break;

	case CPUFREQ_GOV_STOP:
		mutex_lock(&dbs_mutex);
		dbs_timer_exit(this_dbs_info);
		sysfs_remove_group(&policy->kobj, &dbs_attr_group);
		dbs_enable--;
		mutex_unlock(&dbs_mutex);

		break;

	case CPUFREQ_GOV_LIMITS:
		mutex_lock(&dbs_mutex);
		if (policy->max < this_dbs_info->cur_policy->cur)
			__cpufreq_driver_target(this_dbs_info->cur_policy,
			                        policy->max,
			                        CPUFREQ_RELATION_H);
		else if (policy->min > this_dbs_info->cur_policy->cur)
			__cpufreq_driver_target(this_dbs_info->cur_policy,
			                        policy->min,
			                        CPUFREQ_RELATION_L);
		mutex_unlock(&dbs_mutex);
		break;
	}
	return 0;
}

struct cpufreq_governor cpufreq_gov_ondemand = {
	.name			= "ondemand",
	.governor		= cpufreq_governor_dbs,
	.max_transition_latency = TRANSITION_LATENCY_LIMIT,
	.owner			= THIS_MODULE,
};
EXPORT_SYMBOL(cpufreq_gov_ondemand);

static int __init cpufreq_gov_dbs_init(void)
{
	kondemand_wq = create_workqueue("kondemand");
	if (!kondemand_wq) {
		printk(KERN_ERR "Creation of kondemand failed\n");
		return -EFAULT;
	}
static int od_init(struct dbs_data *dbs_data, bool notify)
static struct policy_dbs_info *od_alloc(void)
{
	struct od_policy_dbs_info *dbs_info;

	dbs_info = kzalloc(sizeof(*dbs_info), GFP_KERNEL);
	return dbs_info ? &dbs_info->policy_dbs : NULL;
}

static void od_free(struct policy_dbs_info *policy_dbs)
{
	kfree(to_dbs_info(policy_dbs));
}

static int od_init(struct dbs_data *dbs_data)
{
	struct od_dbs_tuners *tuners;
	u64 idle_time;
	int cpu;

	tuners = kzalloc(sizeof(*tuners), GFP_KERNEL);
	if (!tuners)
		return -ENOMEM;

	cpu = get_cpu();
	idle_time = get_cpu_idle_time_us(cpu, NULL);
	put_cpu();
	if (idle_time != -1ULL) {
		/* Idle micro accounting is supported. Use finer thresholds */
		dbs_data->up_threshold = MICRO_FREQUENCY_UP_THRESHOLD;
	} else {
		dbs_data->up_threshold = DEF_FREQUENCY_UP_THRESHOLD;
	}

	dbs_data->sampling_down_factor = DEF_SAMPLING_DOWN_FACTOR;
	dbs_data->ignore_nice_load = 0;
	tuners->powersave_bias = default_powersave_bias;
	dbs_data->io_is_busy = should_io_be_busy();

	dbs_data->tuners = tuners;
	return 0;
}

static void od_exit(struct dbs_data *dbs_data)
{
	kfree(dbs_data->tuners);
}

static void od_start(struct cpufreq_policy *policy)
{
	struct od_policy_dbs_info *dbs_info = to_dbs_info(policy->governor_data);

	dbs_info->sample_type = OD_NORMAL_SAMPLE;
	ondemand_powersave_bias_init(policy);
}

static struct od_ops od_ops = {
	.powersave_bias_target = generic_powersave_bias_target,
};

static struct dbs_governor od_dbs_gov = {
	.gov = CPUFREQ_DBS_GOVERNOR_INITIALIZER("ondemand"),
	.kobj_type = { .default_attrs = od_attributes },
	.gov_dbs_update = od_dbs_update,
	.alloc = od_alloc,
	.free = od_free,
	.init = od_init,
	.exit = od_exit,
	.start = od_start,
};

#define CPU_FREQ_GOV_ONDEMAND	(&od_dbs_gov.gov)

static void od_set_powersave_bias(unsigned int powersave_bias)
{
	unsigned int cpu;
	cpumask_t done;

	default_powersave_bias = powersave_bias;
	cpumask_clear(&done);

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct cpufreq_policy *policy;
		struct policy_dbs_info *policy_dbs;
		struct dbs_data *dbs_data;
		struct od_dbs_tuners *od_tuners;

		if (cpumask_test_cpu(cpu, &done))
			continue;

		policy = cpufreq_cpu_get_raw(cpu);
		if (!policy || policy->governor != CPU_FREQ_GOV_ONDEMAND)
			continue;

		policy_dbs = policy->governor_data;
		if (!policy_dbs)
			continue;

		cpumask_or(&done, &done, policy->cpus);

		dbs_data = policy_dbs->dbs_data;
		od_tuners = dbs_data->tuners;
		od_tuners->powersave_bias = default_powersave_bias;
	}
	put_online_cpus();
}

void od_register_powersave_bias_handler(unsigned int (*f)
		(struct cpufreq_policy *, unsigned int, unsigned int),
		unsigned int powersave_bias)
{
	od_ops.powersave_bias_target = f;
	od_set_powersave_bias(powersave_bias);
}
EXPORT_SYMBOL_GPL(od_register_powersave_bias_handler);

void od_unregister_powersave_bias_handler(void)
{
	od_ops.powersave_bias_target = generic_powersave_bias_target;
	od_set_powersave_bias(0);
}
EXPORT_SYMBOL_GPL(od_unregister_powersave_bias_handler);

static int __init cpufreq_gov_dbs_init(void)
{
	return cpufreq_register_governor(CPU_FREQ_GOV_ONDEMAND);
}

static void __exit cpufreq_gov_dbs_exit(void)
{
	cpufreq_unregister_governor(&cpufreq_gov_ondemand);
	destroy_workqueue(kondemand_wq);
}


MODULE_AUTHOR("Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>");
MODULE_AUTHOR("Alexey Starikovskiy <alexey.y.starikovskiy@intel.com>");
MODULE_DESCRIPTION("'cpufreq_ondemand' - A dynamic cpufreq governor for "
                   "Low Latency Frequency Transition capable processors");
	cpufreq_unregister_governor(CPU_FREQ_GOV_ONDEMAND);
}

MODULE_AUTHOR("Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>");
MODULE_AUTHOR("Alexey Starikovskiy <alexey.y.starikovskiy@intel.com>");
MODULE_DESCRIPTION("'cpufreq_ondemand' - A dynamic cpufreq governor for "
	"Low Latency Frequency Transition capable processors");
MODULE_LICENSE("GPL");

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_ONDEMAND
struct cpufreq_governor *cpufreq_default_governor(void)
{
	return CPU_FREQ_GOV_ONDEMAND;
}

fs_initcall(cpufreq_gov_dbs_init);
#else
module_init(cpufreq_gov_dbs_init);
#endif
module_exit(cpufreq_gov_dbs_exit);
