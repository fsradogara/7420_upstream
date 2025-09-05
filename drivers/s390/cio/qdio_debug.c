// SPDX-License-Identifier: GPL-2.0
/*
 *  drivers/s390/cio/qdio_debug.c
 *
 *  Copyright IBM Corp. 2008
 *
 *  Author: Jan Glauber (jang@linux.vnet.ibm.com)
 */
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <asm/qdio.h>
 *  Copyright IBM Corp. 2008, 2009
 *
 *  Author: Jan Glauber (jang@linux.vnet.ibm.com)
 */
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <asm/debug.h>
#include "qdio_debug.h"
#include "qdio.h"

debug_info_t *qdio_dbf_setup;
debug_info_t *qdio_dbf_trace;

static struct dentry *debugfs_root;
#define MAX_DEBUGFS_QUEUES	32
static struct dentry *debugfs_queues[MAX_DEBUGFS_QUEUES] = { NULL };
static DEFINE_MUTEX(debugfs_mutex);

void qdio_allocate_do_dbf(struct qdio_initialize *init_data)
{
	char dbf_text[20];

	sprintf(dbf_text, "qfmt:%x", init_data->q_format);
	QDIO_DBF_TEXT0(0, setup, dbf_text);
	QDIO_DBF_HEX0(0, setup, init_data->adapter_name, 8);
	sprintf(dbf_text, "qpff%4x", init_data->qib_param_field_format);
	QDIO_DBF_TEXT0(0, setup, dbf_text);
	QDIO_DBF_HEX0(0, setup, &init_data->qib_param_field, sizeof(void *));
	QDIO_DBF_HEX0(0, setup, &init_data->input_slib_elements, sizeof(void *));
	QDIO_DBF_HEX0(0, setup, &init_data->output_slib_elements, sizeof(void *));
	sprintf(dbf_text, "niq:%4x", init_data->no_input_qs);
	QDIO_DBF_TEXT0(0, setup, dbf_text);
	sprintf(dbf_text, "noq:%4x", init_data->no_output_qs);
	QDIO_DBF_TEXT0(0, setup, dbf_text);
	QDIO_DBF_HEX0(0, setup, &init_data->input_handler, sizeof(void *));
	QDIO_DBF_HEX0(0, setup, &init_data->output_handler, sizeof(void *));
	QDIO_DBF_HEX0(0, setup, &init_data->int_parm, sizeof(long));
	QDIO_DBF_HEX0(0, setup, &init_data->flags, sizeof(long));
	QDIO_DBF_HEX0(0, setup, &init_data->input_sbal_addr_array, sizeof(void *));
	QDIO_DBF_HEX0(0, setup, &init_data->output_sbal_addr_array, sizeof(void *));
}

static void qdio_unregister_dbf_views(void)
{
	if (qdio_dbf_setup)
		debug_unregister(qdio_dbf_setup);
	if (qdio_dbf_trace)
		debug_unregister(qdio_dbf_trace);
}

static int qdio_register_dbf_views(void)
{
	qdio_dbf_setup = debug_register("qdio_setup", QDIO_DBF_SETUP_PAGES,
					QDIO_DBF_SETUP_NR_AREAS,
					QDIO_DBF_SETUP_LEN);
	if (!qdio_dbf_setup)
		goto oom;
	debug_register_view(qdio_dbf_setup, &debug_hex_ascii_view);
	debug_set_level(qdio_dbf_setup, QDIO_DBF_SETUP_LEVEL);

	qdio_dbf_trace = debug_register("qdio_trace", QDIO_DBF_TRACE_PAGES,
					QDIO_DBF_TRACE_NR_AREAS,
					QDIO_DBF_TRACE_LEN);
	if (!qdio_dbf_trace)
		goto oom;
	debug_register_view(qdio_dbf_trace, &debug_hex_ascii_view);
	debug_set_level(qdio_dbf_trace, QDIO_DBF_TRACE_LEVEL);
	return 0;
oom:
	qdio_unregister_dbf_views();
	return -ENOMEM;
debug_info_t *qdio_dbf_error;

static struct dentry *debugfs_root;
#define QDIO_DEBUGFS_NAME_LEN	10
#define QDIO_DBF_NAME_LEN	20

struct qdio_dbf_entry {
	char dbf_name[QDIO_DBF_NAME_LEN];
	debug_info_t *dbf_info;
	struct list_head dbf_list;
};

static LIST_HEAD(qdio_dbf_list);
static DEFINE_MUTEX(qdio_dbf_list_mutex);

static debug_info_t *qdio_get_dbf_entry(char *name)
{
	struct qdio_dbf_entry *entry;
	debug_info_t *rc = NULL;

	mutex_lock(&qdio_dbf_list_mutex);
	list_for_each_entry(entry, &qdio_dbf_list, dbf_list) {
		if (strcmp(entry->dbf_name, name) == 0) {
			rc = entry->dbf_info;
			break;
		}
	}
	mutex_unlock(&qdio_dbf_list_mutex);
	return rc;
}

static void qdio_clear_dbf_list(void)
{
	struct qdio_dbf_entry *entry, *tmp;

	mutex_lock(&qdio_dbf_list_mutex);
	list_for_each_entry_safe(entry, tmp, &qdio_dbf_list, dbf_list) {
		list_del(&entry->dbf_list);
		debug_unregister(entry->dbf_info);
		kfree(entry);
	}
	mutex_unlock(&qdio_dbf_list_mutex);
}

int qdio_allocate_dbf(struct qdio_initialize *init_data,
		       struct qdio_irq *irq_ptr)
{
	char text[QDIO_DBF_NAME_LEN];
	struct qdio_dbf_entry *new_entry;

	DBF_EVENT("qfmt:%1d", init_data->q_format);
	DBF_HEX(init_data->adapter_name, 8);
	DBF_EVENT("qpff%4x", init_data->qib_param_field_format);
	DBF_HEX(&init_data->qib_param_field, sizeof(void *));
	DBF_HEX(&init_data->input_slib_elements, sizeof(void *));
	DBF_HEX(&init_data->output_slib_elements, sizeof(void *));
	DBF_EVENT("niq:%1d noq:%1d", init_data->no_input_qs,
		  init_data->no_output_qs);
	DBF_HEX(&init_data->input_handler, sizeof(void *));
	DBF_HEX(&init_data->output_handler, sizeof(void *));
	DBF_HEX(&init_data->int_parm, sizeof(long));
	DBF_HEX(&init_data->input_sbal_addr_array, sizeof(void *));
	DBF_HEX(&init_data->output_sbal_addr_array, sizeof(void *));
	DBF_EVENT("irq:%8lx", (unsigned long)irq_ptr);

	/* allocate trace view for the interface */
	snprintf(text, QDIO_DBF_NAME_LEN, "qdio_%s",
					dev_name(&init_data->cdev->dev));
	irq_ptr->debug_area = qdio_get_dbf_entry(text);
	if (irq_ptr->debug_area)
		DBF_DEV_EVENT(DBF_ERR, irq_ptr, "dbf reused");
	else {
		irq_ptr->debug_area = debug_register(text, 2, 1, 16);
		if (!irq_ptr->debug_area)
			return -ENOMEM;
		if (debug_register_view(irq_ptr->debug_area,
						&debug_hex_ascii_view)) {
			debug_unregister(irq_ptr->debug_area);
			return -ENOMEM;
		}
		debug_set_level(irq_ptr->debug_area, DBF_WARN);
		DBF_DEV_EVENT(DBF_ERR, irq_ptr, "dbf created");
		new_entry = kzalloc(sizeof(struct qdio_dbf_entry), GFP_KERNEL);
		if (!new_entry) {
			debug_unregister(irq_ptr->debug_area);
			return -ENOMEM;
		}
		strlcpy(new_entry->dbf_name, text, QDIO_DBF_NAME_LEN);
		new_entry->dbf_info = irq_ptr->debug_area;
		mutex_lock(&qdio_dbf_list_mutex);
		list_add(&new_entry->dbf_list, &qdio_dbf_list);
		mutex_unlock(&qdio_dbf_list_mutex);
	}
	return 0;
}

static int qstat_show(struct seq_file *m, void *v)
{
	unsigned char state;
	struct qdio_q *q = m->private;
	int i;

	if (!q)
		return 0;

	seq_printf(m, "device state indicator: %d\n", *q->irq_ptr->dsci);
	seq_printf(m, "nr_used: %d\n", atomic_read(&q->nr_buf_used));
	seq_printf(m, "ftc: %d\n", q->first_to_check);
	seq_printf(m, "last_move_ftc: %d\n", q->last_move_ftc);
	seq_printf(m, "polling: %d\n", q->u.in.polling);
	seq_printf(m, "slsb buffer states:\n");

	qdio_siga_sync_q(q);
	for (i = 0; i < QDIO_MAX_BUFFERS_PER_Q; i++) {
		get_buf_state(q, i, &state);
	seq_printf(m, "Timestamp: %Lx  Last AI: %Lx\n",
		   q->timestamp, last_ai_time);
	seq_printf(m, "nr_used: %d  ftc: %d  last_move: %d\n",
		   atomic_read(&q->nr_buf_used),
		   q->first_to_check, q->last_move);
	if (q->is_input_q) {
		seq_printf(m, "polling: %d  ack start: %d  ack count: %d\n",
			   q->u.in.polling, q->u.in.ack_start,
			   q->u.in.ack_count);
		seq_printf(m, "DSCI: %d   IRQs disabled: %u\n",
			   *(u32 *)q->irq_ptr->dsci,
			   test_bit(QDIO_QUEUE_IRQS_DISABLED,
			   &q->u.in.queue_irq_state));
	}
	seq_printf(m, "SBAL states:\n");
	seq_printf(m, "|0      |8      |16     |24     |32     |40     |48     |56  63|\n");

	for (i = 0; i < QDIO_MAX_BUFFERS_PER_Q; i++) {
		debug_get_buf_state(q, i, &state);
		switch (state) {
		case SLSB_P_INPUT_NOT_INIT:
		case SLSB_P_OUTPUT_NOT_INIT:
			seq_printf(m, "N");
			break;
		case SLSB_P_OUTPUT_PENDING:
			seq_printf(m, "P");
			break;
		case SLSB_P_INPUT_PRIMED:
		case SLSB_CU_OUTPUT_PRIMED:
			seq_printf(m, "+");
			break;
		case SLSB_P_INPUT_ACK:
			seq_printf(m, "A");
			break;
		case SLSB_P_INPUT_ERROR:
		case SLSB_P_OUTPUT_ERROR:
			seq_printf(m, "x");
			break;
		case SLSB_CU_INPUT_EMPTY:
		case SLSB_P_OUTPUT_EMPTY:
			seq_printf(m, "-");
			break;
		case SLSB_P_INPUT_HALTED:
		case SLSB_P_OUTPUT_HALTED:
			seq_printf(m, ".");
			break;
		default:
			seq_printf(m, "?");
		}
		if (i == 63)
			seq_printf(m, "\n");
	}
	seq_printf(m, "\n");
	return 0;
}

static ssize_t qstat_seq_write(struct file *file, const char __user *buf,
			       size_t count, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct qdio_q *q = seq->private;

	if (!q)
		return 0;

	if (q->is_input_q)
		xchg(q->irq_ptr->dsci, 1);
	local_bh_disable();
	tasklet_schedule(&q->tasklet);
	local_bh_enable();
	return count;
	seq_printf(m, "|64     |72     |80     |88     |96     |104    |112    |   127|\n");

	seq_printf(m, "\nSBAL statistics:");
	if (!q->irq_ptr->perf_stat_enabled) {
		seq_printf(m, " disabled\n");
		return 0;
	}

	seq_printf(m, "\n1          2..        4..        8..        "
		   "16..       32..       64..       127\n");
	for (i = 0; i < ARRAY_SIZE(q->q_stats.nr_sbals); i++)
		seq_printf(m, "%-10u ", q->q_stats.nr_sbals[i]);
	seq_printf(m, "\nError      NOP        Total\n%-10u %-10u %-10u\n\n",
		   q->q_stats.nr_sbal_error, q->q_stats.nr_sbal_nop,
		   q->q_stats.nr_sbal_total);
	return 0;
}

static int qstat_seq_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, qstat_show,
			   filp->f_path.dentry->d_inode->i_private);
}

static void get_queue_name(struct qdio_q *q, struct ccw_device *cdev, char *name)
{
	memset(name, 0, sizeof(name));
	sprintf(name, "%s", cdev->dev.bus_id);
	if (q->is_input_q)
		sprintf(name + strlen(name), "_input");
	else
		sprintf(name + strlen(name), "_output");
	sprintf(name + strlen(name), "_%d", q->nr);
}

static void remove_debugfs_entry(struct qdio_q *q)
{
	int i;

	for (i = 0; i < MAX_DEBUGFS_QUEUES; i++) {
		if (!debugfs_queues[i])
			continue;
		if (debugfs_queues[i]->d_inode->i_private == q) {
			debugfs_remove(debugfs_queues[i]);
			debugfs_queues[i] = NULL;
		}
	}
}

static struct file_operations debugfs_fops = {
	.owner	 = THIS_MODULE,
	.open	 = qstat_seq_open,
	.read	 = seq_read,
	.write	 = qstat_seq_write,
			   file_inode(filp)->i_private);
}

static const struct file_operations debugfs_fops = {
	.owner	 = THIS_MODULE,
	.open	 = qstat_seq_open,
	.read	 = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static void setup_debugfs_entry(struct qdio_q *q, struct ccw_device *cdev)
{
	int i = 0;
	char name[40];

	while (debugfs_queues[i] != NULL) {
		i++;
		if (i >= MAX_DEBUGFS_QUEUES)
			return;
	}
	get_queue_name(q, cdev, name);
	debugfs_queues[i] = debugfs_create_file(name, S_IFREG | S_IRUGO | S_IWUSR,
						debugfs_root, q, &debugfs_fops);
static char *qperf_names[] = {
	"Assumed adapter interrupts",
	"QDIO interrupts",
	"Requested PCIs",
	"Inbound tasklet runs",
	"Inbound tasklet resched",
	"Inbound tasklet resched2",
	"Outbound tasklet runs",
	"SIGA read",
	"SIGA write",
	"SIGA sync",
	"Inbound calls",
	"Inbound handler",
	"Inbound stop_polling",
	"Inbound queue full",
	"Outbound calls",
	"Outbound handler",
	"Outbound queue full",
	"Outbound fast_requeue",
	"Outbound target_full",
	"QEBSM eqbs",
	"QEBSM eqbs partial",
	"QEBSM sqbs",
	"QEBSM sqbs partial",
	"Discarded interrupts"
};

static int qperf_show(struct seq_file *m, void *v)
{
	struct qdio_irq *irq_ptr = m->private;
	unsigned int *stat;
	int i;

	if (!irq_ptr)
		return 0;
	if (!irq_ptr->perf_stat_enabled) {
		seq_printf(m, "disabled\n");
		return 0;
	}
	stat = (unsigned int *)&irq_ptr->perf_stat;

	for (i = 0; i < ARRAY_SIZE(qperf_names); i++)
		seq_printf(m, "%26s:\t%u\n",
			   qperf_names[i], *(stat + i));
	return 0;
}

static ssize_t qperf_seq_write(struct file *file, const char __user *ubuf,
			       size_t count, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct qdio_irq *irq_ptr = seq->private;
	struct qdio_q *q;
	unsigned long val;
	int ret, i;

	if (!irq_ptr)
		return 0;

	ret = kstrtoul_from_user(ubuf, count, 10, &val);
	if (ret)
		return ret;

	switch (val) {
	case 0:
		irq_ptr->perf_stat_enabled = 0;
		memset(&irq_ptr->perf_stat, 0, sizeof(irq_ptr->perf_stat));
		for_each_input_queue(irq_ptr, q, i)
			memset(&q->q_stats, 0, sizeof(q->q_stats));
		for_each_output_queue(irq_ptr, q, i)
			memset(&q->q_stats, 0, sizeof(q->q_stats));
		break;
	case 1:
		irq_ptr->perf_stat_enabled = 1;
		break;
	}
	return count;
}

static int qperf_seq_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, qperf_show,
			   file_inode(filp)->i_private);
}

static const struct file_operations debugfs_perf_fops = {
	.owner	 = THIS_MODULE,
	.open	 = qperf_seq_open,
	.read	 = seq_read,
	.write	 = qperf_seq_write,
	.llseek  = seq_lseek,
	.release = single_release,
};

static void setup_debugfs_entry(struct qdio_q *q)
{
	char name[QDIO_DEBUGFS_NAME_LEN];

	snprintf(name, QDIO_DEBUGFS_NAME_LEN, "%s_%d",
		 q->is_input_q ? "input" : "output",
		 q->nr);
	q->debugfs_q = debugfs_create_file(name, S_IFREG | S_IRUGO | S_IWUSR,
				q->irq_ptr->debugfs_dev, q, &debugfs_fops);
	if (IS_ERR(q->debugfs_q))
		q->debugfs_q = NULL;
}

void qdio_setup_debug_entries(struct qdio_irq *irq_ptr, struct ccw_device *cdev)
{
	struct qdio_q *q;
	int i;

	mutex_lock(&debugfs_mutex);
	for_each_input_queue(irq_ptr, q, i)
		setup_debugfs_entry(q, cdev);
	for_each_output_queue(irq_ptr, q, i)
		setup_debugfs_entry(q, cdev);
	mutex_unlock(&debugfs_mutex);
}

void qdio_shutdown_debug_entries(struct qdio_irq *irq_ptr, struct ccw_device *cdev)
	irq_ptr->debugfs_dev = debugfs_create_dir(dev_name(&cdev->dev),
						  debugfs_root);
	if (IS_ERR(irq_ptr->debugfs_dev))
		irq_ptr->debugfs_dev = NULL;

	irq_ptr->debugfs_perf = debugfs_create_file("statistics",
				S_IFREG | S_IRUGO | S_IWUSR,
				irq_ptr->debugfs_dev, irq_ptr,
				&debugfs_perf_fops);
	if (IS_ERR(irq_ptr->debugfs_perf))
		irq_ptr->debugfs_perf = NULL;

	for_each_input_queue(irq_ptr, q, i)
		setup_debugfs_entry(q);
	for_each_output_queue(irq_ptr, q, i)
		setup_debugfs_entry(q);
}

void qdio_shutdown_debug_entries(struct qdio_irq *irq_ptr)
{
	struct qdio_q *q;
	int i;

	mutex_lock(&debugfs_mutex);
	for_each_input_queue(irq_ptr, q, i)
		remove_debugfs_entry(q);
	for_each_output_queue(irq_ptr, q, i)
		remove_debugfs_entry(q);
	mutex_unlock(&debugfs_mutex);
	for_each_input_queue(irq_ptr, q, i)
		debugfs_remove(q->debugfs_q);
	for_each_output_queue(irq_ptr, q, i)
		debugfs_remove(q->debugfs_q);
	debugfs_remove(irq_ptr->debugfs_perf);
	debugfs_remove(irq_ptr->debugfs_dev);
}

int __init qdio_debug_init(void)
{
	debugfs_root = debugfs_create_dir("qdio_queues", NULL);
	return qdio_register_dbf_views();
	debugfs_root = debugfs_create_dir("qdio", NULL);

	qdio_dbf_setup = debug_register("qdio_setup", 16, 1, 16);
	debug_register_view(qdio_dbf_setup, &debug_hex_ascii_view);
	debug_set_level(qdio_dbf_setup, DBF_INFO);
	DBF_EVENT("dbf created\n");

	qdio_dbf_error = debug_register("qdio_error", 4, 1, 16);
	debug_register_view(qdio_dbf_error, &debug_hex_ascii_view);
	debug_set_level(qdio_dbf_error, DBF_INFO);
	DBF_ERROR("dbf created\n");
	return 0;
}

void qdio_debug_exit(void)
{
	debugfs_remove(debugfs_root);
	qdio_unregister_dbf_views();
	qdio_clear_dbf_list();
	debugfs_remove(debugfs_root);
	debug_unregister(qdio_dbf_setup);
	debug_unregister(qdio_dbf_error);
}
