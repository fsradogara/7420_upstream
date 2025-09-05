/*
 * linux/fs/9p/trans_fd.c
 *
 * Fd transport layer.  Includes deprecated socket layer.
 *
 *  Copyright (C) 2006 by Russ Cox <rsc@swtch.com>
 *  Copyright (C) 2004-2005 by Latchesar Ionkov <lucho@ionkov.net>
 *  Copyright (C) 2004-2008 by Eric Van Hensbergen <ericvh@gmail.com>
 *  Copyright (C) 1997-2002 by Ron Minnich <rminnich@sarnoff.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to:
 *  Free Software Foundation
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02111-1301  USA
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/in.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/ipv6.h>
#include <linux/kthread.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/un.h>
#include <linux/uaccess.h>
#include <linux/inet.h>
#include <linux/idr.h>
#include <linux/file.h>
#include <linux/parser.h>
#include <net/9p/9p.h>
#include <net/9p/transport.h>

#define P9_PORT 564
#define MAX_SOCK_BUF (64*1024)
#define ERREQFLUSH	1
#define SCHED_TIMEOUT	10
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <net/9p/9p.h>
#include <net/9p/client.h>
#include <net/9p/transport.h>

#include <linux/syscalls.h> /* killme */

#define P9_PORT 564
#define MAX_SOCK_BUF (64*1024)
#define MAXPOLLWADDR	2

static struct p9_trans_module p9_tcp_trans;
static struct p9_trans_module p9_fd_trans;

/**
 * struct p9_fd_opts - per-transport options
 * @rfd: file descriptor for reading (trans=fd)
 * @wfd: file descriptor for writing (trans=fd)
 * @port: port to connect to (trans=tcp)
 *
 */

struct p9_fd_opts {
	int rfd;
	int wfd;
	u16 port;
};

	int privport;
	bool privport;
};

/*
  * Option Parsing (code inspired by NFS code)
  *  - a little lazy - parse all fd-transport options
  */

enum {
	/* Options that take integer arguments */
	Opt_port, Opt_rfdno, Opt_wfdno, Opt_err,
	/* Options that take no arguments */
	Opt_privport,
};

static const match_table_t tokens = {
	{Opt_port, "port=%u"},
	{Opt_rfdno, "rfdno=%u"},
	{Opt_wfdno, "wfdno=%u"},
	{Opt_privport, "privport"},
	{Opt_err, NULL},
};

enum {
	Rworksched = 1,		/* read work scheduled or running */
	Rpending = 2,		/* can read */
	Wworksched = 4,		/* write work scheduled or running */
	Wpending = 8,		/* can write */
};

struct p9_poll_wait {
	struct p9_conn *conn;
	wait_queue_entry_t wait;
	wait_queue_head_t *wait_addr;
};

/**
 * struct p9_conn - fd mux connection state information
 * @mux_list: list link for mux to manage multiple connections (?)
 * @client: reference to client instance for this connection
 * @err: error state
 * @req_list: accounting for requests which have been sent
 * @unsent_req_list: accounting for requests that haven't been sent
 * @req: current request being processed (if any)
 * @tmp_buf: temporary buffer to read in header
 * @rc: temporary fcall for reading current frame
 * @wpos: write position for current frame
 * @wsize: amount of data to write for current frame
 * @wbuf: current write buffer
 * @poll_pending_link: pending links to be polled per conn
 * @poll_wait: array of wait_q's for various worker threads
 * @pt: poll state
 * @rq: current read work
 * @wq: current write work
 * @wsched: ????
 *
 */

struct p9_conn {
	struct list_head mux_list;
	struct p9_client *client;
	int err;
	struct list_head req_list;
	struct list_head unsent_req_list;
	struct p9_req_t *req;
	char tmp_buf[7];
	struct p9_fcall rc;
	int wpos;
	int wsize;
	char *wbuf;
	struct list_head poll_pending_link;
	struct p9_poll_wait poll_wait[MAXPOLLWADDR];
	poll_table pt;
	struct work_struct rq;
	struct work_struct wq;
	unsigned long wsched;
};

/**
 * struct p9_trans_fd - transport state
 * @rd: reference to file to read from
 * @wr: reference of file to write to
 * @conn: connection state reference
 *
 */

struct p9_trans_fd {
	struct file *rd;
	struct file *wr;
	struct p9_conn *conn;
};

/*
  * Option Parsing (code inspired by NFS code)
  *  - a little lazy - parse all fd-transport options
  */

enum {
	/* Options that take integer arguments */
	Opt_port, Opt_rfdno, Opt_wfdno, Opt_err,
};

static match_table_t tokens = {
	{Opt_port, "port=%u"},
	{Opt_rfdno, "rfdno=%u"},
	{Opt_wfdno, "wfdno=%u"},
	{Opt_err, NULL},
};

enum {
	Rworksched = 1,		/* read work scheduled or running */
	Rpending = 2,		/* can read */
	Wworksched = 4,		/* write work scheduled or running */
	Wpending = 8,		/* can write */
};

enum {
	None,
	Flushing,
	Flushed,
};

struct p9_req;
typedef void (*p9_conn_req_callback)(struct p9_req *req, void *a);

/**
 * struct p9_req - fd mux encoding of an rpc transaction
 * @lock: protects req_list
 * @tag: numeric tag for rpc transaction
 * @tcall: request &p9_fcall structure
 * @rcall: response &p9_fcall structure
 * @err: error state
 * @cb: callback for when response is received
 * @cba: argument to pass to callback
 * @flush: flag to indicate RPC has been flushed
 * @req_list: list link for higher level objects to chain requests
 *
 */

struct p9_req {
	spinlock_t lock;
	int tag;
	struct p9_fcall *tcall;
	struct p9_fcall *rcall;
	int err;
	p9_conn_req_callback cb;
	void *cba;
	int flush;
	struct list_head req_list;
};

struct p9_mux_poll_task {
	struct task_struct *task;
	struct list_head mux_list;
	int muxnum;
};

/**
 * struct p9_conn - fd mux connection state information
 * @lock: protects mux_list (?)
 * @mux_list: list link for mux to manage multiple connections (?)
 * @poll_task: task polling on this connection
 * @msize: maximum size for connection (dup)
 * @extended: 9p2000.u flag (dup)
 * @trans: reference to transport instance for this connection
 * @tagpool: id accounting for transactions
 * @err: error state
 * @req_list: accounting for requests which have been sent
 * @unsent_req_list: accounting for requests that haven't been sent
 * @rcall: current response &p9_fcall structure
 * @rpos: read position in current frame
 * @rbuf: current read buffer
 * @wpos: write position for current frame
 * @wsize: amount of data to write for current frame
 * @wbuf: current write buffer
 * @poll_wait: array of wait_q's for various worker threads
 * @poll_waddr: ????
 * @pt: poll state
 * @rq: current read work
 * @wq: current write work
 * @wsched: ????
 *
 */

struct p9_conn {
	spinlock_t lock; /* protect lock structure */
	struct list_head mux_list;
	struct p9_mux_poll_task *poll_task;
	int msize;
	unsigned char extended;
	struct p9_trans *trans;
	struct p9_idpool *tagpool;
	int err;
	struct list_head req_list;
	struct list_head unsent_req_list;
	struct p9_fcall *rcall;
	int rpos;
	char *rbuf;
	int wpos;
	int wsize;
	char *wbuf;
	wait_queue_t poll_wait[MAXPOLLWADDR];
	wait_queue_head_t *poll_waddr[MAXPOLLWADDR];
	poll_table pt;
	struct work_struct rq;
	struct work_struct wq;
	unsigned long wsched;
};

/**
 * struct p9_mux_rpc - fd mux rpc accounting structure
 * @m: connection this request was issued on
 * @err: error state
 * @tcall: request &p9_fcall
 * @rcall: response &p9_fcall
 * @wqueue: wait queue that client is blocked on for this rpc
 *
 * Bug: isn't this information duplicated elsewhere like &p9_req
 */

struct p9_mux_rpc {
	struct p9_conn *m;
	int err;
	struct p9_fcall *tcall;
	struct p9_fcall *rcall;
	wait_queue_head_t wqueue;
};

static int p9_poll_proc(void *);
static void p9_read_work(struct work_struct *work);
static void p9_write_work(struct work_struct *work);
static void p9_pollwait(struct file *filp, wait_queue_head_t *wait_address,
								poll_table *p);
static int p9_fd_write(struct p9_trans *trans, void *v, int len);
static int p9_fd_read(struct p9_trans *trans, void *v, int len);

static DEFINE_MUTEX(p9_mux_task_lock);
static struct workqueue_struct *p9_mux_wq;

static int p9_mux_num;
static int p9_mux_poll_task_num;
static struct p9_mux_poll_task p9_mux_poll_tasks[100];

static void p9_conn_destroy(struct p9_conn *);
static unsigned int p9_fd_poll(struct p9_trans *trans,
						struct poll_table_struct *pt);

#ifdef P9_NONBLOCK
static int p9_conn_rpcnb(struct p9_conn *m, struct p9_fcall *tc,
	p9_conn_req_callback cb, void *a);
#endif /* P9_NONBLOCK */

static void p9_conn_cancel(struct p9_conn *m, int err);

static u16 p9_mux_get_tag(struct p9_conn *m)
{
	int tag;

	tag = p9_idpool_get(m->tagpool);
	if (tag < 0)
		return P9_NOTAG;
	else
		return (u16) tag;
}

static void p9_mux_put_tag(struct p9_conn *m, u16 tag)
{
	if (tag != P9_NOTAG && p9_idpool_check(tag, m->tagpool))
		p9_idpool_put(tag, m->tagpool);
}

/**
 * p9_mux_calc_poll_procs - calculates the number of polling procs
 * @muxnum: number of mounts
 *
 * Calculation is based on the number of mounted v9fs filesystems.
 * The current implementation returns sqrt of the number of mounts.
 */

static int p9_mux_calc_poll_procs(int muxnum)
{
	int n;

	if (p9_mux_poll_task_num)
		n = muxnum / p9_mux_poll_task_num +
		    (muxnum % p9_mux_poll_task_num ? 1 : 0);
	else
		n = 1;

	if (n > ARRAY_SIZE(p9_mux_poll_tasks))
		n = ARRAY_SIZE(p9_mux_poll_tasks);

	return n;
}

static int p9_mux_poll_start(struct p9_conn *m)
{
	int i, n;
	struct p9_mux_poll_task *vpt, *vptlast;
	struct task_struct *pproc;

	P9_DPRINTK(P9_DEBUG_MUX, "mux %p muxnum %d procnum %d\n", m, p9_mux_num,
		p9_mux_poll_task_num);
	mutex_lock(&p9_mux_task_lock);

	n = p9_mux_calc_poll_procs(p9_mux_num + 1);
	if (n > p9_mux_poll_task_num) {
		for (i = 0; i < ARRAY_SIZE(p9_mux_poll_tasks); i++) {
			if (p9_mux_poll_tasks[i].task == NULL) {
				vpt = &p9_mux_poll_tasks[i];
				P9_DPRINTK(P9_DEBUG_MUX, "create proc %p\n",
									vpt);
				pproc = kthread_create(p9_poll_proc, vpt,
								"v9fs-poll");

				if (!IS_ERR(pproc)) {
					vpt->task = pproc;
					INIT_LIST_HEAD(&vpt->mux_list);
					vpt->muxnum = 0;
					p9_mux_poll_task_num++;
					wake_up_process(vpt->task);
				}
				break;
			}
		}

		if (i >= ARRAY_SIZE(p9_mux_poll_tasks))
			P9_DPRINTK(P9_DEBUG_ERROR,
					"warning: no free poll slots\n");
	}

	n = (p9_mux_num + 1) / p9_mux_poll_task_num +
	    ((p9_mux_num + 1) % p9_mux_poll_task_num ? 1 : 0);

	vptlast = NULL;
	for (i = 0; i < ARRAY_SIZE(p9_mux_poll_tasks); i++) {
		vpt = &p9_mux_poll_tasks[i];
		if (vpt->task != NULL) {
			vptlast = vpt;
			if (vpt->muxnum < n) {
				P9_DPRINTK(P9_DEBUG_MUX, "put in proc %d\n", i);
				list_add(&m->mux_list, &vpt->mux_list);
				vpt->muxnum++;
				m->poll_task = vpt;
				memset(&m->poll_waddr, 0,
							sizeof(m->poll_waddr));
				init_poll_funcptr(&m->pt, p9_pollwait);
				break;
			}
		}
	}

	if (i >= ARRAY_SIZE(p9_mux_poll_tasks)) {
		if (vptlast == NULL) {
			mutex_unlock(&p9_mux_task_lock);
			return -ENOMEM;
		}

		P9_DPRINTK(P9_DEBUG_MUX, "put in proc %d\n", i);
		list_add(&m->mux_list, &vptlast->mux_list);
		vptlast->muxnum++;
		m->poll_task = vptlast;
		memset(&m->poll_waddr, 0, sizeof(m->poll_waddr));
		init_poll_funcptr(&m->pt, p9_pollwait);
	}

	p9_mux_num++;
	mutex_unlock(&p9_mux_task_lock);

	return 0;
}

static void p9_mux_poll_stop(struct p9_conn *m)
{
	int i;
	struct p9_mux_poll_task *vpt;

	mutex_lock(&p9_mux_task_lock);
	vpt = m->poll_task;
	list_del(&m->mux_list);
	for (i = 0; i < ARRAY_SIZE(m->poll_waddr); i++) {
		if (m->poll_waddr[i] != NULL) {
			remove_wait_queue(m->poll_waddr[i], &m->poll_wait[i]);
			m->poll_waddr[i] = NULL;
		}
	}
	vpt->muxnum--;
	if (!vpt->muxnum) {
		P9_DPRINTK(P9_DEBUG_MUX, "destroy proc %p\n", vpt);
		kthread_stop(vpt->task);
		vpt->task = NULL;
		p9_mux_poll_task_num--;
	}
	p9_mux_num--;
	mutex_unlock(&p9_mux_task_lock);
}

/**
 * p9_conn_create - allocate and initialize the per-session mux data
 * @trans: transport structure
 *
 * Note: Creates the polling task if this is the first session.
 */

static struct p9_conn *p9_conn_create(struct p9_trans *trans)
{
	int i, n;
	struct p9_conn *m;

	P9_DPRINTK(P9_DEBUG_MUX, "transport %p msize %d\n", trans,
								trans->msize);
	m = kzalloc(sizeof(struct p9_conn), GFP_KERNEL);
	if (!m)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&m->lock);
	INIT_LIST_HEAD(&m->mux_list);
	m->msize = trans->msize;
	m->extended = trans->extended;
	m->trans = trans;
	m->tagpool = p9_idpool_create();
	if (IS_ERR(m->tagpool)) {
		kfree(m);
		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&m->req_list);
	INIT_LIST_HEAD(&m->unsent_req_list);
	INIT_WORK(&m->rq, p9_read_work);
	INIT_WORK(&m->wq, p9_write_work);
	n = p9_mux_poll_start(m);
	if (n) {
		kfree(m);
		return ERR_PTR(n);
	}

	n = p9_fd_poll(trans, &m->pt);
	if (n & POLLIN) {
		P9_DPRINTK(P9_DEBUG_MUX, "mux %p can read\n", m);
		set_bit(Rpending, &m->wsched);
	}

	if (n & POLLOUT) {
		P9_DPRINTK(P9_DEBUG_MUX, "mux %p can write\n", m);
		set_bit(Wpending, &m->wsched);
	}

	for (i = 0; i < ARRAY_SIZE(m->poll_waddr); i++) {
		if (IS_ERR(m->poll_waddr[i])) {
			p9_mux_poll_stop(m);
			kfree(m);
			return (void *)m->poll_waddr;	/* the error code */
		}
	}

	return m;
}

/**
 * p9_mux_destroy - cancels all pending requests and frees mux resources
 * @m: mux to destroy
 *
 */

static void p9_conn_destroy(struct p9_conn *m)
{
	P9_DPRINTK(P9_DEBUG_MUX, "mux %p prev %p next %p\n", m,
		m->mux_list.prev, m->mux_list.next);

	p9_mux_poll_stop(m);
	cancel_work_sync(&m->rq);
	cancel_work_sync(&m->wq);

	p9_conn_cancel(m, -ECONNRESET);

	m->trans = NULL;
	p9_idpool_destroy(m->tagpool);
	kfree(m);
}

/**
 * p9_pollwait - add poll task to the wait queue
 * @filp: file pointer being polled
 * @wait_address: wait_q to block on
 * @p: poll state
 *
 * called by files poll operation to add v9fs-poll task to files wait queue
 */

static void
p9_pollwait(struct file *filp, wait_queue_head_t *wait_address, poll_table *p)
{
	int i;
	struct p9_conn *m;

	m = container_of(p, struct p9_conn, pt);
	for (i = 0; i < ARRAY_SIZE(m->poll_waddr); i++)
		if (m->poll_waddr[i] == NULL)
			break;

	if (i >= ARRAY_SIZE(m->poll_waddr)) {
		P9_DPRINTK(P9_DEBUG_ERROR, "not enough wait_address slots\n");
		return;
	}

	m->poll_waddr[i] = wait_address;

	if (!wait_address) {
		P9_DPRINTK(P9_DEBUG_ERROR, "no wait_address\n");
		m->poll_waddr[i] = ERR_PTR(-EIO);
		return;
	}

	init_waitqueue_entry(&m->poll_wait[i], m->poll_task->task);
	add_wait_queue(wait_address, &m->poll_wait[i]);
}

/**
 * p9_poll_mux - polls a mux and schedules read or write works if necessary
 * @m: connection to poll
 *
 */

static void p9_poll_mux(struct p9_conn *m)
{
	int n;

	if (m->err < 0)
		return;

	n = p9_fd_poll(m->trans, NULL);
	if (n < 0 || n & (POLLERR | POLLHUP | POLLNVAL)) {
		P9_DPRINTK(P9_DEBUG_MUX, "error mux %p err %d\n", m, n);
		if (n >= 0)
			n = -ECONNRESET;
		p9_conn_cancel(m, n);
	}

	if (n & POLLIN) {
		set_bit(Rpending, &m->wsched);
		P9_DPRINTK(P9_DEBUG_MUX, "mux %p can read\n", m);
		if (!test_and_set_bit(Rworksched, &m->wsched)) {
			P9_DPRINTK(P9_DEBUG_MUX, "schedule read work %p\n", m);
			queue_work(p9_mux_wq, &m->rq);
		}
	}

	if (n & POLLOUT) {
		set_bit(Wpending, &m->wsched);
		P9_DPRINTK(P9_DEBUG_MUX, "mux %p can write\n", m);
		if ((m->wsize || !list_empty(&m->unsent_req_list))
		    && !test_and_set_bit(Wworksched, &m->wsched)) {
			P9_DPRINTK(P9_DEBUG_MUX, "schedule write work %p\n", m);
			queue_work(p9_mux_wq, &m->wq);
		}
	}
}

/**
 * p9_poll_proc - poll worker thread
 * @a: thread state and arguments
 *
 * polls all v9fs transports for new events and queues the appropriate
 * work to the work queue
 *
 */

static int p9_poll_proc(void *a)
{
	struct p9_conn *m, *mtmp;
	struct p9_mux_poll_task *vpt;

	vpt = a;
	P9_DPRINTK(P9_DEBUG_MUX, "start %p %p\n", current, vpt);
	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);

		list_for_each_entry_safe(m, mtmp, &vpt->mux_list, mux_list) {
			p9_poll_mux(m);
		}

		P9_DPRINTK(P9_DEBUG_MUX, "sleeping...\n");
		schedule_timeout(SCHED_TIMEOUT * HZ);
	}

	__set_current_state(TASK_RUNNING);
	P9_DPRINTK(P9_DEBUG_MUX, "finish\n");
	return 0;
}

/**
 * p9_write_work - called when a transport can send some data
 * @work: container for work to be done
 *
 */

static void p9_write_work(struct work_struct *work)
{
	int n, err;
	struct p9_conn *m;
	struct p9_req *req;

	m = container_of(work, struct p9_conn, wq);

	if (m->err < 0) {
		clear_bit(Wworksched, &m->wsched);
		return;
	}

	if (!m->wsize) {
		if (list_empty(&m->unsent_req_list)) {
			clear_bit(Wworksched, &m->wsched);
			return;
		}

		spin_lock(&m->lock);
again:
		req = list_entry(m->unsent_req_list.next, struct p9_req,
			       req_list);
		list_move_tail(&req->req_list, &m->req_list);
		if (req->err == ERREQFLUSH)
			goto again;

		m->wbuf = req->tcall->sdata;
		m->wsize = req->tcall->size;
		m->wpos = 0;
		spin_unlock(&m->lock);
	}

	P9_DPRINTK(P9_DEBUG_MUX, "mux %p pos %d size %d\n", m, m->wpos,
								m->wsize);
	clear_bit(Wpending, &m->wsched);
	err = p9_fd_write(m->trans, m->wbuf + m->wpos, m->wsize - m->wpos);
	P9_DPRINTK(P9_DEBUG_MUX, "mux %p sent %d bytes\n", m, err);
	if (err == -EAGAIN) {
		clear_bit(Wworksched, &m->wsched);
		return;
	}

	if (err < 0)
		goto error;
	else if (err == 0) {
		err = -EREMOTEIO;
		goto error;
	}

	m->wpos += err;
	if (m->wpos == m->wsize)
		m->wpos = m->wsize = 0;

	if (m->wsize == 0 && !list_empty(&m->unsent_req_list)) {
		if (test_and_clear_bit(Wpending, &m->wsched))
			n = POLLOUT;
		else
			n = p9_fd_poll(m->trans, NULL);

		if (n & POLLOUT) {
			P9_DPRINTK(P9_DEBUG_MUX, "schedule write work %p\n", m);
			queue_work(p9_mux_wq, &m->wq);
		} else
			clear_bit(Wworksched, &m->wsched);
	} else
		clear_bit(Wworksched, &m->wsched);

	return;

error:
	p9_conn_cancel(m, err);
	clear_bit(Wworksched, &m->wsched);
}

static void process_request(struct p9_conn *m, struct p9_req *req)
{
	int ecode;
	struct p9_str *ename;

	if (!req->err && req->rcall->id == P9_RERROR) {
		ecode = req->rcall->params.rerror.errno;
		ename = &req->rcall->params.rerror.error;

		P9_DPRINTK(P9_DEBUG_MUX, "Rerror %.*s\n", ename->len,
								ename->str);

		if (m->extended)
			req->err = -ecode;

		if (!req->err) {
			req->err = p9_errstr2errno(ename->str, ename->len);

			/* string match failed */
			if (!req->err) {
				PRINT_FCALL_ERROR("unknown error", req->rcall);
				req->err = -ESERVERFAULT;
			}
		}
	} else if (req->tcall && req->rcall->id != req->tcall->id + 1) {
		P9_DPRINTK(P9_DEBUG_ERROR,
				"fcall mismatch: expected %d, got %d\n",
				req->tcall->id + 1, req->rcall->id);
		if (!req->err)
			req->err = -EIO;
	}
}

/**
 * p9_read_work - called when there is some data to be read from a transport
 * @work: container of work to be done
 *
 */

static void p9_read_work(struct work_struct *work)
{
	int n, err;
	struct p9_conn *m;
	struct p9_req *req, *rptr, *rreq;
	struct p9_fcall *rcall;
	char *rbuf;

	m = container_of(work, struct p9_conn, rq);

	if (m->err < 0)
		return;

	rcall = NULL;
	P9_DPRINTK(P9_DEBUG_MUX, "start mux %p pos %d\n", m, m->rpos);

	if (!m->rcall) {
		m->rcall =
		    kmalloc(sizeof(struct p9_fcall) + m->msize, GFP_KERNEL);
		if (!m->rcall) {
			err = -ENOMEM;
			goto error;
		}

		m->rbuf = (char *)m->rcall + sizeof(struct p9_fcall);
		m->rpos = 0;
	}

	clear_bit(Rpending, &m->wsched);
	err = p9_fd_read(m->trans, m->rbuf + m->rpos, m->msize - m->rpos);
	P9_DPRINTK(P9_DEBUG_MUX, "mux %p got %d bytes\n", m, err);
	if (err == -EAGAIN) {
		clear_bit(Rworksched, &m->wsched);
		return;
	}

	if (err <= 0)
		goto error;

	m->rpos += err;
	while (m->rpos > 4) {
		n = le32_to_cpu(*(__le32 *) m->rbuf);
		if (n >= m->msize) {
			P9_DPRINTK(P9_DEBUG_ERROR,
				"requested packet size too big: %d\n", n);
			err = -EIO;
			goto error;
		}

		if (m->rpos < n)
			break;

		err =
		    p9_deserialize_fcall(m->rbuf, n, m->rcall, m->extended);
		if (err < 0)
			goto error;

#ifdef CONFIG_NET_9P_DEBUG
		if ((p9_debug_level&P9_DEBUG_FCALL) == P9_DEBUG_FCALL) {
			char buf[150];

			p9_printfcall(buf, sizeof(buf), m->rcall,
				m->extended);
			printk(KERN_NOTICE ">>> %p %s\n", m, buf);
		}
#endif

		rcall = m->rcall;
		rbuf = m->rbuf;
		if (m->rpos > n) {
			m->rcall = kmalloc(sizeof(struct p9_fcall) + m->msize,
					   GFP_KERNEL);
			if (!m->rcall) {
				err = -ENOMEM;
				goto error;
			}

			m->rbuf = (char *)m->rcall + sizeof(struct p9_fcall);
			memmove(m->rbuf, rbuf + n, m->rpos - n);
			m->rpos -= n;
		} else {
			m->rcall = NULL;
			m->rbuf = NULL;
			m->rpos = 0;
		}

		P9_DPRINTK(P9_DEBUG_MUX, "mux %p fcall id %d tag %d\n", m,
							rcall->id, rcall->tag);

		req = NULL;
		spin_lock(&m->lock);
		list_for_each_entry_safe(rreq, rptr, &m->req_list, req_list) {
			if (rreq->tag == rcall->tag) {
				req = rreq;
				if (req->flush != Flushing)
					list_del(&req->req_list);
				break;
			}
		}
		spin_unlock(&m->lock);

		if (req) {
			req->rcall = rcall;
			process_request(m, req);

			if (req->flush != Flushing) {
				if (req->cb)
					(*req->cb) (req, req->cba);
				else
					kfree(req->rcall);
			}
		} else {
			if (err >= 0 && rcall->id != P9_RFLUSH)
				P9_DPRINTK(P9_DEBUG_ERROR,
				  "unexpected response mux %p id %d tag %d\n",
				  m, rcall->id, rcall->tag);
			kfree(rcall);
		}
	}

	if (!list_empty(&m->req_list)) {
		if (test_and_clear_bit(Rpending, &m->wsched))
			n = POLLIN;
		else
			n = p9_fd_poll(m->trans, NULL);

		if (n & POLLIN) {
			P9_DPRINTK(P9_DEBUG_MUX, "schedule read work %p\n", m);
			queue_work(p9_mux_wq, &m->rq);
		} else
			clear_bit(Rworksched, &m->wsched);
	} else
		clear_bit(Rworksched, &m->wsched);

	return;

error:
	p9_conn_cancel(m, err);
	clear_bit(Rworksched, &m->wsched);
}

/**
 * p9_send_request - send 9P request
 * The function can sleep until the request is scheduled for sending.
 * The function can be interrupted. Return from the function is not
 * a guarantee that the request is sent successfully. Can return errors
 * that can be retrieved by PTR_ERR macros.
 *
 * @m: mux data
 * @tc: request to be sent
 * @cb: callback function to call when response is received
 * @cba: parameter to pass to the callback function
 *
 */

static struct p9_req *p9_send_request(struct p9_conn *m,
					  struct p9_fcall *tc,
					  p9_conn_req_callback cb, void *cba)
{
	int n;
	struct p9_req *req;

	P9_DPRINTK(P9_DEBUG_MUX, "mux %p task %p tcall %p id %d\n", m, current,
		tc, tc->id);
	if (m->err < 0)
		return ERR_PTR(m->err);

	req = kmalloc(sizeof(struct p9_req), GFP_KERNEL);
	if (!req)
		return ERR_PTR(-ENOMEM);

	if (tc->id == P9_TVERSION)
		n = P9_NOTAG;
	else
		n = p9_mux_get_tag(m);

	if (n < 0) {
		kfree(req);
		return ERR_PTR(-ENOMEM);
	}

	p9_set_tag(tc, n);

#ifdef CONFIG_NET_9P_DEBUG
	if ((p9_debug_level&P9_DEBUG_FCALL) == P9_DEBUG_FCALL) {
		char buf[150];

		p9_printfcall(buf, sizeof(buf), tc, m->extended);
		printk(KERN_NOTICE "<<< %p %s\n", m, buf);
	}
#endif

	spin_lock_init(&req->lock);
	req->tag = n;
	req->tcall = tc;
	req->rcall = NULL;
	req->err = 0;
	req->cb = cb;
	req->cba = cba;
	req->flush = None;

	spin_lock(&m->lock);
	list_add_tail(&req->req_list, &m->unsent_req_list);
	spin_unlock(&m->lock);

	if (test_and_clear_bit(Wpending, &m->wsched))
		n = POLLOUT;
	else
		n = p9_fd_poll(m->trans, NULL);

	if (n & POLLOUT && !test_and_set_bit(Wworksched, &m->wsched))
		queue_work(p9_mux_wq, &m->wq);

	return req;
}

static void p9_mux_free_request(struct p9_conn *m, struct p9_req *req)
{
	p9_mux_put_tag(m, req->tag);
	kfree(req);
}

static void p9_mux_flush_cb(struct p9_req *freq, void *a)
{
	int tag;
	struct p9_conn *m;
	struct p9_req *req, *rreq, *rptr;

	m = a;
	P9_DPRINTK(P9_DEBUG_MUX, "mux %p tc %p rc %p err %d oldtag %d\n", m,
		freq->tcall, freq->rcall, freq->err,
		freq->tcall->params.tflush.oldtag);

	spin_lock(&m->lock);
	tag = freq->tcall->params.tflush.oldtag;
	req = NULL;
	list_for_each_entry_safe(rreq, rptr, &m->req_list, req_list) {
		if (rreq->tag == tag) {
			req = rreq;
			list_del(&req->req_list);
			break;
		}
	}
	spin_unlock(&m->lock);

	if (req) {
		spin_lock(&req->lock);
		req->flush = Flushed;
		spin_unlock(&req->lock);

		if (req->cb)
			(*req->cb) (req, req->cba);
		else
			kfree(req->rcall);
	}

	kfree(freq->tcall);
	kfree(freq->rcall);
	p9_mux_free_request(m, freq);
}

static int
p9_mux_flush_request(struct p9_conn *m, struct p9_req *req)
{
	struct p9_fcall *fc;
	struct p9_req *rreq, *rptr;

	P9_DPRINTK(P9_DEBUG_MUX, "mux %p req %p tag %d\n", m, req, req->tag);

	/* if a response was received for a request, do nothing */
	spin_lock(&req->lock);
	if (req->rcall || req->err) {
		spin_unlock(&req->lock);
		P9_DPRINTK(P9_DEBUG_MUX,
			"mux %p req %p response already received\n", m, req);
		return 0;
	}

	req->flush = Flushing;
	spin_unlock(&req->lock);

	spin_lock(&m->lock);
	/* if the request is not sent yet, just remove it from the list */
	list_for_each_entry_safe(rreq, rptr, &m->unsent_req_list, req_list) {
		if (rreq->tag == req->tag) {
			P9_DPRINTK(P9_DEBUG_MUX,
			   "mux %p req %p request is not sent yet\n", m, req);
			list_del(&rreq->req_list);
			req->flush = Flushed;
			spin_unlock(&m->lock);
			if (req->cb)
				(*req->cb) (req, req->cba);
			return 0;
		}
	}
	spin_unlock(&m->lock);

	clear_thread_flag(TIF_SIGPENDING);
	fc = p9_create_tflush(req->tag);
	p9_send_request(m, fc, p9_mux_flush_cb, m);
	return 1;
}

static void
p9_conn_rpc_cb(struct p9_req *req, void *a)
{
	struct p9_mux_rpc *r;

	P9_DPRINTK(P9_DEBUG_MUX, "req %p r %p\n", req, a);
	r = a;
	r->rcall = req->rcall;
	r->err = req->err;

	if (req->flush != None && !req->err)
		r->err = -ERESTARTSYS;

	wake_up(&r->wqueue);
}

/**
 * p9_fd_rpc- sends 9P request and waits until a response is available.
 *	The function can be interrupted.
 * @t: transport data
 * @tc: request to be sent
 * @rc: pointer where a pointer to the response is stored
 *
 */

int
p9_fd_rpc(struct p9_trans *t, struct p9_fcall *tc, struct p9_fcall **rc)
{
	struct p9_trans_fd *p = t->priv;
	struct p9_conn *m = p->conn;
	int err, sigpending;
	unsigned long flags;
	struct p9_req *req;
	struct p9_mux_rpc r;

	r.err = 0;
	r.tcall = tc;
	r.rcall = NULL;
	r.m = m;
	init_waitqueue_head(&r.wqueue);

	if (rc)
		*rc = NULL;

	sigpending = 0;
	if (signal_pending(current)) {
		sigpending = 1;
		clear_thread_flag(TIF_SIGPENDING);
	}

	req = p9_send_request(m, tc, p9_conn_rpc_cb, &r);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		P9_DPRINTK(P9_DEBUG_MUX, "error %d\n", err);
		return err;
	}

	err = wait_event_interruptible(r.wqueue, r.rcall != NULL || r.err < 0);
	if (r.err < 0)
		err = r.err;

	if (err == -ERESTARTSYS && m->trans->status == Connected
							&& m->err == 0) {
		if (p9_mux_flush_request(m, req)) {
			/* wait until we get response of the flush message */
			do {
				clear_thread_flag(TIF_SIGPENDING);
				err = wait_event_interruptible(r.wqueue,
					r.rcall || r.err);
			} while (!r.rcall && !r.err && err == -ERESTARTSYS &&
				m->trans->status == Connected && !m->err);

			err = -ERESTARTSYS;
		}
		sigpending = 1;
	}

	if (sigpending) {
		spin_lock_irqsave(&current->sighand->siglock, flags);
		recalc_sigpending();
		spin_unlock_irqrestore(&current->sighand->siglock, flags);
	}

	if (rc)
		*rc = r.rcall;
	else
		kfree(r.rcall);

	p9_mux_free_request(m, req);
	if (err > 0)
		err = -EIO;

	return err;
}

#ifdef P9_NONBLOCK
/**
 * p9_conn_rpcnb - sends 9P request without waiting for response.
 * @m: mux data
 * @tc: request to be sent
 * @cb: callback function to be called when response arrives
 * @a: value to pass to the callback function
 *
 */

int p9_conn_rpcnb(struct p9_conn *m, struct p9_fcall *tc,
		   p9_conn_req_callback cb, void *a)
{
	int err;
	struct p9_req *req;

	req = p9_send_request(m, tc, cb, a);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		P9_DPRINTK(P9_DEBUG_MUX, "error %d\n", err);
		return PTR_ERR(req);
	}

	P9_DPRINTK(P9_DEBUG_MUX, "mux %p tc %p tag %d\n", m, tc, req->tag);
	return 0;
}
#endif /* P9_NONBLOCK */

	struct p9_conn conn;
};

static void p9_poll_workfn(struct work_struct *work);

static DEFINE_SPINLOCK(p9_poll_lock);
static LIST_HEAD(p9_poll_pending_list);
static DECLARE_WORK(p9_poll_work, p9_poll_workfn);

static unsigned int p9_ipport_resv_min = P9_DEF_MIN_RESVPORT;
static unsigned int p9_ipport_resv_max = P9_DEF_MAX_RESVPORT;

static void p9_mux_poll_stop(struct p9_conn *m)
{
	unsigned long flags;
	int i;

	for (i = 0; i < ARRAY_SIZE(m->poll_wait); i++) {
		struct p9_poll_wait *pwait = &m->poll_wait[i];

		if (pwait->wait_addr) {
			remove_wait_queue(pwait->wait_addr, &pwait->wait);
			pwait->wait_addr = NULL;
		}
	}

	spin_lock_irqsave(&p9_poll_lock, flags);
	list_del_init(&m->poll_pending_link);
	spin_unlock_irqrestore(&p9_poll_lock, flags);

	flush_work(&p9_poll_work);
}

/**
 * p9_conn_cancel - cancel all pending requests with error
 * @m: mux data
 * @err: error code
 *
 */

void p9_conn_cancel(struct p9_conn *m, int err)
{
	struct p9_req *req, *rtmp;
	LIST_HEAD(cancel_list);

	P9_DPRINTK(P9_DEBUG_ERROR, "mux %p err %d\n", m, err);
	m->err = err;
	spin_lock(&m->lock);
static void p9_conn_cancel(struct p9_conn *m, int err)
{
	struct p9_req_t *req, *rtmp;
	LIST_HEAD(cancel_list);

	p9_debug(P9_DEBUG_ERROR, "mux %p err %d\n", m, err);

	spin_lock(&m->client->lock);

	if (m->err) {
		spin_unlock(&m->client->lock);
		return;
	}

	m->err = err;

	list_for_each_entry_safe(req, rtmp, &m->req_list, req_list) {
		list_move(&req->req_list, &cancel_list);
	}
	list_for_each_entry_safe(req, rtmp, &m->unsent_req_list, req_list) {
		list_move(&req->req_list, &cancel_list);
	}
	spin_unlock(&m->lock);

	list_for_each_entry_safe(req, rtmp, &cancel_list, req_list) {
		list_del(&req->req_list);
		if (!req->err)
			req->err = err;

		if (req->cb)
			(*req->cb) (req, req->cba);
		else
			kfree(req->rcall);
	}
}

/**
 * parse_options - parse mount options into session structure
 * @options: options string passed from mount
 * @opts: transport-specific structure to parse options into
 *
 * Returns 0 upon success, -ERRNO upon failure
 */

static int parse_opts(char *params, struct p9_fd_opts *opts)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int option;
	char *options;
	int ret;

	opts->port = P9_PORT;
	opts->rfd = ~0;
	opts->wfd = ~0;

	if (!params)
		return 0;

	options = kstrdup(params, GFP_KERNEL);
	if (!options) {
		P9_DPRINTK(P9_DEBUG_ERROR,
				"failed to allocate copy of option string\n");
		return -ENOMEM;
	}

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		int r;
		if (!*p)
			continue;
		token = match_token(p, tokens, args);
		r = match_int(&args[0], &option);
		if (r < 0) {
			P9_DPRINTK(P9_DEBUG_ERROR,
			 "integer field, but no integer?\n");
			ret = r;
			continue;
		}
		switch (token) {
		case Opt_port:
			opts->port = option;
			break;
		case Opt_rfdno:
			opts->rfd = option;
			break;
		case Opt_wfdno:
			opts->wfd = option;
			break;
		default:
			continue;
		}
	}
	kfree(options);
	return 0;
}

static int p9_fd_open(struct p9_trans *trans, int rfd, int wfd)
{
	struct p9_trans_fd *ts = kmalloc(sizeof(struct p9_trans_fd),
					   GFP_KERNEL);
	if (!ts)
		return -ENOMEM;

	ts->rd = fget(rfd);
	ts->wr = fget(wfd);
	if (!ts->rd || !ts->wr) {
		if (ts->rd)
			fput(ts->rd);
		if (ts->wr)
			fput(ts->wr);
		kfree(ts);
		return -EIO;
	}

	trans->priv = ts;
	trans->status = Connected;

	return 0;
}

static int p9_socket_open(struct p9_trans *trans, struct socket *csocket)
{
	int fd, ret;

	csocket->sk->sk_allocation = GFP_NOIO;
	fd = sock_map_fd(csocket, 0);
	if (fd < 0) {
		P9_EPRINTK(KERN_ERR, "p9_socket_open: failed to map fd\n");
		return fd;
	}

	ret = p9_fd_open(trans, fd, fd);
	if (ret < 0) {
		P9_EPRINTK(KERN_ERR, "p9_socket_open: failed to open fd\n");
		sockfd_put(csocket);
		return ret;
	}

	((struct p9_trans_fd *)trans->priv)->rd->f_flags |= O_NONBLOCK;

	return 0;
}

/**
 * p9_fd_read- read from a fd
 * @trans: transport instance state
 * @v: buffer to receive data into
 * @len: size of receive buffer
 *
 */

static int p9_fd_read(struct p9_trans *trans, void *v, int len)
{
	int ret;
	struct p9_trans_fd *ts = NULL;

	if (trans && trans->status != Disconnected)
		ts = trans->priv;

	if (!ts)
		return -EREMOTEIO;

	if (!(ts->rd->f_flags & O_NONBLOCK))
		P9_DPRINTK(P9_DEBUG_ERROR, "blocking read ...\n");

	ret = kernel_read(ts->rd, ts->rd->f_pos, v, len);
	if (ret <= 0 && ret != -ERESTARTSYS && ret != -EAGAIN)
		trans->status = Disconnected;
	return ret;
}

/**
 * p9_fd_write - write to a socket
 * @trans: transport instance state
 * @v: buffer to send data from
 * @len: size of send buffer
 *
 */

static int p9_fd_write(struct p9_trans *trans, void *v, int len)
{
	int ret;
	mm_segment_t oldfs;
	struct p9_trans_fd *ts = NULL;

	if (trans && trans->status != Disconnected)
		ts = trans->priv;

	if (!ts)
		return -EREMOTEIO;

	if (!(ts->wr->f_flags & O_NONBLOCK))
		P9_DPRINTK(P9_DEBUG_ERROR, "blocking write ...\n");

	oldfs = get_fs();
	set_fs(get_ds());
	/* The cast to a user pointer is valid due to the set_fs() */
	ret = vfs_write(ts->wr, (void __user *)v, len, &ts->wr->f_pos);
	set_fs(oldfs);

	if (ret <= 0 && ret != -ERESTARTSYS && ret != -EAGAIN)
		trans->status = Disconnected;
	return ret;
}

static unsigned int
p9_fd_poll(struct p9_trans *trans, struct poll_table_struct *pt)
	spin_unlock_irqrestore(&m->client->lock, flags);

	list_for_each_entry_safe(req, rtmp, &cancel_list, req_list) {
		p9_debug(P9_DEBUG_ERROR, "call back req %p\n", req);
		list_del(&req->req_list);
		if (!req->t_err)
			req->t_err = err;
		p9_client_cb(m->client, req, REQ_STATUS_ERROR);
	}
	spin_unlock(&m->client->lock);
}

static __poll_t
p9_fd_poll(struct p9_client *client, struct poll_table_struct *pt, int *err)
{
	__poll_t ret;
	struct p9_trans_fd *ts = NULL;

	if (trans && trans->status == Connected)
		ts = trans->priv;
	if (client && client->status == Connected)
		ts = client->trans;

	if (!ts)
		return -EREMOTEIO;

	if (!ts->rd->f_op || !ts->rd->f_op->poll)
		return -EIO;

	if (!ts->wr->f_op || !ts->wr->f_op->poll)
	if (!ts->rd->f_op->poll)
		return -EIO;

	if (!ts->wr->f_op->poll)
		return -EIO;

	ret = ts->rd->f_op->poll(ts->rd, pt);
	if (ret < 0)
		return ret;

	if (ts->rd != ts->wr) {
		n = ts->wr->f_op->poll(ts->wr, pt);
		if (n < 0)
			return n;
		ret = (ret & ~POLLOUT) | (n & ~POLLIN);
	if (!ts) {
		if (err)
			*err = -EREMOTEIO;
		return EPOLLERR;
	}

	ret = vfs_poll(ts->rd, pt);
	if (ts->rd != ts->wr)
		ret = (ret & ~EPOLLOUT) | (vfs_poll(ts->wr, pt) & ~EPOLLIN);
	return ret;
}

/**
 * p9_fd_close - shutdown socket
 * @trans: private socket structure
 *
 */

static void p9_fd_close(struct p9_trans *trans)
{
	struct p9_trans_fd *ts;

	if (!trans)
		return;

	ts = xchg(&trans->priv, NULL);

	if (!ts)
		return;

	p9_conn_destroy(ts->conn);

	trans->status = Disconnected;
 * p9_fd_read- read from a fd
 * @client: client instance
 * @v: buffer to receive data into
 * @len: size of receive buffer
 *
 */

static int p9_fd_read(struct p9_client *client, void *v, int len)
{
	int ret;
	struct p9_trans_fd *ts = NULL;
	loff_t pos;

	if (client && client->status != Disconnected)
		ts = client->trans;

	if (!ts)
		return -EREMOTEIO;

	if (!(ts->rd->f_flags & O_NONBLOCK))
		p9_debug(P9_DEBUG_ERROR, "blocking read ...\n");

	pos = ts->rd->f_pos;
	ret = kernel_read(ts->rd, v, len, &pos);
	if (ret <= 0 && ret != -ERESTARTSYS && ret != -EAGAIN)
		client->status = Disconnected;
	return ret;
}

/**
 * p9_read_work - called when there is some data to be read from a transport
 * @work: container of work to be done
 *
 */

static void p9_read_work(struct work_struct *work)
{
	__poll_t n;
	int err;
	struct p9_conn *m;
	int status = REQ_STATUS_ERROR;

	m = container_of(work, struct p9_conn, rq);

	if (m->err < 0)
		return;

	p9_debug(P9_DEBUG_TRANS, "start mux %p pos %zd\n", m, m->rc.offset);

	if (!m->rc.sdata) {
		m->rc.sdata = m->tmp_buf;
		m->rc.offset = 0;
		m->rc.capacity = 7; /* start by reading header */
	}

	clear_bit(Rpending, &m->wsched);
	p9_debug(P9_DEBUG_TRANS, "read mux %p pos %zd size: %zd = %zd\n",
		 m, m->rc.offset, m->rc.capacity,
		 m->rc.capacity - m->rc.offset);
	err = p9_fd_read(m->client, m->rc.sdata + m->rc.offset,
			 m->rc.capacity - m->rc.offset);
	p9_debug(P9_DEBUG_TRANS, "mux %p got %d bytes\n", m, err);
	if (err == -EAGAIN)
		goto end_clear;

	if (err <= 0)
		goto error;

	m->rc.offset += err;

	/* header read in */
	if ((!m->req) && (m->rc.offset == m->rc.capacity)) {
		p9_debug(P9_DEBUG_TRANS, "got new header\n");

		/* Header size */
		m->rc.size = 7;
		err = p9_parse_header(&m->rc, &m->rc.size, NULL, NULL, 0);
		if (err) {
			p9_debug(P9_DEBUG_ERROR,
				 "error parsing header: %d\n", err);
			goto error;
		}

		if (m->rc.size >= m->client->msize) {
			p9_debug(P9_DEBUG_ERROR,
				 "requested packet size too big: %d\n",
				 m->rc.size);
			err = -EIO;
			goto error;
		}

		p9_debug(P9_DEBUG_TRANS,
			 "mux %p pkt: size: %d bytes tag: %d\n",
			 m, m->rc.size, m->rc.tag);

		m->req = p9_tag_lookup(m->client, m->rc.tag);
		if (!m->req || (m->req->status != REQ_STATUS_SENT)) {
			p9_debug(P9_DEBUG_ERROR, "Unexpected packet tag %d\n",
				 m->rc.tag);
			err = -EIO;
			goto error;
		}

		if (m->req->rc == NULL) {
			p9_debug(P9_DEBUG_ERROR,
				 "No recv fcall for tag %d (req %p), disconnecting!\n",
				 m->rc.tag, m->req);
			m->req = NULL;
			err = -EIO;
			goto error;
		}
		m->rc.sdata = (char *)m->req->rc + sizeof(struct p9_fcall);
		memcpy(m->rc.sdata, m->tmp_buf, m->rc.capacity);
		m->rc.capacity = m->rc.size;
	}

	/* packet is read in
	 * not an else because some packets (like clunk) have no payload
	 */
	if ((m->req) && (m->rc.offset == m->rc.capacity)) {
		p9_debug(P9_DEBUG_TRANS, "got new packet\n");
		m->req->rc->size = m->rc.offset;
		spin_lock(&m->client->lock);
		if (m->req->status != REQ_STATUS_ERROR)
			status = REQ_STATUS_RCVD;
		list_del(&m->req->req_list);
		/* update req->status while holding client->lock  */
		p9_client_cb(m->client, m->req, status);
		spin_unlock(&m->client->lock);
		m->rc.sdata = NULL;
		m->rc.offset = 0;
		m->rc.capacity = 0;
		m->req = NULL;
	}

end_clear:
	clear_bit(Rworksched, &m->wsched);

	if (!list_empty(&m->req_list)) {
		if (test_and_clear_bit(Rpending, &m->wsched))
			n = EPOLLIN;
		else
			n = p9_fd_poll(m->client, NULL, NULL);

		if ((n & EPOLLIN) && !test_and_set_bit(Rworksched, &m->wsched)) {
			p9_debug(P9_DEBUG_TRANS, "sched read work %p\n", m);
			schedule_work(&m->rq);
		}
	}

	return;
error:
	p9_conn_cancel(m, err);
	clear_bit(Rworksched, &m->wsched);
}

/**
 * p9_fd_write - write to a socket
 * @client: client instance
 * @v: buffer to send data from
 * @len: size of send buffer
 *
 */

static int p9_fd_write(struct p9_client *client, void *v, int len)
{
	ssize_t ret;
	struct p9_trans_fd *ts = NULL;

	if (client && client->status != Disconnected)
		ts = client->trans;

	if (!ts)
		return -EREMOTEIO;

	if (!(ts->wr->f_flags & O_NONBLOCK))
		p9_debug(P9_DEBUG_ERROR, "blocking write ...\n");

	ret = kernel_write(ts->wr, v, len, &ts->wr->f_pos);
	if (ret <= 0 && ret != -ERESTARTSYS && ret != -EAGAIN)
		client->status = Disconnected;
	return ret;
}

/**
 * p9_write_work - called when a transport can send some data
 * @work: container for work to be done
 *
 */

static void p9_write_work(struct work_struct *work)
{
	__poll_t n;
	int err;
	struct p9_conn *m;
	struct p9_req_t *req;

	m = container_of(work, struct p9_conn, wq);

	if (m->err < 0) {
		clear_bit(Wworksched, &m->wsched);
		return;
	}

	if (!m->wsize) {
		spin_lock(&m->client->lock);
		if (list_empty(&m->unsent_req_list)) {
			clear_bit(Wworksched, &m->wsched);
			spin_unlock(&m->client->lock);
			return;
		}

		req = list_entry(m->unsent_req_list.next, struct p9_req_t,
			       req_list);
		req->status = REQ_STATUS_SENT;
		p9_debug(P9_DEBUG_TRANS, "move req %p\n", req);
		list_move_tail(&req->req_list, &m->req_list);

		m->wbuf = req->tc->sdata;
		m->wsize = req->tc->size;
		m->wpos = 0;
		spin_unlock(&m->client->lock);
	}

	p9_debug(P9_DEBUG_TRANS, "mux %p pos %d size %d\n",
		 m, m->wpos, m->wsize);
	clear_bit(Wpending, &m->wsched);
	err = p9_fd_write(m->client, m->wbuf + m->wpos, m->wsize - m->wpos);
	p9_debug(P9_DEBUG_TRANS, "mux %p sent %d bytes\n", m, err);
	if (err == -EAGAIN)
		goto end_clear;


	if (err < 0)
		goto error;
	else if (err == 0) {
		err = -EREMOTEIO;
		goto error;
	}

	m->wpos += err;
	if (m->wpos == m->wsize)
		m->wpos = m->wsize = 0;

end_clear:
	clear_bit(Wworksched, &m->wsched);

	if (m->wsize || !list_empty(&m->unsent_req_list)) {
		if (test_and_clear_bit(Wpending, &m->wsched))
			n = EPOLLOUT;
		else
			n = p9_fd_poll(m->client, NULL, NULL);

		if ((n & EPOLLOUT) &&
		   !test_and_set_bit(Wworksched, &m->wsched)) {
			p9_debug(P9_DEBUG_TRANS, "sched write work %p\n", m);
			schedule_work(&m->wq);
		}
	}

	return;

error:
	p9_conn_cancel(m, err);
	clear_bit(Wworksched, &m->wsched);
}

static int p9_pollwake(wait_queue_entry_t *wait, unsigned int mode, int sync, void *key)
{
	struct p9_poll_wait *pwait =
		container_of(wait, struct p9_poll_wait, wait);
	struct p9_conn *m = pwait->conn;
	unsigned long flags;

	spin_lock_irqsave(&p9_poll_lock, flags);
	if (list_empty(&m->poll_pending_link))
		list_add_tail(&m->poll_pending_link, &p9_poll_pending_list);
	spin_unlock_irqrestore(&p9_poll_lock, flags);

	schedule_work(&p9_poll_work);
	return 1;
}

/**
 * p9_pollwait - add poll task to the wait queue
 * @filp: file pointer being polled
 * @wait_address: wait_q to block on
 * @p: poll state
 *
 * called by files poll operation to add v9fs-poll task to files wait queue
 */

static void
p9_pollwait(struct file *filp, wait_queue_head_t *wait_address, poll_table *p)
{
	struct p9_conn *m = container_of(p, struct p9_conn, pt);
	struct p9_poll_wait *pwait = NULL;
	int i;

	for (i = 0; i < ARRAY_SIZE(m->poll_wait); i++) {
		if (m->poll_wait[i].wait_addr == NULL) {
			pwait = &m->poll_wait[i];
			break;
		}
	}

	if (!pwait) {
		p9_debug(P9_DEBUG_ERROR, "not enough wait_address slots\n");
		return;
	}

	pwait->conn = m;
	pwait->wait_addr = wait_address;
	init_waitqueue_func_entry(&pwait->wait, p9_pollwake);
	add_wait_queue(wait_address, &pwait->wait);
}

/**
 * p9_conn_create - initialize the per-session mux data
 * @client: client instance
 *
 * Note: Creates the polling task if this is the first session.
 */

static void p9_conn_create(struct p9_client *client)
{
	__poll_t n;
	struct p9_trans_fd *ts = client->trans;
	struct p9_conn *m = &ts->conn;

	p9_debug(P9_DEBUG_TRANS, "client %p msize %d\n", client, client->msize);

	INIT_LIST_HEAD(&m->mux_list);
	m->client = client;

	INIT_LIST_HEAD(&m->req_list);
	INIT_LIST_HEAD(&m->unsent_req_list);
	INIT_WORK(&m->rq, p9_read_work);
	INIT_WORK(&m->wq, p9_write_work);
	INIT_LIST_HEAD(&m->poll_pending_link);
	init_poll_funcptr(&m->pt, p9_pollwait);

	n = p9_fd_poll(client, &m->pt, NULL);
	if (n & EPOLLIN) {
		p9_debug(P9_DEBUG_TRANS, "mux %p can read\n", m);
		set_bit(Rpending, &m->wsched);
	}

	if (n & EPOLLOUT) {
		p9_debug(P9_DEBUG_TRANS, "mux %p can write\n", m);
		set_bit(Wpending, &m->wsched);
	}
}

/**
 * p9_poll_mux - polls a mux and schedules read or write works if necessary
 * @m: connection to poll
 *
 */

static void p9_poll_mux(struct p9_conn *m)
{
	__poll_t n;
	int err = -ECONNRESET;

	if (m->err < 0)
		return;

	n = p9_fd_poll(m->client, NULL, &err);
	if (n & (EPOLLERR | EPOLLHUP | EPOLLNVAL)) {
		p9_debug(P9_DEBUG_TRANS, "error mux %p err %d\n", m, n);
		p9_conn_cancel(m, err);
	}

	if (n & EPOLLIN) {
		set_bit(Rpending, &m->wsched);
		p9_debug(P9_DEBUG_TRANS, "mux %p can read\n", m);
		if (!test_and_set_bit(Rworksched, &m->wsched)) {
			p9_debug(P9_DEBUG_TRANS, "sched read work %p\n", m);
			schedule_work(&m->rq);
		}
	}

	if (n & EPOLLOUT) {
		set_bit(Wpending, &m->wsched);
		p9_debug(P9_DEBUG_TRANS, "mux %p can write\n", m);
		if ((m->wsize || !list_empty(&m->unsent_req_list)) &&
		    !test_and_set_bit(Wworksched, &m->wsched)) {
			p9_debug(P9_DEBUG_TRANS, "sched write work %p\n", m);
			schedule_work(&m->wq);
		}
	}
}

/**
 * p9_fd_request - send 9P request
 * The function can sleep until the request is scheduled for sending.
 * The function can be interrupted. Return from the function is not
 * a guarantee that the request is sent successfully.
 *
 * @client: client instance
 * @req: request to be sent
 *
 */

static int p9_fd_request(struct p9_client *client, struct p9_req_t *req)
{
	__poll_t n;
	struct p9_trans_fd *ts = client->trans;
	struct p9_conn *m = &ts->conn;

	p9_debug(P9_DEBUG_TRANS, "mux %p task %p tcall %p id %d\n",
		 m, current, req->tc, req->tc->id);
	if (m->err < 0)
		return m->err;

	spin_lock(&client->lock);
	req->status = REQ_STATUS_UNSENT;
	list_add_tail(&req->req_list, &m->unsent_req_list);
	spin_unlock(&client->lock);

	if (test_and_clear_bit(Wpending, &m->wsched))
		n = EPOLLOUT;
	else
		n = p9_fd_poll(m->client, NULL, NULL);

	if (n & EPOLLOUT && !test_and_set_bit(Wworksched, &m->wsched))
		schedule_work(&m->wq);

	return 0;
}

static int p9_fd_cancel(struct p9_client *client, struct p9_req_t *req)
{
	int ret = 1;

	p9_debug(P9_DEBUG_TRANS, "client %p req %p\n", client, req);

	spin_lock(&client->lock);

	if (req->status == REQ_STATUS_UNSENT) {
		list_del(&req->req_list);
		req->status = REQ_STATUS_FLSHD;
		ret = 0;
	}
	spin_unlock(&client->lock);

	return ret;
}

static int p9_fd_cancelled(struct p9_client *client, struct p9_req_t *req)
{
	p9_debug(P9_DEBUG_TRANS, "client %p req %p\n", client, req);

	/* we haven't received a response for oldreq,
	 * remove it from the list.
	 */
	spin_lock(&client->lock);
	list_del(&req->req_list);
	spin_unlock(&client->lock);

	return 0;
}

static int p9_fd_show_options(struct seq_file *m, struct p9_client *clnt)
{
	if (clnt->trans_mod == &p9_tcp_trans) {
		if (clnt->trans_opts.tcp.port != P9_PORT)
			seq_printf(m, ",port=%u", clnt->trans_opts.tcp.port);
	} else if (clnt->trans_mod == &p9_fd_trans) {
		if (clnt->trans_opts.fd.rfd != ~0)
			seq_printf(m, ",rfd=%u", clnt->trans_opts.fd.rfd);
		if (clnt->trans_opts.fd.wfd != ~0)
			seq_printf(m, ",wfd=%u", clnt->trans_opts.fd.wfd);
	}
	return 0;
}

/**
 * parse_opts - parse mount options into p9_fd_opts structure
 * @params: options string passed from mount
 * @opts: fd transport-specific structure to parse options into
 *
 * Returns 0 upon success, -ERRNO upon failure
 */

static int parse_opts(char *params, struct p9_fd_opts *opts)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int option;
	char *options, *tmp_options;

	opts->port = P9_PORT;
	opts->rfd = ~0;
	opts->wfd = ~0;
	opts->privport = false;

	if (!params)
		return 0;

	tmp_options = kstrdup(params, GFP_KERNEL);
	if (!tmp_options) {
		p9_debug(P9_DEBUG_ERROR,
			 "failed to allocate copy of option string\n");
		return -ENOMEM;
	}
	options = tmp_options;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		int r;
		if (!*p)
			continue;
		token = match_token(p, tokens, args);
		if ((token != Opt_err) && (token != Opt_privport)) {
			r = match_int(&args[0], &option);
			if (r < 0) {
				p9_debug(P9_DEBUG_ERROR,
					 "integer field, but no integer?\n");
				continue;
			}
		}
		switch (token) {
		case Opt_port:
			opts->port = option;
			break;
		case Opt_rfdno:
			opts->rfd = option;
			break;
		case Opt_wfdno:
			opts->wfd = option;
			break;
		case Opt_privport:
			opts->privport = true;
			break;
		default:
			continue;
		}
	}

	kfree(tmp_options);
	return 0;
}

static int p9_fd_open(struct p9_client *client, int rfd, int wfd)
{
	struct p9_trans_fd *ts = kzalloc(sizeof(struct p9_trans_fd),
					   GFP_KERNEL);
	if (!ts)
		return -ENOMEM;

	ts->rd = fget(rfd);
	ts->wr = fget(wfd);
	if (!ts->rd || !ts->wr) {
		if (ts->rd)
			fput(ts->rd);
		if (ts->wr)
			fput(ts->wr);
		kfree(ts);
		return -EIO;
	}

	client->trans = ts;
	client->status = Connected;

	return 0;
}

static int p9_socket_open(struct p9_client *client, struct socket *csocket)
{
	struct p9_trans_fd *p;
	struct file *file;

	p = kzalloc(sizeof(struct p9_trans_fd), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	csocket->sk->sk_allocation = GFP_NOIO;
	file = sock_alloc_file(csocket, 0, NULL);
	if (IS_ERR(file)) {
		pr_err("%s (%d): failed to map fd\n",
		       __func__, task_pid_nr(current));
		kfree(p);
		return PTR_ERR(file);
	}

	get_file(file);
	p->wr = p->rd = file;
	client->trans = p;
	client->status = Connected;

	p->rd->f_flags |= O_NONBLOCK;

	p9_conn_create(client);
	return 0;
}

/**
 * p9_mux_destroy - cancels all pending requests of mux
 * @m: mux to destroy
 *
 */

static void p9_conn_destroy(struct p9_conn *m)
{
	p9_debug(P9_DEBUG_TRANS, "mux %p prev %p next %p\n",
		 m, m->mux_list.prev, m->mux_list.next);

	p9_mux_poll_stop(m);
	cancel_work_sync(&m->rq);
	cancel_work_sync(&m->wq);

	p9_conn_cancel(m, -ECONNRESET);

	m->client = NULL;
}

/**
 * p9_fd_close - shutdown file descriptor transport
 * @client: client instance
 *
 */

static void p9_fd_close(struct p9_client *client)
{
	struct p9_trans_fd *ts;

	if (!client)
		return;

	ts = client->trans;
	if (!ts)
		return;

	client->status = Disconnected;

	p9_conn_destroy(&ts->conn);

	if (ts->rd)
		fput(ts->rd);
	if (ts->wr)
		fput(ts->wr);

	kfree(ts);
}

/*
 * stolen from NFS - maybe should be made a generic function?
 */
static inline int valid_ipaddr4(const char *buf)
{
	int rc, count, in[4];

	rc = sscanf(buf, "%d.%d.%d.%d", &in[0], &in[1], &in[2], &in[3]);
	if (rc != 4)
		return -EINVAL;
	for (count = 0; count < 4; count++) {
		if (in[count] > 255)
			return -EINVAL;
	}
	return 0;
}

static struct p9_trans *
p9_trans_create_tcp(const char *addr, char *args, int msize, unsigned char dotu)
{
	int err;
	struct p9_trans *trans;
	struct socket *csocket;
	struct sockaddr_in sin_server;
	struct p9_fd_opts opts;
	struct p9_trans_fd *p;

	err = parse_opts(args, &opts);
	if (err < 0)
		return ERR_PTR(err);

	if (valid_ipaddr4(addr) < 0)
		return ERR_PTR(-EINVAL);

	csocket = NULL;
	trans = kmalloc(sizeof(struct p9_trans), GFP_KERNEL);
	if (!trans)
		return ERR_PTR(-ENOMEM);
	trans->msize = msize;
	trans->extended = dotu;
	trans->rpc = p9_fd_rpc;
	trans->close = p9_fd_close;
static int p9_bind_privport(struct socket *sock)
{
	struct sockaddr_in cl;
	int port, err = -EINVAL;

	memset(&cl, 0, sizeof(cl));
	cl.sin_family = AF_INET;
	cl.sin_addr.s_addr = INADDR_ANY;
	for (port = p9_ipport_resv_max; port >= p9_ipport_resv_min; port--) {
		cl.sin_port = htons((ushort)port);
		err = kernel_bind(sock, (struct sockaddr *)&cl, sizeof(cl));
		if (err != -EADDRINUSE)
			break;
	}
	return err;
}


static int
p9_fd_create_tcp(struct p9_client *client, const char *addr, char *args)
{
	int err;
	struct socket *csocket;
	struct sockaddr_in sin_server;
	struct p9_fd_opts opts;

	err = parse_opts(args, &opts);
	if (err < 0)
		return err;

	if (addr == NULL || valid_ipaddr4(addr) < 0)
		return -EINVAL;

	csocket = NULL;

	client->trans_opts.tcp.port = opts.port;
	client->trans_opts.tcp.privport = opts.privport;
	sin_server.sin_family = AF_INET;
	sin_server.sin_addr.s_addr = in_aton(addr);
	sin_server.sin_port = htons(opts.port);
	sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &csocket);

	if (!csocket) {
		P9_EPRINTK(KERN_ERR, "p9_trans_tcp: problem creating socket\n");
		err = -EIO;
		goto error;
	err = __sock_create(current->nsproxy->net_ns, PF_INET,
			    SOCK_STREAM, IPPROTO_TCP, &csocket, 1);
	if (err) {
		pr_err("%s (%d): problem creating socket\n",
		       __func__, task_pid_nr(current));
		return err;
	}

	if (opts.privport) {
		err = p9_bind_privport(csocket);
		if (err < 0) {
			pr_err("%s (%d): problem binding to privport\n",
			       __func__, task_pid_nr(current));
			sock_release(csocket);
			return err;
		}
	}

	err = csocket->ops->connect(csocket,
				    (struct sockaddr *)&sin_server,
				    sizeof(struct sockaddr_in), 0);
	if (err < 0) {
		P9_EPRINTK(KERN_ERR,
			"p9_trans_tcp: problem connecting socket to %s\n",
			addr);
		goto error;
	}

	err = p9_socket_open(trans, csocket);
	if (err < 0)
		goto error;

	p = (struct p9_trans_fd *) trans->priv;
	p->conn = p9_conn_create(trans);
	if (IS_ERR(p->conn)) {
		err = PTR_ERR(p->conn);
		p->conn = NULL;
		goto error;
	}

	return trans;

error:
	if (csocket)
		sock_release(csocket);

	kfree(trans);
	return ERR_PTR(err);
}

static struct p9_trans *
p9_trans_create_unix(const char *addr, char *args, int msize,
							unsigned char dotu)
		pr_err("%s (%d): problem connecting socket to %s\n",
		       __func__, task_pid_nr(current), addr);
		sock_release(csocket);
		return err;
	}

	return p9_socket_open(client, csocket);
}

static int
p9_fd_create_unix(struct p9_client *client, const char *addr, char *args)
{
	int err;
	struct socket *csocket;
	struct sockaddr_un sun_server;
	struct p9_trans *trans;
	struct p9_trans_fd *p;

	csocket = NULL;
	trans = kmalloc(sizeof(struct p9_trans), GFP_KERNEL);
	if (!trans)
		return ERR_PTR(-ENOMEM);

	trans->rpc = p9_fd_rpc;
	trans->close = p9_fd_close;

	if (strlen(addr) > UNIX_PATH_MAX) {
		P9_EPRINTK(KERN_ERR, "p9_trans_unix: address too long: %s\n",
			addr);
		err = -ENAMETOOLONG;
		goto error;

	csocket = NULL;

	if (addr == NULL)
		return -EINVAL;

	if (strlen(addr) >= UNIX_PATH_MAX) {
		pr_err("%s (%d): address too long: %s\n",
		       __func__, task_pid_nr(current), addr);
		return -ENAMETOOLONG;
	}

	sun_server.sun_family = PF_UNIX;
	strcpy(sun_server.sun_path, addr);
	sock_create_kern(PF_UNIX, SOCK_STREAM, 0, &csocket);
	err = csocket->ops->connect(csocket, (struct sockaddr *)&sun_server,
			sizeof(struct sockaddr_un) - 1, 0);
	if (err < 0) {
		P9_EPRINTK(KERN_ERR,
			"p9_trans_unix: problem connecting socket: %s: %d\n",
			addr, err);
		goto error;
	}

	err = p9_socket_open(trans, csocket);
	if (err < 0)
		goto error;

	trans->msize = msize;
	trans->extended = dotu;
	p = (struct p9_trans_fd *) trans->priv;
	p->conn = p9_conn_create(trans);
	if (IS_ERR(p->conn)) {
		err = PTR_ERR(p->conn);
		p->conn = NULL;
		goto error;
	}

	return trans;

error:
	if (csocket)
		sock_release(csocket);

	kfree(trans);
	return ERR_PTR(err);
}

static struct p9_trans *
p9_trans_create_fd(const char *name, char *args, int msize,
							unsigned char extended)
{
	int err;
	struct p9_trans *trans;
	struct p9_fd_opts opts;
	struct p9_trans_fd *p;
	err = __sock_create(current->nsproxy->net_ns, PF_UNIX,
			    SOCK_STREAM, 0, &csocket, 1);
	if (err < 0) {
		pr_err("%s (%d): problem creating socket\n",
		       __func__, task_pid_nr(current));

		return err;
	}
	err = csocket->ops->connect(csocket, (struct sockaddr *)&sun_server,
			sizeof(struct sockaddr_un) - 1, 0);
	if (err < 0) {
		pr_err("%s (%d): problem connecting socket: %s: %d\n",
		       __func__, task_pid_nr(current), addr, err);
		sock_release(csocket);
		return err;
	}

	return p9_socket_open(client, csocket);
}

static int
p9_fd_create(struct p9_client *client, const char *addr, char *args)
{
	int err;
	struct p9_fd_opts opts;

	parse_opts(args, &opts);
	client->trans_opts.fd.rfd = opts.rfd;
	client->trans_opts.fd.wfd = opts.wfd;

	if (opts.rfd == ~0 || opts.wfd == ~0) {
		printk(KERN_ERR "v9fs: Insufficient options for proto=fd\n");
		return ERR_PTR(-ENOPROTOOPT);
	}

	trans = kmalloc(sizeof(struct p9_trans), GFP_KERNEL);
	if (!trans)
		return ERR_PTR(-ENOMEM);

	trans->rpc = p9_fd_rpc;
	trans->close = p9_fd_close;

	err = p9_fd_open(trans, opts.rfd, opts.wfd);
	if (err < 0)
		goto error;

	trans->msize = msize;
	trans->extended = extended;
	p = (struct p9_trans_fd *) trans->priv;
	p->conn = p9_conn_create(trans);
	if (IS_ERR(p->conn)) {
		err = PTR_ERR(p->conn);
		p->conn = NULL;
		goto error;
	}

	return trans;

error:
	kfree(trans);
	return ERR_PTR(err);
		pr_err("Insufficient options for proto=fd\n");
		return -ENOPROTOOPT;
	}

	err = p9_fd_open(client, opts.rfd, opts.wfd);
	if (err < 0)
		return err;

	p9_conn_create(client);

	return 0;
}

static struct p9_trans_module p9_tcp_trans = {
	.name = "tcp",
	.maxsize = MAX_SOCK_BUF,
	.def = 1,
	.create = p9_trans_create_tcp,
	.def = 0,
	.create = p9_fd_create_tcp,
	.close = p9_fd_close,
	.request = p9_fd_request,
	.cancel = p9_fd_cancel,
	.cancelled = p9_fd_cancelled,
	.show_options = p9_fd_show_options,
	.owner = THIS_MODULE,
};

static struct p9_trans_module p9_unix_trans = {
	.name = "unix",
	.maxsize = MAX_SOCK_BUF,
	.def = 0,
	.create = p9_trans_create_unix,
	.create = p9_fd_create_unix,
	.close = p9_fd_close,
	.request = p9_fd_request,
	.cancel = p9_fd_cancel,
	.cancelled = p9_fd_cancelled,
	.show_options = p9_fd_show_options,
	.owner = THIS_MODULE,
};

static struct p9_trans_module p9_fd_trans = {
	.name = "fd",
	.maxsize = MAX_SOCK_BUF,
	.def = 0,
	.create = p9_trans_create_fd,
	.owner = THIS_MODULE,
};

int p9_trans_fd_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(p9_mux_poll_tasks); i++)
		p9_mux_poll_tasks[i].task = NULL;

	p9_mux_wq = create_workqueue("v9fs");
	if (!p9_mux_wq) {
		printk(KERN_WARNING "v9fs: mux: creating workqueue failed\n");
		return -ENOMEM;
	}

	.create = p9_fd_create,
	.close = p9_fd_close,
	.request = p9_fd_request,
	.cancel = p9_fd_cancel,
	.cancelled = p9_fd_cancelled,
	.show_options = p9_fd_show_options,
	.owner = THIS_MODULE,
};

/**
 * p9_poll_workfn - poll worker thread
 * @work: work queue
 *
 * polls all v9fs transports for new events and queues the appropriate
 * work to the work queue
 *
 */

static void p9_poll_workfn(struct work_struct *work)
{
	unsigned long flags;

	p9_debug(P9_DEBUG_TRANS, "start %p\n", current);

	spin_lock_irqsave(&p9_poll_lock, flags);
	while (!list_empty(&p9_poll_pending_list)) {
		struct p9_conn *conn = list_first_entry(&p9_poll_pending_list,
							struct p9_conn,
							poll_pending_link);
		list_del_init(&conn->poll_pending_link);
		spin_unlock_irqrestore(&p9_poll_lock, flags);

		p9_poll_mux(conn);

		spin_lock_irqsave(&p9_poll_lock, flags);
	}
	spin_unlock_irqrestore(&p9_poll_lock, flags);

	p9_debug(P9_DEBUG_TRANS, "finish\n");
}

int p9_trans_fd_init(void)
{
	v9fs_register_trans(&p9_tcp_trans);
	v9fs_register_trans(&p9_unix_trans);
	v9fs_register_trans(&p9_fd_trans);

	return 0;
}

void p9_trans_fd_exit(void)
{
	v9fs_unregister_trans(&p9_tcp_trans);
	v9fs_unregister_trans(&p9_unix_trans);
	v9fs_unregister_trans(&p9_fd_trans);

	destroy_workqueue(p9_mux_wq);
	flush_work(&p9_poll_work);
	v9fs_unregister_trans(&p9_tcp_trans);
	v9fs_unregister_trans(&p9_unix_trans);
	v9fs_unregister_trans(&p9_fd_trans);
}
