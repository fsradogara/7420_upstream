// SPDX-License-Identifier: GPL-2.0
/*
 * linux/ipc/util.c
 * Copyright (C) 1992 Krishna Balasubramanian
 *
 * Sep 1997 - Call suser() last after "normal" permission checks so we
 *            get BSD style process accounting right.
 *            Occurs in several places in the IPC code.
 *            Chris Evans, <chris@ferret.lmh.ox.ac.uk>
 * Nov 1999 - ipc helper functions, unified SMP locking
 *	      Manfred Spraul <manfred@colorfullife.com>
 * Oct 2002 - One lock per IPC id. RCU ipc_free for lock-free grow_ary().
 *            Mingming Cao <cmm@us.ibm.com>
 * Mar 2006 - support for audit of ipc object properties
 *            Dustin Kirkland <dustin.kirkland@us.ibm.com>
 * Jun 2006 - namespaces ssupport
 *            OpenVZ, SWsoft Inc.
 *            Pavel Emelianov <xemul@openvz.org>
 *
 * General sysv ipc locking scheme:
 *	rcu_read_lock()
 *          obtain the ipc object (kern_ipc_perm) by looking up the id in an idr
 *	    tree.
 *	    - perform initial checks (capabilities, auditing and permission,
 *	      etc).
 *	    - perform read-only operations, such as INFO command, that
 *	      do not demand atomicity
 *	      acquire the ipc lock (kern_ipc_perm.lock) through
 *	      ipc_lock_object()
 *		- perform read-only operations that demand atomicity,
 *		  such as STAT command.
 *		- perform data updates, such as SET, RMID commands and
 *		  mechanism-specific operations (semop/semtimedop,
 *		  msgsnd/msgrcv, shmat/shmdt).
 *	    drop the ipc lock, through ipc_unlock_object().
 *	rcu_read_unlock()
 *
 *  The ids->rwsem must be taken when:
 *	- creating, removing and iterating the existing entries in ipc
 *	  identifier sets.
 *	- iterating through files under /proc/sysvipc/
 *
 *  Note that sems have a special fast path that avoids kern_ipc_perm.lock -
 *  see sem_lock().
 */

#include <linux/mm.h>
#include <linux/shm.h>
#include <linux/init.h>
#include <linux/msg.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/notifier.h>
#include <linux/capability.h>
#include <linux/highuid.h>
#include <linux/security.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/audit.h>
#include <linux/nsproxy.h>
#include <linux/rwsem.h>
#include <linux/memory.h>
#include <linux/ipc_namespace.h>
#include <linux/rhashtable.h>

#include <asm/unistd.h>

#include "util.h"

struct ipc_proc_iface {
	const char *path;
	const char *header;
	int ids;
	int (*show)(struct seq_file *, void *);
};

struct ipc_namespace init_ipc_ns = {
	.kref = {
		.refcount	= ATOMIC_INIT(2),
	},
};

atomic_t nr_ipc_ns = ATOMIC_INIT(1);


#ifdef CONFIG_MEMORY_HOTPLUG

static void ipc_memory_notifier(struct work_struct *work)
{
	ipcns_notify(IPCNS_MEMCHANGED);
}

static DECLARE_WORK(ipc_memory_wq, ipc_memory_notifier);


static int ipc_memory_callback(struct notifier_block *self,
				unsigned long action, void *arg)
{
	switch (action) {
	case MEM_ONLINE:    /* memory successfully brought online */
	case MEM_OFFLINE:   /* or offline: it's time to recompute msgmni */
		/*
		 * This is done by invoking the ipcns notifier chain with the
		 * IPC_MEMCHANGED event.
		 * In order not to keep the lock on the hotplug memory chain
		 * for too long, queue a work item that will, when waken up,
		 * activate the ipcns notification chain.
		 * No need to keep several ipc work items on the queue.
		 */
		if (!work_pending(&ipc_memory_wq))
			schedule_work(&ipc_memory_wq);
		break;
	case MEM_GOING_ONLINE:
	case MEM_GOING_OFFLINE:
	case MEM_CANCEL_ONLINE:
	case MEM_CANCEL_OFFLINE:
	default:
		break;
	}

	return NOTIFY_OK;
}

#endif /* CONFIG_MEMORY_HOTPLUG */

/**
 *	ipc_init	-	initialise IPC subsystem
 *
 *	The various system5 IPC resources (semaphores, messages and shared
 *	memory) are initialised
 *	A callback routine is registered into the memory hotplug notifier
 *	chain: since msgmni scales to lowmem this callback routine will be
 *	called upon successful memory add / remove to recompute msmgni.
 */
 
/**
 * ipc_init - initialise ipc subsystem
 *
 * The various sysv ipc resources (semaphores, messages and shared
 * memory) are initialised.
 *
 * A callback routine is registered into the memory hotplug notifier
 * chain: since msgmni scales to lowmem this callback routine will be
 * called upon successful memory add / remove to recompute msmgni.
 */
static int __init ipc_init(void)
{
	proc_mkdir("sysvipc", NULL);
	sem_init();
	msg_init();
	shm_init();
	hotplug_memory_notifier(ipc_memory_callback, IPC_CALLBACK_PRI);
	register_ipcns_notifier(&init_ipc_ns);
	return 0;
}
__initcall(ipc_init);

/**
 *	ipc_init_ids		-	initialise IPC identifiers
 *	@ids: Identifier set
 *
 *	Set up the sequence range to use for the ipc identifier range (limited
 *	below IPCMNI) then initialise the ids idr.
 */
 
void ipc_init_ids(struct ipc_ids *ids)
{
	init_rwsem(&ids->rw_mutex);

	ids->in_use = 0;
	ids->seq = 0;
	{
		int seq_limit = INT_MAX/SEQ_MULTIPLIER;
		if (seq_limit > USHORT_MAX)
			ids->seq_max = USHORT_MAX;
		 else
		 	ids->seq_max = seq_limit;
	}

	return 0;

	return 0;
}
device_initcall(ipc_init);

static const struct rhashtable_params ipc_kht_params = {
	.head_offset		= offsetof(struct kern_ipc_perm, khtnode),
	.key_offset		= offsetof(struct kern_ipc_perm, key),
	.key_len		= FIELD_SIZEOF(struct kern_ipc_perm, key),
	.locks_mul		= 1,
	.automatic_shrinking	= true,
};

/**
 * ipc_init_ids	- initialise ipc identifiers
 * @ids: ipc identifier set
 *
 * Set up the sequence range to use for the ipc identifier range (limited
 * below IPCMNI) then initialise the keys hashtable and ids idr.
 */
void ipc_init_ids(struct ipc_ids *ids)
{
	ids->in_use = 0;
	ids->seq = 0;
	init_rwsem(&ids->rwsem);
	rhashtable_init(&ids->key_ht, &ipc_kht_params);
	idr_init(&ids->ipcs_idr);
	ids->max_idx = -1;
#ifdef CONFIG_CHECKPOINT_RESTORE
	ids->next_id = -1;
#endif
}

#ifdef CONFIG_PROC_FS
static const struct file_operations sysvipc_proc_fops;
/**
 *	ipc_init_proc_interface	-  Create a proc interface for sysipc types using a seq_file interface.
 *	@path: Path in procfs
 *	@header: Banner to be printed at the beginning of the file.
 *	@ids: ipc id table to iterate.
 *	@show: show routine.
 * ipc_init_proc_interface -  create a proc interface for sysipc types using a seq_file interface.
 * @path: Path in procfs
 * @header: Banner to be printed at the beginning of the file.
 * @ids: ipc id table to iterate.
 * @show: show routine.
 */
void __init ipc_init_proc_interface(const char *path, const char *header,
		int ids, int (*show)(struct seq_file *, void *))
{
	struct proc_dir_entry *pde;
	struct ipc_proc_iface *iface;

	iface = kmalloc(sizeof(*iface), GFP_KERNEL);
	if (!iface)
		return;
	iface->path	= path;
	iface->header	= header;
	iface->ids	= ids;
	iface->show	= show;

	pde = proc_create_data(path,
			       S_IRUGO,        /* world readable */
			       NULL,           /* parent dir */
			       &sysvipc_proc_fops,
			       iface);
	if (!pde) {
		kfree(iface);
	}
	if (!pde)
		kfree(iface);
}
#endif

/**
 *	ipc_findkey	-	find a key in an ipc identifier set	
 *	@ids: Identifier set
 *	@key: The key to find
 *	
 *	Requires ipc_ids.rw_mutex locked.
 *	Returns the LOCKED pointer to the ipc structure if found or NULL
 *	if not.
 *	If key is found ipc points to the owning ipc structure
 */
 
 * ipc_findkey	- find a key in an ipc identifier set
 * @ids: ipc identifier set
 * @key: key to find
 *
 * Returns the locked pointer to the ipc structure if found or NULL
 * otherwise. If key is found ipc points to the owning ipc structure
 *
 * Called with writer ipc_ids.rwsem held.
 */
static struct kern_ipc_perm *ipc_findkey(struct ipc_ids *ids, key_t key)
{
	struct kern_ipc_perm *ipcp;

	ipcp = rhashtable_lookup_fast(&ids->key_ht, &key,
					      ipc_kht_params);
	if (!ipcp)
		return NULL;

		ipc_lock_by_ptr(ipc);
	if (ipcp) {
		rcu_read_lock();
		ipc_lock_object(ipcp);
		return ipcp;
	}

	return NULL;
}

/**
 *	ipc_get_maxid 	-	get the last assigned id
 *	@ids: IPC identifier set
 *
 *	Called with ipc_ids.rw_mutex held.
 */

 * ipc_get_maxid - get the last assigned id
 * @ids: ipc identifier set
	rcu_read_lock();
	ipc_lock_object(ipcp);
	return ipcp;
}

/*
 * Insert new IPC object into idr tree, and set sequence number and id
 * in the correct order.
 * Especially:
 * - the sequence number must be set before inserting the object into the idr,
 *   because the sequence number is accessed without a lock.
 * - the id can/must be set after inserting the object into the idr.
 *   All accesses must be done after getting kern_ipc_perm.lock.
 *
 * The caller must own kern_ipc_perm.lock.of the new object.
 * On error, the function returns a (negative) error code.
 */
static inline int ipc_idr_alloc(struct ipc_ids *ids, struct kern_ipc_perm *new)
{
	int idx, next_id = -1;

#ifdef CONFIG_CHECKPOINT_RESTORE
	next_id = ids->next_id;
	ids->next_id = -1;
#endif

	/*
	 * As soon as a new object is inserted into the idr,
	 * ipc_obtain_object_idr() or ipc_obtain_object_check() can find it,
	 * and the lockless preparations for ipc operations can start.
	 * This means especially: permission checks, audit calls, allocation
	 * of undo structures, ...
	 *
	 * Thus the object must be fully initialized, and if something fails,
	 * then the full tear-down sequence must be followed.
	 * (i.e.: set new->deleted, reduce refcount, call_rcu())
	 */

	if (next_id < 0) { /* !CHECKPOINT_RESTORE or next_id is unset */
		new->seq = ids->seq++;
		if (ids->seq > IPCID_SEQ_MAX)
			ids->seq = 0;
		idx = idr_alloc(&ids->ipcs_idr, new, 0, 0, GFP_NOWAIT);
	} else {
		new->seq = ipcid_to_seqx(next_id);
		idx = idr_alloc(&ids->ipcs_idr, new, ipcid_to_idx(next_id),
				0, GFP_NOWAIT);
	}
	if (idx >= 0)
		new->id = SEQ_MULTIPLIER * new->seq + idx;
	return idx;
}

/**
 *	ipc_addid 	-	add an IPC identifier
 *	@ids: IPC identifier set
 *	@new: new IPC permission set
 *	@size: limit for the number of used ids
 *
 *	Add an entry 'new' to the IPC ids idr. The permissions object is
 *	initialised and the first free entry is set up and the id assigned
 *	is returned. The 'new' entry is returned in a locked state on success.
 *	On failure the entry is not locked and a negative err-code is returned.
 *
 *	Called with ipc_ids.rw_mutex held as a writer.
 */
 
int ipc_addid(struct ipc_ids* ids, struct kern_ipc_perm* new, int size)
{
	int id, err;
 * ipc_addid - add an ipc identifier
 * @ids: ipc identifier set
 * @new: new ipc permission set
 * @limit: limit for the number of used ids
 *
 * Add an entry 'new' to the ipc ids idr. The permissions object is
 * initialised and the first free entry is set up and the index assigned
 * is returned. The 'new' entry is returned in a locked state on success.
 *
 * On failure the entry is not locked and a negative err-code is returned.
 * The caller must use ipc_rcu_putref() to free the identifier.
 *
 * Called with writer ipc_ids.rwsem held.
 */
int ipc_addid(struct ipc_ids *ids, struct kern_ipc_perm *new, int limit)
{
	kuid_t euid;
	kgid_t egid;
	int idx, err;

	/* 1) Initialize the refcount so that ipc_rcu_putref works */
	refcount_set(&new->refcount, 1);

	if (limit > IPCMNI)
		limit = IPCMNI;

	if (ids->in_use >= limit)
		return -ENOSPC;

	err = idr_get_new(&ids->ipcs_idr, new, &id);
	if (err)
		return err;

	ids->in_use++;

	new->cuid = new->uid = current->euid;
	new->gid = new->cgid = current->egid;

	new->seq = ids->seq++;
	if(ids->seq > ids->seq_max)
		ids->seq = 0;

	new->id = ipc_buildid(id, new->seq);
	spin_lock_init(&new->lock);
	new->deleted = 0;
	rcu_read_lock();
	spin_lock(&new->lock);
	idr_preload(GFP_KERNEL);

	spin_lock_init(&new->lock);
	rcu_read_lock();
	spin_lock(&new->lock);

	current_euid_egid(&euid, &egid);
	new->cuid = new->uid = euid;
	new->gid = new->cgid = egid;

	new->deleted = false;

	idx = ipc_idr_alloc(ids, new);
	idr_preload_end();

	if (idx >= 0 && new->key != IPC_PRIVATE) {
		err = rhashtable_insert_fast(&ids->key_ht, &new->khtnode,
					     ipc_kht_params);
		if (err < 0) {
			idr_remove(&ids->ipcs_idr, idx);
			idx = err;
		}
	}
	if (idx < 0) {
		new->deleted = true;
		spin_unlock(&new->lock);
		rcu_read_unlock();
		return idx;
	}

	ids->in_use++;
	if (idx > ids->max_idx)
		ids->max_idx = idx;
	return idx;
}

/**
 *	ipcget_new	-	create a new ipc object
 *	@ns: namespace
 *	@ids: IPC identifer set
 *	@ops: the actual creation routine to call
 *	@params: its parameters
 *
 *	This routine is called by sys_msgget, sys_semget() and sys_shmget()
 *	when the key is IPC_PRIVATE.
 */
static int ipcget_new(struct ipc_namespace *ns, struct ipc_ids *ids,
		struct ipc_ops *ops, struct ipc_params *params)
{
	int err;
retry:
	err = idr_pre_get(&ids->ipcs_idr, GFP_KERNEL);

	if (!err)
		return -ENOMEM;

	down_write(&ids->rw_mutex);
	err = ops->getnew(ns, params);
	up_write(&ids->rw_mutex);

	if (err == -EAGAIN)
		goto retry;

 * ipcget_new -	create a new ipc object
 * @ns: ipc namespace
 * @ids: ipc identifier set
 * @ops: the actual creation routine to call
 * @params: its parameters
 *
 * This routine is called by sys_msgget, sys_semget() and sys_shmget()
 * when the key is IPC_PRIVATE.
 */
static int ipcget_new(struct ipc_namespace *ns, struct ipc_ids *ids,
		const struct ipc_ops *ops, struct ipc_params *params)
{
	int err;

	down_write(&ids->rwsem);
	err = ops->getnew(ns, params);
	up_write(&ids->rwsem);
	return err;
}

/**
 *	ipc_check_perms	-	check security and permissions for an IPC
 *	@ipcp: ipc permission set
 *	@ops: the actual security routine to call
 *	@params: its parameters
 *
 *	This routine is called by sys_msgget(), sys_semget() and sys_shmget()
 *      when the key is not IPC_PRIVATE and that key already exists in the
 *      ids IDR.
 *
 *	On success, the IPC id is returned.
 *
 *	It is called with ipc_ids.rw_mutex and ipcp->lock held.
 */
static int ipc_check_perms(struct kern_ipc_perm *ipcp, struct ipc_ops *ops,
			struct ipc_params *params)
{
	int err;

	if (ipcperms(ipcp, params->flg))
 * ipc_check_perms - check security and permissions for an ipc object
 * @ns: ipc namespace
 * @ipcp: ipc permission set
 * @ops: the actual security routine to call
 * @params: its parameters
 *
 * This routine is called by sys_msgget(), sys_semget() and sys_shmget()
 * when the key is not IPC_PRIVATE and that key already exists in the
 * ds IDR.
 *
 * On success, the ipc id is returned.
 *
 * It is called with ipc_ids.rwsem and ipcp->lock held.
 */
static int ipc_check_perms(struct ipc_namespace *ns,
			   struct kern_ipc_perm *ipcp,
			   const struct ipc_ops *ops,
			   struct ipc_params *params)
{
	int err;

	if (ipcperms(ns, ipcp, params->flg))
		err = -EACCES;
	else {
		err = ops->associate(ipcp, params->flg);
		if (!err)
			err = ipcp->id;
	}

	return err;
}

/**
 *	ipcget_public	-	get an ipc object or create a new one
 *	@ns: namespace
 *	@ids: IPC identifer set
 *	@ops: the actual creation routine to call
 *	@params: its parameters
 *
 *	This routine is called by sys_msgget, sys_semget() and sys_shmget()
 *	when the key is not IPC_PRIVATE.
 *	It adds a new entry if the key is not found and does some permission
 *      / security checkings if the key is found.
 *
 *	On success, the ipc id is returned.
 */
static int ipcget_public(struct ipc_namespace *ns, struct ipc_ids *ids,
		struct ipc_ops *ops, struct ipc_params *params)
 * ipcget_public - get an ipc object or create a new one
 * @ns: ipc namespace
 * @ids: ipc identifier set
 * @ops: the actual creation routine to call
 * @params: its parameters
 *
 * This routine is called by sys_msgget, sys_semget() and sys_shmget()
 * when the key is not IPC_PRIVATE.
 * It adds a new entry if the key is not found and does some permission
 * / security checkings if the key is found.
 *
 * On success, the ipc id is returned.
 */
static int ipcget_public(struct ipc_namespace *ns, struct ipc_ids *ids,
		const struct ipc_ops *ops, struct ipc_params *params)
{
	struct kern_ipc_perm *ipcp;
	int flg = params->flg;
	int err;
retry:
	err = idr_pre_get(&ids->ipcs_idr, GFP_KERNEL);

	/*
	 * Take the lock as a writer since we are potentially going to add
	 * a new entry + read locks are not "upgradable"
	 */
	down_write(&ids->rw_mutex);
	down_write(&ids->rwsem);
	ipcp = ipc_findkey(ids, params->key);
	if (ipcp == NULL) {
		/* key not used */
		if (!(flg & IPC_CREAT))
			err = -ENOENT;
		else if (!err)
			err = -ENOMEM;
		else
			err = ops->getnew(ns, params);
	} else {
		/* ipc object has been locked by ipc_findkey() */

		if (flg & IPC_CREAT && flg & IPC_EXCL)
			err = -EEXIST;
		else {
			err = 0;
			if (ops->more_checks)
				err = ops->more_checks(ipcp, params);
			if (!err)
				/*
				 * ipc_check_perms returns the IPC id on
				 * success
				 */
				err = ipc_check_perms(ipcp, ops, params);
		}
		ipc_unlock(ipcp);
	}
	up_write(&ids->rw_mutex);

	if (err == -EAGAIN)
		goto retry;
				err = ipc_check_perms(ns, ipcp, ops, params);
		}
		ipc_unlock(ipcp);
	}
	up_write(&ids->rwsem);

	return err;
}

/**
 * ipc_kht_remove - remove an ipc from the key hashtable
 * @ids: ipc identifier set
 * @ipcp: ipc perm structure containing the key to remove
 *
 * ipc_ids.rwsem (as a writer) and the spinlock for this ID are held
 * before this function is called, and remain locked on the exit.
 */
static void ipc_kht_remove(struct ipc_ids *ids, struct kern_ipc_perm *ipcp)
{
	if (ipcp->key != IPC_PRIVATE)
		rhashtable_remove_fast(&ids->key_ht, &ipcp->khtnode,
				       ipc_kht_params);
}

/**
 *	ipc_rmid	-	remove an IPC identifier
 *	@ids: IPC identifier set
 *	@ipcp: ipc perm structure containing the identifier to remove
 *
 *	ipc_ids.rw_mutex (as a writer) and the spinlock for this ID are held
 *	before this function is called, and remain locked on the exit.
 */
 
 * ipc_rmid - remove an ipc identifier
 * @ids: ipc identifier set
 * @ipcp: ipc perm structure containing the identifier to remove
 *
 * ipc_ids.rwsem (as a writer) and the spinlock for this ID are held
 * before this function is called, and remain locked on the exit.
 */
void ipc_rmid(struct ipc_ids *ids, struct kern_ipc_perm *ipcp)
{
	int idx = ipcid_to_idx(ipcp->id);

	idr_remove(&ids->ipcs_idr, lid);

	ids->in_use--;

	ipcp->deleted = 1;

	return;
}

/**
 *	ipc_alloc	-	allocate ipc space
 *	@size: size desired
 *
 *	Allocate memory from the appropriate pools and return a pointer to it.
 *	NULL is returned if the allocation fails
 */
 
void* ipc_alloc(int size)
{
	void* out;
	if(size > PAGE_SIZE)
	idr_remove(&ids->ipcs_idr, idx);
	ipc_kht_remove(ids, ipcp);
	ids->in_use--;
	ipcp->deleted = true;

	if (unlikely(idx == ids->max_idx)) {
		do {
			idx--;
			if (idx == -1)
				break;
		} while (!idr_find(&ids->ipcs_idr, idx));
		ids->max_idx = idx;
	}
}

/**
 * ipc_set_key_private - switch the key of an existing ipc to IPC_PRIVATE
 * @ids: ipc identifier set
 * @ipcp: ipc perm structure containing the key to modify
 *
 * ipc_ids.rwsem (as a writer) and the spinlock for this ID are held
 * before this function is called, and remain locked on the exit.
 */
void ipc_set_key_private(struct ipc_ids *ids, struct kern_ipc_perm *ipcp)
{
	ipc_kht_remove(ids, ipcp);
	ipcp->key = IPC_PRIVATE;
}

/**
 *	ipc_free        -       free ipc space
 *	@ptr: pointer returned by ipc_alloc
 *	@size: size of block
 *
 *	Free a block created with ipc_alloc(). The caller must know the size
 *	used in the allocation call.
 */

void ipc_free(void* ptr, int size)
{
	if(size > PAGE_SIZE)
 * ipc_free - free ipc space
 * @ptr: pointer returned by ipc_alloc
 * @size: size of block
 *
 * Free a block created with ipc_alloc(). The caller must know the size
 * used in the allocation call.
 */
void ipc_free(void *ptr, int size)
int ipc_rcu_getref(struct kern_ipc_perm *ptr)
bool ipc_rcu_getref(struct kern_ipc_perm *ptr)
{
	return refcount_inc_not_zero(&ptr->refcount);
}

/*
 * rcu allocations:
 * There are three headers that are prepended to the actual allocation:
 * - during use: ipc_rcu_hdr.
 * - during the rcu grace period: ipc_rcu_grace.
 * - [only if vmalloc]: ipc_rcu_sched.
 * Their lifetime doesn't overlap, thus the headers share the same memory.
 * Unlike a normal union, they are right-aligned, thus some container_of
 * forward/backward casting is necessary:
 */
struct ipc_rcu_hdr
{
	int refcount;
	int is_vmalloc;
	void *data[0];
};


struct ipc_rcu_grace
{
	struct rcu_head rcu;
	/* "void *" makes sure alignment of following data is sane. */
	void *data[0];
};

struct ipc_rcu_sched
{
	struct work_struct work;
	/* "void *" makes sure alignment of following data is sane. */
	void *data[0];
};

#define HDRLEN_KMALLOC		(sizeof(struct ipc_rcu_grace) > sizeof(struct ipc_rcu_hdr) ? \
					sizeof(struct ipc_rcu_grace) : sizeof(struct ipc_rcu_hdr))
#define HDRLEN_VMALLOC		(sizeof(struct ipc_rcu_sched) > HDRLEN_KMALLOC ? \
					sizeof(struct ipc_rcu_sched) : HDRLEN_KMALLOC)

static inline int rcu_use_vmalloc(int size)
{
	/* Too big for a single page? */
	if (HDRLEN_KMALLOC + size > PAGE_SIZE)
		return 1;
	return 0;
}

/**
 *	ipc_rcu_alloc	-	allocate ipc and rcu space 
 *	@size: size desired
 *
 *	Allocate memory for the rcu header structure +  the object.
 *	Returns the pointer to the object.
 *	NULL is returned if the allocation fails. 
 */
 
void* ipc_rcu_alloc(int size)
{
	void* out;
	/* 
	 * We prepend the allocation with the rcu struct, and
	 * workqueue if necessary (for vmalloc). 
	 */
	if (rcu_use_vmalloc(size)) {
		out = vmalloc(HDRLEN_VMALLOC + size);
		if (out) {
			out += HDRLEN_VMALLOC;
			container_of(out, struct ipc_rcu_hdr, data)->is_vmalloc = 1;
			container_of(out, struct ipc_rcu_hdr, data)->refcount = 1;
		}
	} else {
		out = kmalloc(HDRLEN_KMALLOC + size, GFP_KERNEL);
		if (out) {
			out += HDRLEN_KMALLOC;
			container_of(out, struct ipc_rcu_hdr, data)->is_vmalloc = 0;
			container_of(out, struct ipc_rcu_hdr, data)->refcount = 1;
		}
	}

	return out;
}

void ipc_rcu_getref(void *ptr)
{
	container_of(ptr, struct ipc_rcu_hdr, data)->refcount++;
}

static void ipc_do_vfree(struct work_struct *work)
{
	vfree(container_of(work, struct ipc_rcu_sched, work));
}

/**
 * ipc_schedule_free - free ipc + rcu space
 * @head: RCU callback structure for queued work
 * 
 * Since RCU callback function is called in bh,
 * we need to defer the vfree to schedule_work().
 */
static void ipc_schedule_free(struct rcu_head *head)
{
	struct ipc_rcu_grace *grace;
	struct ipc_rcu_sched *sched;

	grace = container_of(head, struct ipc_rcu_grace, rcu);
	sched = container_of(&(grace->data[0]), struct ipc_rcu_sched,
				data[0]);

	INIT_WORK(&sched->work, ipc_do_vfree);
	schedule_work(&sched->work);
}

/**
 * ipc_immediate_free - free ipc + rcu space
 * @head: RCU callback structure that contains pointer to be freed
 *
 * Free from the RCU callback context.
 */
static void ipc_immediate_free(struct rcu_head *head)
{
	struct ipc_rcu_grace *free =
		container_of(head, struct ipc_rcu_grace, rcu);
	kfree(free);
}

void ipc_rcu_putref(void *ptr)
{
	if (--container_of(ptr, struct ipc_rcu_hdr, data)->refcount > 0)
		return;

	if (container_of(ptr, struct ipc_rcu_hdr, data)->is_vmalloc) {
		call_rcu(&container_of(ptr, struct ipc_rcu_grace, data)->rcu,
				ipc_schedule_free);
	} else {
		call_rcu(&container_of(ptr, struct ipc_rcu_grace, data)->rcu,
				ipc_immediate_free);
	}
}

/**
 *	ipcperms	-	check IPC permissions
 *	@ipcp: IPC permission set
 *	@flag: desired permission set.
 *
 *	Check user, group, other permissions for access
 *	to ipc resources. return 0 if allowed
 */
 
int ipcperms (struct kern_ipc_perm *ipcp, short flag)
{	/* flag will most probably be 0 or S_...UGO from <linux/stat.h> */
	int requested_mode, granted_mode, err;

	if (unlikely((err = audit_ipc_obj(ipcp))))
		return err;
	requested_mode = (flag >> 6) | (flag >> 3) | flag;
	granted_mode = ipcp->mode;
	if (current->euid == ipcp->cuid || current->euid == ipcp->uid)
/**
 * ipc_rcu_alloc - allocate ipc and rcu space
 * @size: size desired
 *
 * Allocate memory for the rcu header structure +  the object.
 * Returns the pointer to the object or NULL upon failure.
 */
void *ipc_rcu_alloc(int size)
void ipc_rcu_putref(struct kern_ipc_perm *ptr,
			void (*func)(struct rcu_head *head))
{
	if (!refcount_dec_and_test(&ptr->refcount))
		return;

	call_rcu(&ptr->rcu, func);
}

/**
 * ipcperms - check ipc permissions
 * @ns: ipc namespace
 * @ipcp: ipc permission set
 * @flag: desired permission set
 *
 * Check user, group, other permissions for access
 * to ipc resources. return 0 if allowed
 *
 * @flag will most probably be 0 or ``S_...UGO`` from <linux/stat.h>
 */
int ipcperms(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp, short flag)
{
	kuid_t euid = current_euid();
	int requested_mode, granted_mode;

	audit_ipc_obj(ipcp);
	requested_mode = (flag >> 6) | (flag >> 3) | flag;
	granted_mode = ipcp->mode;
	if (uid_eq(euid, ipcp->cuid) ||
	    uid_eq(euid, ipcp->uid))
		granted_mode >>= 6;
	else if (in_group_p(ipcp->cgid) || in_group_p(ipcp->gid))
		granted_mode >>= 3;
	/* is there some bit set in requested_mode but not in granted_mode? */
	if ((requested_mode & ~granted_mode & 0007) && 
	    !capable(CAP_IPC_OWNER))
	if ((requested_mode & ~granted_mode & 0007) &&
	    !ns_capable(ns->user_ns, CAP_IPC_OWNER))
		return -1;

	return security_ipc_permission(ipcp, flag);
}

/*
 * Functions to convert between the kern_ipc_perm structure and the
 * old/new ipc_perm structures
 */

/**
 *	kernel_to_ipc64_perm	-	convert kernel ipc permissions to user
 *	@in: kernel permissions
 *	@out: new style IPC permissions
 *
 *	Turn the kernel object @in into a set of permissions descriptions
 *	for returning to userspace (@out).
 */
 

void kernel_to_ipc64_perm (struct kern_ipc_perm *in, struct ipc64_perm *out)
{
	out->key	= in->key;
	out->uid	= in->uid;
	out->gid	= in->gid;
	out->cuid	= in->cuid;
	out->cgid	= in->cgid;
 * kernel_to_ipc64_perm	- convert kernel ipc permissions to user
 * @in: kernel permissions
 * @out: new style ipc permissions
 *
 * Turn the kernel object @in into a set of permissions descriptions
 * for returning to userspace (@out).
 */
void kernel_to_ipc64_perm(struct kern_ipc_perm *in, struct ipc64_perm *out)
{
	out->key	= in->key;
	out->uid	= from_kuid_munged(current_user_ns(), in->uid);
	out->gid	= from_kgid_munged(current_user_ns(), in->gid);
	out->cuid	= from_kuid_munged(current_user_ns(), in->cuid);
	out->cgid	= from_kgid_munged(current_user_ns(), in->cgid);
	out->mode	= in->mode;
	out->seq	= in->seq;
}

/**
 *	ipc64_perm_to_ipc_perm	-	convert new ipc permissions to old
 *	@in: new style IPC permissions
 *	@out: old style IPC permissions
 *
 *	Turn the new style permissions object @in into a compatibility
 *	object and store it into the @out pointer.
 */
 
void ipc64_perm_to_ipc_perm (struct ipc64_perm *in, struct ipc_perm *out)
 * ipc64_perm_to_ipc_perm - convert new ipc permissions to old
 * @in: new style ipc permissions
 * @out: old style ipc permissions
 *
 * Turn the new style permissions object @in into a compatibility
 * object and store it into the @out pointer.
 */
void ipc64_perm_to_ipc_perm(struct ipc64_perm *in, struct ipc_perm *out)
{
	out->key	= in->key;
	SET_UID(out->uid, in->uid);
	SET_GID(out->gid, in->gid);
	SET_UID(out->cuid, in->cuid);
	SET_GID(out->cgid, in->cgid);
	out->mode	= in->mode;
	out->seq	= in->seq;
}

/**
 * ipc_lock - Lock an ipc structure without rw_mutex held
 * @ids: IPC identifier set
 * @id: ipc id to look for
 *
 * Look for an id in the ipc ids idr and lock the associated ipc object.
 *
 * The ipc object is locked on exit.
 */

struct kern_ipc_perm *ipc_lock(struct ipc_ids *ids, int id)
 * ipc_obtain_object
 * ipc_obtain_object_idr
 * @ids: ipc identifier set
 * @id: ipc id to look for
 *
 * Look for an id in the ipc ids idr and return associated ipc object.
 *
 * Call inside the RCU critical section.
 * The ipc object is *not* locked on exit.
 */
struct kern_ipc_perm *ipc_obtain_object_idr(struct ipc_ids *ids, int id)
{
	struct kern_ipc_perm *out;
	int idx = ipcid_to_idx(id);

	rcu_read_lock();
	out = idr_find(&ids->ipcs_idr, lid);
	if (out == NULL) {
		rcu_read_unlock();
		return ERR_PTR(-EINVAL);
	}

	spin_lock(&out->lock);
	
	/* ipc_rmid() may have already freed the ID while ipc_lock
	 * was spinning: here verify that the structure is still valid
	 */
	if (out->deleted) {
		spin_unlock(&out->lock);
		rcu_read_unlock();
		return ERR_PTR(-EINVAL);
	}

	return out;
}

struct kern_ipc_perm *ipc_lock_check(struct ipc_ids *ids, int id)
{
	struct kern_ipc_perm *out;

	out = ipc_lock(ids, id);
	if (IS_ERR(out))
		return out;

	if (ipc_checkid(out, id)) {
		ipc_unlock(out);
		return ERR_PTR(-EIDRM);
	}
	if (unlikely(!ids->tables_initialized))
		return ERR_PTR(-EINVAL);

	out = idr_find(&ids->ipcs_idr, lid);
	out = idr_find(&ids->ipcs_idr, idx);
	if (!out)
		return ERR_PTR(-EINVAL);

	return out;
}

/**
 * ipcget - Common sys_*get() code
 * @ns : namsepace
 * @ids : IPC identifier set
 * @ops : operations to be called on ipc object creation, permission checks
 *        and further checks
 * @params : the parameters needed by the previous operations.
 * ipc_lock - lock an ipc structure without rwsem held
 * @ids: ipc identifier set
 * @id: ipc id to look for
 *
 * Look for an id in the ipc ids idr and lock the associated ipc object.
 *
 * The ipc object is locked on successful exit.
 */
struct kern_ipc_perm *ipc_lock(struct ipc_ids *ids, int id)
{
	struct kern_ipc_perm *out;

	rcu_read_lock();
	out = ipc_obtain_object_idr(ids, id);
	if (IS_ERR(out))
		goto err;

	spin_lock(&out->lock);

	/*
	 * ipc_rmid() may have already freed the ID while ipc_lock()
	 * was spinning: here verify that the structure is still valid.
	 * Upon races with RMID, return -EIDRM, thus indicating that
	 * the ID points to a removed identifier.
	 */
	if (ipc_valid_object(out))
		return out;

	spin_unlock(&out->lock);
	out = ERR_PTR(-EIDRM);
err:
	rcu_read_unlock();
	return out;
}

/**
 * ipc_obtain_object_check
 * @ids: ipc identifier set
 * @id: ipc id to look for
 *
 * Similar to ipc_obtain_object_idr() but also checks the ipc object
 * sequence number.
 *
 * Call inside the RCU critical section.
 * The ipc object is *not* locked on exit.
 */
struct kern_ipc_perm *ipc_obtain_object_check(struct ipc_ids *ids, int id)
{
	struct kern_ipc_perm *out = ipc_obtain_object_idr(ids, id);

	if (IS_ERR(out))
		goto out;

	if (ipc_checkid(out, id))
		return ERR_PTR(-EINVAL);
out:
	return out;
}

/**
 * ipcget - Common sys_*get() code
 * @ns: namespace
 * @ids: ipc identifier set
 * @ops: operations to be called on ipc object creation, permission checks
 *       and further checks
 * @params: the parameters needed by the previous operations.
 *
 * Common routine called by sys_msgget(), sys_semget() and sys_shmget().
 */
int ipcget(struct ipc_namespace *ns, struct ipc_ids *ids,
			struct ipc_ops *ops, struct ipc_params *params)
			const struct ipc_ops *ops, struct ipc_params *params)
{
	if (params->key == IPC_PRIVATE)
		return ipcget_new(ns, ids, ops, params);
	else
		return ipcget_public(ns, ids, ops, params);
}

/**
 * ipc_update_perm - update the permissions of an IPC.
 * @in:  the permission given as input.
 * @out: the permission of the ipc to set.
 */
void ipc_update_perm(struct ipc64_perm *in, struct kern_ipc_perm *out)
{
	out->uid = in->uid;
	out->gid = in->gid;
	out->mode = (out->mode & ~S_IRWXUGO)
		| (in->mode & S_IRWXUGO);
}

/**
 * ipcctl_pre_down - retrieve an ipc and check permissions for some IPC_XXX cmd
 * ipc_update_perm - update the permissions of an ipc object
 * @in:  the permission given as input.
 * @out: the permission of the ipc to set.
 */
int ipc_update_perm(struct ipc64_perm *in, struct kern_ipc_perm *out)
{
	kuid_t uid = make_kuid(current_user_ns(), in->uid);
	kgid_t gid = make_kgid(current_user_ns(), in->gid);
	if (!uid_valid(uid) || !gid_valid(gid))
		return -EINVAL;

	out->uid = uid;
	out->gid = gid;
	out->mode = (out->mode & ~S_IRWXUGO)
		| (in->mode & S_IRWXUGO);

	return 0;
}

/**
 * ipcctl_obtain_check - retrieve an ipc object and check permissions
 * @ns:  ipc namespace
 * @ids:  the table of ids where to look for the ipc
 * @id:   the id of the ipc to retrieve
 * @cmd:  the cmd to check
 * @perm: the permission to set
 * @extra_perm: one extra permission parameter used by msq
 *
 * This function does some common audit and permissions check for some IPC_XXX
 * cmd and is called from semctl_down, shmctl_down and msgctl_down.
 * It must be called without any lock held and
 *  - retrieves the ipc with the given id in the given table.
 *  - performs some audit and permission check, depending on the given cmd
 *  - returns the ipc with both ipc and rw_mutex locks held in case of success
 *    or an err-code without any lock held otherwise.
 */
struct kern_ipc_perm *ipcctl_pre_down(struct ipc_ids *ids, int id, int cmd,
				      struct ipc64_perm *perm, int extra_perm)
{
	struct kern_ipc_perm *ipcp;
	int err;

	down_write(&ids->rw_mutex);
	ipcp = ipc_lock_check(ids, id);
	if (IS_ERR(ipcp)) {
		err = PTR_ERR(ipcp);
		goto out_up;
	}

	err = audit_ipc_obj(ipcp);
	if (err)
		goto out_unlock;

	if (cmd == IPC_SET) {
		err = audit_ipc_set_perm(extra_perm, perm->uid,
					 perm->gid, perm->mode);
		if (err)
			goto out_unlock;
	}
	if (current->euid == ipcp->cuid ||
	    current->euid == ipcp->uid || capable(CAP_SYS_ADMIN))
		return ipcp;

	err = -EPERM;
out_unlock:
	ipc_unlock(ipcp);
out_up:
	up_write(&ids->rw_mutex);
	return ERR_PTR(err);
}

#ifdef __ARCH_WANT_IPC_PARSE_VERSION


/**
 *	ipc_parse_version	-	IPC call version
 *	@cmd: pointer to command
 *
 *	Return IPC_64 for new style IPC and IPC_OLD for old style IPC. 
 *	The @cmd value is turned from an encoding command and version into
 *	just the command code.
 */
 
int ipc_parse_version (int *cmd)
 *  - returns a pointer to the ipc object or otherwise, the corresponding error.
 * It must be called without any lock held and:
 *
 * It:
 *   - retrieves the ipc object with the given id in the given table.
 *   - performs some audit and permission check, depending on the given cmd
 *   - returns a pointer to the ipc object or otherwise, the corresponding
 *     error.
 *
 * Call holding the both the rwsem and the rcu read lock.
 */
struct kern_ipc_perm *ipcctl_obtain_check(struct ipc_namespace *ns,
					struct ipc_ids *ids, int id, int cmd,
					struct ipc64_perm *perm, int extra_perm)
{
	kuid_t euid;
	int err = -EPERM;
	struct kern_ipc_perm *ipcp;

	ipcp = ipc_obtain_object_check(ids, id);
	if (IS_ERR(ipcp)) {
		err = PTR_ERR(ipcp);
		goto err;
	}

	audit_ipc_obj(ipcp);
	if (cmd == IPC_SET)
		audit_ipc_set_perm(extra_perm, perm->uid,
				   perm->gid, perm->mode);

	euid = current_euid();
	if (uid_eq(euid, ipcp->cuid) || uid_eq(euid, ipcp->uid)  ||
	    ns_capable(ns->user_ns, CAP_SYS_ADMIN))
		return ipcp; /* successful lookup */
err:
	return ERR_PTR(err);
}

#ifdef CONFIG_ARCH_WANT_IPC_PARSE_VERSION


/**
 * ipc_parse_version - ipc call version
 * @cmd: pointer to command
 *
 * Return IPC_64 for new style IPC and IPC_OLD for old style IPC.
 * The @cmd value is turned from an encoding command and version into
 * just the command code.
 */
int ipc_parse_version(int *cmd)
{
	if (*cmd & IPC_64) {
		*cmd ^= IPC_64;
		return IPC_64;
	} else {
		return IPC_OLD;
	}
}

#endif /* __ARCH_WANT_IPC_PARSE_VERSION */
#endif /* CONFIG_ARCH_WANT_IPC_PARSE_VERSION */

#ifdef CONFIG_PROC_FS
struct ipc_proc_iter {
	struct ipc_namespace *ns;
	struct pid_namespace *pid_ns;
	struct ipc_proc_iface *iface;
};

struct pid_namespace *ipc_seq_pid_ns(struct seq_file *s)
{
	struct ipc_proc_iter *iter = s->private;
	return iter->pid_ns;
}

/*
 * This routine locks the ipc structure found at least at position pos.
 */
static struct kern_ipc_perm *sysvipc_find_ipc(struct ipc_ids *ids, loff_t pos,
					      loff_t *new_pos)
{
	struct kern_ipc_perm *ipc;
	int total, id;

	total = 0;
	for (id = 0; id < pos && total < ids->in_use; id++) {
		ipc = idr_find(&ids->ipcs_idr, id);
		if (ipc != NULL)
			total++;
	}

	if (total >= ids->in_use)
		return NULL;

	for ( ; pos < IPCMNI; pos++) {
		ipc = idr_find(&ids->ipcs_idr, pos);
		if (ipc != NULL) {
			*new_pos = pos + 1;
			ipc_lock_by_ptr(ipc);
	for (; pos < IPCMNI; pos++) {
		ipc = idr_find(&ids->ipcs_idr, pos);
		if (ipc != NULL) {
			*new_pos = pos + 1;
			rcu_read_lock();
			ipc_lock_object(ipc);
			return ipc;
		}
	}

	/* Out of range - return NULL to terminate iteration */
	return NULL;
}

static void *sysvipc_proc_next(struct seq_file *s, void *it, loff_t *pos)
{
	struct ipc_proc_iter *iter = s->private;
	struct ipc_proc_iface *iface = iter->iface;
	struct kern_ipc_perm *ipc = it;

	/* If we had an ipc id locked before, unlock it */
	if (ipc && ipc != SEQ_START_TOKEN)
		ipc_unlock(ipc);

	return sysvipc_find_ipc(&iter->ns->ids[iface->ids], *pos, pos);
}

/*
 * File positions: pos 0 -> header, pos n -> ipc id = n - 1.
 * SeqFile iterator: iterator value locked ipc pointer or SEQ_TOKEN_START.
 */
static void *sysvipc_proc_start(struct seq_file *s, loff_t *pos)
{
	struct ipc_proc_iter *iter = s->private;
	struct ipc_proc_iface *iface = iter->iface;
	struct ipc_ids *ids;

	ids = &iter->ns->ids[iface->ids];

	/*
	 * Take the lock - this will be released by the corresponding
	 * call to stop().
	 */
	down_read(&ids->rw_mutex);
	down_read(&ids->rwsem);

	/* pos < 0 is invalid */
	if (*pos < 0)
		return NULL;

	/* pos == 0 means header */
	if (*pos == 0)
		return SEQ_START_TOKEN;

	/* Find the (pos-1)th ipc */
	return sysvipc_find_ipc(ids, *pos - 1, pos);
}

static void sysvipc_proc_stop(struct seq_file *s, void *it)
{
	struct kern_ipc_perm *ipc = it;
	struct ipc_proc_iter *iter = s->private;
	struct ipc_proc_iface *iface = iter->iface;
	struct ipc_ids *ids;

	/* If we had a locked structure, release it */
	if (ipc && ipc != SEQ_START_TOKEN)
		ipc_unlock(ipc);

	ids = &iter->ns->ids[iface->ids];
	/* Release the lock we took in start() */
	up_read(&ids->rw_mutex);
	up_read(&ids->rwsem);
}

static int sysvipc_proc_show(struct seq_file *s, void *it)
{
	struct ipc_proc_iter *iter = s->private;
	struct ipc_proc_iface *iface = iter->iface;

	if (it == SEQ_START_TOKEN)
		return seq_puts(s, iface->header);
	if (it == SEQ_START_TOKEN) {
		seq_puts(s, iface->header);
		return 0;
	}

	return iface->show(s, it);
}

static struct seq_operations sysvipc_proc_seqops = {
static const struct seq_operations sysvipc_proc_seqops = {
	.start = sysvipc_proc_start,
	.stop  = sysvipc_proc_stop,
	.next  = sysvipc_proc_next,
	.show  = sysvipc_proc_show,
};

static int sysvipc_proc_open(struct inode *inode, struct file *file)
{
	int ret;
	struct seq_file *seq;
	struct ipc_proc_iter *iter;

	ret = -ENOMEM;
	iter = kmalloc(sizeof(*iter), GFP_KERNEL);
	if (!iter)
		goto out;

	ret = seq_open(file, &sysvipc_proc_seqops);
	if (ret)
		goto out_kfree;

	seq = file->private_data;
	seq->private = iter;

	iter->iface = PDE(inode)->data;
	iter->ns    = get_ipc_ns(current->nsproxy->ipc_ns);
out:
	return ret;
out_kfree:
	kfree(iter);
	goto out;
	struct ipc_proc_iter *iter;

	iter = __seq_open_private(file, &sysvipc_proc_seqops, sizeof(*iter));
	if (!iter)
		return -ENOMEM;

	iter->iface = PDE_DATA(inode);
	iter->ns    = get_ipc_ns(current->nsproxy->ipc_ns);
	iter->pid_ns = get_pid_ns(task_active_pid_ns(current));

	return 0;
}

static int sysvipc_proc_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct ipc_proc_iter *iter = seq->private;
	put_ipc_ns(iter->ns);
	put_pid_ns(iter->pid_ns);
	return seq_release_private(inode, file);
}

static const struct file_operations sysvipc_proc_fops = {
	.open    = sysvipc_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = sysvipc_proc_release,
};
#endif /* CONFIG_PROC_FS */
