/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_NET_AFUNIX_H
#define __LINUX_NET_AFUNIX_H

#include <linux/socket.h>
#include <linux/un.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <net/sock.h>

extern void unix_inflight(struct file *fp);
extern void unix_notinflight(struct file *fp);
extern void unix_gc(void);

#define UNIX_HASH_SIZE	256

extern unsigned int unix_tot_inflight;
void unix_inflight(struct file *fp);
void unix_notinflight(struct file *fp);
void unix_inflight(struct user_struct *user, struct file *fp);
void unix_notinflight(struct user_struct *user, struct file *fp);
void unix_gc(void);
void wait_for_unix_gc(void);
struct sock *unix_get_socket(struct file *filp);
struct sock *unix_peer_get(struct sock *);

#define UNIX_HASH_SIZE	256
#define UNIX_HASH_BITS	8

extern unsigned int unix_tot_inflight;
extern spinlock_t unix_table_lock;
extern struct hlist_head unix_socket_table[2 * UNIX_HASH_SIZE];

struct unix_address {
	refcount_t	refcnt;
	int		len;
	unsigned	hash;
	unsigned int	hash;
	struct sockaddr_un name[0];
};

struct unix_skb_parms {
	struct ucred		creds;		/* Skb credentials	*/
	struct pid		*pid;		/* Skb credentials	*/
	kuid_t			uid;
	kgid_t			gid;
	struct scm_fp_list	*fp;		/* Passed files		*/
#ifdef CONFIG_SECURITY_NETWORK
	u32			secid;		/* Security ID		*/
#endif
};

#define UNIXCB(skb) 	(*(struct unix_skb_parms*)&((skb)->cb))
#define UNIXCREDS(skb)	(&UNIXCB((skb)).creds)
#define UNIXSID(skb)	(&UNIXCB((skb)).secid)
	u32			consumed;
} __randomize_layout;

#define UNIXCB(skb) 	(*(struct unix_skb_parms *)&((skb)->cb))

#define unix_state_lock(s)	spin_lock(&unix_sk(s)->lock)
#define unix_state_unlock(s)	spin_unlock(&unix_sk(s)->lock)
#define unix_state_lock_nested(s) \
				spin_lock_nested(&unix_sk(s)->lock, \
				SINGLE_DEPTH_NESTING)

#ifdef __KERNEL__
/* The AF_UNIX socket */
struct unix_sock {
	/* WARNING: sk has to be the first member */
	struct sock		sk;
        struct unix_address     *addr;
        struct dentry		*dentry;
        struct vfsmount		*mnt;
	struct mutex		readlock;
        struct sock		*peer;
        struct sock		*other;
	struct list_head	link;
        atomic_long_t           inflight;
        spinlock_t		lock;
	unsigned int		gc_candidate : 1;
        wait_queue_head_t       peer_wait;
};
#define unix_sk(__sk) ((struct unix_sock *)__sk)

#ifdef CONFIG_SYSCTL
extern int unix_sysctl_register(struct net *net);
extern void unix_sysctl_unregister(struct net *net);
	struct unix_address     *addr;
	struct path		path;
	struct mutex		iolock, bindlock;
	struct sock		*peer;
	struct list_head	link;
	atomic_long_t		inflight;
	spinlock_t		lock;
	unsigned long		gc_flags;
#define UNIX_GC_CANDIDATE	0
#define UNIX_GC_MAYBE_CYCLE	1
	struct socket_wq	peer_wq;
	wait_queue_entry_t		peer_wake;
};

static inline struct unix_sock *unix_sk(const struct sock *sk)
{
	return (struct unix_sock *)sk;
}

#define peer_wait peer_wq.wait

long unix_inq_len(struct sock *sk);
long unix_outq_len(struct sock *sk);

#ifdef CONFIG_SYSCTL
int unix_sysctl_register(struct net *net);
void unix_sysctl_unregister(struct net *net);
#else
static inline int unix_sysctl_register(struct net *net) { return 0; }
static inline void unix_sysctl_unregister(struct net *net) {}
#endif
#endif
#endif
