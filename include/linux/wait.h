/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_WAIT_H
#define _LINUX_WAIT_H

#define WNOHANG		0x00000001
#define WUNTRACED	0x00000002
#define WSTOPPED	WUNTRACED
#define WEXITED		0x00000004
#define WCONTINUED	0x00000008
#define WNOWAIT		0x01000000	/* Don't reap, just poll status.  */

#define __WNOTHREAD	0x20000000	/* Don't wait on children of other threads in this group */
#define __WALL		0x40000000	/* Wait on all children, regardless of type */
#define __WCLONE	0x80000000	/* Wait only on non-SIGCHLD children */

/* First argument to waitid: */
#define P_ALL		0
#define P_PID		1
#define P_PGID		2

#ifdef __KERNEL__

#include <linux/list.h>
#include <linux/stddef.h>
#include <linux/spinlock.h>
#include <asm/system.h>
#include <asm/current.h>

typedef struct __wait_queue wait_queue_t;
typedef int (*wait_queue_func_t)(wait_queue_t *wait, unsigned mode, int sync, void *key);
int default_wake_function(wait_queue_t *wait, unsigned mode, int sync, void *key);

struct __wait_queue {
	unsigned int flags;
#define WQ_FLAG_EXCLUSIVE	0x01
	void *private;
	wait_queue_func_t func;
	struct list_head task_list;
};

struct wait_bit_key {
	void *flags;
	int bit_nr;
};

struct wait_bit_queue {
	struct wait_bit_key key;
	wait_queue_t wait;
};

struct __wait_queue_head {
	spinlock_t lock;
	struct list_head task_list;
/*
 * Linux wait queue related types and methods
 */
#include <linux/list.h>
#include <linux/stddef.h>
#include <linux/spinlock.h>

#include <asm/current.h>
#include <uapi/linux/wait.h>

typedef struct wait_queue_entry wait_queue_entry_t;

typedef int (*wait_queue_func_t)(struct wait_queue_entry *wq_entry, unsigned mode, int flags, void *key);
int default_wake_function(struct wait_queue_entry *wq_entry, unsigned mode, int flags, void *key);

/* wait_queue_entry::flags */
#define WQ_FLAG_EXCLUSIVE	0x01
#define WQ_FLAG_WOKEN		0x02
#define WQ_FLAG_BOOKMARK	0x04

/*
 * A single wait-queue entry structure:
 */
struct wait_queue_entry {
	unsigned int		flags;
	void			*private;
	wait_queue_func_t	func;
	struct list_head	entry;
};

struct wait_queue_head {
	spinlock_t		lock;
	struct list_head	head;
};
typedef struct wait_queue_head wait_queue_head_t;

struct task_struct;

/*
 * Macros for declaration and initialisaton of the datatypes
 */

#define __WAITQUEUE_INITIALIZER(name, tsk) {					\
	.private	= tsk,							\
	.func		= default_wake_function,				\
	.entry		= { NULL, NULL } }

#define DECLARE_WAITQUEUE(name, tsk)						\
	struct wait_queue_entry name = __WAITQUEUE_INITIALIZER(name, tsk)

#define __WAIT_QUEUE_HEAD_INITIALIZER(name) {					\
	.lock		= __SPIN_LOCK_UNLOCKED(name.lock),			\
	.head		= { &(name).head, &(name).head } }

#define DECLARE_WAIT_QUEUE_HEAD(name) \
	struct wait_queue_head name = __WAIT_QUEUE_HEAD_INITIALIZER(name)

extern void __init_waitqueue_head(struct wait_queue_head *wq_head, const char *name, struct lock_class_key *);

extern void init_waitqueue_head(wait_queue_head_t *q);
#define __WAIT_ATOMIC_T_KEY_INITIALIZER(p)				\
	{ .flags = p, .bit_nr = WAIT_ATOMIC_T_BIT_NR, }

extern void __init_waitqueue_head(wait_queue_head_t *q, const char *name, struct lock_class_key *);

#define init_waitqueue_head(q)				\
	do {						\
		static struct lock_class_key __key;	\
							\
		__init_waitqueue_head((q), #q, &__key);	\
#define init_waitqueue_head(wq_head)						\
	do {									\
		static struct lock_class_key __key;				\
										\
		__init_waitqueue_head((wq_head), #wq_head, &__key);		\
	} while (0)

#ifdef CONFIG_LOCKDEP
# define __WAIT_QUEUE_HEAD_INIT_ONSTACK(name) \
	({ init_waitqueue_head(&name); name; })
# define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(name) \
	struct wait_queue_head name = __WAIT_QUEUE_HEAD_INIT_ONSTACK(name)
#else
# define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(name) DECLARE_WAIT_QUEUE_HEAD(name)
#endif

static inline void init_waitqueue_entry(struct wait_queue_entry *wq_entry, struct task_struct *p)
{
	q->flags = 0;
	q->private = p;
	q->func = default_wake_function;
}

static inline void init_waitqueue_func_entry(wait_queue_t *q,
					wait_queue_func_t func)
{
	q->flags = 0;
	q->private = NULL;
	q->func = func;
	q->flags	= 0;
	q->private	= p;
	q->func		= default_wake_function;
	wq_entry->flags		= 0;
	wq_entry->private	= p;
	wq_entry->func		= default_wake_function;
}

static inline void
init_waitqueue_func_entry(struct wait_queue_entry *wq_entry, wait_queue_func_t func)
{
	wq_entry->flags		= 0;
	wq_entry->private	= NULL;
	wq_entry->func		= func;
}

/**
 * waitqueue_active -- locklessly test for waiters on the queue
 * @wq_head: the waitqueue to test for waiters
 *
 * returns true if the wait list is not empty
 *
 * NOTE: this function is lockless and requires care, incorrect usage _will_
 * lead to sporadic and non-obvious failure.
 *
 * Use either while holding wait_queue_head::lock or when used for wakeups
 * with an extra smp_mb() like:
 *
 *      CPU0 - waker                    CPU1 - waiter
 *
 *                                      for (;;) {
 *      @cond = true;                     prepare_to_wait(&wq_head, &wait, state);
 *      smp_mb();                         // smp_mb() from set_current_state()
 *      if (waitqueue_active(wq_head))         if (@cond)
 *        wake_up(wq_head);                      break;
 *                                        schedule();
 *                                      }
 *                                      finish_wait(&wq_head, &wait);
 *
 * Because without the explicit smp_mb() it's possible for the
 * waitqueue_active() load to get hoisted over the @cond store such that we'll
 * observe an empty wait list while the waiter might not observe @cond.
 *
 * Also note that this 'optimization' trades a spin_lock() for an smp_mb(),
 * which (when the lock is uncontended) are of roughly equal cost.
 */
static inline int waitqueue_active(struct wait_queue_head *wq_head)
{
	return !list_empty(&wq_head->head);
}

/*
 * Used to distinguish between sync and async io wait context:
 * sync i/o typically specifies a NULL wait queue entry or a wait
 * queue entry bound to a task (current task) to wake up.
 * aio specifies a wait queue entry with an async notification
 * callback routine, not associated with any task.
 */
#define is_sync_wait(wait)	(!(wait) || ((wait)->private))

extern void add_wait_queue(wait_queue_head_t *q, wait_queue_t *wait);
extern void add_wait_queue_exclusive(wait_queue_head_t *q, wait_queue_t *wait);
extern void remove_wait_queue(wait_queue_head_t *q, wait_queue_t *wait);

static inline void __add_wait_queue(wait_queue_head_t *head, wait_queue_t *new)
/**
 * wq_has_sleeper - check if there are any waiting processes
 * @wq_head: wait queue head
 *
 * Returns true if wq_head has waiting processes
 *
 * Please refer to the comment for waitqueue_active.
 */
static inline bool wq_has_sleeper(struct wait_queue_head *wq_head)
{
	/*
	 * We need to be sure we are in sync with the
	 * add_wait_queue modifications to the wait queue.
	 *
	 * This memory barrier should be paired with one on the
	 * waiting side.
	 */
	smp_mb();
	return waitqueue_active(wq_head);
}

extern void add_wait_queue(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry);
extern void add_wait_queue_exclusive(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry);
extern void remove_wait_queue(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry);

static inline void __add_wait_queue(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
{
	list_add(&wq_entry->entry, &wq_head->head);
}

/*
 * Used for wake-one threads:
 */
static inline void __add_wait_queue_tail(wait_queue_head_t *head,
						wait_queue_t *new)
static inline void
__add_wait_queue_exclusive(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
{
	wq_entry->flags |= WQ_FLAG_EXCLUSIVE;
	__add_wait_queue(wq_head, wq_entry);
}

static inline void __add_wait_queue_entry_tail(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
{
	list_add_tail(&wq_entry->entry, &wq_head->head);
}

static inline void __remove_wait_queue(wait_queue_head_t *head,
							wait_queue_t *old)
static inline void
__add_wait_queue_entry_tail_exclusive(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
{
	wq_entry->flags |= WQ_FLAG_EXCLUSIVE;
	__add_wait_queue_entry_tail(wq_head, wq_entry);
}

static inline void
__remove_wait_queue(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
{
	list_del(&wq_entry->entry);
}

void __wake_up(wait_queue_head_t *q, unsigned int mode, int nr, void *key);
extern void __wake_up_locked(wait_queue_head_t *q, unsigned int mode);
extern void __wake_up_sync(wait_queue_head_t *q, unsigned int mode, int nr);
void __wake_up_bit(wait_queue_head_t *, void *, int);
int __wait_on_bit(wait_queue_head_t *, struct wait_bit_queue *, int (*)(void *), unsigned);
int __wait_on_bit_lock(wait_queue_head_t *, struct wait_bit_queue *, int (*)(void *), unsigned);
void wake_up_bit(void *, int);
int out_of_line_wait_on_bit(void *, int, int (*)(void *), unsigned);
int out_of_line_wait_on_bit_lock(void *, int, int (*)(void *), unsigned);
typedef int wait_bit_action_f(struct wait_bit_key *, int mode);
void __wake_up(wait_queue_head_t *q, unsigned int mode, int nr, void *key);
void __wake_up_locked_key(wait_queue_head_t *q, unsigned int mode, void *key);
void __wake_up_sync_key(wait_queue_head_t *q, unsigned int mode, int nr, void *key);
void __wake_up_locked(wait_queue_head_t *q, unsigned int mode, int nr);
void __wake_up_sync(wait_queue_head_t *q, unsigned int mode, int nr);
void __wake_up_bit(wait_queue_head_t *, void *, int);
int __wait_on_bit(wait_queue_head_t *, struct wait_bit_queue *, wait_bit_action_f *, unsigned);
int __wait_on_bit_lock(wait_queue_head_t *, struct wait_bit_queue *, wait_bit_action_f *, unsigned);
void wake_up_bit(void *, int);
void wake_up_atomic_t(atomic_t *);
int out_of_line_wait_on_bit(void *, int, wait_bit_action_f *, unsigned);
int out_of_line_wait_on_bit_timeout(void *, int, wait_bit_action_f *, unsigned, unsigned long);
int out_of_line_wait_on_bit_lock(void *, int, wait_bit_action_f *, unsigned);
int out_of_line_wait_on_atomic_t(atomic_t *, int (*)(atomic_t *), unsigned);
wait_queue_head_t *bit_waitqueue(void *, int);
void __wake_up(struct wait_queue_head *wq_head, unsigned int mode, int nr, void *key);
void __wake_up_locked_key(struct wait_queue_head *wq_head, unsigned int mode, void *key);
void __wake_up_locked_key_bookmark(struct wait_queue_head *wq_head,
		unsigned int mode, void *key, wait_queue_entry_t *bookmark);
void __wake_up_sync_key(struct wait_queue_head *wq_head, unsigned int mode, int nr, void *key);
void __wake_up_locked(struct wait_queue_head *wq_head, unsigned int mode, int nr);
void __wake_up_sync(struct wait_queue_head *wq_head, unsigned int mode, int nr);

#define wake_up(x)			__wake_up(x, TASK_NORMAL, 1, NULL)
#define wake_up_nr(x, nr)		__wake_up(x, TASK_NORMAL, nr, NULL)
#define wake_up_all(x)			__wake_up(x, TASK_NORMAL, 0, NULL)
#define wake_up_locked(x)		__wake_up_locked((x), TASK_NORMAL)
#define wake_up_locked(x)		__wake_up_locked((x), TASK_NORMAL, 1)
#define wake_up_all_locked(x)		__wake_up_locked((x), TASK_NORMAL, 0)

#define wake_up_interruptible(x)	__wake_up(x, TASK_INTERRUPTIBLE, 1, NULL)
#define wake_up_interruptible_nr(x, nr)	__wake_up(x, TASK_INTERRUPTIBLE, nr, NULL)
#define wake_up_interruptible_all(x)	__wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)
#define wake_up_interruptible_sync(x)	__wake_up_sync((x), TASK_INTERRUPTIBLE, 1)

#ifdef CONFIG_DEBUG_LOCK_ALLOC
/*
 * macro to avoid include hell
 */
#define wake_up_nested(x, s)						\
do {									\
	unsigned long flags;						\
									\
	spin_lock_irqsave_nested(&(x)->lock, flags, (s));		\
	wake_up_locked(x); 						\
	spin_unlock_irqrestore(&(x)->lock, flags);			\
} while (0)
#else
#define wake_up_nested(x, s)		wake_up(x)
#endif

#define __wait_event(wq, condition) 					\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_UNINTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		schedule();						\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
/*
 * Wakeup macros to be used to report events to the targets.
 */
#define poll_to_key(m) ((void *)(__force uintptr_t)(__poll_t)(m))
#define key_to_poll(m) ((__force __poll_t)(uintptr_t)(void *)(m))
#define wake_up_poll(x, m)							\
	__wake_up(x, TASK_NORMAL, 1, poll_to_key(m))
#define wake_up_locked_poll(x, m)						\
	__wake_up_locked_key((x), TASK_NORMAL, poll_to_key(m))
#define wake_up_interruptible_poll(x, m)					\
	__wake_up(x, TASK_INTERRUPTIBLE, 1, poll_to_key(m))
#define wake_up_interruptible_sync_poll(x, m)					\
	__wake_up_sync_key((x), TASK_INTERRUPTIBLE, 1, poll_to_key(m))

#define ___wait_cond_timeout(condition)						\
({										\
	bool __cond = (condition);						\
	if (__cond && !__ret)							\
		__ret = 1;							\
	__cond || !__ret;							\
})

#define ___wait_is_interruptible(state)						\
	(!__builtin_constant_p(state) ||					\
		state == TASK_INTERRUPTIBLE || state == TASK_KILLABLE)		\

extern void init_wait_entry(struct wait_queue_entry *wq_entry, int flags);

/*
 * The below macro ___wait_event() has an explicit shadow of the __ret
 * variable when used from the wait_event_*() macros.
 *
 * This is so that both can use the ___wait_cond_timeout() construct
 * to wrap the condition.
 *
 * The type inconsistency of the wait_event_*() __ret variable is also
 * on purpose; we use long where we can return timeout values and int
 * otherwise.
 */

#define ___wait_event(wq_head, condition, state, exclusive, ret, cmd)		\
({										\
	__label__ __out;							\
	struct wait_queue_entry __wq_entry;					\
	long __ret = ret;	/* explicit shadow */				\
										\
	init_wait_entry(&__wq_entry, exclusive ? WQ_FLAG_EXCLUSIVE : 0);	\
	for (;;) {								\
		long __int = prepare_to_wait_event(&wq_head, &__wq_entry, state);\
										\
		if (condition)							\
			break;							\
										\
		if (___wait_is_interruptible(state) && __int) {			\
			__ret = __int;						\
			goto __out;						\
		}								\
										\
		cmd;								\
	}									\
	finish_wait(&wq_head, &__wq_entry);					\
__out:	__ret;									\
})

#define __wait_event(wq_head, condition)					\
	(void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			    schedule())

/**
 * wait_event - sleep until a condition gets true
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_UNINTERRUPTIBLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 */
#define wait_event(wq, condition) 					\
do {									\
	if (condition)	 						\
#define wait_event(wq, condition)					\
do {									\
	might_sleep();							\
	if (condition)							\
		break;							\
	__wait_event(wq, condition);					\
} while (0)

#define __wait_event_timeout(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_UNINTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		ret = schedule_timeout(ret);				\
		if (!ret)						\
			break;						\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)

#define __io_wait_event(wq, condition)					\
	(void)___wait_event(wq, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
#define wait_event(wq_head, condition)						\
do {										\
	might_sleep();								\
	if (condition)								\
		break;								\
	__wait_event(wq_head, condition);					\
} while (0)

#define __io_wait_event(wq_head, condition)					\
	(void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			    io_schedule())

/*
 * io_wait_event() -- like wait_event() but with io_schedule()
 */
#define io_wait_event(wq_head, condition)					\
do {										\
	might_sleep();								\
	if (condition)								\
		break;								\
	__io_wait_event(wq_head, condition);					\
} while (0)

#define __wait_event_freezable(wq_head, condition)				\
	___wait_event(wq_head, condition, TASK_INTERRUPTIBLE, 0, 0,		\
			    schedule(); try_to_freeze())

/**
 * wait_event_freezable - sleep (or freeze) until a condition gets true
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE -- so as not to contribute
 * to system load) until the @condition evaluates to true. The
 * @condition is checked each time the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 */
#define wait_event_freezable(wq_head, condition)				\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_freezable(wq_head, condition);		\
	__ret;									\
})

#define __wait_event_timeout(wq_head, condition, timeout)			\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_UNINTERRUPTIBLE, 0, timeout,				\
		      __ret = schedule_timeout(__ret))

/**
 * wait_event_timeout - sleep until a condition gets true or a timeout elapses
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, in jiffies
 *
 * The process is put to sleep (TASK_UNINTERRUPTIBLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function returns 0 if the @timeout elapsed, and the remaining
 * jiffies if the condition evaluated to true before the timeout elapsed.
 * Returns:
 * 0 if the @condition evaluated to %false after the @timeout elapsed,
 * 1 if the @condition evaluated to %true after the @timeout elapsed,
 * or the remaining jiffies (at least 1) if the @condition evaluated
 * to %true before the @timeout elapsed.
 */
#define wait_event_timeout(wq, condition, timeout)			\
({									\
	long __ret = timeout;						\
	if (!(condition)) 						\
		__wait_event_timeout(wq, condition, __ret);		\
	__ret;								\
})

#define __wait_event_interruptible(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)

	might_sleep();							\
	if (!___wait_cond_timeout(condition))				\
		__ret = __wait_event_timeout(wq, condition, timeout);	\
	__ret;								\
#define wait_event_timeout(wq_head, condition, timeout)				\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_timeout(wq_head, condition, timeout);	\
	__ret;									\
})

#define __wait_event_freezable_timeout(wq_head, condition, timeout)		\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_INTERRUPTIBLE, 0, timeout,				\
		      __ret = schedule_timeout(__ret); try_to_freeze())

/*
 * like wait_event_timeout() -- except it uses TASK_INTERRUPTIBLE to avoid
 * increasing load and is freezable.
 */
#define wait_event_freezable_timeout(wq_head, condition, timeout)		\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_freezable_timeout(wq_head, condition, timeout); \
	__ret;									\
})

#define __wait_event_exclusive_cmd(wq_head, condition, cmd1, cmd2)		\
	(void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, 1, 0,	\
			    cmd1; schedule(); cmd2)
/*
 * Just like wait_event_cmd(), except it sets exclusive flag
 */
#define wait_event_exclusive_cmd(wq_head, condition, cmd1, cmd2)		\
do {										\
	if (condition)								\
		break;								\
	__wait_event_exclusive_cmd(wq_head, condition, cmd1, cmd2);		\
} while (0)

#define __wait_event_cmd(wq_head, condition, cmd1, cmd2)			\
	(void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			    cmd1; schedule(); cmd2)

/**
 * wait_event_cmd - sleep until a condition gets true
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @cmd1: the command will be executed before sleep
 * @cmd2: the command will be executed after sleep
 *
 * The process is put to sleep (TASK_UNINTERRUPTIBLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 */
#define wait_event_cmd(wq_head, condition, cmd1, cmd2)				\
do {										\
	if (condition)								\
		break;								\
	__wait_event_cmd(wq_head, condition, cmd1, cmd2);			\
} while (0)

#define __wait_event_interruptible(wq_head, condition)				\
	___wait_event(wq_head, condition, TASK_INTERRUPTIBLE, 0, 0,		\
		      schedule())

/**
 * wait_event_interruptible - sleep until a condition gets true
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function will return -ERESTARTSYS if it was interrupted by a
 * signal and 0 if @condition evaluated to true.
 */
#define wait_event_interruptible(wq, condition)				\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_interruptible(wq, condition, __ret);	\
	__ret;								\
})

#define __wait_event_interruptible_timeout(wq, condition, ret)		\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			ret = schedule_timeout(ret);			\
			if (!ret)					\
				break;					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
	might_sleep();							\
	if (!(condition))						\
		__ret = __wait_event_interruptible(wq, condition);	\
	__ret;								\
#define wait_event_interruptible(wq_head, condition)				\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_interruptible(wq_head, condition);		\
	__ret;									\
})

#define __wait_event_interruptible_timeout(wq_head, condition, timeout)		\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_INTERRUPTIBLE, 0, timeout,				\
		      __ret = schedule_timeout(__ret))

/**
 * wait_event_interruptible_timeout - sleep until a condition gets true or a timeout elapses
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, in jiffies
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function returns 0 if the @timeout elapsed, -ERESTARTSYS if it
 * was interrupted by a signal, and the remaining jiffies otherwise
 * if the condition evaluated to true before the timeout elapsed.
 * Returns:
 * 0 if the @condition evaluated to %false after the @timeout elapsed,
 * 1 if the @condition evaluated to %true after the @timeout elapsed,
 * the remaining jiffies (at least 1) if the @condition evaluated
 * to %true before the @timeout elapsed, or -%ERESTARTSYS if it was
 * interrupted by a signal.
 */
#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})

#define __wait_event_interruptible_exclusive(wq, condition, ret)	\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait_exclusive(&wq, &__wait,			\
					TASK_INTERRUPTIBLE);		\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
	might_sleep();							\
	if (!___wait_cond_timeout(condition))				\
		__ret = __wait_event_interruptible_timeout(wq,		\
						condition, timeout);	\
	__ret;								\
#define wait_event_interruptible_timeout(wq_head, condition, timeout)		\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_interruptible_timeout(wq_head,		\
						condition, timeout);		\
	__ret;									\
})

#define __wait_event_hrtimeout(wq_head, condition, timeout, state)		\
({										\
	int __ret = 0;								\
	struct hrtimer_sleeper __t;						\
										\
	hrtimer_init_on_stack(&__t.timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);	\
	hrtimer_init_sleeper(&__t, current);					\
	if ((timeout) != KTIME_MAX)						\
		hrtimer_start_range_ns(&__t.timer, timeout,			\
				       current->timer_slack_ns,			\
				       HRTIMER_MODE_REL);			\
										\
	__ret = ___wait_event(wq_head, condition, state, 0, 0,			\
		if (!__t.task) {						\
			__ret = -ETIME;						\
			break;							\
		}								\
		schedule());							\
										\
	hrtimer_cancel(&__t.timer);						\
	destroy_hrtimer_on_stack(&__t.timer);					\
	__ret;									\
})

/**
 * wait_event_hrtimeout - sleep until a condition gets true or a timeout elapses
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, as a ktime_t
 *
 * The process is put to sleep (TASK_UNINTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function returns 0 if @condition became true, or -ETIME if the timeout
 * elapsed.
 */
#define wait_event_hrtimeout(wq_head, condition, timeout)			\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_hrtimeout(wq_head, condition, timeout,	\
					       TASK_UNINTERRUPTIBLE);		\
	__ret;									\
})

/**
 * wait_event_interruptible_hrtimeout - sleep until a condition gets true or a timeout elapses
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, as a ktime_t
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function returns 0 if @condition became true, -ERESTARTSYS if it was
 * interrupted by a signal, or -ETIME if the timeout elapsed.
 */
#define wait_event_interruptible_hrtimeout(wq, condition, timeout)		\
({										\
	long __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_hrtimeout(wq, condition, timeout,		\
					       TASK_INTERRUPTIBLE);		\
	__ret;									\
})

#define __wait_event_interruptible_exclusive(wq, condition)			\
	___wait_event(wq, condition, TASK_INTERRUPTIBLE, 1, 0,			\
		      schedule())

#define wait_event_interruptible_exclusive(wq, condition)		\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_interruptible_exclusive(wq, condition, __ret);\
	__ret;								\
})

#define __wait_event_killable(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_KILLABLE);		\
		if (condition)						\
			break;						\
		if (!fatal_signal_pending(current)) {			\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
	might_sleep();							\
	if (!(condition))						\
		__ret = __wait_event_interruptible_exclusive(wq, condition);\
	__ret;								\
#define wait_event_interruptible_exclusive(wq, condition)			\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_interruptible_exclusive(wq, condition);	\
	__ret;									\
})

#define __wait_event_killable_exclusive(wq, condition)				\
	___wait_event(wq, condition, TASK_KILLABLE, 1, 0,			\
		      schedule())

#define wait_event_killable_exclusive(wq, condition)				\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_killable_exclusive(wq, condition);		\
	__ret;									\
})


#define __wait_event_freezable_exclusive(wq, condition)				\
	___wait_event(wq, condition, TASK_INTERRUPTIBLE, 1, 0,			\
			schedule(); try_to_freeze())

#define wait_event_freezable_exclusive(wq, condition)				\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_freezable_exclusive(wq, condition);	\
	__ret;									\
})

/**
 * wait_event_idle - wait for a condition without contributing to system load
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_IDLE) until the
 * @condition evaluates to true.
 * The @condition is checked each time the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 */
#define wait_event_idle(wq_head, condition)					\
do {										\
	might_sleep();								\
	if (!(condition))							\
		___wait_event(wq_head, condition, TASK_IDLE, 0, 0, schedule());	\
} while (0)

/**
 * wait_event_idle_exclusive - wait for a condition with contributing to system load
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_IDLE) until the
 * @condition evaluates to true.
 * The @condition is checked each time the waitqueue @wq_head is woken up.
 *
 * The process is put on the wait queue with an WQ_FLAG_EXCLUSIVE flag
 * set thus if other processes wait on the same list, when this
 * process is woken further processes are not considered.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 */
#define wait_event_idle_exclusive(wq_head, condition)				\
do {										\
	might_sleep();								\
	if (!(condition))							\
		___wait_event(wq_head, condition, TASK_IDLE, 1, 0, schedule());	\
} while (0)

#define __wait_event_idle_timeout(wq_head, condition, timeout)			\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_IDLE, 0, timeout,					\
		      __ret = schedule_timeout(__ret))

/**
 * wait_event_idle_timeout - sleep without load until a condition becomes true or a timeout elapses
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, in jiffies
 *
 * The process is put to sleep (TASK_IDLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * Returns:
 * 0 if the @condition evaluated to %false after the @timeout elapsed,
 * 1 if the @condition evaluated to %true after the @timeout elapsed,
 * or the remaining jiffies (at least 1) if the @condition evaluated
 * to %true before the @timeout elapsed.
 */
#define wait_event_idle_timeout(wq_head, condition, timeout)			\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_idle_timeout(wq_head, condition, timeout);	\
	__ret;									\
})

#define __wait_event_idle_exclusive_timeout(wq_head, condition, timeout)	\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_IDLE, 1, timeout,					\
		      __ret = schedule_timeout(__ret))

/**
 * wait_event_idle_exclusive_timeout - sleep without load until a condition becomes true or a timeout elapses
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, in jiffies
 *
 * The process is put to sleep (TASK_IDLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq_head is woken up.
 *
 * The process is put on the wait queue with an WQ_FLAG_EXCLUSIVE flag
 * set thus if other processes wait on the same list, when this
 * process is woken further processes are not considered.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * Returns:
 * 0 if the @condition evaluated to %false after the @timeout elapsed,
 * 1 if the @condition evaluated to %true after the @timeout elapsed,
 * or the remaining jiffies (at least 1) if the @condition evaluated
 * to %true before the @timeout elapsed.
 */
#define wait_event_idle_exclusive_timeout(wq_head, condition, timeout)		\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_idle_exclusive_timeout(wq_head, condition, timeout);\
	__ret;									\
})

extern int do_wait_intr(wait_queue_head_t *, wait_queue_entry_t *);
extern int do_wait_intr_irq(wait_queue_head_t *, wait_queue_entry_t *);

#define __wait_event_interruptible_locked(wq, condition, exclusive, fn)		\
({										\
	int __ret;								\
	DEFINE_WAIT(__wait);							\
	if (exclusive)								\
		__wait.flags |= WQ_FLAG_EXCLUSIVE;				\
	do {									\
		__ret = fn(&(wq), &__wait);					\
		if (__ret)							\
			break;							\
	} while (!(condition));							\
	__remove_wait_queue(&(wq), &__wait);					\
	__set_current_state(TASK_RUNNING);					\
	__ret;									\
})


/**
 * wait_event_interruptible_locked - sleep until a condition gets true
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * It must be called with wq.lock being held.  This spinlock is
 * unlocked while sleeping but @condition testing is done while lock
 * is held and when this macro exits the lock is held.
 *
 * The lock is locked/unlocked using spin_lock()/spin_unlock()
 * functions which must match the way they are locked/unlocked outside
 * of this macro.
 *
 * wake_up_locked() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function will return -ERESTARTSYS if it was interrupted by a
 * signal and 0 if @condition evaluated to true.
 */
#define wait_event_interruptible_locked(wq, condition)				\
	((condition)								\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 0, do_wait_intr))

/**
 * wait_event_interruptible_locked_irq - sleep until a condition gets true
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * It must be called with wq.lock being held.  This spinlock is
 * unlocked while sleeping but @condition testing is done while lock
 * is held and when this macro exits the lock is held.
 *
 * The lock is locked/unlocked using spin_lock_irq()/spin_unlock_irq()
 * functions which must match the way they are locked/unlocked outside
 * of this macro.
 *
 * wake_up_locked() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function will return -ERESTARTSYS if it was interrupted by a
 * signal and 0 if @condition evaluated to true.
 */
#define wait_event_interruptible_locked_irq(wq, condition)			\
	((condition)								\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 0, do_wait_intr_irq))

/**
 * wait_event_interruptible_exclusive_locked - sleep exclusively until a condition gets true
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * It must be called with wq.lock being held.  This spinlock is
 * unlocked while sleeping but @condition testing is done while lock
 * is held and when this macro exits the lock is held.
 *
 * The lock is locked/unlocked using spin_lock()/spin_unlock()
 * functions which must match the way they are locked/unlocked outside
 * of this macro.
 *
 * The process is put on the wait queue with an WQ_FLAG_EXCLUSIVE flag
 * set thus when other process waits process on the list if this
 * process is awaken further processes are not considered.
 *
 * wake_up_locked() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function will return -ERESTARTSYS if it was interrupted by a
 * signal and 0 if @condition evaluated to true.
 */
#define wait_event_interruptible_exclusive_locked(wq, condition)		\
	((condition)								\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 1, do_wait_intr))

/**
 * wait_event_interruptible_exclusive_locked_irq - sleep until a condition gets true
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq is woken up.
 *
 * It must be called with wq.lock being held.  This spinlock is
 * unlocked while sleeping but @condition testing is done while lock
 * is held and when this macro exits the lock is held.
 *
 * The lock is locked/unlocked using spin_lock_irq()/spin_unlock_irq()
 * functions which must match the way they are locked/unlocked outside
 * of this macro.
 *
 * The process is put on the wait queue with an WQ_FLAG_EXCLUSIVE flag
 * set thus when other process waits process on the list if this
 * process is awaken further processes are not considered.
 *
 * wake_up_locked() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function will return -ERESTARTSYS if it was interrupted by a
 * signal and 0 if @condition evaluated to true.
 */
#define wait_event_interruptible_exclusive_locked_irq(wq, condition)		\
	((condition)								\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 1, do_wait_intr_irq))


#define __wait_event_killable(wq, condition)					\
	___wait_event(wq, condition, TASK_KILLABLE, 0, 0, schedule())

/**
 * wait_event_killable - sleep until a condition gets true
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_KILLABLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function will return -ERESTARTSYS if it was interrupted by a
 * signal and 0 if @condition evaluated to true.
 */
#define wait_event_killable(wq, condition)				\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_killable(wq, condition, __ret);		\
	__ret;								\
})

/*
 * Must be called with the spinlock in the wait_queue_head_t held.
 */
static inline void add_wait_queue_exclusive_locked(wait_queue_head_t *q,
						   wait_queue_t * wait)
{
	wait->flags |= WQ_FLAG_EXCLUSIVE;
	__add_wait_queue_tail(q,  wait);
}

/*
 * Must be called with the spinlock in the wait_queue_head_t held.
 */
static inline void remove_wait_queue_locked(wait_queue_head_t *q,
					    wait_queue_t * wait)
{
	__remove_wait_queue(q,  wait);
}

/*
 * These are the old interfaces to sleep waiting for an event.
 * They are racy.  DO NOT use them, use the wait_event* interfaces above.
 * We plan to remove these interfaces.
 */
extern void sleep_on(wait_queue_head_t *q);
extern long sleep_on_timeout(wait_queue_head_t *q,
				      signed long timeout);
extern void interruptible_sleep_on(wait_queue_head_t *q);
extern long interruptible_sleep_on_timeout(wait_queue_head_t *q,
					   signed long timeout);
	might_sleep();							\
	if (!(condition))						\
		__ret = __wait_event_killable(wq, condition);		\
	__ret;								\
#define wait_event_killable(wq_head, condition)					\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_killable(wq_head, condition);		\
	__ret;									\
})

#define __wait_event_killable_timeout(wq_head, condition, timeout)		\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_KILLABLE, 0, timeout,				\
		      __ret = schedule_timeout(__ret))

/**
 * wait_event_killable_timeout - sleep until a condition gets true or a timeout elapses
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, in jiffies
 *
 * The process is put to sleep (TASK_KILLABLE) until the
 * @condition evaluates to true or a kill signal is received.
 * The @condition is checked each time the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * Returns:
 * 0 if the @condition evaluated to %false after the @timeout elapsed,
 * 1 if the @condition evaluated to %true after the @timeout elapsed,
 * the remaining jiffies (at least 1) if the @condition evaluated
 * to %true before the @timeout elapsed, or -%ERESTARTSYS if it was
 * interrupted by a kill signal.
 *
 * Only kill signals interrupt this process.
 */
#define wait_event_killable_timeout(wq_head, condition, timeout)		\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_killable_timeout(wq_head,			\
						condition, timeout);		\
	__ret;									\
})


#define __wait_event_lock_irq(wq_head, condition, lock, cmd)			\
	(void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			    spin_unlock_irq(&lock);				\
			    cmd;						\
			    schedule();						\
			    spin_lock_irq(&lock))

/**
 * wait_event_lock_irq_cmd - sleep until a condition gets true. The
 *			     condition is checked under the lock. This
 *			     is expected to be called with the lock
 *			     taken.
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @lock: a locked spinlock_t, which will be released before cmd
 *	  and schedule() and reacquired afterwards.
 * @cmd: a command which is invoked outside the critical section before
 *	 sleep
 *
 * The process is put to sleep (TASK_UNINTERRUPTIBLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * This is supposed to be called while holding the lock. The lock is
 * dropped before invoking the cmd and going to sleep and is reacquired
 * afterwards.
 */
#define wait_event_lock_irq_cmd(wq_head, condition, lock, cmd)			\
do {										\
	if (condition)								\
		break;								\
	__wait_event_lock_irq(wq_head, condition, lock, cmd);			\
} while (0)

/**
 * wait_event_lock_irq - sleep until a condition gets true. The
 *			 condition is checked under the lock. This
 *			 is expected to be called with the lock
 *			 taken.
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @lock: a locked spinlock_t, which will be released before schedule()
 *	  and reacquired afterwards.
 *
 * The process is put to sleep (TASK_UNINTERRUPTIBLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * This is supposed to be called while holding the lock. The lock is
 * dropped before going to sleep and is reacquired afterwards.
 */
#define wait_event_lock_irq(wq_head, condition, lock)				\
do {										\
	if (condition)								\
		break;								\
	__wait_event_lock_irq(wq_head, condition, lock, );			\
} while (0)


#define __wait_event_interruptible_lock_irq(wq_head, condition, lock, cmd)	\
	___wait_event(wq_head, condition, TASK_INTERRUPTIBLE, 0, 0,		\
		      spin_unlock_irq(&lock);					\
		      cmd;							\
		      schedule();						\
		      spin_lock_irq(&lock))

/**
 * wait_event_interruptible_lock_irq_cmd - sleep until a condition gets true.
 *		The condition is checked under the lock. This is expected to
 *		be called with the lock taken.
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @lock: a locked spinlock_t, which will be released before cmd and
 *	  schedule() and reacquired afterwards.
 * @cmd: a command which is invoked outside the critical section before
 *	 sleep
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received. The @condition is
 * checked each time the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * This is supposed to be called while holding the lock. The lock is
 * dropped before invoking the cmd and going to sleep and is reacquired
 * afterwards.
 *
 * The macro will return -ERESTARTSYS if it was interrupted by a signal
 * and 0 if @condition evaluated to true.
 */
#define wait_event_interruptible_lock_irq_cmd(wq_head, condition, lock, cmd)	\
({										\
	int __ret = 0;								\
	if (!(condition))							\
		__ret = __wait_event_interruptible_lock_irq(wq_head,		\
						condition, lock, cmd);		\
	__ret;									\
})

/**
 * wait_event_interruptible_lock_irq - sleep until a condition gets true.
 *		The condition is checked under the lock. This is expected
 *		to be called with the lock taken.
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @lock: a locked spinlock_t, which will be released before schedule()
 *	  and reacquired afterwards.
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or signal is received. The @condition is
 * checked each time the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * This is supposed to be called while holding the lock. The lock is
 * dropped before going to sleep and is reacquired afterwards.
 *
 * The macro will return -ERESTARTSYS if it was interrupted by a signal
 * and 0 if @condition evaluated to true.
 */
#define wait_event_interruptible_lock_irq(wq_head, condition, lock)		\
({										\
	int __ret = 0;								\
	if (!(condition))							\
		__ret = __wait_event_interruptible_lock_irq(wq_head,		\
						condition, lock,);		\
	__ret;									\
})

#define __wait_event_interruptible_lock_irq_timeout(wq_head, condition,		\
						    lock, timeout)		\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_INTERRUPTIBLE, 0, timeout,				\
		      spin_unlock_irq(&lock);					\
		      __ret = schedule_timeout(__ret);				\
		      spin_lock_irq(&lock));

/**
 * wait_event_interruptible_lock_irq_timeout - sleep until a condition gets
 *		true or a timeout elapses. The condition is checked under
 *		the lock. This is expected to be called with the lock taken.
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @lock: a locked spinlock_t, which will be released before schedule()
 *	  and reacquired afterwards.
 * @timeout: timeout, in jiffies
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or signal is received. The @condition is
 * checked each time the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * This is supposed to be called while holding the lock. The lock is
 * dropped before going to sleep and is reacquired afterwards.
 *
 * The function returns 0 if the @timeout elapsed, -ERESTARTSYS if it
 * was interrupted by a signal, and the remaining jiffies otherwise
 * if the condition evaluated to true before the timeout elapsed.
 */
#define wait_event_interruptible_lock_irq_timeout(wq_head, condition, lock,	\
						  timeout)			\
({										\
	long __ret = timeout;							\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_interruptible_lock_irq_timeout(		\
					wq_head, condition, lock, timeout);	\
	__ret;									\
})

/*
 * Waitqueues which are removed from the waitqueue_head at wakeup time
 */
void prepare_to_wait(wait_queue_head_t *q, wait_queue_t *wait, int state);
void prepare_to_wait_exclusive(wait_queue_head_t *q, wait_queue_t *wait, int state);
void finish_wait(wait_queue_head_t *q, wait_queue_t *wait);
int autoremove_wake_function(wait_queue_t *wait, unsigned mode, int sync, void *key);
int wake_bit_function(wait_queue_t *wait, unsigned mode, int sync, void *key);

#define DEFINE_WAIT(name)						\
	wait_queue_t name = {						\
		.private	= current,				\
		.func		= autoremove_wake_function,		\
		.task_list	= LIST_HEAD_INIT((name).task_list),	\
	}

long prepare_to_wait_event(wait_queue_head_t *q, wait_queue_t *wait, int state);
void finish_wait(wait_queue_head_t *q, wait_queue_t *wait);
void abort_exclusive_wait(wait_queue_head_t *q, wait_queue_t *wait, unsigned int mode, void *key);
long wait_woken(wait_queue_t *wait, unsigned mode, long timeout);
int woken_wake_function(wait_queue_t *wait, unsigned mode, int sync, void *key);
int autoremove_wake_function(wait_queue_t *wait, unsigned mode, int sync, void *key);
int wake_bit_function(wait_queue_t *wait, unsigned mode, int sync, void *key);
void prepare_to_wait(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry, int state);
void prepare_to_wait_exclusive(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry, int state);
long prepare_to_wait_event(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry, int state);
void finish_wait(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry);
long wait_woken(struct wait_queue_entry *wq_entry, unsigned mode, long timeout);
int woken_wake_function(struct wait_queue_entry *wq_entry, unsigned mode, int sync, void *key);
int autoremove_wake_function(struct wait_queue_entry *wq_entry, unsigned mode, int sync, void *key);

#define DEFINE_WAIT_FUNC(name, function)					\
	struct wait_queue_entry name = {					\
		.private	= current,					\
		.func		= function,					\
		.entry		= LIST_HEAD_INIT((name).entry),			\
	}

#define DEFINE_WAIT(name) DEFINE_WAIT_FUNC(name, autoremove_wake_function)

#define DEFINE_WAIT_BIT(name, word, bit)				\
	struct wait_bit_queue name = {					\
		.key = __WAIT_BIT_KEY_INITIALIZER(word, bit),		\
		.wait	= {						\
			.private	= current,			\
			.func		= wake_bit_function,		\
			.task_list	=				\
				LIST_HEAD_INIT((name).wait.task_list),	\
		},							\
	}

#define init_wait(wait)							\
	do {								\
		(wait)->private = current;				\
		(wait)->func = autoremove_wake_function;		\
		INIT_LIST_HEAD(&(wait)->task_list);			\
	} while (0)

		(wait)->flags = 0;					\
	} while (0)


extern int bit_wait(struct wait_bit_key *, int);
extern int bit_wait_io(struct wait_bit_key *, int);
extern int bit_wait_timeout(struct wait_bit_key *, int);
extern int bit_wait_io_timeout(struct wait_bit_key *, int);

/**
 * wait_on_bit - wait for a bit to be cleared
 * @word: the word being waited on, a kernel virtual address
 * @bit: the bit of the word being waited on
 * @action: the function used to sleep, which may take special actions
 * @mode: the task state to sleep in
 *
 * There is a standard hashed waitqueue table for generic use. This
 * is the part of the hashtable's accessor API that waits on a bit.
 * For instance, if one were to have waiters on a bitflag, one would
 * call wait_on_bit() in threads waiting for the bit to clear.
 * One uses wait_on_bit() where one is waiting for the bit to clear,
 * but has no intention of setting it.
 */
static inline int wait_on_bit(void *word, int bit,
				int (*action)(void *), unsigned mode)
{
 * Returned value will be zero if the bit was cleared, or non-zero
 * if the process received a signal and the mode permitted wakeup
 * on that signal.
 */
static inline int
wait_on_bit(unsigned long *word, int bit, unsigned mode)
{
	might_sleep();
	if (!test_bit(bit, word))
		return 0;
	return out_of_line_wait_on_bit(word, bit,
				       bit_wait,
				       mode);
}

/**
 * wait_on_bit_io - wait for a bit to be cleared
 * @word: the word being waited on, a kernel virtual address
 * @bit: the bit of the word being waited on
 * @mode: the task state to sleep in
 *
 * Use the standard hashed waitqueue table to wait for a bit
 * to be cleared.  This is similar to wait_on_bit(), but calls
 * io_schedule() instead of schedule() for the actual waiting.
 *
 * Returned value will be zero if the bit was cleared, or non-zero
 * if the process received a signal and the mode permitted wakeup
 * on that signal.
 */
static inline int
wait_on_bit_io(unsigned long *word, int bit, unsigned mode)
{
	might_sleep();
	if (!test_bit(bit, word))
		return 0;
	return out_of_line_wait_on_bit(word, bit,
				       bit_wait_io,
				       mode);
}

/**
 * wait_on_bit_timeout - wait for a bit to be cleared or a timeout elapses
 * @word: the word being waited on, a kernel virtual address
 * @bit: the bit of the word being waited on
 * @mode: the task state to sleep in
 * @timeout: timeout, in jiffies
 *
 * Use the standard hashed waitqueue table to wait for a bit
 * to be cleared. This is similar to wait_on_bit(), except also takes a
 * timeout parameter.
 *
 * Returned value will be zero if the bit was cleared before the
 * @timeout elapsed, or non-zero if the @timeout elapsed or process
 * received a signal and the mode permitted wakeup on that signal.
 */
static inline int
wait_on_bit_timeout(unsigned long *word, int bit, unsigned mode,
		    unsigned long timeout)
{
	might_sleep();
	if (!test_bit(bit, word))
		return 0;
	return out_of_line_wait_on_bit_timeout(word, bit,
					       bit_wait_timeout,
					       mode, timeout);
}

/**
 * wait_on_bit_action - wait for a bit to be cleared
 * @word: the word being waited on, a kernel virtual address
 * @bit: the bit of the word being waited on
 * @action: the function used to sleep, which may take special actions
 * @mode: the task state to sleep in
 *
 * Use the standard hashed waitqueue table to wait for a bit
 * to be cleared, and allow the waiting action to be specified.
 * This is like wait_on_bit() but allows fine control of how the waiting
 * is done.
 *
 * Returned value will be zero if the bit was cleared, or non-zero
 * if the process received a signal and the mode permitted wakeup
 * on that signal.
 */
static inline int
wait_on_bit_action(unsigned long *word, int bit, wait_bit_action_f *action,
		   unsigned mode)
{
	might_sleep();
	if (!test_bit(bit, word))
		return 0;
	return out_of_line_wait_on_bit(word, bit, action, mode);
}

/**
 * wait_on_bit_lock - wait for a bit to be cleared, when wanting to set it
 * @word: the word being waited on, a kernel virtual address
 * @bit: the bit of the word being waited on
 * @action: the function used to sleep, which may take special actions
 * @mode: the task state to sleep in
 *
 * There is a standard hashed waitqueue table for generic use. This
 * is the part of the hashtable's accessor API that waits on a bit
 * when one intends to set it, for instance, trying to lock bitflags.
 * For instance, if one were to have waiters trying to set bitflag
 * and waiting for it to clear before setting it, one would call
 * wait_on_bit() in threads waiting to be able to set the bit.
 * One uses wait_on_bit_lock() where one is waiting for the bit to
 * clear with the intention of setting it, and when done, clearing it.
 */
static inline int wait_on_bit_lock(void *word, int bit,
				int (*action)(void *), unsigned mode)
{
 *
 * Returns zero if the bit was (eventually) found to be clear and was
 * set.  Returns non-zero if a signal was delivered to the process and
 * the @mode allows that signal to wake the process.
 */
static inline int
wait_on_bit_lock(unsigned long *word, int bit, unsigned mode)
{
	might_sleep();
	if (!test_and_set_bit(bit, word))
		return 0;
	return out_of_line_wait_on_bit_lock(word, bit, bit_wait, mode);
}

/**
 * wait_on_bit_lock_io - wait for a bit to be cleared, when wanting to set it
 * @word: the word being waited on, a kernel virtual address
 * @bit: the bit of the word being waited on
 * @mode: the task state to sleep in
 *
 * Use the standard hashed waitqueue table to wait for a bit
 * to be cleared and then to atomically set it.  This is similar
 * to wait_on_bit(), but calls io_schedule() instead of schedule()
 * for the actual waiting.
 *
 * Returns zero if the bit was (eventually) found to be clear and was
 * set.  Returns non-zero if a signal was delivered to the process and
 * the @mode allows that signal to wake the process.
 */
static inline int
wait_on_bit_lock_io(unsigned long *word, int bit, unsigned mode)
{
	might_sleep();
	if (!test_and_set_bit(bit, word))
		return 0;
	return out_of_line_wait_on_bit_lock(word, bit, bit_wait_io, mode);
}

/**
 * wait_on_bit_lock_action - wait for a bit to be cleared, when wanting to set it
 * @word: the word being waited on, a kernel virtual address
 * @bit: the bit of the word being waited on
 * @action: the function used to sleep, which may take special actions
 * @mode: the task state to sleep in
 *
 * Use the standard hashed waitqueue table to wait for a bit
 * to be cleared and then to set it, and allow the waiting action
 * to be specified.
 * This is like wait_on_bit() but allows fine control of how the waiting
 * is done.
 *
 * Returns zero if the bit was (eventually) found to be clear and was
 * set.  Returns non-zero if a signal was delivered to the process and
 * the @mode allows that signal to wake the process.
 */
static inline int
wait_on_bit_lock_action(unsigned long *word, int bit, wait_bit_action_f *action,
			unsigned mode)
{
	might_sleep();
	if (!test_and_set_bit(bit, word))
		return 0;
	return out_of_line_wait_on_bit_lock(word, bit, action, mode);
}
	
#endif /* __KERNEL__ */

#endif

/**
 * wait_on_atomic_t - Wait for an atomic_t to become 0
 * @val: The atomic value being waited on, a kernel virtual address
 * @action: the function used to sleep, which may take special actions
 * @mode: the task state to sleep in
 *
 * Wait for an atomic_t to become 0.  We abuse the bit-wait waitqueue table for
 * the purpose of getting a waitqueue, but we set the key to a bit number
 * outside of the target 'word'.
 */
static inline
int wait_on_atomic_t(atomic_t *val, int (*action)(atomic_t *), unsigned mode)
{
	might_sleep();
	if (atomic_read(val) == 0)
		return 0;
	return out_of_line_wait_on_atomic_t(val, action, mode);
}

#define init_wait(wait)								\
	do {									\
		(wait)->private = current;					\
		(wait)->func = autoremove_wake_function;			\
		INIT_LIST_HEAD(&(wait)->entry);					\
		(wait)->flags = 0;						\
	} while (0)

#endif /* _LINUX_WAIT_H */
