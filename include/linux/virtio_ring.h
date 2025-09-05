/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VIRTIO_RING_H
#define _LINUX_VIRTIO_RING_H
/* An interface for efficient virtio implementation, currently for use by KVM
 * and lguest, but hopefully others soon.  Do NOT change this since it will
 * break existing servers and clients.
 *
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Copyright Rusty Russell IBM Corporation 2007. */
#include <linux/types.h>

/* This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT	1
/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE	2

/* The Host uses this in used->flags to advise the Guest: don't kick me when
 * you add a buffer.  It's unreliable, so it's simply an optimization.  Guest
 * will still kick if it's out of buffers. */
#define VRING_USED_F_NO_NOTIFY	1
/* The Guest uses this in avail->flags to advise the Host: don't interrupt me
 * when you consume a buffer.  It's unreliable, so it's simply an
 * optimization.  */
#define VRING_AVAIL_F_NO_INTERRUPT	1

/* Virtio ring descriptors: 16 bytes.  These can chain together via "next". */
struct vring_desc
{
	/* Address (guest-physical). */
	__u64 addr;
	/* Length. */
	__u32 len;
	/* The flags as indicated above. */
	__u16 flags;
	/* We chain unused descriptors via this, too */
	__u16 next;
};

struct vring_avail
{
	__u16 flags;
	__u16 idx;
	__u16 ring[];
};

/* u32 is used here for ids for padding reasons. */
struct vring_used_elem
{
	/* Index of start of used descriptor chain. */
	__u32 id;
	/* Total length of the descriptor chain which was used (written to) */
	__u32 len;
};

struct vring_used
{
	__u16 flags;
	__u16 idx;
	struct vring_used_elem ring[];
};

struct vring {
	unsigned int num;

	struct vring_desc *desc;

	struct vring_avail *avail;

	struct vring_used *used;
};

/* The standard layout for the ring is a continuous chunk of memory which looks
 * like this.  We assume num is a power of 2.
 *
 * struct vring
 * {
 *	// The actual descriptors (16 bytes each)
 *	struct vring_desc desc[num];
 *
 *	// A ring of available descriptor heads with free-running index.
 *	__u16 avail_flags;
 *	__u16 avail_idx;
 *	__u16 available[num];
 *
 *	// Padding to the next page boundary.
 *	char pad[];
 *
 *	// A ring of used descriptor heads with free-running index.
 *	__u16 used_flags;
 *	__u16 used_idx;
 *	struct vring_used_elem used[num];
 * };
 */
static inline void vring_init(struct vring *vr, unsigned int num, void *p,
			      unsigned long pagesize)
{
	vr->num = num;
	vr->desc = p;
	vr->avail = p + num*sizeof(struct vring_desc);
	vr->used = (void *)(((unsigned long)&vr->avail->ring[num] + pagesize-1)
			    & ~(pagesize - 1));
}

static inline unsigned vring_size(unsigned int num, unsigned long pagesize)
{
	return ((sizeof(struct vring_desc) * num + sizeof(__u16) * (2 + num)
		 + pagesize - 1) & ~(pagesize - 1))
		+ sizeof(__u16) * 2 + sizeof(struct vring_used_elem) * num;
}

#ifdef __KERNEL__
#include <linux/irqreturn.h>
struct virtio_device;
struct virtqueue;

struct virtqueue *vring_new_virtqueue(unsigned int num,
				      struct virtio_device *vdev,
				      void *pages,
				      void (*notify)(struct virtqueue *vq),
				      void (*callback)(struct virtqueue *vq));

#include <asm/barrier.h>
#include <linux/irqreturn.h>
#include <uapi/linux/virtio_ring.h>

/*
 * Barriers in virtio are tricky.  Non-SMP virtio guests can't assume
 * they're not on an SMP host system, so they need to assume real
 * barriers.  Non-SMP virtio hosts could skip the barriers, but does
 * anyone care?
 *
 * For virtio_pci on SMP, we don't need to order with respect to MMIO
 * accesses through relaxed memory I/O windows, so virt_mb() et al are
 * sufficient.
 *
 * For using virtio to talk to real devices (eg. other heterogeneous
 * CPUs) we do need real barriers.  In theory, we could be using both
 * kinds of virtio, so it's a runtime decision, and the branch is
 * actually quite cheap.
 */

static inline void virtio_mb(bool weak_barriers)
{
	if (weak_barriers)
		virt_mb();
	else
		mb();
}

static inline void virtio_rmb(bool weak_barriers)
{
	if (weak_barriers)
		virt_rmb();
	else
		dma_rmb();
}

static inline void virtio_wmb(bool weak_barriers)
{
	if (weak_barriers)
		virt_wmb();
	else
		dma_wmb();
}

static inline void virtio_store_mb(bool weak_barriers,
				   __virtio16 *p, __virtio16 v)
{
	if (weak_barriers) {
		virt_store_mb(*p, v);
	} else {
		WRITE_ONCE(*p, v);
		mb();
	}
}

struct virtio_device;
struct virtqueue;

/*
 * Creates a virtqueue and allocates the descriptor ring.  If
 * may_reduce_num is set, then this may allocate a smaller ring than
 * expected.  The caller should query virtqueue_get_vring_size to learn
 * the actual size of the ring.
 */
struct virtqueue *vring_create_virtqueue(unsigned int index,
					 unsigned int num,
					 unsigned int vring_align,
					 struct virtio_device *vdev,
					 bool weak_barriers,
					 bool may_reduce_num,
					 bool ctx,
					 bool (*notify)(struct virtqueue *vq),
					 void (*callback)(struct virtqueue *vq),
					 const char *name);

/* Creates a virtqueue with a custom layout. */
struct virtqueue *__vring_new_virtqueue(unsigned int index,
					struct vring vring,
					struct virtio_device *vdev,
					bool weak_barriers,
					bool ctx,
					bool (*notify)(struct virtqueue *),
					void (*callback)(struct virtqueue *),
					const char *name);

/*
 * Creates a virtqueue with a standard layout but a caller-allocated
 * ring.
 */
struct virtqueue *vring_new_virtqueue(unsigned int index,
				      unsigned int num,
				      unsigned int vring_align,
				      struct virtio_device *vdev,
				      bool weak_barriers,
				      bool ctx,
				      void *pages,
				      bool (*notify)(struct virtqueue *vq),
				      void (*callback)(struct virtqueue *vq),
				      const char *name);

/*
 * Destroys a virtqueue.  If created with vring_create_virtqueue, this
 * also frees the ring.
 */
void vring_del_virtqueue(struct virtqueue *vq);

/* Filter out transport-specific feature bits. */
void vring_transport_features(struct virtio_device *vdev);

irqreturn_t vring_interrupt(int irq, void *_vq);
#endif /* __KERNEL__ */
#endif /* _LINUX_VIRTIO_RING_H */
