/**
 * \file drm_auth.c
 * IOCTLs for authentication
 *
 * \author Rickard E. (Rik) Faith <faith@valinux.com>
 * \author Gareth Hughes <gareth@valinux.com>
 */

/*
 * Created: Tue Feb  2 08:37:54 1999 by faith@valinux.com
 *
 * Copyright 1999 Precision Insight, Inc., Cedar Park, Texas.
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
 * All Rights Reserved.
 *
 * Author Rickard E. (Rik) Faith <faith@valinux.com>
 * Author Gareth Hughes <gareth@valinux.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include "drmP.h"

/**
 * Find the file with the given magic number.
 *
 * \param dev DRM device.
 * \param magic magic number.
 *
 * Searches in drm_device::magiclist within all files with the same hash key
 * the one with matching magic number, while holding the drm_device::struct_mutex
 * lock.
 */
static struct drm_file *drm_find_file(struct drm_device * dev, drm_magic_t magic)
{
	struct drm_file *retval = NULL;
	struct drm_magic_entry *pt;
	struct drm_hash_item *hash;

	mutex_lock(&dev->struct_mutex);
	if (!drm_ht_find_item(&dev->magiclist, (unsigned long)magic, &hash)) {
		pt = drm_hash_entry(hash, struct drm_magic_entry, hash_item);
		retval = pt->priv;
	}
	mutex_unlock(&dev->struct_mutex);
	return retval;
}

/**
 * Adds a magic number.
 *
 * \param dev DRM device.
 * \param priv file private data.
 * \param magic magic number.
 *
 * Creates a drm_magic_entry structure and appends to the linked list
 * associated the magic number hash key in drm_device::magiclist, while holding
 * the drm_device::struct_mutex lock.
 */
static int drm_add_magic(struct drm_device * dev, struct drm_file * priv,
			 drm_magic_t magic)
{
	struct drm_magic_entry *entry;

	DRM_DEBUG("%d\n", magic);

	entry = drm_alloc(sizeof(*entry), DRM_MEM_MAGIC);
	if (!entry)
		return -ENOMEM;
	memset(entry, 0, sizeof(*entry));
	entry->priv = priv;

	entry->hash_item.key = (unsigned long)magic;
	mutex_lock(&dev->struct_mutex);
	drm_ht_insert_item(&dev->magiclist, &entry->hash_item);
	list_add_tail(&entry->head, &dev->magicfree);
	mutex_unlock(&dev->struct_mutex);

	return 0;
}

/**
 * Remove a magic number.
 *
 * \param dev DRM device.
 * \param magic magic number.
 *
 * Searches and unlinks the entry in drm_device::magiclist with the magic
 * number hash key, while holding the drm_device::struct_mutex lock.
 */
static int drm_remove_magic(struct drm_device * dev, drm_magic_t magic)
{
	struct drm_magic_entry *pt;
	struct drm_hash_item *hash;

	DRM_DEBUG("%d\n", magic);

	mutex_lock(&dev->struct_mutex);
	if (drm_ht_find_item(&dev->magiclist, (unsigned long)magic, &hash)) {
		mutex_unlock(&dev->struct_mutex);
		return -EINVAL;
	}
	pt = drm_hash_entry(hash, struct drm_magic_entry, hash_item);
	drm_ht_remove_item(&dev->magiclist, hash);
	list_del(&pt->head);
	mutex_unlock(&dev->struct_mutex);

	drm_free(pt, sizeof(*pt), DRM_MEM_MAGIC);

	return 0;
}

/**
 * Get a unique magic number (ioctl).
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg pointer to a resulting drm_auth structure.
 * \return zero on success, or a negative number on failure.
 *
 * If there is a magic number in drm_file::magic then use it, otherwise
 * searches an unique non-zero magic number and add it associating it with \p
 * file_priv.
 */
int drm_getmagic(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	static drm_magic_t sequence = 0;
	static DEFINE_SPINLOCK(lock);
	struct drm_auth *auth = data;

	/* Find unique magic */
	if (file_priv->magic) {
		auth->magic = file_priv->magic;
	} else {
		do {
			spin_lock(&lock);
			if (!sequence)
				++sequence;	/* reserve 0 */
			auth->magic = sequence++;
			spin_unlock(&lock);
		} while (drm_find_file(dev, auth->magic));
		file_priv->magic = auth->magic;
		drm_add_magic(dev, file_priv, auth->magic);
	}

	DRM_DEBUG("%u\n", auth->magic);

	return 0;
}

/**
 * Authenticate with a magic.
 *
 * \param inode device inode.
 * \param file_priv DRM file private.
 * \param cmd command.
 * \param arg pointer to a drm_auth structure.
 * \return zero if authentication successed, or a negative number otherwise.
 *
 * Checks if \p file_priv is associated with the magic number passed in \arg.
#include <drm/drmP.h>
#include "drm_internal.h"
#include "drm_legacy.h"

/**
 * DOC: master and authentication
 *
 * &struct drm_master is used to track groups of clients with open
 * primary/legacy device nodes. For every &struct drm_file which has had at
 * least once successfully became the device master (either through the
 * SET_MASTER IOCTL, or implicitly through opening the primary device node when
 * no one else is the current master that time) there exists one &drm_master.
 * This is noted in &drm_file.is_master. All other clients have just a pointer
 * to the &drm_master they are associated with.
 *
 * In addition only one &drm_master can be the current master for a &drm_device.
 * It can be switched through the DROP_MASTER and SET_MASTER IOCTL, or
 * implicitly through closing/openeing the primary device node. See also
 * drm_is_current_master().
 *
 * Clients can authenticate against the current master (if it matches their own)
 * using the GETMAGIC and AUTHMAGIC IOCTLs. Together with exchanging masters,
 * this allows controlled access to the device for an entire group of mutually
 * trusted clients.
 */

int drm_getmagic(struct drm_device *dev, void *data, struct drm_file *file_priv)
{
	struct drm_auth *auth = data;
	int ret = 0;

	mutex_lock(&dev->master_mutex);
	if (!file_priv->magic) {
		ret = idr_alloc(&file_priv->master->magic_map, file_priv,
				1, 0, GFP_KERNEL);
		if (ret >= 0)
			file_priv->magic = ret;
	}
	auth->magic = file_priv->magic;
	mutex_unlock(&dev->master_mutex);

	DRM_DEBUG("%u\n", auth->magic);

	return ret < 0 ? ret : 0;
}

int drm_authmagic(struct drm_device *dev, void *data,
		  struct drm_file *file_priv)
{
	struct drm_auth *auth = data;
	struct drm_file *file;

	DRM_DEBUG("%u\n", auth->magic);
	if ((file = drm_find_file(dev, auth->magic))) {
		file->authenticated = 1;
		drm_remove_magic(dev, auth->magic);
		return 0;
	}
	return -EINVAL;

	mutex_lock(&dev->master_mutex);
	file = idr_find(&file_priv->master->magic_map, auth->magic);
	if (file) {
		file->authenticated = 1;
		idr_replace(&file_priv->master->magic_map, NULL, auth->magic);
	}
	mutex_unlock(&dev->master_mutex);

	return file ? 0 : -EINVAL;
}

static struct drm_master *drm_master_create(struct drm_device *dev)
{
	struct drm_master *master;

	master = kzalloc(sizeof(*master), GFP_KERNEL);
	if (!master)
		return NULL;

	kref_init(&master->refcount);
	spin_lock_init(&master->lock.spinlock);
	init_waitqueue_head(&master->lock.lock_queue);
	idr_init(&master->magic_map);
	master->dev = dev;

	return master;
}

static int drm_set_master(struct drm_device *dev, struct drm_file *fpriv,
			  bool new_master)
{
	int ret = 0;

	dev->master = drm_master_get(fpriv->master);
	if (dev->driver->master_set) {
		ret = dev->driver->master_set(dev, fpriv, new_master);
		if (unlikely(ret != 0)) {
			drm_master_put(&dev->master);
		}
	}

	return ret;
}

static int drm_new_set_master(struct drm_device *dev, struct drm_file *fpriv)
{
	struct drm_master *old_master;
	int ret;

	lockdep_assert_held_once(&dev->master_mutex);

	old_master = fpriv->master;
	fpriv->master = drm_master_create(dev);
	if (!fpriv->master) {
		fpriv->master = old_master;
		return -ENOMEM;
	}

	if (dev->driver->master_create) {
		ret = dev->driver->master_create(dev, fpriv->master);
		if (ret)
			goto out_err;
	}
	fpriv->is_master = 1;
	fpriv->authenticated = 1;

	ret = drm_set_master(dev, fpriv, true);
	if (ret)
		goto out_err;

	if (old_master)
		drm_master_put(&old_master);

	return 0;

out_err:
	/* drop references and restore old master on failure */
	drm_master_put(&fpriv->master);
	fpriv->master = old_master;

	return ret;
}

int drm_setmaster_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv)
{
	int ret = 0;

	mutex_lock(&dev->master_mutex);
	if (drm_is_current_master(file_priv))
		goto out_unlock;

	if (dev->master) {
		ret = -EINVAL;
		goto out_unlock;
	}

	if (!file_priv->master) {
		ret = -EINVAL;
		goto out_unlock;
	}

	if (!file_priv->is_master) {
		ret = drm_new_set_master(dev, file_priv);
		goto out_unlock;
	}

	ret = drm_set_master(dev, file_priv, false);
out_unlock:
	mutex_unlock(&dev->master_mutex);
	return ret;
}

static void drm_drop_master(struct drm_device *dev,
			    struct drm_file *fpriv)
{
	if (dev->driver->master_drop)
		dev->driver->master_drop(dev, fpriv);
	drm_master_put(&dev->master);
}

int drm_dropmaster_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file_priv)
{
	int ret = -EINVAL;

	mutex_lock(&dev->master_mutex);
	if (!drm_is_current_master(file_priv))
		goto out_unlock;

	if (!dev->master)
		goto out_unlock;

	ret = 0;
	drm_drop_master(dev, file_priv);
out_unlock:
	mutex_unlock(&dev->master_mutex);
	return ret;
}

int drm_master_open(struct drm_file *file_priv)
{
	struct drm_device *dev = file_priv->minor->dev;
	int ret = 0;

	/* if there is no current master make this fd it, but do not create
	 * any master object for render clients */
	mutex_lock(&dev->master_mutex);
	if (!dev->master)
		ret = drm_new_set_master(dev, file_priv);
	else
		file_priv->master = drm_master_get(dev->master);
	mutex_unlock(&dev->master_mutex);

	return ret;
}

void drm_master_release(struct drm_file *file_priv)
{
	struct drm_device *dev = file_priv->minor->dev;
	struct drm_master *master = file_priv->master;

	mutex_lock(&dev->master_mutex);
	if (file_priv->magic)
		idr_remove(&file_priv->master->magic_map, file_priv->magic);

	if (!drm_is_current_master(file_priv))
		goto out;

	if (drm_core_check_feature(dev, DRIVER_LEGACY)) {
		/*
		 * Since the master is disappearing, so is the
		 * possibility to lock.
		 */
		mutex_lock(&dev->struct_mutex);
		if (master->lock.hw_lock) {
			if (dev->sigdata.lock == master->lock.hw_lock)
				dev->sigdata.lock = NULL;
			master->lock.hw_lock = NULL;
			master->lock.file_priv = NULL;
			wake_up_interruptible_all(&master->lock.lock_queue);
		}
		mutex_unlock(&dev->struct_mutex);
	}

	if (dev->master == file_priv->master)
		drm_drop_master(dev, file_priv);
out:
	/* drop the master reference held by the file priv */
	if (file_priv->master)
		drm_master_put(&file_priv->master);
	mutex_unlock(&dev->master_mutex);
}

/**
 * drm_is_current_master - checks whether @priv is the current master
 * @fpriv: DRM file private
 *
 * Checks whether @fpriv is current master on its device. This decides whether a
 * client is allowed to run DRM_MASTER IOCTLs.
 *
 * Most of the modern IOCTL which require DRM_MASTER are for kernel modesetting
 * - the current master is assumed to own the non-shareable display hardware.
 */
bool drm_is_current_master(struct drm_file *fpriv)
{
	return fpriv->is_master && fpriv->master == fpriv->minor->dev->master;
}
EXPORT_SYMBOL(drm_is_current_master);

/**
 * drm_master_get - reference a master pointer
 * @master: &struct drm_master
 *
 * Increments the reference count of @master and returns a pointer to @master.
 */
struct drm_master *drm_master_get(struct drm_master *master)
{
	kref_get(&master->refcount);
	return master;
}
EXPORT_SYMBOL(drm_master_get);

static void drm_master_destroy(struct kref *kref)
{
	struct drm_master *master = container_of(kref, struct drm_master, refcount);
	struct drm_device *dev = master->dev;

	if (dev->driver->master_destroy)
		dev->driver->master_destroy(dev, master);

	drm_legacy_master_rmmaps(dev, master);

	idr_destroy(&master->magic_map);
	kfree(master->unique);
	kfree(master);
}

/**
 * drm_master_put - unreference and clear a master pointer
 * @master: pointer to a pointer of &struct drm_master
 *
 * This decrements the &drm_master behind @master and sets it to NULL.
 */
void drm_master_put(struct drm_master **master)
{
	kref_put(&(*master)->refcount, drm_master_destroy);
	*master = NULL;
}
EXPORT_SYMBOL(drm_master_put);
