/*
 * Copyright (c) 2000-2002,2005 Silicon Graphics, Inc.
 * Copyright (c) 2008 Dave Chinner
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_types.h"
#include "xfs_log.h"
#include "xfs_inum.h"
#include "xfs_trans.h"
#include "xfs_sb.h"
#include "xfs_ag.h"
#include "xfs_dmapi.h"
#include "xfs_mount.h"
#include "xfs_trans_priv.h"
#include "xfs_error.h"

STATIC void xfs_ail_insert(xfs_ail_t *, xfs_log_item_t *);
STATIC xfs_log_item_t * xfs_ail_delete(xfs_ail_t *, xfs_log_item_t *);
STATIC xfs_log_item_t * xfs_ail_min(xfs_ail_t *);
STATIC xfs_log_item_t * xfs_ail_next(xfs_ail_t *, xfs_log_item_t *);

#ifdef DEBUG
STATIC void xfs_ail_check(xfs_ail_t *, xfs_log_item_t *);
#else
#define	xfs_ail_check(a,l)
#endif /* DEBUG */


/*
 * This is called by the log manager code to determine the LSN
 * of the tail of the log.  This is exactly the LSN of the first
 * item in the AIL.  If the AIL is empty, then this function
 * returns 0.
 *
 * We need the AIL lock in order to get a coherent read of the
 * lsn of the last item in the AIL.
 */
xfs_lsn_t
xfs_trans_tail_ail(
	xfs_mount_t	*mp)
{
	xfs_lsn_t	lsn;
	xfs_log_item_t	*lip;

	spin_lock(&mp->m_ail_lock);
	lip = xfs_ail_min(&mp->m_ail);
	if (lip == NULL) {
		lsn = (xfs_lsn_t)0;
	} else {
		lsn = lip->li_lsn;
	}
	spin_unlock(&mp->m_ail_lock);

	return lsn;
}

/*
 * xfs_trans_push_ail
 *
 * This routine is called to move the tail of the AIL forward.  It does this by
 * trying to flush items in the AIL whose lsns are below the given
 * threshold_lsn.
 *
 * the push is run asynchronously in a separate thread, so we return the tail
 * of the log right now instead of the tail after the push. This means we will
 * either continue right away, or we will sleep waiting on the async thread to
 * do it's work.
 *
 * We do this unlocked - we only need to know whether there is anything in the
 * AIL at the time we are called. We don't need to access the contents of
 * any of the objects, so the lock is not needed.
 */
void
xfs_trans_push_ail(
	xfs_mount_t		*mp,
	xfs_lsn_t		threshold_lsn)
{
	xfs_log_item_t		*lip;

	lip = xfs_ail_min(&mp->m_ail);
	if (lip && !XFS_FORCED_SHUTDOWN(mp)) {
		if (XFS_LSN_CMP(threshold_lsn, mp->m_ail.xa_target) > 0)
			xfsaild_wakeup(mp, threshold_lsn);
	}
}

/*
 * Return the item in the AIL with the current lsn.
 * Return the current tree generation number for use
 * in calls to xfs_trans_next_ail().
 */
STATIC xfs_log_item_t *
xfs_trans_first_push_ail(
	xfs_mount_t	*mp,
	int		*gen,
	xfs_lsn_t	lsn)
{
	xfs_log_item_t	*lip;

	lip = xfs_ail_min(&mp->m_ail);
	*gen = (int)mp->m_ail.xa_gen;
	if (lsn == 0)
		return lip;

	list_for_each_entry(lip, &mp->m_ail.xa_ail, li_ail) {
		if (XFS_LSN_CMP(lip->li_lsn, lsn) >= 0)
			return lip;
	}

	return NULL;
}

/*
 * Function that does the work of pushing on the AIL
 */
long
xfsaild_push(
	xfs_mount_t	*mp,
	xfs_lsn_t	*last_lsn)
{
	long		tout = 1000; /* milliseconds */
	xfs_lsn_t	last_pushed_lsn = *last_lsn;
	xfs_lsn_t	target =  mp->m_ail.xa_target;
	xfs_lsn_t	lsn;
	xfs_log_item_t	*lip;
	int		gen;
	int		restarts;
	int		flush_log, count, stuck;

#define	XFS_TRANS_PUSH_AIL_RESTARTS	10

	spin_lock(&mp->m_ail_lock);
	lip = xfs_trans_first_push_ail(mp, &gen, *last_lsn);
	if (!lip || XFS_FORCED_SHUTDOWN(mp)) {
		/*
		 * AIL is empty or our push has reached the end.
		 */
		spin_unlock(&mp->m_ail_lock);
		last_pushed_lsn = 0;
		goto out;
	}

	XFS_STATS_INC(xs_push_ail);

	/*
	 * While the item we are looking at is below the given threshold
	 * try to flush it out. We'd like not to stop until we've at least
	 * tried to push on everything in the AIL with an LSN less than
	 * the given threshold.
	 *
	 * However, we will stop after a certain number of pushes and wait
	 * for a reduced timeout to fire before pushing further. This
	 * prevents use from spinning when we can't do anything or there is
	 * lots of contention on the AIL lists.
	 */
	tout = 10;
	lsn = lip->li_lsn;
	flush_log = stuck = count = restarts = 0;
	while ((XFS_LSN_CMP(lip->li_lsn, target) < 0)) {
		int	lock_result;
		/*
		 * If we can lock the item without sleeping, unlock the AIL
		 * lock and flush the item.  Then re-grab the AIL lock so we
		 * can look for the next item on the AIL. List changes are
		 * handled by the AIL lookup functions internally
		 *
		 * If we can't lock the item, either its holder will flush it
		 * or it is already being flushed or it is being relogged.  In
		 * any of these case it is being taken care of and we can just
		 * skip to the next item in the list.
		 */
		lock_result = IOP_TRYLOCK(lip);
		spin_unlock(&mp->m_ail_lock);
		switch (lock_result) {
		case XFS_ITEM_SUCCESS:
			XFS_STATS_INC(xs_push_ail_success);
			IOP_PUSH(lip);
			last_pushed_lsn = lsn;
			break;

		case XFS_ITEM_PUSHBUF:
			XFS_STATS_INC(xs_push_ail_pushbuf);
			IOP_PUSHBUF(lip);
			last_pushed_lsn = lsn;
			break;

		case XFS_ITEM_PINNED:
			XFS_STATS_INC(xs_push_ail_pinned);
			stuck++;
			flush_log = 1;
			break;

		case XFS_ITEM_LOCKED:
			XFS_STATS_INC(xs_push_ail_locked);
			last_pushed_lsn = lsn;
			stuck++;
			break;

		case XFS_ITEM_FLUSHING:
			XFS_STATS_INC(xs_push_ail_flushing);
			last_pushed_lsn = lsn;
			stuck++;
			break;

		default:
			ASSERT(0);
			break;
		}

		spin_lock(&mp->m_ail_lock);
		/* should we bother continuing? */
		if (XFS_FORCED_SHUTDOWN(mp))
			break;
		ASSERT(mp->m_log);

		count++;

		/*
		 * Are there too many items we can't do anything with?
		 * If we we are skipping too many items because we can't flush
		 * them or they are already being flushed, we back off and
		 * given them time to complete whatever operation is being
		 * done. i.e. remove pressure from the AIL while we can't make
		 * progress so traversals don't slow down further inserts and
		 * removals to/from the AIL.
		 *
		 * The value of 100 is an arbitrary magic number based on
		 * observation.
		 */
		if (stuck > 100)
			break;

		lip = xfs_trans_next_ail(mp, lip, &gen, &restarts);
		if (lip == NULL)
			break;
		if (restarts > XFS_TRANS_PUSH_AIL_RESTARTS)
			break;
		lsn = lip->li_lsn;
	}
	spin_unlock(&mp->m_ail_lock);

	if (flush_log) {
		/*
		 * If something we need to push out was pinned, then
		 * push out the log so it will become unpinned and
		 * move forward in the AIL.
		 */
		XFS_STATS_INC(xs_push_ail_flush);
		xfs_log_force(mp, (xfs_lsn_t)0, XFS_LOG_FORCE);
	}

	if (!count) {
		/* We're past our target or empty, so idle */
		tout = 1000;
	} else if (XFS_LSN_CMP(lsn, target) >= 0) {
		/*
		 * We reached the target so wait a bit longer for I/O to
		 * complete and remove pushed items from the AIL before we
		 * start the next scan from the start of the AIL.
		 */
		tout += 20;
		last_pushed_lsn = 0;
	} else if ((restarts > XFS_TRANS_PUSH_AIL_RESTARTS) ||
		   ((stuck * 100) / count > 90)) {
		/*
		 * Either there is a lot of contention on the AIL or we
		 * are stuck due to operations in progress. "Stuck" in this
		 * case is defined as >90% of the items we tried to push
		 * were stuck.
		 *
		 * Backoff a bit more to allow some I/O to complete before
		 * continuing from where we were.
		 */
		tout += 10;
	}
out:
	*last_lsn = last_pushed_lsn;
	return tout;
}	/* xfsaild_push */


/*
 * This is to be called when an item is unlocked that may have
 * been in the AIL.  It will wake up the first member of the AIL
 * wait list if this item's unlocking might allow it to progress.
 * If the item is in the AIL, then we need to get the AIL lock
 * while doing our checking so we don't race with someone going
 * to sleep waiting for this event in xfs_trans_push_ail().
 */
void
xfs_trans_unlocked_item(
	xfs_mount_t	*mp,
	xfs_log_item_t	*lip)
{
	xfs_log_item_t	*min_lip;

	/*
	 * If we're forcibly shutting down, we may have
	 * unlocked log items arbitrarily. The last thing
	 * we want to do is to move the tail of the log
	 * over some potentially valid data.
	 */
	if (!(lip->li_flags & XFS_LI_IN_AIL) ||
	    XFS_FORCED_SHUTDOWN(mp)) {
		return;
	}

	/*
	 * This is the one case where we can call into xfs_ail_min()
	 * without holding the AIL lock because we only care about the
	 * case where we are at the tail of the AIL.  If the object isn't
	 * at the tail, it doesn't matter what result we get back.  This
	 * is slightly racy because since we were just unlocked, we could
	 * go to sleep between the call to xfs_ail_min and the call to
	 * xfs_log_move_tail, have someone else lock us, commit to us disk,
	 * move us out of the tail of the AIL, and then we wake up.  However,
	 * the call to xfs_log_move_tail() doesn't do anything if there's
	 * not enough free space to wake people up so we're safe calling it.
	 */
	min_lip = xfs_ail_min(&mp->m_ail);

	if (min_lip == lip)
		xfs_log_move_tail(mp, 1);
}	/* xfs_trans_unlocked_item */


/*
 * Update the position of the item in the AIL with the new
 * lsn.  If it is not yet in the AIL, add it.  Otherwise, move
 * it to its new position by removing it and re-adding it.
 *
 * Wakeup anyone with an lsn less than the item's lsn.  If the item
 * we move in the AIL is the minimum one, update the tail lsn in the
 * log manager.
 *
 * Increment the AIL's generation count to indicate that the tree
 * has changed.
 *
 * This function must be called with the AIL lock held.  The lock
 * is dropped before returning.
 */
void
xfs_trans_update_ail(
	xfs_mount_t	*mp,
	xfs_log_item_t	*lip,
	xfs_lsn_t	lsn) __releases(mp->m_ail_lock)
{
	xfs_log_item_t		*dlip=NULL;
	xfs_log_item_t		*mlip;	/* ptr to minimum lip */

	mlip = xfs_ail_min(&mp->m_ail);

	if (lip->li_flags & XFS_LI_IN_AIL) {
		dlip = xfs_ail_delete(&mp->m_ail, lip);
		ASSERT(dlip == lip);
	} else {
		lip->li_flags |= XFS_LI_IN_AIL;
	}

	lip->li_lsn = lsn;

	xfs_ail_insert(&mp->m_ail, lip);
	mp->m_ail.xa_gen++;

	if (mlip == dlip) {
		mlip = xfs_ail_min(&mp->m_ail);
		spin_unlock(&mp->m_ail_lock);
		xfs_log_move_tail(mp, mlip->li_lsn);
	} else {
		spin_unlock(&mp->m_ail_lock);
	}


}	/* xfs_trans_update_ail */

/*
 * Delete the given item from the AIL.  It must already be in
 * the AIL.
 *
 * Wakeup anyone with an lsn less than item's lsn.    If the item
 * we delete in the AIL is the minimum one, update the tail lsn in the
 * log manager.
 *
 * Clear the IN_AIL flag from the item, reset its lsn to 0, and
 * bump the AIL's generation count to indicate that the tree
 * has changed.
 *
 * This function must be called with the AIL lock held.  The lock
 * is dropped before returning.
 */
void
xfs_trans_delete_ail(
	xfs_mount_t	*mp,
	xfs_log_item_t	*lip) __releases(mp->m_ail_lock)
{
	xfs_log_item_t		*dlip;
	xfs_log_item_t		*mlip;

	if (lip->li_flags & XFS_LI_IN_AIL) {
		mlip = xfs_ail_min(&mp->m_ail);
		dlip = xfs_ail_delete(&mp->m_ail, lip);
		ASSERT(dlip == lip);


		lip->li_flags &= ~XFS_LI_IN_AIL;
		lip->li_lsn = 0;
		mp->m_ail.xa_gen++;

		if (mlip == dlip) {
			mlip = xfs_ail_min(&mp->m_ail);
			spin_unlock(&mp->m_ail_lock);
			xfs_log_move_tail(mp, (mlip ? mlip->li_lsn : 0));
		} else {
			spin_unlock(&mp->m_ail_lock);
		}
	}
	else {
		/*
		 * If the file system is not being shutdown, we are in
		 * serious trouble if we get to this stage.
		 */
		if (XFS_FORCED_SHUTDOWN(mp))
			spin_unlock(&mp->m_ail_lock);
		else {
			xfs_cmn_err(XFS_PTAG_AILDELETE, CE_ALERT, mp,
		"%s: attempting to delete a log item that is not in the AIL",
					__func__);
			spin_unlock(&mp->m_ail_lock);
			xfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
		}
	}
}



/*
 * Return the item in the AIL with the smallest lsn.
 * Return the current tree generation number for use
 * in calls to xfs_trans_next_ail().
 */
xfs_log_item_t *
xfs_trans_first_ail(
	xfs_mount_t	*mp,
	int		*gen)
{
	xfs_log_item_t	*lip;

	lip = xfs_ail_min(&mp->m_ail);
	*gen = (int)mp->m_ail.xa_gen;

	return lip;
}

/*
 * If the generation count of the tree has not changed since the
 * caller last took something from the AIL, then return the elmt
 * in the tree which follows the one given.  If the count has changed,
 * then return the minimum elmt of the AIL and bump the restarts counter
 * if one is given.
 */
xfs_log_item_t *
xfs_trans_next_ail(
	xfs_mount_t	*mp,
	xfs_log_item_t	*lip,
	int		*gen,
	int		*restarts)
{
	xfs_log_item_t	*nlip;

	ASSERT(mp && lip && gen);
	if (mp->m_ail.xa_gen == *gen) {
		nlip = xfs_ail_next(&mp->m_ail, lip);
	} else {
		nlip = xfs_ail_min(&mp->m_ail);
		*gen = (int)mp->m_ail.xa_gen;
		if (restarts != NULL) {
			XFS_STATS_INC(xs_push_ail_restarts);
			(*restarts)++;
		}
	}

	return (nlip);
}


/*
 * The active item list (AIL) is a doubly linked list of log
 * items sorted by ascending lsn.  The base of the list is
 * a forw/back pointer pair embedded in the xfs mount structure.
 * The base is initialized with both pointers pointing to the
 * base.  This case always needs to be distinguished, because
 * the base has no lsn to look at.  We almost always insert
 * at the end of the list, so on inserts we search from the
 * end of the list to find where the new item belongs.
 */

/*
 * Initialize the doubly linked list to point only to itself.
 */
int
xfs_trans_ail_init(
	xfs_mount_t	*mp)
{
	INIT_LIST_HEAD(&mp->m_ail.xa_ail);
	return xfsaild_start(mp);
}

void
xfs_trans_ail_destroy(
	xfs_mount_t	*mp)
{
	xfsaild_stop(mp);
}

/*
 * Insert the given log item into the AIL.
 * We almost always insert at the end of the list, so on inserts
 * we search from the end of the list to find where the
 * new item belongs.
 */
STATIC void
xfs_ail_insert(
	xfs_ail_t	*ailp,
	xfs_log_item_t	*lip)
/* ARGSUSED */
{
	xfs_log_item_t	*next_lip;

	/*
	 * If the list is empty, just insert the item.
	 */
	if (list_empty(&ailp->xa_ail)) {
		list_add(&lip->li_ail, &ailp->xa_ail);
		return;
	}

	list_for_each_entry_reverse(next_lip, &ailp->xa_ail, li_ail) {
		if (XFS_LSN_CMP(next_lip->li_lsn, lip->li_lsn) <= 0)
			break;
	}

	ASSERT((&next_lip->li_ail == &ailp->xa_ail) ||
	       (XFS_LSN_CMP(next_lip->li_lsn, lip->li_lsn) <= 0));

	list_add(&lip->li_ail, &next_lip->li_ail);

	xfs_ail_check(ailp, lip);
	return;
}

/*
 * Delete the given item from the AIL.  Return a pointer to the item.
 */
/*ARGSUSED*/
STATIC xfs_log_item_t *
xfs_ail_delete(
	xfs_ail_t	*ailp,
	xfs_log_item_t	*lip)
/* ARGSUSED */
{
	xfs_ail_check(ailp, lip);

	list_del(&lip->li_ail);

	return lip;
}

/*
 * Return a pointer to the first item in the AIL.
 * If the AIL is empty, then return NULL.
 */
STATIC xfs_log_item_t *
xfs_ail_min(
	xfs_ail_t	*ailp)
/* ARGSUSED */
{
	if (list_empty(&ailp->xa_ail))
		return NULL;

	return list_first_entry(&ailp->xa_ail, xfs_log_item_t, li_ail);
}

/*
 * Return a pointer to the item which follows
 * the given item in the AIL.  If the given item
 * is the last item in the list, then return NULL.
 */
STATIC xfs_log_item_t *
xfs_ail_next(
	xfs_ail_t	*ailp,
	xfs_log_item_t	*lip)
/* ARGSUSED */
{
	if (lip->li_ail.next == &ailp->xa_ail)
		return NULL;

	return list_first_entry(&lip->li_ail, xfs_log_item_t, li_ail);
}
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_trans.h"
#include "xfs_trans_priv.h"
#include "xfs_trace.h"
#include "xfs_error.h"
#include "xfs_log.h"

#ifdef DEBUG
/*
 * Check that the list is sorted as it should be.
 */
STATIC void
xfs_ail_check(
	xfs_ail_t 	*ailp,
	struct xfs_ail	*ailp,
	xfs_log_item_t	*lip)
{
	xfs_log_item_t	*prev_lip;

	if (list_empty(&ailp->xa_ail))
		return;

	/*
	 * Check the next and previous entries are valid.
	 */
	ASSERT((lip->li_flags & XFS_LI_IN_AIL) != 0);
	prev_lip = list_entry(lip->li_ail.prev, xfs_log_item_t, li_ail);
	if (&prev_lip->li_ail != &ailp->xa_ail)
		ASSERT(XFS_LSN_CMP(prev_lip->li_lsn, lip->li_lsn) <= 0);

	prev_lip = list_entry(lip->li_ail.next, xfs_log_item_t, li_ail);
	if (&prev_lip->li_ail != &ailp->xa_ail)
		ASSERT(XFS_LSN_CMP(prev_lip->li_lsn, lip->li_lsn) >= 0);


#ifdef XFS_TRANS_DEBUG
	/*
	 * Walk the list checking lsn ordering, and that every entry has the
	 * XFS_LI_IN_AIL flag set. This is really expensive, so only do it
	 * when specifically debugging the transaction subsystem.
	 */
	prev_lip = list_entry(&ailp->xa_ail, xfs_log_item_t, li_ail);
	list_for_each_entry(lip, &ailp->xa_ail, li_ail) {
		if (&prev_lip->li_ail != &ailp->xa_ail)
			ASSERT(XFS_LSN_CMP(prev_lip->li_lsn, lip->li_lsn) <= 0);
		ASSERT((lip->li_flags & XFS_LI_IN_AIL) != 0);
		prev_lip = lip;
	}
#endif /* XFS_TRANS_DEBUG */
}
#endif /* DEBUG */
}
#else /* !DEBUG */
#define	xfs_ail_check(a,l)
#endif /* DEBUG */

/*
 * Return a pointer to the last item in the AIL.  If the AIL is empty, then
 * return NULL.
 */
static xfs_log_item_t *
xfs_ail_max(
	struct xfs_ail  *ailp)
{
	if (list_empty(&ailp->xa_ail))
		return NULL;

	return list_entry(ailp->xa_ail.prev, xfs_log_item_t, li_ail);
}

/*
 * Return a pointer to the item which follows the given item in the AIL.  If
 * the given item is the last item in the list, then return NULL.
 */
static xfs_log_item_t *
xfs_ail_next(
	struct xfs_ail  *ailp,
	xfs_log_item_t  *lip)
{
	if (lip->li_ail.next == &ailp->xa_ail)
		return NULL;

	return list_first_entry(&lip->li_ail, xfs_log_item_t, li_ail);
}

/*
 * This is called by the log manager code to determine the LSN of the tail of
 * the log.  This is exactly the LSN of the first item in the AIL.  If the AIL
 * is empty, then this function returns 0.
 *
 * We need the AIL lock in order to get a coherent read of the lsn of the last
 * item in the AIL.
 */
xfs_lsn_t
xfs_ail_min_lsn(
	struct xfs_ail	*ailp)
{
	xfs_lsn_t	lsn = 0;
	xfs_log_item_t	*lip;

	spin_lock(&ailp->xa_lock);
	lip = xfs_ail_min(ailp);
	if (lip)
		lsn = lip->li_lsn;
	spin_unlock(&ailp->xa_lock);

	return lsn;
}

/*
 * Return the maximum lsn held in the AIL, or zero if the AIL is empty.
 */
static xfs_lsn_t
xfs_ail_max_lsn(
	struct xfs_ail  *ailp)
{
	xfs_lsn_t       lsn = 0;
	xfs_log_item_t  *lip;

	spin_lock(&ailp->xa_lock);
	lip = xfs_ail_max(ailp);
	if (lip)
		lsn = lip->li_lsn;
	spin_unlock(&ailp->xa_lock);

	return lsn;
}

/*
 * The cursor keeps track of where our current traversal is up to by tracking
 * the next item in the list for us. However, for this to be safe, removing an
 * object from the AIL needs to invalidate any cursor that points to it. hence
 * the traversal cursor needs to be linked to the struct xfs_ail so that
 * deletion can search all the active cursors for invalidation.
 */
STATIC void
xfs_trans_ail_cursor_init(
	struct xfs_ail		*ailp,
	struct xfs_ail_cursor	*cur)
{
	cur->item = NULL;
	list_add_tail(&cur->list, &ailp->xa_cursors);
}

/*
 * Get the next item in the traversal and advance the cursor.  If the cursor
 * was invalidated (indicated by a lip of 1), restart the traversal.
 */
struct xfs_log_item *
xfs_trans_ail_cursor_next(
	struct xfs_ail		*ailp,
	struct xfs_ail_cursor	*cur)
{
	struct xfs_log_item	*lip = cur->item;

	if ((uintptr_t)lip & 1)
		lip = xfs_ail_min(ailp);
	if (lip)
		cur->item = xfs_ail_next(ailp, lip);
	return lip;
}

/*
 * When the traversal is complete, we need to remove the cursor from the list
 * of traversing cursors.
 */
void
xfs_trans_ail_cursor_done(
	struct xfs_ail_cursor	*cur)
{
	cur->item = NULL;
	list_del_init(&cur->list);
}

/*
 * Invalidate any cursor that is pointing to this item. This is called when an
 * item is removed from the AIL. Any cursor pointing to this object is now
 * invalid and the traversal needs to be terminated so it doesn't reference a
 * freed object. We set the low bit of the cursor item pointer so we can
 * distinguish between an invalidation and the end of the list when getting the
 * next item from the cursor.
 */
STATIC void
xfs_trans_ail_cursor_clear(
	struct xfs_ail		*ailp,
	struct xfs_log_item	*lip)
{
	struct xfs_ail_cursor	*cur;

	list_for_each_entry(cur, &ailp->xa_cursors, list) {
		if (cur->item == lip)
			cur->item = (struct xfs_log_item *)
					((uintptr_t)cur->item | 1);
	}
}

/*
 * Find the first item in the AIL with the given @lsn by searching in ascending
 * LSN order and initialise the cursor to point to the next item for a
 * ascending traversal.  Pass a @lsn of zero to initialise the cursor to the
 * first item in the AIL. Returns NULL if the list is empty.
 */
xfs_log_item_t *
xfs_trans_ail_cursor_first(
	struct xfs_ail		*ailp,
	struct xfs_ail_cursor	*cur,
	xfs_lsn_t		lsn)
{
	xfs_log_item_t		*lip;

	xfs_trans_ail_cursor_init(ailp, cur);

	if (lsn == 0) {
		lip = xfs_ail_min(ailp);
		goto out;
	}

	list_for_each_entry(lip, &ailp->xa_ail, li_ail) {
		if (XFS_LSN_CMP(lip->li_lsn, lsn) >= 0)
			goto out;
	}
	return NULL;

out:
	if (lip)
		cur->item = xfs_ail_next(ailp, lip);
	return lip;
}

static struct xfs_log_item *
__xfs_trans_ail_cursor_last(
	struct xfs_ail		*ailp,
	xfs_lsn_t		lsn)
{
	xfs_log_item_t		*lip;

	list_for_each_entry_reverse(lip, &ailp->xa_ail, li_ail) {
		if (XFS_LSN_CMP(lip->li_lsn, lsn) <= 0)
			return lip;
	}
	return NULL;
}

/*
 * Find the last item in the AIL with the given @lsn by searching in descending
 * LSN order and initialise the cursor to point to that item.  If there is no
 * item with the value of @lsn, then it sets the cursor to the last item with an
 * LSN lower than @lsn.  Returns NULL if the list is empty.
 */
struct xfs_log_item *
xfs_trans_ail_cursor_last(
	struct xfs_ail		*ailp,
	struct xfs_ail_cursor	*cur,
	xfs_lsn_t		lsn)
{
	xfs_trans_ail_cursor_init(ailp, cur);
	cur->item = __xfs_trans_ail_cursor_last(ailp, lsn);
	return cur->item;
}

/*
 * Splice the log item list into the AIL at the given LSN. We splice to the
 * tail of the given LSN to maintain insert order for push traversals. The
 * cursor is optional, allowing repeated updates to the same LSN to avoid
 * repeated traversals.  This should not be called with an empty list.
 */
static void
xfs_ail_splice(
	struct xfs_ail		*ailp,
	struct xfs_ail_cursor	*cur,
	struct list_head	*list,
	xfs_lsn_t		lsn)
{
	struct xfs_log_item	*lip;

	ASSERT(!list_empty(list));

	/*
	 * Use the cursor to determine the insertion point if one is
	 * provided.  If not, or if the one we got is not valid,
	 * find the place in the AIL where the items belong.
	 */
	lip = cur ? cur->item : NULL;
	if (!lip || (uintptr_t)lip & 1)
		lip = __xfs_trans_ail_cursor_last(ailp, lsn);

	/*
	 * If a cursor is provided, we know we're processing the AIL
	 * in lsn order, and future items to be spliced in will
	 * follow the last one being inserted now.  Update the
	 * cursor to point to that last item, now while we have a
	 * reliable pointer to it.
	 */
	if (cur)
		cur->item = list_entry(list->prev, struct xfs_log_item, li_ail);

	/*
	 * Finally perform the splice.  Unless the AIL was empty,
	 * lip points to the item in the AIL _after_ which the new
	 * items should go.  If lip is null the AIL was empty, so
	 * the new items go at the head of the AIL.
	 */
	if (lip)
		list_splice(list, &lip->li_ail);
	else
		list_splice(list, &ailp->xa_ail);
}

/*
 * Delete the given item from the AIL.  Return a pointer to the item.
 */
static void
xfs_ail_delete(
	struct xfs_ail  *ailp,
	xfs_log_item_t  *lip)
{
	xfs_ail_check(ailp, lip);
	list_del(&lip->li_ail);
	xfs_trans_ail_cursor_clear(ailp, lip);
}

static inline uint
xfsaild_push_item(
	struct xfs_ail		*ailp,
	struct xfs_log_item	*lip)
{
	/*
	 * If log item pinning is enabled, skip the push and track the item as
	 * pinned. This can help induce head-behind-tail conditions.
	 */
	if (XFS_TEST_ERROR(false, ailp->xa_mount, XFS_ERRTAG_LOG_ITEM_PIN))
		return XFS_ITEM_PINNED;

	return lip->li_ops->iop_push(lip, &ailp->xa_buf_list);
}

static long
xfsaild_push(
	struct xfs_ail		*ailp)
{
	xfs_mount_t		*mp = ailp->xa_mount;
	struct xfs_ail_cursor	cur;
	xfs_log_item_t		*lip;
	xfs_lsn_t		lsn;
	xfs_lsn_t		target;
	long			tout;
	int			stuck = 0;
	int			flushing = 0;
	int			count = 0;

	/*
	 * If we encountered pinned items or did not finish writing out all
	 * buffers the last time we ran, force the log first and wait for it
	 * before pushing again.
	 */
	if (ailp->xa_log_flush && ailp->xa_last_pushed_lsn == 0 &&
	    (!list_empty_careful(&ailp->xa_buf_list) ||
	     xfs_ail_min_lsn(ailp))) {
		ailp->xa_log_flush = 0;

		XFS_STATS_INC(mp, xs_push_ail_flush);
		xfs_log_force(mp, XFS_LOG_SYNC);
	}

	spin_lock(&ailp->xa_lock);

	/* barrier matches the xa_target update in xfs_ail_push() */
	smp_rmb();
	target = ailp->xa_target;
	ailp->xa_target_prev = target;

	lip = xfs_trans_ail_cursor_first(ailp, &cur, ailp->xa_last_pushed_lsn);
	if (!lip) {
		/*
		 * If the AIL is empty or our push has reached the end we are
		 * done now.
		 */
		xfs_trans_ail_cursor_done(&cur);
		spin_unlock(&ailp->xa_lock);
		goto out_done;
	}

	XFS_STATS_INC(mp, xs_push_ail);

	lsn = lip->li_lsn;
	while ((XFS_LSN_CMP(lip->li_lsn, target) <= 0)) {
		int	lock_result;

		/*
		 * Note that iop_push may unlock and reacquire the AIL lock.  We
		 * rely on the AIL cursor implementation to be able to deal with
		 * the dropped lock.
		 */
		lock_result = xfsaild_push_item(ailp, lip);
		switch (lock_result) {
		case XFS_ITEM_SUCCESS:
			XFS_STATS_INC(mp, xs_push_ail_success);
			trace_xfs_ail_push(lip);

			ailp->xa_last_pushed_lsn = lsn;
			break;

		case XFS_ITEM_FLUSHING:
			/*
			 * The item or its backing buffer is already beeing
			 * flushed.  The typical reason for that is that an
			 * inode buffer is locked because we already pushed the
			 * updates to it as part of inode clustering.
			 *
			 * We do not want to to stop flushing just because lots
			 * of items are already beeing flushed, but we need to
			 * re-try the flushing relatively soon if most of the
			 * AIL is beeing flushed.
			 */
			XFS_STATS_INC(mp, xs_push_ail_flushing);
			trace_xfs_ail_flushing(lip);

			flushing++;
			ailp->xa_last_pushed_lsn = lsn;
			break;

		case XFS_ITEM_PINNED:
			XFS_STATS_INC(mp, xs_push_ail_pinned);
			trace_xfs_ail_pinned(lip);

			stuck++;
			ailp->xa_log_flush++;
			break;
		case XFS_ITEM_LOCKED:
			XFS_STATS_INC(mp, xs_push_ail_locked);
			trace_xfs_ail_locked(lip);

			stuck++;
			break;
		default:
			ASSERT(0);
			break;
		}

		count++;

		/*
		 * Are there too many items we can't do anything with?
		 *
		 * If we we are skipping too many items because we can't flush
		 * them or they are already being flushed, we back off and
		 * given them time to complete whatever operation is being
		 * done. i.e. remove pressure from the AIL while we can't make
		 * progress so traversals don't slow down further inserts and
		 * removals to/from the AIL.
		 *
		 * The value of 100 is an arbitrary magic number based on
		 * observation.
		 */
		if (stuck > 100)
			break;

		lip = xfs_trans_ail_cursor_next(ailp, &cur);
		if (lip == NULL)
			break;
		lsn = lip->li_lsn;
	}
	xfs_trans_ail_cursor_done(&cur);
	spin_unlock(&ailp->xa_lock);

	if (xfs_buf_delwri_submit_nowait(&ailp->xa_buf_list))
		ailp->xa_log_flush++;

	if (!count || XFS_LSN_CMP(lsn, target) >= 0) {
out_done:
		/*
		 * We reached the target or the AIL is empty, so wait a bit
		 * longer for I/O to complete and remove pushed items from the
		 * AIL before we start the next scan from the start of the AIL.
		 */
		tout = 50;
		ailp->xa_last_pushed_lsn = 0;
	} else if (((stuck + flushing) * 100) / count > 90) {
		/*
		 * Either there is a lot of contention on the AIL or we are
		 * stuck due to operations in progress. "Stuck" in this case
		 * is defined as >90% of the items we tried to push were stuck.
		 *
		 * Backoff a bit more to allow some I/O to complete before
		 * restarting from the start of the AIL. This prevents us from
		 * spinning on the same items, and if they are pinned will all
		 * the restart to issue a log force to unpin the stuck items.
		 */
		tout = 20;
		ailp->xa_last_pushed_lsn = 0;
	} else {
		/*
		 * Assume we have more work to do in a short while.
		 */
		tout = 10;
	}

	return tout;
}

static int
xfsaild(
	void		*data)
{
	struct xfs_ail	*ailp = data;
	long		tout = 0;	/* milliseconds */

	current->flags |= PF_MEMALLOC;
	set_freezable();

	while (!kthread_should_stop()) {
		if (tout && tout <= 20)
			__set_current_state(TASK_KILLABLE);
		else
			__set_current_state(TASK_INTERRUPTIBLE);

		spin_lock(&ailp->xa_lock);

		/*
		 * Idle if the AIL is empty and we are not racing with a target
		 * update. We check the AIL after we set the task to a sleep
		 * state to guarantee that we either catch an xa_target update
		 * or that a wake_up resets the state to TASK_RUNNING.
		 * Otherwise, we run the risk of sleeping indefinitely.
		 *
		 * The barrier matches the xa_target update in xfs_ail_push().
		 */
		smp_rmb();
		if (!xfs_ail_min(ailp) &&
		    ailp->xa_target == ailp->xa_target_prev) {
			spin_unlock(&ailp->xa_lock);
			freezable_schedule();
			tout = 0;
			continue;
		}
		spin_unlock(&ailp->xa_lock);

		if (tout)
			freezable_schedule_timeout(msecs_to_jiffies(tout));

		__set_current_state(TASK_RUNNING);

		try_to_freeze();

		tout = xfsaild_push(ailp);
	}

	return 0;
}

/*
 * This routine is called to move the tail of the AIL forward.  It does this by
 * trying to flush items in the AIL whose lsns are below the given
 * threshold_lsn.
 *
 * The push is run asynchronously in a workqueue, which means the caller needs
 * to handle waiting on the async flush for space to become available.
 * We don't want to interrupt any push that is in progress, hence we only queue
 * work if we set the pushing bit approriately.
 *
 * We do this unlocked - we only need to know whether there is anything in the
 * AIL at the time we are called. We don't need to access the contents of
 * any of the objects, so the lock is not needed.
 */
void
xfs_ail_push(
	struct xfs_ail	*ailp,
	xfs_lsn_t	threshold_lsn)
{
	xfs_log_item_t	*lip;

	lip = xfs_ail_min(ailp);
	if (!lip || XFS_FORCED_SHUTDOWN(ailp->xa_mount) ||
	    XFS_LSN_CMP(threshold_lsn, ailp->xa_target) <= 0)
		return;

	/*
	 * Ensure that the new target is noticed in push code before it clears
	 * the XFS_AIL_PUSHING_BIT.
	 */
	smp_wmb();
	xfs_trans_ail_copy_lsn(ailp, &ailp->xa_target, &threshold_lsn);
	smp_wmb();

	wake_up_process(ailp->xa_task);
}

/*
 * Push out all items in the AIL immediately
 */
void
xfs_ail_push_all(
	struct xfs_ail  *ailp)
{
	xfs_lsn_t       threshold_lsn = xfs_ail_max_lsn(ailp);

	if (threshold_lsn)
		xfs_ail_push(ailp, threshold_lsn);
}

/*
 * Push out all items in the AIL immediately and wait until the AIL is empty.
 */
void
xfs_ail_push_all_sync(
	struct xfs_ail  *ailp)
{
	struct xfs_log_item	*lip;
	DEFINE_WAIT(wait);

	spin_lock(&ailp->xa_lock);
	while ((lip = xfs_ail_max(ailp)) != NULL) {
		prepare_to_wait(&ailp->xa_empty, &wait, TASK_UNINTERRUPTIBLE);
		ailp->xa_target = lip->li_lsn;
		wake_up_process(ailp->xa_task);
		spin_unlock(&ailp->xa_lock);
		schedule();
		spin_lock(&ailp->xa_lock);
	}
	spin_unlock(&ailp->xa_lock);

	finish_wait(&ailp->xa_empty, &wait);
}

/*
 * xfs_trans_ail_update - bulk AIL insertion operation.
 *
 * @xfs_trans_ail_update takes an array of log items that all need to be
 * positioned at the same LSN in the AIL. If an item is not in the AIL, it will
 * be added.  Otherwise, it will be repositioned  by removing it and re-adding
 * it to the AIL. If we move the first item in the AIL, update the log tail to
 * match the new minimum LSN in the AIL.
 *
 * This function takes the AIL lock once to execute the update operations on
 * all the items in the array, and as such should not be called with the AIL
 * lock held. As a result, once we have the AIL lock, we need to check each log
 * item LSN to confirm it needs to be moved forward in the AIL.
 *
 * To optimise the insert operation, we delete all the items from the AIL in
 * the first pass, moving them into a temporary list, then splice the temporary
 * list into the correct position in the AIL. This avoids needing to do an
 * insert operation on every item.
 *
 * This function must be called with the AIL lock held.  The lock is dropped
 * before returning.
 */
void
xfs_trans_ail_update_bulk(
	struct xfs_ail		*ailp,
	struct xfs_ail_cursor	*cur,
	struct xfs_log_item	**log_items,
	int			nr_items,
	xfs_lsn_t		lsn) __releases(ailp->xa_lock)
{
	xfs_log_item_t		*mlip;
	int			mlip_changed = 0;
	int			i;
	LIST_HEAD(tmp);

	ASSERT(nr_items > 0);		/* Not required, but true. */
	mlip = xfs_ail_min(ailp);

	for (i = 0; i < nr_items; i++) {
		struct xfs_log_item *lip = log_items[i];
		if (lip->li_flags & XFS_LI_IN_AIL) {
			/* check if we really need to move the item */
			if (XFS_LSN_CMP(lsn, lip->li_lsn) <= 0)
				continue;

			trace_xfs_ail_move(lip, lip->li_lsn, lsn);
			xfs_ail_delete(ailp, lip);
			if (mlip == lip)
				mlip_changed = 1;
		} else {
			lip->li_flags |= XFS_LI_IN_AIL;
			trace_xfs_ail_insert(lip, 0, lsn);
		}
		lip->li_lsn = lsn;
		list_add(&lip->li_ail, &tmp);
	}

	if (!list_empty(&tmp))
		xfs_ail_splice(ailp, cur, &tmp, lsn);

	if (mlip_changed) {
		if (!XFS_FORCED_SHUTDOWN(ailp->xa_mount))
			xlog_assign_tail_lsn_locked(ailp->xa_mount);
		spin_unlock(&ailp->xa_lock);

		xfs_log_space_wake(ailp->xa_mount);
	} else {
		spin_unlock(&ailp->xa_lock);
	}
}

bool
xfs_ail_delete_one(
	struct xfs_ail		*ailp,
	struct xfs_log_item	*lip)
{
	struct xfs_log_item	*mlip = xfs_ail_min(ailp);

	trace_xfs_ail_delete(lip, mlip->li_lsn, lip->li_lsn);
	xfs_ail_delete(ailp, lip);
	xfs_clear_li_failed(lip);
	lip->li_flags &= ~XFS_LI_IN_AIL;
	lip->li_lsn = 0;

	return mlip == lip;
}

/**
 * Remove a log items from the AIL
 *
 * @xfs_trans_ail_delete_bulk takes an array of log items that all need to
 * removed from the AIL. The caller is already holding the AIL lock, and done
 * all the checks necessary to ensure the items passed in via @log_items are
 * ready for deletion. This includes checking that the items are in the AIL.
 *
 * For each log item to be removed, unlink it  from the AIL, clear the IN_AIL
 * flag from the item and reset the item's lsn to 0. If we remove the first
 * item in the AIL, update the log tail to match the new minimum LSN in the
 * AIL.
 *
 * This function will not drop the AIL lock until all items are removed from
 * the AIL to minimise the amount of lock traffic on the AIL. This does not
 * greatly increase the AIL hold time, but does significantly reduce the amount
 * of traffic on the lock, especially during IO completion.
 *
 * This function must be called with the AIL lock held.  The lock is dropped
 * before returning.
 */
void
xfs_trans_ail_delete(
	struct xfs_ail		*ailp,
	struct xfs_log_item	*lip,
	int			shutdown_type) __releases(ailp->xa_lock)
{
	struct xfs_mount	*mp = ailp->xa_mount;
	bool			mlip_changed;

	if (!(lip->li_flags & XFS_LI_IN_AIL)) {
		spin_unlock(&ailp->xa_lock);
		if (!XFS_FORCED_SHUTDOWN(mp)) {
			xfs_alert_tag(mp, XFS_PTAG_AILDELETE,
	"%s: attempting to delete a log item that is not in the AIL",
					__func__);
			xfs_force_shutdown(mp, shutdown_type);
		}
		return;
	}

	mlip_changed = xfs_ail_delete_one(ailp, lip);
	if (mlip_changed) {
		if (!XFS_FORCED_SHUTDOWN(mp))
			xlog_assign_tail_lsn_locked(mp);
		if (list_empty(&ailp->xa_ail))
			wake_up_all(&ailp->xa_empty);
	}

	spin_unlock(&ailp->xa_lock);
	if (mlip_changed)
		xfs_log_space_wake(ailp->xa_mount);
}

int
xfs_trans_ail_init(
	xfs_mount_t	*mp)
{
	struct xfs_ail	*ailp;

	ailp = kmem_zalloc(sizeof(struct xfs_ail), KM_MAYFAIL);
	if (!ailp)
		return -ENOMEM;

	ailp->xa_mount = mp;
	INIT_LIST_HEAD(&ailp->xa_ail);
	INIT_LIST_HEAD(&ailp->xa_cursors);
	spin_lock_init(&ailp->xa_lock);
	INIT_LIST_HEAD(&ailp->xa_buf_list);
	init_waitqueue_head(&ailp->xa_empty);

	ailp->xa_task = kthread_run(xfsaild, ailp, "xfsaild/%s",
			ailp->xa_mount->m_fsname);
	if (IS_ERR(ailp->xa_task))
		goto out_free_ailp;

	mp->m_ail = ailp;
	return 0;

out_free_ailp:
	kmem_free(ailp);
	return -ENOMEM;
}

void
xfs_trans_ail_destroy(
	xfs_mount_t	*mp)
{
	struct xfs_ail	*ailp = mp->m_ail;

	kthread_stop(ailp->xa_task);
	kmem_free(ailp);
}
