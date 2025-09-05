/*
 *   fs/cifs/transport.c
 *
 *   Copyright (C) International Business Machines  Corp., 2002,2008
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *   Jeremy Allison (jra@samba.org) 2006.
 *
 *   This library is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU Lesser General Public License as published
 *   by the Free Software Foundation; either version 2.1 of the License, or
 *   (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with this library; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/net.h>
#include <linux/delay.h>
#include <linux/gfp.h>
#include <linux/wait.h>
#include <linux/net.h>
#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/tcp.h>
#include <linux/bvec.h>
#include <linux/highmem.h>
#include <linux/uaccess.h>
#include <asm/processor.h>
#include <linux/mempool.h>
#include "cifspdu.h"
#include "cifsglob.h"
#include "cifsproto.h"
#include "cifs_debug.h"
#include "smb2proto.h"
#include "smbdirect.h"

/* Max number of iovectors we can use off the stack when sending requests. */
#define CIFS_MAX_IOV_SIZE 8

extern mempool_t *cifs_mid_poolp;
extern struct kmem_cache *cifs_oplock_cachep;

static struct mid_q_entry *
AllocMidQEntry(const struct smb_hdr *smb_buffer, struct cifsSesInfo *ses)
{
	struct mid_q_entry *temp;

	if (ses == NULL) {
		cERROR(1, ("Null session passed in to AllocMidQEntry"));
		return NULL;
	}
	if (ses->server == NULL) {
		cERROR(1, ("Null TCP session in AllocMidQEntry"));
		return NULL;
	}

	temp = (struct mid_q_entry *) mempool_alloc(cifs_mid_poolp,
						    GFP_KERNEL | GFP_NOFS);
void
cifs_wake_up_task(struct mid_q_entry *mid)
{
	wake_up_process(mid->callback_data);
}

struct mid_q_entry *
AllocMidQEntry(const struct smb_hdr *smb_buffer, struct TCP_Server_Info *server)
{
	struct mid_q_entry *temp;

	if (server == NULL) {
		cifs_dbg(VFS, "Null TCP session in AllocMidQEntry\n");
		return NULL;
	}

	temp = mempool_alloc(cifs_mid_poolp, GFP_NOFS);
	if (temp == NULL)
		return temp;
	else {
		memset(temp, 0, sizeof(struct mid_q_entry));
		temp->mid = smb_buffer->Mid;	/* always LE */
		temp->pid = current->pid;
		temp->command = smb_buffer->Command;
		cFYI(1, ("For smb_command %d", temp->command));
	/*	do_gettimeofday(&temp->when_sent);*/ /* easier to use jiffies */
		/* when mid allocated can be before when sent */
		temp->when_alloc = jiffies;
		temp->ses = ses;
		temp->tsk = current;
	}

	spin_lock(&GlobalMid_Lock);
	list_add_tail(&temp->qhead, &ses->server->pending_mid_q);
	atomic_inc(&midCount);
	temp->midState = MID_REQUEST_ALLOCATED;
	spin_unlock(&GlobalMid_Lock);
	return temp;
}

static void
DeleteMidQEntry(struct mid_q_entry *midEntry)
{
#ifdef CONFIG_CIFS_STATS2
	unsigned long now;
#endif
	spin_lock(&GlobalMid_Lock);
	midEntry->midState = MID_FREE;
	list_del(&midEntry->qhead);
	atomic_dec(&midCount);
	spin_unlock(&GlobalMid_Lock);
	if (midEntry->largeBuf)
		temp->mid = get_mid(smb_buffer);
		temp->pid = current->pid;
		temp->command = cpu_to_le16(smb_buffer->Command);
		cifs_dbg(FYI, "For smb_command %d\n", smb_buffer->Command);
	memset(temp, 0, sizeof(struct mid_q_entry));
	kref_init(&temp->refcount);
	temp->mid = get_mid(smb_buffer);
	temp->pid = current->pid;
	temp->command = cpu_to_le16(smb_buffer->Command);
	cifs_dbg(FYI, "For smb_command %d\n", smb_buffer->Command);
	/*	do_gettimeofday(&temp->when_sent);*/ /* easier to use jiffies */
	/* when mid allocated can be before when sent */
	temp->when_alloc = jiffies;
	temp->server = server;

	/*
	 * The default is for the mid to be synchronous, so the
	 * default callback just wakes up the current task.
	 */
	temp->callback = cifs_wake_up_task;
	temp->callback_data = current;

	atomic_inc(&midCount);
	temp->mid_state = MID_REQUEST_ALLOCATED;
	return temp;
}

static void _cifs_mid_q_entry_release(struct kref *refcount)
{
	struct mid_q_entry *mid = container_of(refcount, struct mid_q_entry,
					       refcount);

	mempool_free(mid, cifs_mid_poolp);
}

void cifs_mid_q_entry_release(struct mid_q_entry *midEntry)
{
	spin_lock(&GlobalMid_Lock);
	kref_put(&midEntry->refcount, _cifs_mid_q_entry_release);
	spin_unlock(&GlobalMid_Lock);
}

void
DeleteMidQEntry(struct mid_q_entry *midEntry)
{
#ifdef CONFIG_CIFS_STATS2
	__le16 command = midEntry->server->vals->lock_cmd;
	unsigned long now;
#endif
	midEntry->mid_state = MID_FREE;
	atomic_dec(&midCount);
	if (midEntry->large_buf)
		cifs_buf_release(midEntry->resp_buf);
	else
		cifs_small_buf_release(midEntry->resp_buf);
#ifdef CONFIG_CIFS_STATS2
	now = jiffies;
	/* commands taking longer than one second are indications that
	   something is wrong, unless it is quite a slow link or server */
	if ((now - midEntry->when_alloc) > HZ) {
		if ((cifsFYI & CIFS_TIMER) &&
		   (midEntry->command != SMB_COM_LOCKING_ANDX)) {
			printk(KERN_DEBUG " CIFS slow rsp: cmd %d mid %d",
			       midEntry->command, midEntry->mid);
			printk(" A: 0x%lx S: 0x%lx R: 0x%lx\n",
	if (time_after(now, midEntry->when_alloc + HZ)) {
		if ((cifsFYI & CIFS_TIMER) && (midEntry->command != command)) {
	if (time_after(now, midEntry->when_alloc + HZ) &&
	    (midEntry->command != command)) {
		/* smb2slowcmd[NUMBER_OF_SMB2_COMMANDS] counts by command */
		if ((le16_to_cpu(midEntry->command) < NUMBER_OF_SMB2_COMMANDS) &&
		    (le16_to_cpu(midEntry->command) >= 0))
			cifs_stats_inc(&midEntry->server->smb2slowcmd[le16_to_cpu(midEntry->command)]);

		trace_smb3_slow_rsp(le16_to_cpu(midEntry->command),
			       midEntry->mid, midEntry->pid,
			       midEntry->when_sent, midEntry->when_received);
		if (cifsFYI & CIFS_TIMER) {
			pr_debug(" CIFS slow rsp: cmd %d mid %llu",
			       midEntry->command, midEntry->mid);
			pr_info(" A: 0x%lx S: 0x%lx R: 0x%lx\n",
			       now - midEntry->when_alloc,
			       now - midEntry->when_sent,
			       now - midEntry->when_received);
		}
	}
#endif
	cifs_mid_q_entry_release(midEntry);
}

struct oplock_q_entry *
AllocOplockQEntry(struct inode *pinode, __u16 fid, struct cifsTconInfo *tcon)
{
	struct oplock_q_entry *temp;
	if ((pinode == NULL) || (tcon == NULL)) {
		cERROR(1, ("Null parms passed to AllocOplockQEntry"));
		return NULL;
	}
	temp = (struct oplock_q_entry *) kmem_cache_alloc(cifs_oplock_cachep,
						       GFP_KERNEL);
	if (temp == NULL)
		return temp;
	else {
		temp->pinode = pinode;
		temp->tcon = tcon;
		temp->netfid = fid;
		spin_lock(&GlobalMid_Lock);
		list_add_tail(&temp->qhead, &GlobalOplock_Q);
		spin_unlock(&GlobalMid_Lock);
	}
	return temp;

}

void DeleteOplockQEntry(struct oplock_q_entry *oplockEntry)
{
	spin_lock(&GlobalMid_Lock);
    /* should we check if list empty first? */
	list_del(&oplockEntry->qhead);
	spin_unlock(&GlobalMid_Lock);
	kmem_cache_free(cifs_oplock_cachep, oplockEntry);
}


void DeleteTconOplockQEntries(struct cifsTconInfo *tcon)
{
	struct oplock_q_entry *temp;

	if (tcon == NULL)
		return;

	spin_lock(&GlobalMid_Lock);
	list_for_each_entry(temp, &GlobalOplock_Q, qhead) {
		if ((temp->tcon) && (temp->tcon == tcon)) {
			list_del(&temp->qhead);
			kmem_cache_free(cifs_oplock_cachep, temp);
		}
	}
	spin_unlock(&GlobalMid_Lock);
}

int
smb_send(struct socket *ssocket, struct smb_hdr *smb_buffer,
	 unsigned int smb_buf_length, struct sockaddr *sin)
{
	int rc = 0;
	int i = 0;
	struct msghdr smb_msg;
	struct kvec iov;
	unsigned len = smb_buf_length + 4;

	if (ssocket == NULL)
		return -ENOTSOCK; /* BB eventually add reconnect code here */
	iov.iov_base = smb_buffer;
	iov.iov_len = len;

	smb_msg.msg_name = sin;
	smb_msg.msg_namelen = sizeof(struct sockaddr);
	smb_msg.msg_control = NULL;
	smb_msg.msg_controllen = 0;
	smb_msg.msg_flags = MSG_DONTWAIT + MSG_NOSIGNAL; /* BB add more flags?*/

	/* smb header is converted in header_assemble. bcc and rest of SMB word
	   area, and byte area if necessary, is converted to littleendian in
	   cifssmb.c and RFC1001 len is converted to bigendian in smb_send
	   Flags2 is converted in SendReceive */

	smb_buffer->smb_buf_length = cpu_to_be32(smb_buffer->smb_buf_length);
	cFYI(1, ("Sending smb of length %d", smb_buf_length));
	dump_smb(smb_buffer, len);

	while (len > 0) {
		rc = kernel_sendmsg(ssocket, &smb_msg, &iov, 1, len);
		if ((rc == -ENOSPC) || (rc == -EAGAIN)) {
			i++;
		/* smaller timeout here than send2 since smaller size */
		/* Although it may not be required, this also is smaller
		   oplock break time */
			if (i > 12) {
				cERROR(1,
				   ("sends on sock %p stuck for 7 seconds",
				    ssocket));
				rc = -EAGAIN;
				break;
			}
			msleep(1 << i);
			continue;
		}
		if (rc < 0)
			break;
		else
			i = 0; /* reset i after each successful send */
		iov.iov_base += rc;
		iov.iov_len -= rc;
		len -= rc;
	}

	if (rc < 0) {
		cERROR(1, ("Error %d sending data on socket to server", rc));
	} else {
		rc = 0;
	}

	/* Don't want to modify the buffer as a
	   side effect of this call. */
	smb_buffer->smb_buf_length = smb_buf_length;

	return rc;
}

static int
smb_send2(struct socket *ssocket, struct kvec *iov, int n_vec,
	  struct sockaddr *sin)
void
cifs_delete_mid(struct mid_q_entry *mid)
{
	spin_lock(&GlobalMid_Lock);
	list_del_init(&mid->qhead);
	mid->mid_flags |= MID_DELETED;
	spin_unlock(&GlobalMid_Lock);

	DeleteMidQEntry(mid);
}

/*
 * smb_send_kvec - send an array of kvecs to the server
 * @server:	Server to send the data to
 * @smb_msg:	Message to send
 * @sent:	amount of data sent on socket is stored here
 *
 * Our basic "send data to server" function. Should be called with srv_mutex
 * held. The caller is responsible for handling the results.
 */
static int
smb_send_kvec(struct TCP_Server_Info *server, struct msghdr *smb_msg,
	      size_t *sent)
{
	int rc = 0;
	int i = 0;
	struct msghdr smb_msg;
	struct smb_hdr *smb_buffer = iov[0].iov_base;
	unsigned int len = iov[0].iov_len;
	unsigned int total_len;
	int first_vec = 0;
	unsigned int smb_buf_length = smb_buffer->smb_buf_length;

	if (ssocket == NULL)
		return -ENOTSOCK; /* BB eventually add reconnect code here */

	smb_msg.msg_name = sin;
	smb_msg.msg_namelen = sizeof(struct sockaddr);
	smb_msg.msg_control = NULL;
	smb_msg.msg_controllen = 0;
	smb_msg.msg_flags = MSG_DONTWAIT + MSG_NOSIGNAL; /* BB add more flags?*/

	/* smb header is converted in header_assemble. bcc and rest of SMB word
	   area, and byte area if necessary, is converted to littleendian in
	   cifssmb.c and RFC1001 len is converted to bigendian in smb_send
	   Flags2 is converted in SendReceive */


	total_len = 0;
	for (i = 0; i < n_vec; i++)
		total_len += iov[i].iov_len;

	smb_buffer->smb_buf_length = cpu_to_be32(smb_buffer->smb_buf_length);
	cFYI(1, ("Sending smb:  total_len %d", total_len));
	dump_smb(smb_buffer, len);

	i = 0;
	while (total_len) {
		rc = kernel_sendmsg(ssocket, &smb_msg, &iov[first_vec],
				    n_vec - first_vec, total_len);
		if ((rc == -ENOSPC) || (rc == -EAGAIN)) {
			i++;
			if (i >= 14) {
				cERROR(1,
				   ("sends on sock %p stuck for 15 seconds",
				    ssocket));
	unsigned int remaining;
	size_t first_vec = 0;
	int retries = 0;
	struct socket *ssocket = server->ssocket;

	*sent = 0;

	smb_msg->msg_name = (struct sockaddr *) &server->dstaddr;
	smb_msg->msg_namelen = sizeof(struct sockaddr);
	smb_msg->msg_control = NULL;
	smb_msg->msg_controllen = 0;
	if (server->noblocksnd)
		smb_msg->msg_flags = MSG_DONTWAIT + MSG_NOSIGNAL;
	else
		smb_msg->msg_flags = MSG_NOSIGNAL;

	while (msg_data_left(smb_msg)) {
		/*
		 * If blocking send, we try 3 times, since each can block
		 * for 5 seconds. For nonblocking  we have to try more
		 * but wait increasing amounts of time allowing time for
		 * socket to clear.  The overall time we wait in either
		 * case to send on the socket is about 15 seconds.
		 * Similarly we wait for 15 seconds for a response from
		 * the server in SendReceive[2] for the server to send
		 * a response back for most types of requests (except
		 * SMB Write past end of file which can be slow, and
		 * blocking lock operations). NFS waits slightly longer
		 * than CIFS, but this can make it take longer for
		 * nonresponsive servers to be detected and 15 seconds
		 * is more than enough time for modern networks to
		 * send a packet.  In most cases if we fail to send
		 * after the retries we will kill the socket and
		 * reconnect which may clear the network problem.
		 */
		rc = sock_sendmsg(ssocket, smb_msg);
		if (rc == -EAGAIN) {
			retries++;
			if (retries >= 14 ||
			    (!server->noblocksnd && (retries > 2))) {
				cifs_dbg(VFS, "sends on sock %p stuck for 15 seconds\n",
					 ssocket);
				return -EAGAIN;
			}
			msleep(1 << retries);
			continue;
		}
		if (rc < 0)
			break;

		if (rc >= total_len) {
			WARN_ON(rc > total_len);
			break;
		}
		if (rc == 0) {
			/* should never happen, letting socket clear before
			   retrying is our only obvious option here */
			cERROR(1, ("tcp sent no data"));
			msleep(500);
			continue;
		}
		total_len -= rc;

		if (rc < 0)
			return rc;

		if (rc == 0) {
			/* should never happen, letting socket clear before
			   retrying is our only obvious option here */
			cifs_dbg(VFS, "tcp sent no data\n");
			msleep(500);
			continue;
		}

		remaining -= rc;

		/* the line below resets i */
		for (i = first_vec; i < n_vec; i++) {
			if (iov[i].iov_len) {
				if (rc > iov[i].iov_len) {
					rc -= iov[i].iov_len;
					iov[i].iov_len = 0;
				} else {
					iov[i].iov_base += rc;
					iov[i].iov_len -= rc;
					first_vec = i;
					break;
				}
			}
		}
		i = 0; /* in case we get ENOSPC on the next send */
	}

	if (rc < 0) {
		cERROR(1, ("Error %d sending data on socket to server", rc));
	} else
		rc = 0;

	/* Don't want to modify the buffer as a
	   side effect of this call. */
	smb_buffer->smb_buf_length = smb_buf_length;

		i = 0; /* in case we get ENOSPC on the next send */
		rc = 0;
		/* send was at least partially successful */
		*sent += rc;
		retries = 0; /* in case we get ENOSPC on the next send */
	}
	return 0;
}

unsigned long
smb_rqst_len(struct TCP_Server_Info *server, struct smb_rqst *rqst)
{
	unsigned int i;
	struct kvec *iov;
	int nvec;
	unsigned long buflen = 0;

	if (server->vals->header_preamble_size == 0 &&
	    rqst->rq_nvec >= 2 && rqst->rq_iov[0].iov_len == 4) {
		iov = &rqst->rq_iov[1];
		nvec = rqst->rq_nvec - 1;
	} else {
		iov = rqst->rq_iov;
		nvec = rqst->rq_nvec;
	}

	/* total up iov array first */
	for (i = 0; i < nvec; i++)
		buflen += iov[i].iov_len;

	/*
	 * Add in the page array if there is one. The caller needs to make
	 * sure rq_offset and rq_tailsz are set correctly. If a buffer of
	 * multiple pages ends at page boundary, rq_tailsz needs to be set to
	 * PAGE_SIZE.
	 */
	if (rqst->rq_npages) {
		if (rqst->rq_npages == 1)
			buflen += rqst->rq_tailsz;
		else {
			/*
			 * If there is more than one page, calculate the
			 * buffer length based on rq_offset and rq_tailsz
			 */
			buflen += rqst->rq_pagesz * (rqst->rq_npages - 1) -
					rqst->rq_offset;
			buflen += rqst->rq_tailsz;
		}
	}

	return buflen;
}

static int
__smb_send_rqst(struct TCP_Server_Info *server, int num_rqst,
		struct smb_rqst *rqst)
{
	int rc = 0;
	struct kvec *iov;
	int n_vec;
	unsigned int send_length = 0;
	unsigned int i, j;
	size_t total_len = 0, sent, size;
	struct socket *ssocket = server->ssocket;
	struct msghdr smb_msg;
	int val = 1;
	__be32 rfc1002_marker;

	if (cifs_rdma_enabled(server) && server->smbd_conn) {
		rc = smbd_send(server, rqst);
		goto smbd_done;
	}
	if (ssocket == NULL)
		return -ENOTSOCK;

	/* cork the socket */
	kernel_setsockopt(ssocket, SOL_TCP, TCP_CORK,
				(char *)&val, sizeof(val));

	for (j = 0; j < num_rqst; j++)
		send_length += smb_rqst_len(server, &rqst[j]);
	rfc1002_marker = cpu_to_be32(send_length);

	/* Generate a rfc1002 marker for SMB2+ */
	if (server->vals->header_preamble_size == 0) {
		struct kvec hiov = {
			.iov_base = &rfc1002_marker,
			.iov_len  = 4
		};
		iov_iter_kvec(&smb_msg.msg_iter, WRITE | ITER_KVEC, &hiov,
			      1, 4);
		rc = smb_send_kvec(server, &smb_msg, &sent);
		if (rc < 0)
			goto uncork;

		total_len += sent;
		send_length += 4;
	}

	cifs_dbg(FYI, "Sending smb: smb_len=%u\n", send_length);

	for (j = 0; j < num_rqst; j++) {
		iov = rqst[j].rq_iov;
		n_vec = rqst[j].rq_nvec;

		size = 0;
		for (i = 0; i < n_vec; i++) {
			dump_smb(iov[i].iov_base, iov[i].iov_len);
			size += iov[i].iov_len;
		}

		iov_iter_kvec(&smb_msg.msg_iter, WRITE | ITER_KVEC,
			      iov, n_vec, size);

		rc = smb_send_kvec(server, &smb_msg, &sent);
		if (rc < 0)
			goto uncork;

		total_len += sent;

		/* now walk the page array and send each page in it */
		for (i = 0; i < rqst[j].rq_npages; i++) {
			struct bio_vec bvec;

			bvec.bv_page = rqst[j].rq_pages[i];
			rqst_page_get_length(&rqst[j], i, &bvec.bv_len,
					     &bvec.bv_offset);

			iov_iter_bvec(&smb_msg.msg_iter, WRITE | ITER_BVEC,
				      &bvec, 1, bvec.bv_len);
			rc = smb_send_kvec(server, &smb_msg, &sent);
			if (rc < 0)
				break;

			total_len += sent;
		}
	}

uncork:
	/* uncork it */
	val = 0;
	kernel_setsockopt(ssocket, SOL_TCP, TCP_CORK,
				(char *)&val, sizeof(val));

	if ((total_len > 0) && (total_len != send_length)) {
		cifs_dbg(FYI, "partial send (wanted=%u sent=%zu): terminating session\n",
			 send_length, total_len);
		/*
		 * If we have only sent part of an SMB then the next SMB could
		 * be taken as the remainder of this one. We need to kill the
		 * socket so the server throws away the partial SMB
		 */
		server->tcpStatus = CifsNeedReconnect;
		trace_smb3_partial_send_reconnect(server->CurrentMid,
						  server->hostname);
	}
smbd_done:
	if (rc < 0 && rc != -EINTR)
		cifs_dbg(VFS, "Error %d sending data on socket to server\n",
			 rc);
	else if (rc > 0)
		rc = 0;

	return rc;
}

static int wait_for_free_request(struct cifsSesInfo *ses, const int long_op)
{
	if (long_op == CIFS_ASYNC_OP) {
		/* oplock breaks must not be held up */
		atomic_inc(&ses->server->inFlight);
	} else {
		spin_lock(&GlobalMid_Lock);
		while (1) {
			if (atomic_read(&ses->server->inFlight) >=
					cifs_max_pending){
				spin_unlock(&GlobalMid_Lock);
#ifdef CONFIG_CIFS_STATS2
				atomic_inc(&ses->server->num_waiters);
#endif
				wait_event(ses->server->request_q,
					atomic_read(&ses->server->inFlight)
					 < cifs_max_pending);
#ifdef CONFIG_CIFS_STATS2
				atomic_dec(&ses->server->num_waiters);
#endif
				spin_lock(&GlobalMid_Lock);
			} else {
				if (ses->server->tcpStatus == CifsExiting) {
					spin_unlock(&GlobalMid_Lock);
					return -ENOENT;
				}

				/* can not count locking commands against total
				   as they are allowed to block on server */

				/* update # of requests on the wire to server */
				if (long_op != CIFS_BLOCKING_OP)
					atomic_inc(&ses->server->inFlight);
				spin_unlock(&GlobalMid_Lock);
				break;
			}
static int
smb_send_rqst(struct TCP_Server_Info *server, int num_rqst,
	      struct smb_rqst *rqst, int flags)
{
	struct kvec iov;
	struct smb2_transform_hdr tr_hdr;
	struct smb_rqst cur_rqst[MAX_COMPOUND];
	int rc;

	if (!(flags & CIFS_TRANSFORM_REQ))
		return __smb_send_rqst(server, num_rqst, rqst);

	if (num_rqst > MAX_COMPOUND - 1)
		return -ENOMEM;

	memset(&cur_rqst[0], 0, sizeof(cur_rqst));
	memset(&iov, 0, sizeof(iov));
	memset(&tr_hdr, 0, sizeof(tr_hdr));

	iov.iov_base = &tr_hdr;
	iov.iov_len = sizeof(tr_hdr);
	cur_rqst[0].rq_iov = &iov;
	cur_rqst[0].rq_nvec = 1;

	if (!server->ops->init_transform_rq) {
		cifs_dbg(VFS, "Encryption requested but transform callback "
			 "is missing\n");
		return -EIO;
	}

	rc = server->ops->init_transform_rq(server, num_rqst + 1,
					    &cur_rqst[0], rqst);
	if (rc)
		return rc;

	rc = __smb_send_rqst(server, num_rqst + 1, &cur_rqst[0]);
	smb3_free_compound_rqst(num_rqst, &cur_rqst[1]);
	return rc;
}

int
smb_send(struct TCP_Server_Info *server, struct smb_hdr *smb_buffer,
	 unsigned int smb_buf_length)
{
	struct kvec iov[2];
	struct smb_rqst rqst = { .rq_iov = iov,
				 .rq_nvec = 2 };

	iov[0].iov_base = smb_buffer;
	iov[0].iov_len = 4;
	iov[1].iov_base = (char *)smb_buffer + 4;
	iov[1].iov_len = smb_buf_length;

	return __smb_send_rqst(server, 1, &rqst);
}

static int
wait_for_free_credits(struct TCP_Server_Info *server, const int timeout,
		      int *credits)
{
	int rc;

	spin_lock(&server->req_lock);
	if (timeout == CIFS_ASYNC_OP) {
		/* oplock breaks must not be held up */
		server->in_flight++;
		*credits -= 1;
		spin_unlock(&server->req_lock);
		return 0;
	}

	while (1) {
		if (*credits <= 0) {
			spin_unlock(&server->req_lock);
			cifs_num_waiters_inc(server);
			rc = wait_event_killable(server->request_q,
						 has_credits(server, credits));
			cifs_num_waiters_dec(server);
			if (rc)
				return rc;
			spin_lock(&server->req_lock);
		} else {
			if (server->tcpStatus == CifsExiting) {
				spin_unlock(&server->req_lock);
				return -ENOENT;
			}

			/*
			 * Can not count locking commands against total
			 * as they are allowed to block on server.
			 */

			/* update # of requests on the wire to server */
			if (timeout != CIFS_BLOCKING_OP) {
				*credits -= 1;
				server->in_flight++;
			}
			spin_unlock(&server->req_lock);
			break;
		}
	}
	return 0;
}

static int allocate_mid(struct cifsSesInfo *ses, struct smb_hdr *in_buf,
static int
wait_for_free_request(struct TCP_Server_Info *server, const int timeout,
		      const int optype)
{
	int *val;

	val = server->ops->get_credits_field(server, optype);
	/* Since an echo is already inflight, no need to wait to send another */
	if (*val <= 0 && optype == CIFS_ECHO_OP)
		return -EAGAIN;
	return wait_for_free_credits(server, timeout, val);
}

int
cifs_wait_mtu_credits(struct TCP_Server_Info *server, unsigned int size,
		      unsigned int *num, unsigned int *credits)
{
	*num = size;
	*credits = 0;
	return 0;
}

static int allocate_mid(struct cifs_ses *ses, struct smb_hdr *in_buf,
			struct mid_q_entry **ppmidQ)
{
	if (ses->server->tcpStatus == CifsExiting) {
		return -ENOENT;
	} else if (ses->server->tcpStatus == CifsNeedReconnect) {
		cFYI(1, ("tcp session dead - return to caller to retry"));
		return -EAGAIN;
	} else if (ses->status != CifsGood) {
		/* check if SMB session is bad because we are setting it up */
	}

	if (ses->server->tcpStatus == CifsNeedReconnect) {
		cifs_dbg(FYI, "tcp session dead - return to caller to retry\n");
		return -EAGAIN;
	}

	if (ses->status == CifsNew) {
		if ((in_buf->Command != SMB_COM_SESSION_SETUP_ANDX) &&
			(in_buf->Command != SMB_COM_NEGOTIATE))
			return -EAGAIN;
		/* else ok - we are setting up session */
	}
	*ppmidQ = AllocMidQEntry(in_buf, ses);
	if (*ppmidQ == NULL)
		return -ENOMEM;
	return 0;
}

static int wait_for_response(struct cifsSesInfo *ses,
			struct mid_q_entry *midQ,
			unsigned long timeout,
			unsigned long time_to_wait)
{
	unsigned long curr_timeout;

	for (;;) {
		curr_timeout = timeout + jiffies;
		wait_event(ses->server->response_q,
			(!(midQ->midState == MID_REQUEST_SUBMITTED)) ||
			time_after(jiffies, curr_timeout) ||
			((ses->server->tcpStatus != CifsGood) &&
			 (ses->server->tcpStatus != CifsNew)));

		if (time_after(jiffies, curr_timeout) &&
			(midQ->midState == MID_REQUEST_SUBMITTED) &&
			((ses->server->tcpStatus == CifsGood) ||
			 (ses->server->tcpStatus == CifsNew))) {

			unsigned long lrt;

			/* We timed out. Is the server still
			   sending replies ? */
			spin_lock(&GlobalMid_Lock);
			lrt = ses->server->lstrp;
			spin_unlock(&GlobalMid_Lock);

			/* Calculate time_to_wait past last receive time.
			 Although we prefer not to time out if the
			 server is still responding - we will time
			 out if the server takes more than 15 (or 45
			 or 180) seconds to respond to this request
			 and has not responded to any request from
			 other threads on the client within 10 seconds */
			lrt += time_to_wait;
			if (time_after(jiffies, lrt)) {
				/* No replies for time_to_wait. */
				cERROR(1, ("server not responding"));
				return -1;
			}
		} else {
			return 0;
		}
	}
}


	if (ses->status == CifsExiting) {
		/* check if SMB session is bad because we are setting it up */
		if (in_buf->Command != SMB_COM_LOGOFF_ANDX)
			return -EAGAIN;
		/* else ok - we are shutting down session */
	}

	*ppmidQ = AllocMidQEntry(in_buf, ses->server);
	if (*ppmidQ == NULL)
		return -ENOMEM;
	spin_lock(&GlobalMid_Lock);
	list_add_tail(&(*ppmidQ)->qhead, &ses->server->pending_mid_q);
	spin_unlock(&GlobalMid_Lock);
	return 0;
}

static int
wait_for_response(struct TCP_Server_Info *server, struct mid_q_entry *midQ)
{
	int error;

	error = wait_event_freezekillable_unsafe(server->response_q,
				    midQ->mid_state != MID_REQUEST_SUBMITTED);
	if (error < 0)
		return -ERESTARTSYS;

	return 0;
}

struct mid_q_entry *
cifs_setup_async_request(struct TCP_Server_Info *server, struct smb_rqst *rqst)
{
	int rc;
	struct smb_hdr *hdr = (struct smb_hdr *)rqst->rq_iov[0].iov_base;
	struct mid_q_entry *mid;

	if (rqst->rq_iov[0].iov_len != 4 ||
	    rqst->rq_iov[0].iov_base + 4 != rqst->rq_iov[1].iov_base)
		return ERR_PTR(-EIO);

	/* enable signing if server requires it */
	if (server->sign)
		hdr->Flags2 |= SMBFLG2_SECURITY_SIGNATURE;

	mid = AllocMidQEntry(hdr, server);
	if (mid == NULL)
		return ERR_PTR(-ENOMEM);

	rc = cifs_sign_rqst(rqst, server, &mid->sequence_number);
	if (rc) {
		DeleteMidQEntry(mid);
		return ERR_PTR(rc);
	}

	return mid;
}

/*
 * Send a SMB request and set the callback function in the mid to handle
 * the result. Caller is responsible for dealing with timeouts.
 */
int
cifs_call_async(struct TCP_Server_Info *server, struct smb_rqst *rqst,
		mid_receive_t *receive, mid_callback_t *callback,
		mid_handle_t *handle, void *cbdata, const int flags)
{
	int rc, timeout, optype;
	struct mid_q_entry *mid;
	unsigned int credits = 0;

	timeout = flags & CIFS_TIMEOUT_MASK;
	optype = flags & CIFS_OP_MASK;

	if ((flags & CIFS_HAS_CREDITS) == 0) {
		rc = wait_for_free_request(server, timeout, optype);
		if (rc)
			return rc;
		credits = 1;
	}

	mutex_lock(&server->srv_mutex);
	mid = server->ops->setup_async_request(server, rqst);
	if (IS_ERR(mid)) {
		mutex_unlock(&server->srv_mutex);
		add_credits_and_wake_if(server, credits, optype);
		return PTR_ERR(mid);
	}

	mid->receive = receive;
	mid->callback = callback;
	mid->callback_data = cbdata;
	mid->handle = handle;
	mid->mid_state = MID_REQUEST_SUBMITTED;

	/* put it on the pending_mid_q */
	spin_lock(&GlobalMid_Lock);
	list_add_tail(&mid->qhead, &server->pending_mid_q);
	spin_unlock(&GlobalMid_Lock);

	/*
	 * Need to store the time in mid before calling I/O. For call_async,
	 * I/O response may come back and free the mid entry on another thread.
	 */
	cifs_save_when_sent(mid);
	cifs_in_send_inc(server);
	rc = smb_send_rqst(server, 1, rqst, flags);
	cifs_in_send_dec(server);

	if (rc < 0) {
		revert_current_mid(server, mid->credits);
		server->sequence_number -= 2;
		cifs_delete_mid(mid);
	}

	mutex_unlock(&server->srv_mutex);

	if (rc == 0)
		return 0;

	add_credits_and_wake_if(server, credits, optype);
	return rc;
}

/*
 *
 * Send an SMB Request.  No response info (other than return code)
 * needs to be parsed.
 *
 * flags indicate the type of request buffer and how long to wait
 * and whether to log NT STATUS code (error) before mapping it to POSIX error
 *
 */
int
SendReceiveNoRsp(const unsigned int xid, struct cifsSesInfo *ses,
		struct smb_hdr *in_buf, int flags)
SendReceiveNoRsp(const unsigned int xid, struct cifs_ses *ses,
		 char *in_buf, int flags)
{
	int rc;
	struct kvec iov[1];
	struct kvec rsp_iov;
	int resp_buf_type;

	iov[0].iov_base = (char *)in_buf;
	iov[0].iov_len = in_buf->smb_buf_length + 4;
	flags |= CIFS_NO_RESP;
	rc = SendReceive2(xid, ses, iov, 1, &resp_buf_type, flags);
	cFYI(DBG2, ("SendRcvNoRsp flags %d rc %d", flags, rc));
	iov[0].iov_base = in_buf;
	iov[0].iov_len = get_rfc1002_length(in_buf) + 4;
	flags |= CIFS_NO_RESP;
	rc = SendReceive2(xid, ses, iov, 1, &resp_buf_type, flags, &rsp_iov);
	cifs_dbg(NOISY, "SendRcvNoRsp flags %d rc %d\n", flags, rc);

	return rc;
}

int
SendReceive2(const unsigned int xid, struct cifsSesInfo *ses,
	     struct kvec *iov, int n_vec, int *pRespBufType /* ret */,
	     const int flags)
{
	int rc = 0;
	int long_op;
	unsigned int receive_len;
	unsigned long timeout;
	struct mid_q_entry *midQ;
	struct smb_hdr *in_buf = iov[0].iov_base;

	long_op = flags & CIFS_TIMEOUT_MASK;

	*pRespBufType = CIFS_NO_BUFFER;  /* no response buf yet */

	if ((ses == NULL) || (ses->server == NULL)) {
		cifs_small_buf_release(in_buf);
		cERROR(1, ("Null session"));
static int
cifs_sync_mid_result(struct mid_q_entry *mid, struct TCP_Server_Info *server)
{
	int rc = 0;

	cifs_dbg(FYI, "%s: cmd=%d mid=%llu state=%d\n",
		 __func__, le16_to_cpu(mid->command), mid->mid, mid->mid_state);

	spin_lock(&GlobalMid_Lock);
	switch (mid->mid_state) {
	case MID_RESPONSE_RECEIVED:
		spin_unlock(&GlobalMid_Lock);
		return rc;
	case MID_RETRY_NEEDED:
		rc = -EAGAIN;
		break;
	case MID_RESPONSE_MALFORMED:
		rc = -EIO;
		break;
	case MID_SHUTDOWN:
		rc = -EHOSTDOWN;
		break;
	default:
		list_del_init(&mid->qhead);
		cifs_dbg(VFS, "%s: invalid mid state mid=%llu state=%d\n",
			 __func__, mid->mid, mid->mid_state);
		rc = -EIO;
	}
	spin_unlock(&GlobalMid_Lock);

	DeleteMidQEntry(mid);
	return rc;
}

static inline int
send_cancel(struct TCP_Server_Info *server, struct smb_rqst *rqst,
	    struct mid_q_entry *mid)
{
	return server->ops->send_cancel ?
				server->ops->send_cancel(server, rqst, mid) : 0;
}

int
cifs_check_receive(struct mid_q_entry *mid, struct TCP_Server_Info *server,
		   bool log_error)
{
	unsigned int len = get_rfc1002_length(mid->resp_buf) + 4;

	dump_smb(mid->resp_buf, min_t(u32, 92, len));

	/* convert the length into a more usable form */
	if (server->sign) {
		struct kvec iov[2];
		int rc = 0;
		struct smb_rqst rqst = { .rq_iov = iov,
					 .rq_nvec = 2 };

		iov[0].iov_base = mid->resp_buf;
		iov[0].iov_len = 4;
		iov[1].iov_base = (char *)mid->resp_buf + 4;
		iov[1].iov_len = len - 4;
		/* FIXME: add code to kill session */
		rc = cifs_verify_signature(&rqst, server,
					   mid->sequence_number);
		if (rc)
			cifs_dbg(VFS, "SMB signature verification returned error = %d\n",
				 rc);
	}

	/* BB special case reconnect tid and uid here? */
	return map_smb_to_linux_error(mid->resp_buf, log_error);
}

struct mid_q_entry *
cifs_setup_request(struct cifs_ses *ses, struct smb_rqst *rqst)
{
	int rc;
	struct smb_hdr *hdr = (struct smb_hdr *)rqst->rq_iov[0].iov_base;
	struct mid_q_entry *mid;

	if (rqst->rq_iov[0].iov_len != 4 ||
	    rqst->rq_iov[0].iov_base + 4 != rqst->rq_iov[1].iov_base)
		return ERR_PTR(-EIO);

	rc = allocate_mid(ses, hdr, &mid);
	if (rc)
		return ERR_PTR(rc);
	rc = cifs_sign_rqst(rqst, ses->server, &mid->sequence_number);
	if (rc) {
		cifs_delete_mid(mid);
		return ERR_PTR(rc);
	}
	return mid;
}

static void
cifs_noop_callback(struct mid_q_entry *mid)
{
}

int
compound_send_recv(const unsigned int xid, struct cifs_ses *ses,
		   const int flags, const int num_rqst, struct smb_rqst *rqst,
		   int *resp_buf_type, struct kvec *resp_iov)
{
	int i, j, rc = 0;
	int timeout, optype;
	struct mid_q_entry *midQ[MAX_COMPOUND];
	bool cancelled_mid[MAX_COMPOUND] = {false};
	unsigned int credits[MAX_COMPOUND] = {0};
	char *buf;

	timeout = flags & CIFS_TIMEOUT_MASK;
	optype = flags & CIFS_OP_MASK;

	for (i = 0; i < num_rqst; i++)
		resp_buf_type[i] = CIFS_NO_BUFFER;  /* no response buf yet */

	if ((ses == NULL) || (ses->server == NULL)) {
		cifs_dbg(VFS, "Null session\n");
		return -EIO;
	}

	if (ses->server->tcpStatus == CifsExiting) {
		cifs_small_buf_release(in_buf);
		return -ENOENT;
	}

	/* Ensure that we do not send more than 50 overlapping requests
	   to the same server. We may make this configurable later or
	   use ses->maxReq */

	rc = wait_for_free_request(ses, long_op);
	if (rc) {
		cifs_small_buf_release(in_buf);
		return rc;
	}

	/* make sure that we sign in the same order that we send on this socket
	   and avoid races inside tcp sendmsg code that could cause corruption
	   of smb data */

	down(&ses->server->tcpSem);

	rc = allocate_mid(ses, in_buf, &midQ);
	if (rc) {
		up(&ses->server->tcpSem);
		cifs_small_buf_release(in_buf);
		/* Update # of requests on wire to server */
		atomic_dec(&ses->server->inFlight);
		wake_up(&ses->server->request_q);
		return rc;
	}
	rc = cifs_sign_smb2(iov, n_vec, ses->server, &midQ->sequence_number);

	midQ->midState = MID_REQUEST_SUBMITTED;
#ifdef CONFIG_CIFS_STATS2
	atomic_inc(&ses->server->inSend);
#endif
	rc = smb_send2(ses->server->ssocket, iov, n_vec,
		      (struct sockaddr *) &(ses->server->addr.sockAddr));
#ifdef CONFIG_CIFS_STATS2
	atomic_dec(&ses->server->inSend);
	midQ->when_sent = jiffies;
#endif

	up(&ses->server->tcpSem);
	cifs_small_buf_release(in_buf);

	if (rc < 0)
		goto out;

	if (long_op == CIFS_STD_OP)
		timeout = 15 * HZ;
	else if (long_op == CIFS_VLONG_OP) /* e.g. slow writes past EOF */
		timeout = 180 * HZ;
	else if (long_op == CIFS_LONG_OP)
		timeout = 45 * HZ; /* should be greater than
			servers oplock break timeout (about 43 seconds) */
	else if (long_op == CIFS_ASYNC_OP)
		goto out;
	else if (long_op == CIFS_BLOCKING_OP)
		timeout = 0x7FFFFFFF; /*  large, but not so large as to wrap */
	else {
		cERROR(1, ("unknown timeout flag %d", long_op));
		rc = -EIO;
		goto out;
	}

	/* wait for 15 seconds or until woken up due to response arriving or
	   due to last connection to this server being unmounted */
	if (signal_pending(current)) {
		/* if signal pending do not hold up user for full smb timeout
		but we still give response a chance to complete */
		timeout = 2 * HZ;
	}

	/* No user interrupts in wait - wreaks havoc with performance */
	wait_for_response(ses, midQ, timeout, 10 * HZ);

	spin_lock(&GlobalMid_Lock);
	if (midQ->resp_buf) {
		spin_unlock(&GlobalMid_Lock);
		receive_len = midQ->resp_buf->smb_buf_length;
	} else {
		cERROR(1, ("No response to cmd %d mid %d",
			midQ->command, midQ->mid));
		if (midQ->midState == MID_REQUEST_SUBMITTED) {
			if (ses->server->tcpStatus == CifsExiting)
				rc = -EHOSTDOWN;
			else {
				ses->server->tcpStatus = CifsNeedReconnect;
				midQ->midState = MID_RETRY_NEEDED;
			}
		}

		if (rc != -EHOSTDOWN) {
			if (midQ->midState == MID_RETRY_NEEDED) {
				rc = -EAGAIN;
				cFYI(1, ("marking request for retry"));
			} else {
				rc = -EIO;
			}
		}
		spin_unlock(&GlobalMid_Lock);
		DeleteMidQEntry(midQ);
		/* Update # of requests on wire to server */
		atomic_dec(&ses->server->inFlight);
		wake_up(&ses->server->request_q);
		return rc;
	}

	if (receive_len > CIFSMaxBufSize + MAX_CIFS_HDR_SIZE) {
		cERROR(1, ("Frame too large received.  Length: %d  Xid: %d",
			receive_len, xid));
		rc = -EIO;
	} else {		/* rcvd frame is ok */
		if (midQ->resp_buf &&
			(midQ->midState == MID_RESPONSE_RECEIVED)) {

			iov[0].iov_base = (char *)midQ->resp_buf;
			if (midQ->largeBuf)
				*pRespBufType = CIFS_LARGE_BUFFER;
			else
				*pRespBufType = CIFS_SMALL_BUFFER;
			iov[0].iov_len = receive_len + 4;

			dump_smb(midQ->resp_buf, 80);
			/* convert the length into a more usable form */
			if ((receive_len > 24) &&
			   (ses->server->secMode & (SECMODE_SIGN_REQUIRED |
					SECMODE_SIGN_ENABLED))) {
				rc = cifs_verify_signature(midQ->resp_buf,
						&ses->server->mac_signing_key,
						midQ->sequence_number+1);
				if (rc) {
					cERROR(1, ("Unexpected SMB signature"));
					/* BB FIXME add code to kill session */
				}
			}

			/* BB special case reconnect tid and uid here? */
			rc = map_smb_to_linux_error(midQ->resp_buf,
						flags & CIFS_LOG_ERROR);

			/* convert ByteCount if necessary */
			if (receive_len >= sizeof(struct smb_hdr) - 4
			    /* do not count RFC1001 header */  +
			    (2 * midQ->resp_buf->WordCount) + 2 /* bcc */ )
				BCC(midQ->resp_buf) =
					le16_to_cpu(BCC_LE(midQ->resp_buf));
			if ((flags & CIFS_NO_RESP) == 0)
				midQ->resp_buf = NULL;  /* mark it so buf will
							   not be freed by
							   DeleteMidQEntry */
		} else {
			rc = -EIO;
			cFYI(1, ("Bad MID state?"));
		}
	}

out:
	DeleteMidQEntry(midQ);
	atomic_dec(&ses->server->inFlight);
	wake_up(&ses->server->request_q);
		cifs_small_buf_release(buf);
	if (ses->server->tcpStatus == CifsExiting)
		return -ENOENT;

	/*
	 * Ensure we obtain 1 credit per request in the compound chain.
	 * It can be optimized further by waiting for all the credits
	 * at once but this can wait long enough if we don't have enough
	 * credits due to some heavy operations in progress or the server
	 * not granting us much, so a fallback to the current approach is
	 * needed anyway.
	 */
	for (i = 0; i < num_rqst; i++) {
		rc = wait_for_free_request(ses->server, timeout, optype);
		if (rc) {
			/*
			 * We haven't sent an SMB packet to the server yet but
			 * we already obtained credits for i requests in the
			 * compound chain - need to return those credits back
			 * for future use. Note that we need to call add_credits
			 * multiple times to match the way we obtained credits
			 * in the first place and to account for in flight
			 * requests correctly.
			 */
			for (j = 0; j < i; j++)
				add_credits(ses->server, 1, optype);
			return rc;
		}
		credits[i] = 1;
	}

	/*
	 * Make sure that we sign in the same order that we send on this socket
	 * and avoid races inside tcp sendmsg code that could cause corruption
	 * of smb data.
	 */

	mutex_lock(&ses->server->srv_mutex);

	for (i = 0; i < num_rqst; i++) {
		midQ[i] = ses->server->ops->setup_request(ses, &rqst[i]);
		if (IS_ERR(midQ[i])) {
			revert_current_mid(ses->server, i);
			for (j = 0; j < i; j++)
				cifs_delete_mid(midQ[j]);
			mutex_unlock(&ses->server->srv_mutex);

			/* Update # of requests on wire to server */
			for (j = 0; j < num_rqst; j++)
				add_credits(ses->server, credits[j], optype);
			return PTR_ERR(midQ[i]);
		}

		midQ[i]->mid_state = MID_REQUEST_SUBMITTED;
		/*
		 * We don't invoke the callback compounds unless it is the last
		 * request.
		 */
		if (i < num_rqst - 1)
			midQ[i]->callback = cifs_noop_callback;
	}
	cifs_in_send_inc(ses->server);
	rc = smb_send_rqst(ses->server, num_rqst, rqst, flags);
	cifs_in_send_dec(ses->server);

	for (i = 0; i < num_rqst; i++)
		cifs_save_when_sent(midQ[i]);

	if (rc < 0) {
		revert_current_mid(ses->server, num_rqst);
		ses->server->sequence_number -= 2;
	}

	mutex_unlock(&ses->server->srv_mutex);

	if (rc < 0)
		goto out;

	/*
	 * Compounding is never used during session establish.
	 */
	if ((ses->status == CifsNew) || (optype & CIFS_NEG_OP))
		smb311_update_preauth_hash(ses, rqst[0].rq_iov,
					   rqst[0].rq_nvec);

	if (timeout == CIFS_ASYNC_OP)
		goto out;

	for (i = 0; i < num_rqst; i++) {
		rc = wait_for_response(ses->server, midQ[i]);
		if (rc != 0) {
			cifs_dbg(FYI, "Cancelling wait for mid %llu\n",
				 midQ[i]->mid);
			send_cancel(ses->server, &rqst[i], midQ[i]);
			spin_lock(&GlobalMid_Lock);
			if (midQ[i]->mid_state == MID_REQUEST_SUBMITTED) {
				midQ[i]->mid_flags |= MID_WAIT_CANCELLED;
				midQ[i]->callback = DeleteMidQEntry;
				cancelled_mid[i] = true;
			}
			spin_unlock(&GlobalMid_Lock);
		}
	}

	for (i = 0; i < num_rqst; i++)
		if (!cancelled_mid[i] && midQ[i]->resp_buf
		    && (midQ[i]->mid_state == MID_RESPONSE_RECEIVED))
			credits[i] = ses->server->ops->get_credits(midQ[i]);

	for (i = 0; i < num_rqst; i++) {
		if (rc < 0)
			goto out;

		rc = cifs_sync_mid_result(midQ[i], ses->server);
		if (rc != 0) {
			/* mark this mid as cancelled to not free it below */
			cancelled_mid[i] = true;
			goto out;
		}

		if (!midQ[i]->resp_buf ||
		    midQ[i]->mid_state != MID_RESPONSE_RECEIVED) {
			rc = -EIO;
			cifs_dbg(FYI, "Bad MID state?\n");
			goto out;
		}

		buf = (char *)midQ[i]->resp_buf;
		resp_iov[i].iov_base = buf;
		resp_iov[i].iov_len = midQ[i]->resp_buf_size +
			ses->server->vals->header_preamble_size;

		if (midQ[i]->large_buf)
			resp_buf_type[i] = CIFS_LARGE_BUFFER;
		else
			resp_buf_type[i] = CIFS_SMALL_BUFFER;

		rc = ses->server->ops->check_receive(midQ[i], ses->server,
						     flags & CIFS_LOG_ERROR);

		/* mark it so buf will not be freed by cifs_delete_mid */
		if ((flags & CIFS_NO_RESP) == 0)
			midQ[i]->resp_buf = NULL;

	}

	/*
	 * Compounding is never used during session establish.
	 */
	if ((ses->status == CifsNew) || (optype & CIFS_NEG_OP)) {
		struct kvec iov = {
			.iov_base = resp_iov[0].iov_base,
			.iov_len = resp_iov[0].iov_len
		};
		smb311_update_preauth_hash(ses, &iov, 1);
	}

out:
	/*
	 * This will dequeue all mids. After this it is important that the
	 * demultiplex_thread will not process any of these mids any futher.
	 * This is prevented above by using a noop callback that will not
	 * wake this thread except for the very last PDU.
	 */
	for (i = 0; i < num_rqst; i++) {
		if (!cancelled_mid[i])
			cifs_delete_mid(midQ[i]);
		add_credits(ses->server, credits[i], optype);
	}

	return rc;
}

int
SendReceive(const unsigned int xid, struct cifsSesInfo *ses,
	    struct smb_hdr *in_buf, struct smb_hdr *out_buf,
	    int *pbytes_returned, const int long_op)
{
	int rc = 0;
	unsigned int receive_len;
	unsigned long timeout;
	struct mid_q_entry *midQ;

	if (ses == NULL) {
		cERROR(1, ("Null smb session"));
		return -EIO;
	}
	if (ses->server == NULL) {
		cERROR(1, ("Null tcp session"));
cifs_send_recv(const unsigned int xid, struct cifs_ses *ses,
	       struct smb_rqst *rqst, int *resp_buf_type, const int flags,
	       struct kvec *resp_iov)
{
	return compound_send_recv(xid, ses, flags, 1, rqst, resp_buf_type,
				  resp_iov);
}

int
SendReceive2(const unsigned int xid, struct cifs_ses *ses,
	     struct kvec *iov, int n_vec, int *resp_buf_type /* ret */,
	     const int flags, struct kvec *resp_iov)
{
	struct smb_rqst rqst;
	struct kvec s_iov[CIFS_MAX_IOV_SIZE], *new_iov;
	int rc;

	if (n_vec + 1 > CIFS_MAX_IOV_SIZE) {
		new_iov = kmalloc_array(n_vec + 1, sizeof(struct kvec),
					GFP_KERNEL);
		if (!new_iov) {
			/* otherwise cifs_send_recv below sets resp_buf_type */
			*resp_buf_type = CIFS_NO_BUFFER;
			return -ENOMEM;
		}
	} else
		new_iov = s_iov;

	/* 1st iov is a RFC1001 length followed by the rest of the packet */
	memcpy(new_iov + 1, iov, (sizeof(struct kvec) * n_vec));

	new_iov[0].iov_base = new_iov[1].iov_base;
	new_iov[0].iov_len = 4;
	new_iov[1].iov_base += 4;
	new_iov[1].iov_len -= 4;

	memset(&rqst, 0, sizeof(struct smb_rqst));
	rqst.rq_iov = new_iov;
	rqst.rq_nvec = n_vec + 1;

	rc = cifs_send_recv(xid, ses, &rqst, resp_buf_type, flags, resp_iov);
	if (n_vec + 1 > CIFS_MAX_IOV_SIZE)
		kfree(new_iov);
	return rc;
}

int
SendReceive(const unsigned int xid, struct cifs_ses *ses,
	    struct smb_hdr *in_buf, struct smb_hdr *out_buf,
	    int *pbytes_returned, const int timeout)
{
	int rc = 0;
	struct mid_q_entry *midQ;
	unsigned int len = be32_to_cpu(in_buf->smb_buf_length);
	struct kvec iov = { .iov_base = in_buf, .iov_len = len };
	struct smb_rqst rqst = { .rq_iov = &iov, .rq_nvec = 1 };

	if (ses == NULL) {
		cifs_dbg(VFS, "Null smb session\n");
		return -EIO;
	}
	if (ses->server == NULL) {
		cifs_dbg(VFS, "Null tcp session\n");
		return -EIO;
	}

	if (ses->server->tcpStatus == CifsExiting)
		return -ENOENT;

	/* Ensure that we do not send more than 50 overlapping requests
	   to the same server. We may make this configurable later or
	   use ses->maxReq */

	rc = wait_for_free_request(ses, long_op);
	if (be32_to_cpu(in_buf->smb_buf_length) > CIFSMaxBufSize +
			MAX_CIFS_HDR_SIZE - 4) {
	if (len > CIFSMaxBufSize + MAX_CIFS_HDR_SIZE - 4) {
		cifs_dbg(VFS, "Illegal length, greater than maximum frame, %d\n",
			 len);
		return -EIO;
	}

	rc = wait_for_free_request(ses->server, timeout, 0);
	if (rc)
		return rc;

	/* make sure that we sign in the same order that we send on this socket
	   and avoid races inside tcp sendmsg code that could cause corruption
	   of smb data */

	down(&ses->server->tcpSem);

	rc = allocate_mid(ses, in_buf, &midQ);
	if (rc) {
		up(&ses->server->tcpSem);
		/* Update # of requests on wire to server */
		atomic_dec(&ses->server->inFlight);
		wake_up(&ses->server->request_q);
		return rc;
	}

	if (in_buf->smb_buf_length > CIFSMaxBufSize + MAX_CIFS_HDR_SIZE - 4) {
		cERROR(1, ("Illegal length, greater than maximum frame, %d",
			in_buf->smb_buf_length));
		DeleteMidQEntry(midQ);
		up(&ses->server->tcpSem);
		/* Update # of requests on wire to server */
		atomic_dec(&ses->server->inFlight);
		wake_up(&ses->server->request_q);
		return -EIO;
	}

	rc = cifs_sign_smb(in_buf, ses->server, &midQ->sequence_number);

	midQ->midState = MID_REQUEST_SUBMITTED;
#ifdef CONFIG_CIFS_STATS2
	atomic_inc(&ses->server->inSend);
#endif
	rc = smb_send(ses->server->ssocket, in_buf, in_buf->smb_buf_length,
		      (struct sockaddr *) &(ses->server->addr.sockAddr));
#ifdef CONFIG_CIFS_STATS2
	atomic_dec(&ses->server->inSend);
	midQ->when_sent = jiffies;
#endif
	up(&ses->server->tcpSem);
	mutex_lock(&ses->server->srv_mutex);

	rc = allocate_mid(ses, in_buf, &midQ);
	if (rc) {
		mutex_unlock(&ses->server->srv_mutex);
		/* Update # of requests on wire to server */
		add_credits(ses->server, 1, 0);
		return rc;
	}

	rc = cifs_sign_smb(in_buf, ses->server, &midQ->sequence_number);
	if (rc) {
		mutex_unlock(&ses->server->srv_mutex);
		goto out;
	}

	midQ->mid_state = MID_REQUEST_SUBMITTED;

	cifs_in_send_inc(ses->server);
	rc = smb_send(ses->server, in_buf, len);
	cifs_in_send_dec(ses->server);
	cifs_save_when_sent(midQ);

	if (rc < 0)
		ses->server->sequence_number -= 2;

	mutex_unlock(&ses->server->srv_mutex);

	if (rc < 0)
		goto out;

	if (long_op == CIFS_STD_OP)
		timeout = 15 * HZ;
	/* wait for 15 seconds or until woken up due to response arriving or
	   due to last connection to this server being unmounted */
	else if (long_op == CIFS_ASYNC_OP)
		goto out;
	else if (long_op == CIFS_VLONG_OP) /* writes past EOF can be slow */
		timeout = 180 * HZ;
	else if (long_op == CIFS_LONG_OP)
		timeout = 45 * HZ; /* should be greater than
			servers oplock break timeout (about 43 seconds) */
	else if (long_op == CIFS_BLOCKING_OP)
		timeout = 0x7FFFFFFF; /* large but no so large as to wrap */
	else {
		cERROR(1, ("unknown timeout flag %d", long_op));
		rc = -EIO;
		goto out;
	}

	if (signal_pending(current)) {
		/* if signal pending do not hold up user for full smb timeout
		but we still give response a chance to complete */
		timeout = 2 * HZ;
	}

	/* No user interrupts in wait - wreaks havoc with performance */
	wait_for_response(ses, midQ, timeout, 10 * HZ);

	spin_lock(&GlobalMid_Lock);
	if (midQ->resp_buf) {
		spin_unlock(&GlobalMid_Lock);
		receive_len = midQ->resp_buf->smb_buf_length;
	} else {
		cERROR(1, ("No response for cmd %d mid %d",
			  midQ->command, midQ->mid));
		if (midQ->midState == MID_REQUEST_SUBMITTED) {
			if (ses->server->tcpStatus == CifsExiting)
				rc = -EHOSTDOWN;
			else {
				ses->server->tcpStatus = CifsNeedReconnect;
				midQ->midState = MID_RETRY_NEEDED;
			}
		}

		if (rc != -EHOSTDOWN) {
			if (midQ->midState == MID_RETRY_NEEDED) {
				rc = -EAGAIN;
				cFYI(1, ("marking request for retry"));
			} else {
				rc = -EIO;
			}
		}
		spin_unlock(&GlobalMid_Lock);
		DeleteMidQEntry(midQ);
		/* Update # of requests on wire to server */
		atomic_dec(&ses->server->inFlight);
		wake_up(&ses->server->request_q);
		return rc;
	}

	if (receive_len > CIFSMaxBufSize + MAX_CIFS_HDR_SIZE) {
		cERROR(1, ("Frame too large received.  Length: %d  Xid: %d",
			receive_len, xid));
		rc = -EIO;
	} else {		/* rcvd frame is ok */

		if (midQ->resp_buf && out_buf
		    && (midQ->midState == MID_RESPONSE_RECEIVED)) {
			out_buf->smb_buf_length = receive_len;
			memcpy((char *)out_buf + 4,
			       (char *)midQ->resp_buf + 4,
			       receive_len);

			dump_smb(out_buf, 92);
			/* convert the length into a more usable form */
			if ((receive_len > 24) &&
			   (ses->server->secMode & (SECMODE_SIGN_REQUIRED |
					SECMODE_SIGN_ENABLED))) {
				rc = cifs_verify_signature(out_buf,
						&ses->server->mac_signing_key,
						midQ->sequence_number+1);
				if (rc) {
					cERROR(1, ("Unexpected SMB signature"));
					/* BB FIXME add code to kill session */
				}
			}

			*pbytes_returned = out_buf->smb_buf_length;

			/* BB special case reconnect tid and uid here? */
			rc = map_smb_to_linux_error(out_buf, 0 /* no log */ );

			/* convert ByteCount if necessary */
			if (receive_len >= sizeof(struct smb_hdr) - 4
			    /* do not count RFC1001 header */  +
			    (2 * out_buf->WordCount) + 2 /* bcc */ )
				BCC(out_buf) = le16_to_cpu(BCC_LE(out_buf));
		} else {
			rc = -EIO;
			cERROR(1, ("Bad MID state?"));
		}
	}

out:
	DeleteMidQEntry(midQ);
	atomic_dec(&ses->server->inFlight);
	wake_up(&ses->server->request_q);
	if (timeout == CIFS_ASYNC_OP)
		goto out;

	rc = wait_for_response(ses->server, midQ);
	if (rc != 0) {
		send_cancel(ses->server, &rqst, midQ);
		spin_lock(&GlobalMid_Lock);
		if (midQ->mid_state == MID_REQUEST_SUBMITTED) {
			/* no longer considered to be "in-flight" */
			midQ->callback = DeleteMidQEntry;
			spin_unlock(&GlobalMid_Lock);
			add_credits(ses->server, 1, 0);
			return rc;
		}
		spin_unlock(&GlobalMid_Lock);
	}

	rc = cifs_sync_mid_result(midQ, ses->server);
	if (rc != 0) {
		add_credits(ses->server, 1, 0);
		return rc;
	}

	if (!midQ->resp_buf || !out_buf ||
	    midQ->mid_state != MID_RESPONSE_RECEIVED) {
		rc = -EIO;
		cifs_dbg(VFS, "Bad MID state?\n");
		goto out;
	}

	*pbytes_returned = get_rfc1002_length(midQ->resp_buf);
	memcpy(out_buf, midQ->resp_buf, *pbytes_returned + 4);
	rc = cifs_check_receive(midQ, ses->server, 0);
out:
	cifs_delete_mid(midQ);
	add_credits(ses->server, 1, 0);

	return rc;
}

/* Send an NT_CANCEL SMB to cause the POSIX blocking lock to return. */

static int
send_nt_cancel(struct cifsTconInfo *tcon, struct smb_hdr *in_buf,
		struct mid_q_entry *midQ)
{
	int rc = 0;
	struct cifsSesInfo *ses = tcon->ses;
	__u16 mid = in_buf->Mid;

	header_assemble(in_buf, SMB_COM_NT_CANCEL, tcon, 0);
	in_buf->Mid = mid;
	down(&ses->server->tcpSem);
	rc = cifs_sign_smb(in_buf, ses->server, &midQ->sequence_number);
	if (rc) {
		up(&ses->server->tcpSem);
		return rc;
	}
	rc = smb_send(ses->server->ssocket, in_buf, in_buf->smb_buf_length,
	      (struct sockaddr *) &(ses->server->addr.sockAddr));
	up(&ses->server->tcpSem);
	return rc;
}

/* We send a LOCKINGX_CANCEL_LOCK to cause the Windows
   blocking lock to return. */

static int
send_lock_cancel(const unsigned int xid, struct cifsTconInfo *tcon,
send_lock_cancel(const unsigned int xid, struct cifs_tcon *tcon,
			struct smb_hdr *in_buf,
			struct smb_hdr *out_buf)
{
	int bytes_returned;
	struct cifsSesInfo *ses = tcon->ses;
	struct cifs_ses *ses = tcon->ses;
	LOCK_REQ *pSMB = (LOCK_REQ *)in_buf;

	/* We just modify the current in_buf to change
	   the type of lock from LOCKING_ANDX_SHARED_LOCK
	   or LOCKING_ANDX_EXCLUSIVE_LOCK to
	   LOCKING_ANDX_CANCEL_LOCK. */

	pSMB->LockType = LOCKING_ANDX_CANCEL_LOCK|LOCKING_ANDX_LARGE_FILES;
	pSMB->Timeout = 0;
	pSMB->hdr.Mid = GetNextMid(ses->server);

	return SendReceive(xid, ses, in_buf, out_buf,
			&bytes_returned, CIFS_STD_OP);
}

int
SendReceiveBlockingLock(const unsigned int xid, struct cifsTconInfo *tcon,
	pSMB->hdr.Mid = get_next_mid(ses->server);

	return SendReceive(xid, ses, in_buf, out_buf,
			&bytes_returned, 0);
}

int
SendReceiveBlockingLock(const unsigned int xid, struct cifs_tcon *tcon,
	    struct smb_hdr *in_buf, struct smb_hdr *out_buf,
	    int *pbytes_returned)
{
	int rc = 0;
	int rstart = 0;
	unsigned int receive_len;
	struct mid_q_entry *midQ;
	struct cifsSesInfo *ses;

	if (tcon == NULL || tcon->ses == NULL) {
		cERROR(1, ("Null smb session"));
	struct mid_q_entry *midQ;
	struct cifs_ses *ses;
	unsigned int len = be32_to_cpu(in_buf->smb_buf_length);
	struct kvec iov = { .iov_base = in_buf, .iov_len = len };
	struct smb_rqst rqst = { .rq_iov = &iov, .rq_nvec = 1 };

	if (tcon == NULL || tcon->ses == NULL) {
		cifs_dbg(VFS, "Null smb session\n");
		return -EIO;
	}
	ses = tcon->ses;

	if (ses->server == NULL) {
		cERROR(1, ("Null tcp session"));
		cifs_dbg(VFS, "Null tcp session\n");
		return -EIO;
	}

	if (ses->server->tcpStatus == CifsExiting)
		return -ENOENT;

	/* Ensure that we do not send more than 50 overlapping requests
	   to the same server. We may make this configurable later or
	   use ses->maxReq */

	rc = wait_for_free_request(ses, CIFS_BLOCKING_OP);
	if (be32_to_cpu(in_buf->smb_buf_length) > CIFSMaxBufSize +
			MAX_CIFS_HDR_SIZE - 4) {
	if (len > CIFSMaxBufSize + MAX_CIFS_HDR_SIZE - 4) {
		cifs_dbg(VFS, "Illegal length, greater than maximum frame, %d\n",
			 len);
		return -EIO;
	}

	rc = wait_for_free_request(ses->server, CIFS_BLOCKING_OP, 0);
	if (rc)
		return rc;

	/* make sure that we sign in the same order that we send on this socket
	   and avoid races inside tcp sendmsg code that could cause corruption
	   of smb data */

	down(&ses->server->tcpSem);

	rc = allocate_mid(ses, in_buf, &midQ);
	if (rc) {
		up(&ses->server->tcpSem);
		return rc;
	}

	if (in_buf->smb_buf_length > CIFSMaxBufSize + MAX_CIFS_HDR_SIZE - 4) {
		up(&ses->server->tcpSem);
		cERROR(1, ("Illegal length, greater than maximum frame, %d",
			in_buf->smb_buf_length));
		DeleteMidQEntry(midQ);
		return -EIO;
	}

	rc = cifs_sign_smb(in_buf, ses->server, &midQ->sequence_number);

	midQ->midState = MID_REQUEST_SUBMITTED;
#ifdef CONFIG_CIFS_STATS2
	atomic_inc(&ses->server->inSend);
#endif
	rc = smb_send(ses->server->ssocket, in_buf, in_buf->smb_buf_length,
		      (struct sockaddr *) &(ses->server->addr.sockAddr));
#ifdef CONFIG_CIFS_STATS2
	atomic_dec(&ses->server->inSend);
	midQ->when_sent = jiffies;
#endif
	up(&ses->server->tcpSem);

	if (rc < 0) {
		DeleteMidQEntry(midQ);
	mutex_lock(&ses->server->srv_mutex);

	rc = allocate_mid(ses, in_buf, &midQ);
	if (rc) {
		mutex_unlock(&ses->server->srv_mutex);
		return rc;
	}

	rc = cifs_sign_smb(in_buf, ses->server, &midQ->sequence_number);
	if (rc) {
		cifs_delete_mid(midQ);
		mutex_unlock(&ses->server->srv_mutex);
		return rc;
	}

	midQ->mid_state = MID_REQUEST_SUBMITTED;
	cifs_in_send_inc(ses->server);
	rc = smb_send(ses->server, in_buf, len);
	cifs_in_send_dec(ses->server);
	cifs_save_when_sent(midQ);

	if (rc < 0)
		ses->server->sequence_number -= 2;

	mutex_unlock(&ses->server->srv_mutex);

	if (rc < 0) {
		cifs_delete_mid(midQ);
		return rc;
	}

	/* Wait for a reply - allow signals to interrupt. */
	rc = wait_event_interruptible(ses->server->response_q,
		(!(midQ->midState == MID_REQUEST_SUBMITTED)) ||
		(!(midQ->mid_state == MID_REQUEST_SUBMITTED)) ||
		((ses->server->tcpStatus != CifsGood) &&
		 (ses->server->tcpStatus != CifsNew)));

	/* Were we interrupted by a signal ? */
	if ((rc == -ERESTARTSYS) &&
		(midQ->midState == MID_REQUEST_SUBMITTED) &&
		(midQ->mid_state == MID_REQUEST_SUBMITTED) &&
		((ses->server->tcpStatus == CifsGood) ||
		 (ses->server->tcpStatus == CifsNew))) {

		if (in_buf->Command == SMB_COM_TRANSACTION2) {
			/* POSIX lock. We send a NT_CANCEL SMB to cause the
			   blocking lock to return. */

			rc = send_nt_cancel(tcon, in_buf, midQ);
			if (rc) {
				DeleteMidQEntry(midQ);
			rc = send_cancel(ses->server, in_buf, midQ);
			rc = send_cancel(ses->server, &rqst, midQ);
			if (rc) {
				cifs_delete_mid(midQ);
				return rc;
			}
		} else {
			/* Windows lock. We send a LOCKINGX_CANCEL_LOCK
			   to cause the blocking lock to return. */

			rc = send_lock_cancel(xid, tcon, in_buf, out_buf);

			/* If we get -ENOLCK back the lock may have
			   already been removed. Don't exit in this case. */
			if (rc && rc != -ENOLCK) {
				DeleteMidQEntry(midQ);
				cifs_delete_mid(midQ);
				return rc;
			}
		}

		/* Wait 5 seconds for the response. */
		if (wait_for_response(ses, midQ, 5 * HZ, 5 * HZ) == 0) {
			/* We got the response - restart system call. */
			rstart = 1;
		}
	}

	spin_lock(&GlobalMid_Lock);
	if (midQ->resp_buf) {
		spin_unlock(&GlobalMid_Lock);
		receive_len = midQ->resp_buf->smb_buf_length;
	} else {
		cERROR(1, ("No response for cmd %d mid %d",
			  midQ->command, midQ->mid));
		if (midQ->midState == MID_REQUEST_SUBMITTED) {
			if (ses->server->tcpStatus == CifsExiting)
				rc = -EHOSTDOWN;
			else {
				ses->server->tcpStatus = CifsNeedReconnect;
				midQ->midState = MID_RETRY_NEEDED;
			}
		}

		if (rc != -EHOSTDOWN) {
			if (midQ->midState == MID_RETRY_NEEDED) {
				rc = -EAGAIN;
				cFYI(1, ("marking request for retry"));
			} else {
				rc = -EIO;
			}
		}
		spin_unlock(&GlobalMid_Lock);
		DeleteMidQEntry(midQ);
		return rc;
	}

	if (receive_len > CIFSMaxBufSize + MAX_CIFS_HDR_SIZE) {
		cERROR(1, ("Frame too large received.  Length: %d  Xid: %d",
			receive_len, xid));
		rc = -EIO;
	} else {		/* rcvd frame is ok */

		if (midQ->resp_buf && out_buf
		    && (midQ->midState == MID_RESPONSE_RECEIVED)) {
			out_buf->smb_buf_length = receive_len;
			memcpy((char *)out_buf + 4,
			       (char *)midQ->resp_buf + 4,
			       receive_len);

			dump_smb(out_buf, 92);
			/* convert the length into a more usable form */
			if ((receive_len > 24) &&
			   (ses->server->secMode & (SECMODE_SIGN_REQUIRED |
					SECMODE_SIGN_ENABLED))) {
				rc = cifs_verify_signature(out_buf,
						&ses->server->mac_signing_key,
						midQ->sequence_number+1);
				if (rc) {
					cERROR(1, ("Unexpected SMB signature"));
					/* BB FIXME add code to kill session */
				}
			}

			*pbytes_returned = out_buf->smb_buf_length;

			/* BB special case reconnect tid and uid here? */
			rc = map_smb_to_linux_error(out_buf, 0 /* no log */ );

			/* convert ByteCount if necessary */
			if (receive_len >= sizeof(struct smb_hdr) - 4
			    /* do not count RFC1001 header */  +
			    (2 * out_buf->WordCount) + 2 /* bcc */ )
				BCC(out_buf) = le16_to_cpu(BCC_LE(out_buf));
		} else {
			rc = -EIO;
			cERROR(1, ("Bad MID state?"));
		}
	}
	DeleteMidQEntry(midQ);
		rc = wait_for_response(ses->server, midQ);
		if (rc) {
			send_cancel(ses->server, &rqst, midQ);
			spin_lock(&GlobalMid_Lock);
			if (midQ->mid_state == MID_REQUEST_SUBMITTED) {
				/* no longer considered to be "in-flight" */
				midQ->callback = DeleteMidQEntry;
				spin_unlock(&GlobalMid_Lock);
				return rc;
			}
			spin_unlock(&GlobalMid_Lock);
		}

		/* We got the response - restart system call. */
		rstart = 1;
	}

	rc = cifs_sync_mid_result(midQ, ses->server);
	if (rc != 0)
		return rc;

	/* rcvd frame is ok */
	if (out_buf == NULL || midQ->mid_state != MID_RESPONSE_RECEIVED) {
		rc = -EIO;
		cifs_dbg(VFS, "Bad MID state?\n");
		goto out;
	}

	*pbytes_returned = get_rfc1002_length(midQ->resp_buf);
	memcpy(out_buf, midQ->resp_buf, *pbytes_returned + 4);
	rc = cifs_check_receive(midQ, ses->server, 0);
out:
	cifs_delete_mid(midQ);
	if (rstart && rc == -EACCES)
		return -ERESTARTSYS;
	return rc;
}
