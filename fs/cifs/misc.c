/*
 *   fs/cifs/misc.c
 *
 *   Copyright (C) International Business Machines  Corp., 2002,2008
 *   Author(s): Steve French (sfrench@us.ibm.com)
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

#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/mempool.h>
#include <linux/vmalloc.h>
#include "cifspdu.h"
#include "cifsglob.h"
#include "cifsproto.h"
#include "cifs_debug.h"
#include "smberr.h"
#include "nterr.h"
#include "cifs_unicode.h"

extern mempool_t *cifs_sm_req_poolp;
extern mempool_t *cifs_req_poolp;
extern struct task_struct *oplockThread;
#ifdef CONFIG_CIFS_SMB2
#include "smb2pdu.h"

extern mempool_t *cifs_sm_req_poolp;
extern mempool_t *cifs_req_poolp;

/* The xid serves as a useful identifier for each incoming vfs request,
   in a similar way to the mid which is useful to track each sent smb,
   and CurrentXid can also provide a running counter (although it
   will eventually wrap past zero) of the total vfs operations handled
   since the cifs fs was mounted */

unsigned int
_GetXid(void)
_get_xid(void)
{
	unsigned int xid;

	spin_lock(&GlobalMid_Lock);
	GlobalTotalActiveXid++;

	/* keep high water mark for number of simultaneous ops in filesystem */
	if (GlobalTotalActiveXid > GlobalMaxActiveXid)
		GlobalMaxActiveXid = GlobalTotalActiveXid;
	if (GlobalTotalActiveXid > 65000)
		cFYI(1, ("warning: more than 65000 requests active"));
		cifs_dbg(FYI, "warning: more than 65000 requests active\n");
	xid = GlobalCurrentXid++;
	spin_unlock(&GlobalMid_Lock);
	return xid;
}

void
_FreeXid(unsigned int xid)
_free_xid(unsigned int xid)
{
	spin_lock(&GlobalMid_Lock);
	/* if (GlobalTotalActiveXid == 0)
		BUG(); */
	GlobalTotalActiveXid--;
	spin_unlock(&GlobalMid_Lock);
}

struct cifsSesInfo *
sesInfoAlloc(void)
{
	struct cifsSesInfo *ret_buf;

	ret_buf = kzalloc(sizeof(struct cifsSesInfo), GFP_KERNEL);
	if (ret_buf) {
		write_lock(&GlobalSMBSeslock);
		atomic_inc(&sesInfoAllocCount);
		ret_buf->status = CifsNew;
		list_add(&ret_buf->cifsSessionList, &GlobalSMBSessionList);
		init_MUTEX(&ret_buf->sesSem);
		write_unlock(&GlobalSMBSeslock);
struct cifs_ses *
sesInfoAlloc(void)
{
	struct cifs_ses *ret_buf;

	ret_buf = kzalloc(sizeof(struct cifs_ses), GFP_KERNEL);
	if (ret_buf) {
		atomic_inc(&sesInfoAllocCount);
		ret_buf->status = CifsNew;
		++ret_buf->ses_count;
		INIT_LIST_HEAD(&ret_buf->smb_ses_list);
		INIT_LIST_HEAD(&ret_buf->tcon_list);
		mutex_init(&ret_buf->session_mutex);
		spin_lock_init(&ret_buf->iface_lock);
	}
	return ret_buf;
}

void
sesInfoFree(struct cifsSesInfo *buf_to_free)
{
	if (buf_to_free == NULL) {
		cFYI(1, ("Null buffer passed to sesInfoFree"));
		return;
	}

	write_lock(&GlobalSMBSeslock);
	atomic_dec(&sesInfoAllocCount);
	list_del(&buf_to_free->cifsSessionList);
	write_unlock(&GlobalSMBSeslock);
	kfree(buf_to_free->serverOS);
	kfree(buf_to_free->serverDomain);
	kfree(buf_to_free->serverNOS);
	kfree(buf_to_free->password);
	kfree(buf_to_free->domainName);
	kfree(buf_to_free);
}

struct cifsTconInfo *
tconInfoAlloc(void)
{
	struct cifsTconInfo *ret_buf;
	ret_buf = kzalloc(sizeof(struct cifsTconInfo), GFP_KERNEL);
	if (ret_buf) {
		write_lock(&GlobalSMBSeslock);
		atomic_inc(&tconInfoAllocCount);
		list_add(&ret_buf->cifsConnectionList,
			 &GlobalTreeConnectionList);
		ret_buf->tidStatus = CifsNew;
		INIT_LIST_HEAD(&ret_buf->openFileList);
		init_MUTEX(&ret_buf->tconSem);
#ifdef CONFIG_CIFS_STATS
		spin_lock_init(&ret_buf->stat_lock);
#endif
		write_unlock(&GlobalSMBSeslock);
sesInfoFree(struct cifs_ses *buf_to_free)
{
	if (buf_to_free == NULL) {
		cifs_dbg(FYI, "Null buffer passed to sesInfoFree\n");
		return;
	}

	atomic_dec(&sesInfoAllocCount);
	kfree(buf_to_free->serverOS);
	kfree(buf_to_free->serverDomain);
	kfree(buf_to_free->serverNOS);
	kzfree(buf_to_free->password);
	kfree(buf_to_free->user_name);
	kfree(buf_to_free->domainName);
	kzfree(buf_to_free->auth_key.response);
	kfree(buf_to_free->iface_list);
	kzfree(buf_to_free);
}

struct cifs_tcon *
tconInfoAlloc(void)
{
	struct cifs_tcon *ret_buf;
	ret_buf = kzalloc(sizeof(struct cifs_tcon), GFP_KERNEL);
	if (ret_buf) {
		atomic_inc(&tconInfoAllocCount);
		ret_buf->tidStatus = CifsNew;
		++ret_buf->tc_count;
		INIT_LIST_HEAD(&ret_buf->openFileList);
		INIT_LIST_HEAD(&ret_buf->tcon_list);
		spin_lock_init(&ret_buf->open_file_lock);
		mutex_init(&ret_buf->crfid.fid_mutex);
		ret_buf->crfid.fid = kzalloc(sizeof(struct cifs_fid),
					     GFP_KERNEL);
		spin_lock_init(&ret_buf->stat_lock);
	}
	return ret_buf;
}

void
tconInfoFree(struct cifsTconInfo *buf_to_free)
{
	if (buf_to_free == NULL) {
		cFYI(1, ("Null buffer passed to tconInfoFree"));
		return;
	}
	write_lock(&GlobalSMBSeslock);
	atomic_dec(&tconInfoAllocCount);
	list_del(&buf_to_free->cifsConnectionList);
	write_unlock(&GlobalSMBSeslock);
	kfree(buf_to_free->nativeFileSystem);
tconInfoFree(struct cifs_tcon *buf_to_free)
{
	if (buf_to_free == NULL) {
		cifs_dbg(FYI, "Null buffer passed to tconInfoFree\n");
		return;
	}
	atomic_dec(&tconInfoAllocCount);
	kfree(buf_to_free->nativeFileSystem);
	kzfree(buf_to_free->password);
	kfree(buf_to_free->crfid.fid);
	kfree(buf_to_free);
}

struct smb_hdr *
cifs_buf_get(void)
{
	struct smb_hdr *ret_buf = NULL;

/* We could use negotiated size instead of max_msgsize -
   but it may be more efficient to always alloc same size
   albeit slightly larger than necessary and maxbuffersize
   defaults to this and can not be bigger */
	ret_buf = (struct smb_hdr *) mempool_alloc(cifs_req_poolp,
						   GFP_KERNEL | GFP_NOFS);
	size_t buf_size = sizeof(struct smb_hdr);

#ifdef CONFIG_CIFS_SMB2
	/*
	 * SMB2 header is bigger than CIFS one - no problems to clean some
	 * more bytes for CIFS.
	 */
	size_t buf_size = sizeof(struct smb2_sync_hdr);

	/*
	 * We could use negotiated size instead of max_msgsize -
	 * but it may be more efficient to always alloc same size
	 * albeit slightly larger than necessary and maxbuffersize
	 * defaults to this and can not be bigger.
	 */
	ret_buf = mempool_alloc(cifs_req_poolp, GFP_NOFS);

	/* clear the first few header bytes */
	/* for most paths, more is cleared in header_assemble */
	if (ret_buf) {
		memset(ret_buf, 0, sizeof(struct smb_hdr) + 3);
		memset(ret_buf, 0, buf_size + 3);
		atomic_inc(&bufAllocCount);
	memset(ret_buf, 0, buf_size + 3);
	atomic_inc(&bufAllocCount);
#ifdef CONFIG_CIFS_STATS2
	atomic_inc(&totBufAllocCount);
#endif /* CONFIG_CIFS_STATS2 */

	return ret_buf;
}

void
cifs_buf_release(void *buf_to_free)
{
	if (buf_to_free == NULL) {
		/* cFYI(1, ("Null buffer passed to cifs_buf_release"));*/
		/* cifs_dbg(FYI, "Null buffer passed to cifs_buf_release\n");*/
		return;
	}
	mempool_free(buf_to_free, cifs_req_poolp);

	atomic_dec(&bufAllocCount);
	return;
}

struct smb_hdr *
cifs_small_buf_get(void)
{
	struct smb_hdr *ret_buf = NULL;

/* We could use negotiated size instead of max_msgsize -
   but it may be more efficient to always alloc same size
   albeit slightly larger than necessary and maxbuffersize
   defaults to this and can not be bigger */
	ret_buf = (struct smb_hdr *) mempool_alloc(cifs_sm_req_poolp,
						   GFP_KERNEL | GFP_NOFS);
	ret_buf = mempool_alloc(cifs_sm_req_poolp, GFP_NOFS);
	/* No need to clear memory here, cleared in header assemble */
	/*	memset(ret_buf, 0, sizeof(struct smb_hdr) + 27);*/
	atomic_inc(&smBufAllocCount);
#ifdef CONFIG_CIFS_STATS2
	atomic_inc(&totSmBufAllocCount);
#endif /* CONFIG_CIFS_STATS2 */

	return ret_buf;
}

void
cifs_small_buf_release(void *buf_to_free)
{

	if (buf_to_free == NULL) {
		cFYI(1, ("Null buffer passed to cifs_small_buf_release"));
		cifs_dbg(FYI, "Null buffer passed to cifs_small_buf_release\n");
		return;
	}
	mempool_free(buf_to_free, cifs_sm_req_poolp);

	atomic_dec(&smBufAllocCount);
	return;
}

/*
	Find a free multiplex id (SMB mid). Otherwise there could be
	mid collisions which might cause problems, demultiplexing the
	wrong response to this request. Multiplex ids could collide if
	one of a series requests takes much longer than the others, or
	if a very large number of long lived requests (byte range
	locks or FindNotify requests) are pending.  No more than
	64K-1 requests can be outstanding at one time.  If no
	mids are available, return zero.  A future optimization
	could make the combination of mids and uid the key we use
	to demultiplex on (rather than mid alone).
	In addition to the above check, the cifs demultiplex
	code already used the command code as a secondary
	check of the frame and if signing is negotiated the
	response would be discarded if the mid were the same
	but the signature was wrong.  Since the mid is not put in the
	pending queue until later (when it is about to be dispatched)
	we do have to limit the number of outstanding requests
	to somewhat less than 64K-1 although it is hard to imagine
	so many threads being in the vfs at one time.
*/
__u16 GetNextMid(struct TCP_Server_Info *server)
{
	__u16 mid = 0;
	__u16 last_mid;
	int   collision;

	if (server == NULL)
		return mid;

	spin_lock(&GlobalMid_Lock);
	last_mid = server->CurrentMid; /* we do not want to loop forever */
	server->CurrentMid++;
	/* This nested loop looks more expensive than it is.
	In practice the list of pending requests is short,
	fewer than 50, and the mids are likely to be unique
	on the first pass through the loop unless some request
	takes longer than the 64 thousand requests before it
	(and it would also have to have been a request that
	 did not time out) */
	while (server->CurrentMid != last_mid) {
		struct list_head *tmp;
		struct mid_q_entry *mid_entry;

		collision = 0;
		if (server->CurrentMid == 0)
			server->CurrentMid++;

		list_for_each(tmp, &server->pending_mid_q) {
			mid_entry = list_entry(tmp, struct mid_q_entry, qhead);

			if ((mid_entry->mid == server->CurrentMid) &&
			    (mid_entry->midState == MID_REQUEST_SUBMITTED)) {
				/* This mid is in use, try a different one */
				collision = 1;
				break;
			}
		}
		if (collision == 0) {
			mid = server->CurrentMid;
			break;
		}
		server->CurrentMid++;
	}
	spin_unlock(&GlobalMid_Lock);
	return mid;
void
free_rsp_buf(int resp_buftype, void *rsp)
{
	if (resp_buftype == CIFS_SMALL_BUFFER)
		cifs_small_buf_release(rsp);
	else if (resp_buftype == CIFS_LARGE_BUFFER)
		cifs_buf_release(rsp);
}

/* NB: MID can not be set if treeCon not passed in, in that
   case it is responsbility of caller to set the mid */
void
header_assemble(struct smb_hdr *buffer, char smb_command /* command */ ,
		const struct cifsTconInfo *treeCon, int word_count
		/* length of fixed section (word count) in two byte units  */)
{
	struct list_head *temp_item;
	struct cifsSesInfo *ses;
		const struct cifs_tcon *treeCon, int word_count
		/* length of fixed section (word count) in two byte units  */)
{
	char *temp = (char *) buffer;

	memset(temp, 0, 256); /* bigger than MAX_CIFS_HDR_SIZE */

	buffer->smb_buf_length =
	    (2 * word_count) + sizeof(struct smb_hdr) -
	    4 /*  RFC 1001 length field does not count */  +
	    2 /* for bcc field itself */ ;
	/* Note that this is the only network field that has to be converted
	   to big endian and it is done just before we send it */
	buffer->smb_buf_length = cpu_to_be32(
	    (2 * word_count) + sizeof(struct smb_hdr) -
	    4 /*  RFC 1001 length field does not count */  +
	    2 /* for bcc field itself */) ;

	buffer->Protocol[0] = 0xFF;
	buffer->Protocol[1] = 'S';
	buffer->Protocol[2] = 'M';
	buffer->Protocol[3] = 'B';
	buffer->Command = smb_command;
	buffer->Flags = 0x00;	/* case sensitive */
	buffer->Flags2 = SMBFLG2_KNOWS_LONG_NAMES;
	buffer->Pid = cpu_to_le16((__u16)current->tgid);
	buffer->PidHigh = cpu_to_le16((__u16)(current->tgid >> 16));
	spin_lock(&GlobalMid_Lock);
	spin_unlock(&GlobalMid_Lock);
	if (treeCon) {
		buffer->Tid = treeCon->tid;
		if (treeCon->ses) {
			if (treeCon->ses->capabilities & CAP_UNICODE)
				buffer->Flags2 |= SMBFLG2_UNICODE;
			if (treeCon->ses->capabilities & CAP_STATUS32)
				buffer->Flags2 |= SMBFLG2_ERR_STATUS;

			/* Uid is not converted */
			buffer->Uid = treeCon->ses->Suid;
			buffer->Mid = GetNextMid(treeCon->ses->server);
			if (multiuser_mount != 0) {
		/* For the multiuser case, there are few obvious technically  */
		/* possible mechanisms to match the local linux user (uid)    */
		/* to a valid remote smb user (smb_uid):		      */
		/* 	1) Query Winbind (or other local pam/nss daemon       */
		/* 	  for userid/password/logon_domain or credential      */
		/*      2) Query Winbind for uid to sid to username mapping   */
		/* 	   and see if we have a matching password for existing*/
		/*         session for that user perhas getting password by   */
		/*         adding a new pam_cifs module that stores passwords */
		/*         so that the cifs vfs can get at that for all logged*/
		/*	   on users					      */
		/*	3) (Which is the mechanism we have chosen)	      */
		/*	   Search through sessions to the same server for a   */
		/*	   a match on the uid that was passed in on mount     */
		/*         with the current processes uid (or euid?) and use  */
		/* 	   that smb uid.   If no existing smb session for     */
		/* 	   that uid found, use the default smb session ie     */
		/*         the smb session for the volume mounted which is    */
		/* 	   the same as would be used if the multiuser mount   */
		/* 	   flag were disabled.  */

		/*  BB Add support for establishing new tCon and SMB Session  */
		/*      with userid/password pairs found on the smb session   */
		/*	for other target tcp/ip addresses 		BB    */
				if (current->fsuid != treeCon->ses->linux_uid) {
					cFYI(1, ("Multiuser mode and UID "
						 "did not match tcon uid"));
					read_lock(&GlobalSMBSeslock);
					list_for_each(temp_item, &GlobalSMBSessionList) {
						ses = list_entry(temp_item, struct cifsSesInfo, cifsSessionList);
						if (ses->linux_uid == current->fsuid) {
							if (ses->server == treeCon->ses->server) {
								cFYI(1, ("found matching uid substitute right smb_uid"));
								buffer->Uid = ses->Suid;
								break;
							} else {
				/* BB eventually call cifs_setup_session here */
								cFYI(1, ("local UID found but no smb sess with this server exists"));
							}
						}
					}
					read_unlock(&GlobalSMBSeslock);
				}
			}
			buffer->Mid = get_next_mid(treeCon->ses->server);
		}
		if (treeCon->Flags & SMB_SHARE_IS_IN_DFS)
			buffer->Flags2 |= SMBFLG2_DFS;
		if (treeCon->nocase)
			buffer->Flags  |= SMBFLG_CASELESS;
		if ((treeCon->ses) && (treeCon->ses->server))
			if (treeCon->ses->server->secMode &
			  (SECMODE_SIGN_REQUIRED | SECMODE_SIGN_ENABLED))
			if (treeCon->ses->server->sign)
				buffer->Flags2 |= SMBFLG2_SECURITY_SIGNATURE;
	}

/*  endian conversion of flags is now done just before sending */
	buffer->WordCount = (char) word_count;
	return;
}

static int
checkSMBhdr(struct smb_hdr *smb, __u16 mid)
{
	/* Make sure that this really is an SMB, that it is a response,
	   and that the message ids match */
	if ((*(__le32 *) smb->Protocol == cpu_to_le32(0x424d53ff)) &&
		(mid == smb->Mid)) {
		if (smb->Flags & SMBFLG_RESPONSE)
			return 0;
		else {
		/* only one valid case where server sends us request */
			if (smb->Command == SMB_COM_LOCKING_ANDX)
				return 0;
			else
				cERROR(1, ("Received Request not response"));
		}
	} else { /* bad signature or mid */
		if (*(__le32 *) smb->Protocol != cpu_to_le32(0x424d53ff))
			cERROR(1,
			       ("Bad protocol string signature header %x",
				*(unsigned int *) smb->Protocol));
		if (mid != smb->Mid)
			cERROR(1, ("Mids do not match"));
	}
	cERROR(1, ("bad smb detected. The Mid=%d", smb->Mid));
check_smb_hdr(struct smb_hdr *smb)
{
	/* does it have the right SMB "signature" ? */
	if (*(__le32 *) smb->Protocol != cpu_to_le32(0x424d53ff)) {
		cifs_dbg(VFS, "Bad protocol string signature header 0x%x\n",
			 *(unsigned int *)smb->Protocol);
		return 1;
	}

	/* if it's a response then accept */
	if (smb->Flags & SMBFLG_RESPONSE)
		return 0;

	/* only one valid case where server sends us request */
	if (smb->Command == SMB_COM_LOCKING_ANDX)
		return 0;

	cifs_dbg(VFS, "Server sent request, not response. mid=%u\n",
		 get_mid(smb));
	return 1;
}

int
checkSMB(struct smb_hdr *smb, __u16 mid, unsigned int length)
{
	__u32 len = smb->smb_buf_length;
	__u32 clc_len;  /* calculated length */
	cFYI(0, ("checkSMB Length: 0x%x, smb_buf_length: 0x%x", length, len));

	if (length < 2 + sizeof(struct smb_hdr)) {
		if ((length >= sizeof(struct smb_hdr) - 1)
			    && (smb->Status.CifsError != 0)) {
			smb->WordCount = 0;
			/* some error cases do not return wct and bcc */
			return 0;
		} else if ((length == sizeof(struct smb_hdr) + 1) &&
checkSMB(char *buf, unsigned int total_read)
checkSMB(char *buf, unsigned int total_read, struct TCP_Server_Info *server)
{
	struct smb_hdr *smb = (struct smb_hdr *)buf;
	__u32 rfclen = be32_to_cpu(smb->smb_buf_length);
	__u32 clc_len;  /* calculated length */
	cifs_dbg(FYI, "checkSMB Length: 0x%x, smb_buf_length: 0x%x\n",
		 total_read, rfclen);

	/* is this frame too small to even get to a BCC? */
	if (total_read < 2 + sizeof(struct smb_hdr)) {
		if ((total_read >= sizeof(struct smb_hdr) - 1)
			    && (smb->Status.CifsError != 0)) {
			/* it's an error return */
			smb->WordCount = 0;
			/* some error cases do not return wct and bcc */
			return 0;
		} else if ((total_read == sizeof(struct smb_hdr) + 1) &&
				(smb->WordCount == 0)) {
			char *tmp = (char *)smb;
			/* Need to work around a bug in two servers here */
			/* First, check if the part of bcc they sent was zero */
			if (tmp[sizeof(struct smb_hdr)] == 0) {
				/* some servers return only half of bcc
				 * on simple responses (wct, bcc both zero)
				 * in particular have seen this on
				 * ulogoffX and FindClose. This leaves
				 * one byte of bcc potentially unitialized
				 */
				/* zero rest of bcc */
				tmp[sizeof(struct smb_hdr)+1] = 0;
				return 0;
			}
			cERROR(1, ("rcvd invalid byte count (bcc)"));
		} else {
			cERROR(1, ("Length less than smb header size"));
		}
		return 1;
	}
	if (len > CIFSMaxBufSize + MAX_CIFS_HDR_SIZE - 4) {
		cERROR(1, ("smb length greater than MaxBufSize, mid=%d",
				   smb->Mid));
		return 1;
	}

	if (checkSMBhdr(smb, mid))
		return 1;
	clc_len = smbCalcSize_LE(smb);

	if (4 + len != length) {
		cERROR(1, ("Length read does not match RFC1001 length %d",
			   len));
		return 1;
	}

	if (4 + len != clc_len) {
		/* check if bcc wrapped around for large read responses */
		if ((len > 64 * 1024) && (len > clc_len)) {
			/* check if lengths match mod 64K */
			if (((4 + len) & 0xFFFF) == (clc_len & 0xFFFF))
				return 0; /* bcc wrapped */
		}
		cFYI(1, ("Calculated size %d vs length %d mismatch for mid %d",
				clc_len, 4 + len, smb->Mid));
		/* Windows XP can return a few bytes too much, presumably
		an illegal pad, at the end of byte range lock responses
		so we allow for that three byte pad, as long as actual
		received length is as long or longer than calculated length */
		/* We have now had to extend this more, since there is a
		case in which it needs to be bigger still to handle a
		malformed response to transact2 findfirst from WinXP when
		access denied is returned and thus bcc and wct are zero
		but server says length is 0x21 bytes too long as if the server
		forget to reset the smb rfc1001 length when it reset the
		wct and bcc to minimum size and drop the t2 parms and data */
		if ((4+len > clc_len) && (len <= clc_len + 512))
			return 0;
		else {
			cERROR(1, ("RFC1001 size %d bigger than SMB for Mid=%d",
					len, smb->Mid));
			return 1;
			cifs_dbg(VFS, "rcvd invalid byte count (bcc)\n");
		} else {
			cifs_dbg(VFS, "Length less than smb header size\n");
		}
		return -EIO;
	}

	/* otherwise, there is enough to get to the BCC */
	if (check_smb_hdr(smb))
		return -EIO;
	clc_len = smbCalcSize(smb, server);

	if (4 + rfclen != total_read) {
		cifs_dbg(VFS, "Length read does not match RFC1001 length %d\n",
			 rfclen);
		return -EIO;
	}

	if (4 + rfclen != clc_len) {
		__u16 mid = get_mid(smb);
		/* check if bcc wrapped around for large read responses */
		if ((rfclen > 64 * 1024) && (rfclen > clc_len)) {
			/* check if lengths match mod 64K */
			if (((4 + rfclen) & 0xFFFF) == (clc_len & 0xFFFF))
				return 0; /* bcc wrapped */
		}
		cifs_dbg(FYI, "Calculated size %u vs length %u mismatch for mid=%u\n",
			 clc_len, 4 + rfclen, mid);

		if (4 + rfclen < clc_len) {
			cifs_dbg(VFS, "RFC1001 size %u smaller than SMB for mid=%u\n",
				 rfclen, mid);
			return -EIO;
		} else if (rfclen > clc_len + 512) {
			/*
			 * Some servers (Windows XP in particular) send more
			 * data than the lengths in the SMB packet would
			 * indicate on certain calls (byte range locks and
			 * trans2 find first calls in particular). While the
			 * client can handle such a frame by ignoring the
			 * trailing data, we choose limit the amount of extra
			 * data to 512 bytes.
			 */
			cifs_dbg(VFS, "RFC1001 size %u more than 512 bytes larger than SMB for mid=%u\n",
				 rfclen, mid);
			return -EIO;
		}
	}
	return 0;
}

bool
is_valid_oplock_break(struct smb_hdr *buf, struct TCP_Server_Info *srv)
{
	struct smb_com_lock_req *pSMB = (struct smb_com_lock_req *)buf;
	struct list_head *tmp;
	struct list_head *tmp1;
	struct cifsTconInfo *tcon;
	struct cifsFileInfo *netfile;

	cFYI(1, ("Checking for oplock break or dnotify response"));
is_valid_oplock_break(char *buffer, struct TCP_Server_Info *srv)
{
	struct smb_hdr *buf = (struct smb_hdr *)buffer;
	struct smb_com_lock_req *pSMB = (struct smb_com_lock_req *)buf;
	struct list_head *tmp, *tmp1, *tmp2;
	struct cifs_ses *ses;
	struct cifs_tcon *tcon;
	struct cifsInodeInfo *pCifsInode;
	struct cifsFileInfo *netfile;

	cifs_dbg(FYI, "Checking for oplock break or dnotify response\n");
	if ((pSMB->hdr.Command == SMB_COM_NT_TRANSACT) &&
	   (pSMB->hdr.Flags & SMBFLG_RESPONSE)) {
		struct smb_com_transaction_change_notify_rsp *pSMBr =
			(struct smb_com_transaction_change_notify_rsp *)buf;
		struct file_notify_information *pnotify;
		__u32 data_offset = 0;
		if (pSMBr->ByteCount > sizeof(struct file_notify_information)) {
		size_t len = srv->total_read - sizeof(pSMBr->hdr.smb_buf_length);

		if (get_bcc(buf) > sizeof(struct file_notify_information)) {
			data_offset = le32_to_cpu(pSMBr->DataOffset);

			if (data_offset >
			    len - sizeof(struct file_notify_information)) {
				cifs_dbg(FYI, "invalid data_offset %u\n",
					 data_offset);
				return true;
			}
			pnotify = (struct file_notify_information *)
				((char *)&pSMBr->hdr.Protocol + data_offset);
			cFYI(1, ("dnotify on %s Action: 0x%x",
				 pnotify->FileName, pnotify->Action));
			cifs_dbg(FYI, "dnotify on %s Action: 0x%x\n",
				 pnotify->FileName, pnotify->Action);
			/*   cifs_dump_mem("Rcvd notify Data: ",buf,
				sizeof(struct smb_hdr)+60); */
			return true;
		}
		if (pSMBr->hdr.Status.CifsError) {
			cFYI(1, ("notify err 0x%d",
				pSMBr->hdr.Status.CifsError));
			cifs_dbg(FYI, "notify err 0x%x\n",
				 pSMBr->hdr.Status.CifsError);
			return true;
		}
		return false;
	}
	if (pSMB->hdr.Command != SMB_COM_LOCKING_ANDX)
		return false;
	if (pSMB->hdr.Flags & SMBFLG_RESPONSE) {
		/* no sense logging error on invalid handle on oplock
		   break - harmless race between close request and oplock
		   break response is expected from time to time writing out
		   large dirty files cached on the client */
		if ((NT_STATUS_INVALID_HANDLE) ==
		   le32_to_cpu(pSMB->hdr.Status.CifsError)) {
			cFYI(1, ("invalid handle on oplock break"));
			cifs_dbg(FYI, "invalid handle on oplock break\n");
			return true;
		} else if (ERRbadfid ==
		   le16_to_cpu(pSMB->hdr.Status.DosError.Error)) {
			return true;
		} else {
			return false; /* on valid oplock brk we get "request" */
		}
	}
	if (pSMB->hdr.WordCount != 8)
		return false;

	cFYI(1, ("oplock type 0x%d level 0x%d",
		 pSMB->LockType, pSMB->OplockLevel));
	cifs_dbg(FYI, "oplock type 0x%x level 0x%x\n",
		 pSMB->LockType, pSMB->OplockLevel);
	if (!(pSMB->LockType & LOCKING_ANDX_OPLOCK_RELEASE))
		return false;

	/* look up tcon based on tid & uid */
	read_lock(&GlobalSMBSeslock);
	list_for_each(tmp, &GlobalTreeConnectionList) {
		tcon = list_entry(tmp, struct cifsTconInfo, cifsConnectionList);
		if ((tcon->tid == buf->Tid) && (srv == tcon->ses->server)) {
			cifs_stats_inc(&tcon->num_oplock_brks);
			list_for_each(tmp1, &tcon->openFileList) {
				netfile = list_entry(tmp1, struct cifsFileInfo,
						     tlist);
				if (pSMB->Fid == netfile->netfid) {
					struct cifsInodeInfo *pCifsInode;
					read_unlock(&GlobalSMBSeslock);
					cFYI(1,
					    ("file id match, oplock break"));
					pCifsInode =
						CIFS_I(netfile->pInode);
					pCifsInode->clientCanCacheAll = false;
					if (pSMB->OplockLevel == 0)
						pCifsInode->clientCanCacheRead
							= false;
					pCifsInode->oplockPending = true;
					AllocOplockQEntry(netfile->pInode,
							  netfile->netfid,
							  tcon);
					cFYI(1,
					    ("about to wake up oplock thread"));
					if (oplockThread)
					    wake_up_process(oplockThread);
					return true;
				}
			}
			read_unlock(&GlobalSMBSeslock);
			cFYI(1, ("No matching file for oplock break"));
			return true;
		}
	}
	read_unlock(&GlobalSMBSeslock);
	cFYI(1, ("Can not process oplock break for non-existent connection"));
	spin_lock(&cifs_tcp_ses_lock);
	list_for_each(tmp, &srv->smb_ses_list) {
		ses = list_entry(tmp, struct cifs_ses, smb_ses_list);
		list_for_each(tmp1, &ses->tcon_list) {
			tcon = list_entry(tmp1, struct cifs_tcon, tcon_list);
			if (tcon->tid != buf->Tid)
				continue;

			cifs_stats_inc(&tcon->stats.cifs_stats.num_oplock_brks);
			spin_lock(&tcon->open_file_lock);
			list_for_each(tmp2, &tcon->openFileList) {
				netfile = list_entry(tmp2, struct cifsFileInfo,
						     tlist);
				if (pSMB->Fid != netfile->fid.netfid)
					continue;

				cifs_dbg(FYI, "file id match, oplock break\n");
				pCifsInode = CIFS_I(d_inode(netfile->dentry));

				set_bit(CIFS_INODE_PENDING_OPLOCK_BREAK,
					&pCifsInode->flags);

				/*
				 * Set flag if the server downgrades the oplock
				 * to L2 else clear.
				 */
				if (pSMB->OplockLevel)
					set_bit(
					   CIFS_INODE_DOWNGRADE_OPLOCK_TO_L2,
					   &pCifsInode->flags);
				else
					clear_bit(
					   CIFS_INODE_DOWNGRADE_OPLOCK_TO_L2,
					   &pCifsInode->flags);

				queue_work(cifsoplockd_wq,
					   &netfile->oplock_break);
				netfile->oplock_break_cancelled = false;

				spin_unlock(&tcon->open_file_lock);
				spin_unlock(&cifs_tcp_ses_lock);
				return true;
			}
			spin_unlock(&tcon->open_file_lock);
			spin_unlock(&cifs_tcp_ses_lock);
			cifs_dbg(FYI, "No matching file for oplock break\n");
			return true;
		}
	}
	spin_unlock(&cifs_tcp_ses_lock);
	cifs_dbg(FYI, "Can not process oplock break for non-existent connection\n");
	return true;
}

void
dump_smb(struct smb_hdr *smb_buf, int smb_buf_length)
{
	int i, j;
	char debug_line[17];
	unsigned char *buffer;

	if (traceSMB == 0)
		return;

	buffer = (unsigned char *) smb_buf;
	for (i = 0, j = 0; i < smb_buf_length; i++, j++) {
		if (i % 8 == 0) {
			/* have reached the beginning of line */
			printk(KERN_DEBUG "| ");
			j = 0;
		}
		printk("%0#4x ", buffer[i]);
		debug_line[2 * j] = ' ';
		if (isprint(buffer[i]))
			debug_line[1 + (2 * j)] = buffer[i];
		else
			debug_line[1 + (2 * j)] = '_';

		if (i % 8 == 7) {
			/* reached end of line, time to print ascii */
			debug_line[16] = 0;
			printk(" | %s\n", debug_line);
		}
	}
	for (; j < 8; j++) {
		printk("     ");
		debug_line[2 * j] = ' ';
		debug_line[1 + (2 * j)] = ' ';
	}
	printk(" | %s\n", debug_line);
	return;
}

/* Windows maps these to the user defined 16 bit Unicode range since they are
   reserved symbols (along with \ and /), otherwise illegal to store
   in filenames in NTFS */
#define UNI_ASTERIK     (__u16) ('*' + 0xF000)
#define UNI_QUESTION    (__u16) ('?' + 0xF000)
#define UNI_COLON       (__u16) (':' + 0xF000)
#define UNI_GRTRTHAN    (__u16) ('>' + 0xF000)
#define UNI_LESSTHAN    (__u16) ('<' + 0xF000)
#define UNI_PIPE        (__u16) ('|' + 0xF000)
#define UNI_SLASH       (__u16) ('\\' + 0xF000)

/* Convert 16 bit Unicode pathname from wire format to string in current code
   page.  Conversion may involve remapping up the seven characters that are
   only legal in POSIX-like OS (if they are present in the string). Path
   names are little endian 16 bit Unicode on the wire */
int
cifs_convertUCSpath(char *target, const __le16 *source, int maxlen,
		    const struct nls_table *cp)
{
	int i, j, len;
	__u16 src_char;

	for (i = 0, j = 0; i < maxlen; i++) {
		src_char = le16_to_cpu(source[i]);
		switch (src_char) {
			case 0:
				goto cUCS_out; /* BB check this BB */
			case UNI_COLON:
				target[j] = ':';
				break;
			case UNI_ASTERIK:
				target[j] = '*';
				break;
			case UNI_QUESTION:
				target[j] = '?';
				break;
			/* BB We can not handle remapping slash until
			   all the calls to build_path_from_dentry
			   are modified, as they use slash as separator BB */
			/* case UNI_SLASH:
				target[j] = '\\';
				break;*/
			case UNI_PIPE:
				target[j] = '|';
				break;
			case UNI_GRTRTHAN:
				target[j] = '>';
				break;
			case UNI_LESSTHAN:
				target[j] = '<';
				break;
			default:
				len = cp->uni2char(src_char, &target[j],
						NLS_MAX_CHARSET_SIZE);
				if (len > 0) {
					j += len;
					continue;
				} else {
					target[j] = '?';
				}
		}
		j++;
		/* make sure we do not overrun callers allocated temp buffer */
		if (j >= (2 * NAME_MAX))
			break;
	}
cUCS_out:
	target[j] = 0;
	return j;
}

/* Convert 16 bit Unicode pathname to wire format from string in current code
   page.  Conversion may involve remapping up the seven characters that are
   only legal in POSIX-like OS (if they are present in the string). Path
   names are little endian 16 bit Unicode on the wire */
int
cifsConvertToUCS(__le16 *target, const char *source, int maxlen,
		 const struct nls_table *cp, int mapChars)
{
	int i, j, charlen;
	int len_remaining = maxlen;
	char src_char;
	__u16 temp;

	if (!mapChars)
		return cifs_strtoUCS(target, source, PATH_MAX, cp);

	for (i = 0, j = 0; i < maxlen; j++) {
		src_char = source[i];
		switch (src_char) {
			case 0:
				target[j] = 0;
				goto ctoUCS_out;
			case ':':
				target[j] = cpu_to_le16(UNI_COLON);
				break;
			case '*':
				target[j] = cpu_to_le16(UNI_ASTERIK);
				break;
			case '?':
				target[j] = cpu_to_le16(UNI_QUESTION);
				break;
			case '<':
				target[j] = cpu_to_le16(UNI_LESSTHAN);
				break;
			case '>':
				target[j] = cpu_to_le16(UNI_GRTRTHAN);
				break;
			case '|':
				target[j] = cpu_to_le16(UNI_PIPE);
				break;
			/* BB We can not handle remapping slash until
			   all the calls to build_path_from_dentry
			   are modified, as they use slash as separator BB */
			/* case '\\':
				target[j] = cpu_to_le16(UNI_SLASH);
				break;*/
			default:
				charlen = cp->char2uni(source+i,
					len_remaining, &temp);
				/* if no match, use question mark, which
				at least in some cases servers as wild card */
				if (charlen < 1) {
					target[j] = cpu_to_le16(0x003f);
					charlen = 1;
				} else
					target[j] = cpu_to_le16(temp);
				len_remaining -= charlen;
				/* character may take more than one byte in the
				   the source string, but will take exactly two
				   bytes in the target string */
				i += charlen;
				continue;
		}
		i++; /* move to next char in source string */
		len_remaining--;
	}

ctoUCS_out:
	return i;
dump_smb(void *buf, int smb_buf_length)
{
	if (traceSMB == 0)
		return;

	print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_NONE, 8, 2, buf,
		       smb_buf_length, true);
}

void
cifs_autodisable_serverino(struct cifs_sb_info *cifs_sb)
{
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_SERVER_INUM) {
		cifs_sb->mnt_cifs_flags &= ~CIFS_MOUNT_SERVER_INUM;
		cifs_dbg(VFS, "Autodisabling the use of server inode numbers on %s. This server doesn't seem to support them properly. Hardlinks will not be recognized on this mount. Consider mounting with the \"noserverino\" option to silence this message.\n",
			 cifs_sb_master_tcon(cifs_sb)->treeName);
	}
}

void cifs_set_oplock_level(struct cifsInodeInfo *cinode, __u32 oplock)
{
	oplock &= 0xF;

	if (oplock == OPLOCK_EXCLUSIVE) {
		cinode->oplock = CIFS_CACHE_WRITE_FLG | CIFS_CACHE_READ_FLG;
		cifs_dbg(FYI, "Exclusive Oplock granted on inode %p\n",
			 &cinode->vfs_inode);
	} else if (oplock == OPLOCK_READ) {
		cinode->oplock = CIFS_CACHE_READ_FLG;
		cifs_dbg(FYI, "Level II Oplock granted on inode %p\n",
			 &cinode->vfs_inode);
	} else
		cinode->oplock = 0;
}

/*
 * We wait for oplock breaks to be processed before we attempt to perform
 * writes.
 */
int cifs_get_writer(struct cifsInodeInfo *cinode)
{
	int rc;

start:
	rc = wait_on_bit(&cinode->flags, CIFS_INODE_PENDING_OPLOCK_BREAK,
			 TASK_KILLABLE);
	if (rc)
		return rc;

	spin_lock(&cinode->writers_lock);
	if (!cinode->writers)
		set_bit(CIFS_INODE_PENDING_WRITERS, &cinode->flags);
	cinode->writers++;
	/* Check to see if we have started servicing an oplock break */
	if (test_bit(CIFS_INODE_PENDING_OPLOCK_BREAK, &cinode->flags)) {
		cinode->writers--;
		if (cinode->writers == 0) {
			clear_bit(CIFS_INODE_PENDING_WRITERS, &cinode->flags);
			wake_up_bit(&cinode->flags, CIFS_INODE_PENDING_WRITERS);
		}
		spin_unlock(&cinode->writers_lock);
		goto start;
	}
	spin_unlock(&cinode->writers_lock);
	return 0;
}

void cifs_put_writer(struct cifsInodeInfo *cinode)
{
	spin_lock(&cinode->writers_lock);
	cinode->writers--;
	if (cinode->writers == 0) {
		clear_bit(CIFS_INODE_PENDING_WRITERS, &cinode->flags);
		wake_up_bit(&cinode->flags, CIFS_INODE_PENDING_WRITERS);
	}
	spin_unlock(&cinode->writers_lock);
}

void cifs_done_oplock_break(struct cifsInodeInfo *cinode)
{
	clear_bit(CIFS_INODE_PENDING_OPLOCK_BREAK, &cinode->flags);
	wake_up_bit(&cinode->flags, CIFS_INODE_PENDING_OPLOCK_BREAK);
}

bool
backup_cred(struct cifs_sb_info *cifs_sb)
{
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_CIFS_BACKUPUID) {
		if (uid_eq(cifs_sb->mnt_backupuid, current_fsuid()))
			return true;
	}
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_CIFS_BACKUPGID) {
		if (in_group_p(cifs_sb->mnt_backupgid))
			return true;
	}

	return false;
}

void
cifs_del_pending_open(struct cifs_pending_open *open)
{
	spin_lock(&tlink_tcon(open->tlink)->open_file_lock);
	list_del(&open->olist);
	spin_unlock(&tlink_tcon(open->tlink)->open_file_lock);
}

void
cifs_add_pending_open_locked(struct cifs_fid *fid, struct tcon_link *tlink,
			     struct cifs_pending_open *open)
{
	memcpy(open->lease_key, fid->lease_key, SMB2_LEASE_KEY_SIZE);
	open->oplock = CIFS_OPLOCK_NO_CHANGE;
	open->tlink = tlink;
	fid->pending_open = open;
	list_add_tail(&open->olist, &tlink_tcon(tlink)->pending_opens);
}

void
cifs_add_pending_open(struct cifs_fid *fid, struct tcon_link *tlink,
		      struct cifs_pending_open *open)
{
	spin_lock(&tlink_tcon(tlink)->open_file_lock);
	cifs_add_pending_open_locked(fid, tlink, open);
	spin_unlock(&tlink_tcon(open->tlink)->open_file_lock);
}

/* parses DFS refferal V3 structure
 * caller is responsible for freeing target_nodes
 * returns:
 * - on success - 0
 * - on failure - errno
 */
int
parse_dfs_referrals(struct get_dfs_referral_rsp *rsp, u32 rsp_size,
		    unsigned int *num_of_nodes,
		    struct dfs_info3_param **target_nodes,
		    const struct nls_table *nls_codepage, int remap,
		    const char *searchName, bool is_unicode)
{
	int i, rc = 0;
	char *data_end;
	struct dfs_referral_level_3 *ref;

	*num_of_nodes = le16_to_cpu(rsp->NumberOfReferrals);

	if (*num_of_nodes < 1) {
		cifs_dbg(VFS, "num_referrals: must be at least > 0, but we get num_referrals = %d\n",
			 *num_of_nodes);
		rc = -EINVAL;
		goto parse_DFS_referrals_exit;
	}

	ref = (struct dfs_referral_level_3 *) &(rsp->referrals);
	if (ref->VersionNumber != cpu_to_le16(3)) {
		cifs_dbg(VFS, "Referrals of V%d version are not supported, should be V3\n",
			 le16_to_cpu(ref->VersionNumber));
		rc = -EINVAL;
		goto parse_DFS_referrals_exit;
	}

	/* get the upper boundary of the resp buffer */
	data_end = (char *)rsp + rsp_size;

	cifs_dbg(FYI, "num_referrals: %d dfs flags: 0x%x ...\n",
		 *num_of_nodes, le32_to_cpu(rsp->DFSFlags));

	*target_nodes = kcalloc(*num_of_nodes, sizeof(struct dfs_info3_param),
				GFP_KERNEL);
	if (*target_nodes == NULL) {
		rc = -ENOMEM;
		goto parse_DFS_referrals_exit;
	}

	/* collect necessary data from referrals */
	for (i = 0; i < *num_of_nodes; i++) {
		char *temp;
		int max_len;
		struct dfs_info3_param *node = (*target_nodes)+i;

		node->flags = le32_to_cpu(rsp->DFSFlags);
		if (is_unicode) {
			__le16 *tmp = kmalloc(strlen(searchName)*2 + 2,
						GFP_KERNEL);
			if (tmp == NULL) {
				rc = -ENOMEM;
				goto parse_DFS_referrals_exit;
			}
			cifsConvertToUTF16((__le16 *) tmp, searchName,
					   PATH_MAX, nls_codepage, remap);
			node->path_consumed = cifs_utf16_bytes(tmp,
					le16_to_cpu(rsp->PathConsumed),
					nls_codepage);
			kfree(tmp);
		} else
			node->path_consumed = le16_to_cpu(rsp->PathConsumed);

		node->server_type = le16_to_cpu(ref->ServerType);
		node->ref_flag = le16_to_cpu(ref->ReferralEntryFlags);

		/* copy DfsPath */
		temp = (char *)ref + le16_to_cpu(ref->DfsPathOffset);
		max_len = data_end - temp;
		node->path_name = cifs_strndup_from_utf16(temp, max_len,
						is_unicode, nls_codepage);
		if (!node->path_name) {
			rc = -ENOMEM;
			goto parse_DFS_referrals_exit;
		}

		/* copy link target UNC */
		temp = (char *)ref + le16_to_cpu(ref->NetworkAddressOffset);
		max_len = data_end - temp;
		node->node_name = cifs_strndup_from_utf16(temp, max_len,
						is_unicode, nls_codepage);
		if (!node->node_name) {
			rc = -ENOMEM;
			goto parse_DFS_referrals_exit;
		}

		ref++;
	}

parse_DFS_referrals_exit:
	if (rc) {
		free_dfs_info_array(*target_nodes, *num_of_nodes);
		*target_nodes = NULL;
		*num_of_nodes = 0;
	}
	return rc;
}

struct cifs_aio_ctx *
cifs_aio_ctx_alloc(void)
{
	struct cifs_aio_ctx *ctx;

	ctx = kzalloc(sizeof(struct cifs_aio_ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	INIT_LIST_HEAD(&ctx->list);
	mutex_init(&ctx->aio_mutex);
	init_completion(&ctx->done);
	kref_init(&ctx->refcount);
	return ctx;
}

void
cifs_aio_ctx_release(struct kref *refcount)
{
	struct cifs_aio_ctx *ctx = container_of(refcount,
					struct cifs_aio_ctx, refcount);

	cifsFileInfo_put(ctx->cfile);
	kvfree(ctx->bv);
	kfree(ctx);
}

#define CIFS_AIO_KMALLOC_LIMIT (1024 * 1024)

int
setup_aio_ctx_iter(struct cifs_aio_ctx *ctx, struct iov_iter *iter, int rw)
{
	ssize_t rc;
	unsigned int cur_npages;
	unsigned int npages = 0;
	unsigned int i;
	size_t len;
	size_t count = iov_iter_count(iter);
	unsigned int saved_len;
	size_t start;
	unsigned int max_pages = iov_iter_npages(iter, INT_MAX);
	struct page **pages = NULL;
	struct bio_vec *bv = NULL;

	if (iter->type & ITER_KVEC) {
		memcpy(&ctx->iter, iter, sizeof(struct iov_iter));
		ctx->len = count;
		iov_iter_advance(iter, count);
		return 0;
	}

	if (max_pages * sizeof(struct bio_vec) <= CIFS_AIO_KMALLOC_LIMIT)
		bv = kmalloc_array(max_pages, sizeof(struct bio_vec),
				   GFP_KERNEL);

	if (!bv) {
		bv = vmalloc(array_size(max_pages, sizeof(struct bio_vec)));
		if (!bv)
			return -ENOMEM;
	}

	if (max_pages * sizeof(struct page *) <= CIFS_AIO_KMALLOC_LIMIT)
		pages = kmalloc_array(max_pages, sizeof(struct page *),
				      GFP_KERNEL);

	if (!pages) {
		pages = vmalloc(array_size(max_pages, sizeof(struct page *)));
		if (!pages) {
			kvfree(bv);
			return -ENOMEM;
		}
	}

	saved_len = count;

	while (count && npages < max_pages) {
		rc = iov_iter_get_pages(iter, pages, count, max_pages, &start);
		if (rc < 0) {
			cifs_dbg(VFS, "couldn't get user pages (rc=%zd)\n", rc);
			break;
		}

		if (rc > count) {
			cifs_dbg(VFS, "get pages rc=%zd more than %zu\n", rc,
				 count);
			break;
		}

		iov_iter_advance(iter, rc);
		count -= rc;
		rc += start;
		cur_npages = DIV_ROUND_UP(rc, PAGE_SIZE);

		if (npages + cur_npages > max_pages) {
			cifs_dbg(VFS, "out of vec array capacity (%u vs %u)\n",
				 npages + cur_npages, max_pages);
			break;
		}

		for (i = 0; i < cur_npages; i++) {
			len = rc > PAGE_SIZE ? PAGE_SIZE : rc;
			bv[npages + i].bv_page = pages[i];
			bv[npages + i].bv_offset = start;
			bv[npages + i].bv_len = len - start;
			rc -= len;
			start = 0;
		}

		npages += cur_npages;
	}

	kvfree(pages);
	ctx->bv = bv;
	ctx->len = saved_len - count;
	ctx->npages = npages;
	iov_iter_bvec(&ctx->iter, ITER_BVEC | rw, ctx->bv, npages, ctx->len);
	return 0;
}

/**
 * cifs_alloc_hash - allocate hash and hash context together
 *
 * The caller has to make sure @sdesc is initialized to either NULL or
 * a valid context. Both can be freed via cifs_free_hash().
 */
int
cifs_alloc_hash(const char *name,
		struct crypto_shash **shash, struct sdesc **sdesc)
{
	int rc = 0;
	size_t size;

	if (*sdesc != NULL)
		return 0;

	*shash = crypto_alloc_shash(name, 0, 0);
	if (IS_ERR(*shash)) {
		cifs_dbg(VFS, "could not allocate crypto %s\n", name);
		rc = PTR_ERR(*shash);
		*shash = NULL;
		*sdesc = NULL;
		return rc;
	}

	size = sizeof(struct shash_desc) + crypto_shash_descsize(*shash);
	*sdesc = kmalloc(size, GFP_KERNEL);
	if (*sdesc == NULL) {
		cifs_dbg(VFS, "no memory left to allocate crypto %s\n", name);
		crypto_free_shash(*shash);
		*shash = NULL;
		return -ENOMEM;
	}

	(*sdesc)->shash.tfm = *shash;
	(*sdesc)->shash.flags = 0x0;
	return 0;
}

/**
 * cifs_free_hash - free hash and hash context together
 *
 * Freeing a NULL hash or context is safe.
 */
void
cifs_free_hash(struct crypto_shash **shash, struct sdesc **sdesc)
{
	kfree(*sdesc);
	*sdesc = NULL;
	if (*shash)
		crypto_free_shash(*shash);
	*shash = NULL;
}

/**
 * rqst_page_get_length - obtain the length and offset for a page in smb_rqst
 * Input: rqst - a smb_rqst, page - a page index for rqst
 * Output: *len - the length for this page, *offset - the offset for this page
 */
void rqst_page_get_length(struct smb_rqst *rqst, unsigned int page,
				unsigned int *len, unsigned int *offset)
{
	*len = rqst->rq_pagesz;
	*offset = (page == 0) ? rqst->rq_offset : 0;

	if (rqst->rq_npages == 1 || page == rqst->rq_npages-1)
		*len = rqst->rq_tailsz;
	else if (page == 0)
		*len = rqst->rq_pagesz - rqst->rq_offset;
}
