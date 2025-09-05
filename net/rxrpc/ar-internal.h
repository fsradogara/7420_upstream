/* AF_RXRPC internal definitions
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/atomic.h>
#include <linux/seqlock.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/sock.h>
#include <net/af_rxrpc.h>
#include "protocol.h"

#if 0
#define CHECK_SLAB_OKAY(X)				     \
	BUG_ON(atomic_read((X)) >> (sizeof(atomic_t) - 2) == \
	       (POISON_FREE << 8 | POISON_FREE))
#else
#define CHECK_SLAB_OKAY(X) do {} while (0)
#endif

#define FCRYPT_BSIZE 8
struct rxrpc_crypt {
	union {
		u8	x[FCRYPT_BSIZE];
		__be32	n[2];
	};
} __attribute__((aligned(8)));

#define rxrpc_queue_work(WS)	queue_work(rxrpc_workqueue, (WS))
#define rxrpc_queue_delayed_work(WS,D)	\
	queue_delayed_work(rxrpc_workqueue, (WS), (D))

struct rxrpc_connection;

/*
 * Mark applied to socket buffers.
 */
enum rxrpc_skb_mark {
	RXRPC_SKB_MARK_DATA,		/* data message */
	RXRPC_SKB_MARK_FINAL_ACK,	/* final ACK received message */
	RXRPC_SKB_MARK_BUSY,		/* server busy message */
	RXRPC_SKB_MARK_REMOTE_ABORT,	/* remote abort message */
	RXRPC_SKB_MARK_LOCAL_ABORT,	/* local abort message */
	RXRPC_SKB_MARK_NET_ERROR,	/* network error message */
	RXRPC_SKB_MARK_LOCAL_ERROR,	/* local error message */
	RXRPC_SKB_MARK_NEW_CALL,	/* local error message */
};

/*
 * sk_state for RxRPC sockets
 */
enum {
	RXRPC_UNBOUND = 0,
	RXRPC_CLIENT_UNBOUND,		/* Unbound socket used as client */
	RXRPC_CLIENT_BOUND,		/* client local address bound */
	RXRPC_SERVER_BOUND,		/* server local address bound */
	RXRPC_SERVER_BOUND2,		/* second server local address bound */
	RXRPC_SERVER_LISTENING,		/* server listening for connections */
	RXRPC_SERVER_LISTEN_DISABLED,	/* server listening disabled */
	RXRPC_CLOSE,			/* socket is being closed */
};

/*
 * Per-network namespace data.
 */
struct rxrpc_net {
	struct proc_dir_entry	*proc_net;	/* Subdir in /proc/net */
	u32			epoch;		/* Local epoch for detecting local-end reset */
	struct list_head	calls;		/* List of calls active in this namespace */
	rwlock_t		call_lock;	/* Lock for ->calls */

	struct list_head	conn_proc_list;	/* List of conns in this namespace for proc */
	struct list_head	service_conns;	/* Service conns in this namespace */
	rwlock_t		conn_lock;	/* Lock for ->conn_proc_list, ->service_conns */
	struct delayed_work	service_conn_reaper;

	unsigned int		nr_client_conns;
	unsigned int		nr_active_client_conns;
	bool			kill_all_client_conns;
	spinlock_t		client_conn_cache_lock; /* Lock for ->*_client_conns */
	spinlock_t		client_conn_discard_lock; /* Prevent multiple discarders */
	struct list_head	waiting_client_conns;
	struct list_head	active_client_conns;
	struct list_head	idle_client_conns;
	struct delayed_work	client_conn_reaper;

	struct list_head	local_endpoints;
	struct mutex		local_mutex;	/* Lock for ->local_endpoints */

	spinlock_t		peer_hash_lock;	/* Lock for ->peer_hash */
	DECLARE_HASHTABLE	(peer_hash, 10);
};

/*
 * Service backlog preallocation.
 *
 * This contains circular buffers of preallocated peers, connections and calls
 * for incoming service calls and their head and tail pointers.  This allows
 * calls to be set up in the data_ready handler, thereby avoiding the need to
 * shuffle packets around so much.
 */
struct rxrpc_backlog {
	unsigned short		peer_backlog_head;
	unsigned short		peer_backlog_tail;
	unsigned short		conn_backlog_head;
	unsigned short		conn_backlog_tail;
	unsigned short		call_backlog_head;
	unsigned short		call_backlog_tail;
#define RXRPC_BACKLOG_MAX	32
	struct rxrpc_peer	*peer_backlog[RXRPC_BACKLOG_MAX];
	struct rxrpc_connection	*conn_backlog[RXRPC_BACKLOG_MAX];
	struct rxrpc_call	*call_backlog[RXRPC_BACKLOG_MAX];
};

/*
 * RxRPC socket definition
 */
struct rxrpc_sock {
	/* WARNING: sk has to be the first member */
	struct sock		sk;
	rxrpc_notify_new_call_t	notify_new_call; /* Func to notify of new call */
	rxrpc_discard_new_call_t discard_new_call; /* Func to discard a new call */
	struct rxrpc_local	*local;		/* local endpoint */
	struct rxrpc_backlog	*backlog;	/* Preallocation for services */
	spinlock_t		incoming_lock;	/* Incoming call vs service shutdown lock */
	struct list_head	sock_calls;	/* List of calls owned by this socket */
	struct list_head	to_be_accepted;	/* calls awaiting acceptance */
	struct list_head	recvmsg_q;	/* Calls awaiting recvmsg's attention  */
	rwlock_t		recvmsg_lock;	/* Lock for recvmsg_q */
	struct key		*key;		/* security for this socket */
	struct key		*securities;	/* list of server security descriptors */
	struct rb_root		calls;		/* User ID -> call mapping */
	unsigned long		flags;
#define RXRPC_SOCK_CONNECTED		0	/* connect_srx is set */
	rwlock_t		call_lock;	/* lock for calls */
	u32			min_sec_level;	/* minimum security level */
#define RXRPC_SECURITY_MAX	RXRPC_SECURITY_ENCRYPT
	bool			exclusive;	/* Exclusive connection for a client socket */
	u16			second_service;	/* Additional service bound to the endpoint */
	struct {
		/* Service upgrade information */
		u16		from;		/* Service ID to upgrade (if not 0) */
		u16		to;		/* service ID to upgrade to */
	} service_upgrade;
	sa_family_t		family;		/* Protocol family created with */
	struct sockaddr_rxrpc	srx;		/* Primary Service/local addresses */
	struct sockaddr_rxrpc	connect_srx;	/* Default client address from connect() */
};

#define rxrpc_sk(__sk) container_of((__sk), struct rxrpc_sock, sk)

/*
 * CPU-byteorder normalised Rx packet header.
 */
struct rxrpc_host_header {
	u32		epoch;		/* client boot timestamp */
	u32		cid;		/* connection and channel ID */
	u32		callNumber;	/* call ID (0 for connection-level packets) */
	u32		seq;		/* sequence number of pkt in call stream */
	u32		serial;		/* serial number of pkt sent to network */
	u8		type;		/* packet type */
	u8		flags;		/* packet flags */
	u8		userStatus;	/* app-layer defined status */
	u8		securityIndex;	/* security protocol ID */
	union {
		u16	_rsvd;		/* reserved */
		u16	cksum;		/* kerberos security checksum */
	};
	u16		serviceId;	/* service ID */
} __packed;

/*
 * RxRPC socket buffer private variables
 * - max 48 bytes (struct sk_buff::cb)
 */
struct rxrpc_skb_priv {
	union {
		unsigned	offset;		/* offset into buffer of next read */
		unsigned int	offset;		/* offset into buffer of next read */
		u8		nr_jumbo;	/* Number of jumbo subpackets */
	};
	union {
		int		remain;		/* amount of space remaining for next write */
	};

	struct rxrpc_host_header hdr;		/* RxRPC packet header from this packet */
};

#define rxrpc_skb(__skb) ((struct rxrpc_skb_priv *) &(__skb)->cb)

/*
 * RxRPC security module interface
 */
struct rxrpc_security {
	const char		*name;		/* name of this service */
	u8			security_index;	/* security type provided */

	/* Initialise a security service */
	int (*init)(void);

	/* Clean up a security service */
	void (*exit)(void);

	/* initialise a connection's security */
	int (*init_connection_security)(struct rxrpc_connection *);

	/* prime a connection's packet security */
	int (*prime_packet_security)(struct rxrpc_connection *);

	/* impose security on a packet */
	int (*secure_packet)(struct rxrpc_call *,
			     struct sk_buff *,
			     size_t,
			     void *);

	/* verify the security on a received packet */
	int (*verify_packet)(struct rxrpc_call *, struct sk_buff *,
			     unsigned int, unsigned int, rxrpc_seq_t, u16);

	/* Locate the data in a received packet that has been verified. */
	void (*locate_data)(struct rxrpc_call *, struct sk_buff *,
			    unsigned int *, unsigned int *);

	/* issue a challenge */
	int (*issue_challenge)(struct rxrpc_connection *);

	/* respond to a challenge */
	int (*respond_to_challenge)(struct rxrpc_connection *,
				    struct sk_buff *,
				    u32 *);

	/* verify a response */
	int (*verify_response)(struct rxrpc_connection *,
			       struct sk_buff *,
			       u32 *);

	/* clear connection security */
	void (*clear)(struct rxrpc_connection *);
};

/*
 * RxRPC local transport endpoint description
 * - owned by a single AF_RXRPC socket
 * - pointed to by transport socket struct sk_user_data
 */
struct rxrpc_local {
	struct rcu_head		rcu;
	atomic_t		usage;
	struct rxrpc_net	*rxnet;		/* The network ns in which this resides */
	struct list_head	link;
	struct socket		*socket;	/* my UDP socket */
	struct work_struct	processor;
	struct rxrpc_sock __rcu	*service;	/* Service(s) listening on this endpoint */
	struct rw_semaphore	defrag_sem;	/* control re-enablement of IP DF bit */
	struct sk_buff_head	reject_queue;	/* packets awaiting rejection */
	struct sk_buff_head	event_queue;	/* endpoint event packets awaiting processing */
	struct rb_root		client_conns;	/* Client connections by socket params */
	spinlock_t		client_conns_lock; /* Lock for client_conns */
	spinlock_t		lock;		/* access lock */
	rwlock_t		services_lock;	/* lock for services list */
	int			debug_id;	/* debug ID for printks */
	bool			dead;
	struct sockaddr_rxrpc	srx;		/* local address */
};

/*
 * RxRPC remote transport endpoint definition
 * - matched by local endpoint, remote port, address and protocol type
 */
struct rxrpc_peer {
	struct rcu_head		rcu;		/* This must be first */
	atomic_t		usage;
	unsigned		if_mtu;		/* interface MTU for this peer */
	unsigned		mtu;		/* network MTU for this peer */
	unsigned		maxdata;	/* data size (MTU - hdrsize) */
	unsigned long		hash_key;
	struct hlist_node	hash_link;
	struct rxrpc_local	*local;
	struct hlist_head	error_targets;	/* targets for net error distribution */
	struct work_struct	error_distributor;
	struct rb_root		service_conns;	/* Service connections */
	seqlock_t		service_conn_lock;
	spinlock_t		lock;		/* access lock */
	unsigned int		if_mtu;		/* interface MTU for this peer */
	unsigned int		mtu;		/* network MTU for this peer */
	unsigned int		maxdata;	/* data size (MTU - hdrsize) */
	unsigned short		hdrsize;	/* header size (IP + UDP + RxRPC) */
	int			debug_id;	/* debug ID for printks */
	int			error_report;	/* Net (+0) or local (+1000000) to distribute */
#define RXRPC_LOCAL_ERROR_OFFSET 1000000
	struct sockaddr_rxrpc	srx;		/* remote address */

	/* calculated RTT cache */
#define RXRPC_RTT_CACHE_SIZE 32
	suseconds_t		rtt;		/* current RTT estimate (in uS) */
	unsigned		rtt_point;	/* next entry at which to insert */
	unsigned		rtt_usage;	/* amount of cache actually used */
	unsigned int		rtt_point;	/* next entry at which to insert */
	unsigned int		rtt_usage;	/* amount of cache actually used */
	suseconds_t		rtt_cache[RXRPC_RTT_CACHE_SIZE]; /* calculated RTT cache */
	ktime_t			rtt_last_req;	/* Time of last RTT request */
	u64			rtt;		/* Current RTT estimate (in nS) */
	u64			rtt_sum;	/* Sum of cache contents */
	u64			rtt_cache[RXRPC_RTT_CACHE_SIZE]; /* Determined RTT cache */
	u8			rtt_cursor;	/* next entry at which to insert */
	u8			rtt_usage;	/* amount of cache actually used */

	u8			cong_cwnd;	/* Congestion window size */
};

/*
 * Keys for matching a connection.
 */
struct rxrpc_transport {
	struct rxrpc_local	*local;		/* local transport endpoint */
	struct rxrpc_peer	*peer;		/* remote transport endpoint */
	struct work_struct	error_handler;	/* network error distributor */
	struct rb_root		bundles;	/* client connection bundles on this transport */
	struct rb_root		client_conns;	/* client connections on this transport */
	struct rb_root		server_conns;	/* server connections on this transport */
	struct list_head	link;		/* link in master session list */
	struct sk_buff_head	error_queue;	/* error packets awaiting processing */
	time_t			put_time;	/* time at which to reap */
	unsigned long		put_time;	/* time at which to reap */
	spinlock_t		client_lock;	/* client connection allocation lock */
	rwlock_t		conn_lock;	/* lock for active/dead connections */
	atomic_t		usage;
	int			debug_id;	/* debug ID for printks */
	unsigned int		conn_idcounter;	/* connection ID counter (client) */
struct rxrpc_conn_proto {
	union {
		struct {
			u32	epoch;		/* epoch of this connection */
			u32	cid;		/* connection ID */
		};
		u64		index_key;
	};
};

struct rxrpc_conn_parameters {
	struct rxrpc_local	*local;		/* Representation of local endpoint */
	struct rxrpc_peer	*peer;		/* Remote endpoint */
	struct key		*key;		/* Security details */
	bool			exclusive;	/* T if conn is exclusive */
	bool			upgrade;	/* T if service ID can be upgraded */
	u16			service_id;	/* Service ID for this connection */
	u32			security_level;	/* Security level selected */
};

/*
 * Bits in the connection flags.
 */
struct rxrpc_conn_bundle {
	struct rb_node		node;		/* node in transport's lookup tree */
	struct list_head	unused_conns;	/* unused connections in this bundle */
	struct list_head	avail_conns;	/* available connections in this bundle */
	struct list_head	busy_conns;	/* busy connections in this bundle */
	struct key		*key;		/* security for this bundle */
	wait_queue_head_t	chanwait;	/* wait for channel to become available */
	atomic_t		usage;
	int			debug_id;	/* debug ID for printks */
	unsigned short		num_conns;	/* number of connections in this bundle */
	__be16			service_id;	/* service ID */
	uint8_t			security_ix;	/* security type */
	u8			security_ix;	/* security type */
enum rxrpc_conn_flag {
	RXRPC_CONN_HAS_IDR,		/* Has a client conn ID assigned */
	RXRPC_CONN_IN_SERVICE_CONNS,	/* Conn is in peer->service_conns */
	RXRPC_CONN_IN_CLIENT_CONNS,	/* Conn is in local->client_conns */
	RXRPC_CONN_EXPOSED,		/* Conn has extra ref for exposure */
	RXRPC_CONN_DONT_REUSE,		/* Don't reuse this connection */
	RXRPC_CONN_COUNTED,		/* Counted by rxrpc_nr_client_conns */
	RXRPC_CONN_PROBING_FOR_UPGRADE,	/* Probing for service upgrade */
};

/*
 * Events that can be raised upon a connection.
 */
enum rxrpc_conn_event {
	RXRPC_CONN_EV_CHALLENGE,	/* Send challenge packet */
};

/*
 * The connection cache state.
 */
enum rxrpc_conn_cache_state {
	RXRPC_CONN_CLIENT_INACTIVE,	/* Conn is not yet listed */
	RXRPC_CONN_CLIENT_WAITING,	/* Conn is on wait list, waiting for capacity */
	RXRPC_CONN_CLIENT_ACTIVE,	/* Conn is on active list, doing calls */
	RXRPC_CONN_CLIENT_UPGRADE,	/* Conn is on active list, probing for upgrade */
	RXRPC_CONN_CLIENT_CULLED,	/* Conn is culled and delisted, doing calls */
	RXRPC_CONN_CLIENT_IDLE,		/* Conn is on idle list, doing mostly nothing */
	RXRPC_CONN__NR_CACHE_STATES
};

/*
 * The connection protocol state.
 */
enum rxrpc_conn_proto_state {
	RXRPC_CONN_UNUSED,		/* Connection not yet attempted */
	RXRPC_CONN_CLIENT,		/* Client connection */
	RXRPC_CONN_SERVICE_PREALLOC,	/* Service connection preallocation */
	RXRPC_CONN_SERVICE_UNSECURED,	/* Service unsecured connection */
	RXRPC_CONN_SERVICE_CHALLENGING,	/* Service challenging for security */
	RXRPC_CONN_SERVICE,		/* Service secured connection */
	RXRPC_CONN_REMOTELY_ABORTED,	/* Conn aborted by peer */
	RXRPC_CONN_LOCALLY_ABORTED,	/* Conn aborted locally */
	RXRPC_CONN__NR_STATES
};

/*
 * RxRPC connection definition
 * - matched by { local, peer, epoch, conn_id, direction }
 * - each connection can only handle four simultaneous calls
 */
struct rxrpc_connection {
	struct rxrpc_transport	*trans;		/* transport session */
	struct rxrpc_conn_bundle *bundle;	/* connection bundle (client) */
	struct work_struct	processor;	/* connection event processor */
	struct rb_node		node;		/* node in transport's lookup tree */
	struct list_head	link;		/* link in master connection list */
	struct list_head	bundle_link;	/* link in bundle */
	struct rb_root		calls;		/* calls on this connection */
	struct sk_buff_head	rx_queue;	/* received conn-level packets */
	struct rxrpc_call	*channels[RXRPC_MAXCALLS]; /* channels (active calls) */
	struct rxrpc_security	*security;	/* applied security module */
	struct key		*key;		/* security for this connection (client) */
	struct key		*server_key;	/* security for this service */
	struct crypto_blkcipher	*cipher;	/* encryption handle */
	struct rxrpc_crypt	csum_iv;	/* packet checksum base */
	unsigned long		events;
#define RXRPC_CONN_CHALLENGE	0		/* send challenge packet */
	time_t			put_time;	/* time at which to reap */
	unsigned long		put_time;	/* time at which to reap */
	rwlock_t		lock;		/* access lock */
	spinlock_t		state_lock;	/* state-change lock */
	atomic_t		usage;
	u32			real_conn_id;	/* connection ID (host-endian) */
	enum {					/* current state of connection */
		RXRPC_CONN_UNUSED,		/* - connection not yet attempted */
		RXRPC_CONN_CLIENT,		/* - client connection */
		RXRPC_CONN_SERVER_UNSECURED,	/* - server unsecured connection */
		RXRPC_CONN_SERVER_CHALLENGING,	/* - server challenging for security */
		RXRPC_CONN_SERVER,		/* - server secured connection */
		RXRPC_CONN_REMOTELY_ABORTED,	/* - conn aborted by peer */
		RXRPC_CONN_LOCALLY_ABORTED,	/* - conn aborted locally */
		RXRPC_CONN_NETWORK_ERROR,	/* - conn terminated by network error */
	} state;
	int			error;		/* error code for local abort */
	int			debug_id;	/* debug ID for printks */
	unsigned		call_counter;	/* call ID counter */
	unsigned int		call_counter;	/* call ID counter */
	atomic_t		serial;		/* packet serial number counter */
	atomic_t		hi_serial;	/* highest serial number received */
	u8			avail_calls;	/* number of calls available */
	u8			size_align;	/* data size alignment (for security) */
	u8			header_size;	/* rxrpc + security header size */
	u8			security_size;	/* security header size */
	u32			security_level;	/* security level negotiated */
	u32			security_nonce;	/* response re-use preventer */
	struct rxrpc_conn_proto	proto;
	struct rxrpc_conn_parameters params;

	atomic_t		usage;
	struct rcu_head		rcu;
	struct list_head	cache_link;

	spinlock_t		channel_lock;
	unsigned char		active_chans;	/* Mask of active channels */
#define RXRPC_ACTIVE_CHANS_MASK	((1 << RXRPC_MAXCALLS) - 1)
	struct list_head	waiting_calls;	/* Calls waiting for channels */
	struct rxrpc_channel {
		struct rxrpc_call __rcu	*call;		/* Active call */
		u32			call_id;	/* ID of current call */
		u32			call_counter;	/* Call ID counter */
		u32			last_call;	/* ID of last call */
		u8			last_type;	/* Type of last packet */
		union {
			u32		last_seq;
			u32		last_abort;
		};
	} channels[RXRPC_MAXCALLS];

	struct work_struct	processor;	/* connection event processor */
	union {
		struct rb_node	client_node;	/* Node in local->client_conns */
		struct rb_node	service_node;	/* Node in peer->service_conns */
	};
	struct list_head	proc_link;	/* link in procfs list */
	struct list_head	link;		/* link in master connection list */
	struct sk_buff_head	rx_queue;	/* received conn-level packets */
	const struct rxrpc_security *security;	/* applied security module */
	struct key		*server_key;	/* security for this service */
	struct crypto_skcipher	*cipher;	/* encryption handle */
	struct rxrpc_crypt	csum_iv;	/* packet checksum base */
	unsigned long		flags;
	unsigned long		events;
	unsigned long		idle_timestamp;	/* Time at which last became idle */
	spinlock_t		state_lock;	/* state-change lock */
	enum rxrpc_conn_cache_state cache_state;
	enum rxrpc_conn_proto_state state;	/* current state of connection */
	u32			local_abort;	/* local abort code */
	u32			remote_abort;	/* remote abort code */
	int			debug_id;	/* debug ID for printks */
	atomic_t		serial;		/* packet serial number counter */
	unsigned int		hi_serial;	/* highest serial number received */
	u32			security_nonce;	/* response re-use preventer */
	u16			service_id;	/* Service ID, possibly upgraded */
	u8			size_align;	/* data size alignment (for security) */
	u8			security_size;	/* security header size */
	u8			security_ix;	/* security type */
	u8			out_clientflag;	/* RXRPC_CLIENT_INITIATED if we are client */
};

/*
 * Flags in call->flags.
 */
enum rxrpc_call_flag {
	RXRPC_CALL_RELEASED,		/* call has been released - no more message to userspace */
	RXRPC_CALL_HAS_USERID,		/* has a user ID attached */
	RXRPC_CALL_IS_SERVICE,		/* Call is service call */
	RXRPC_CALL_EXPOSED,		/* The call was exposed to the world */
	RXRPC_CALL_RX_LAST,		/* Received the last packet (at rxtx_top) */
	RXRPC_CALL_TX_LAST,		/* Last packet in Tx buffer (at rxtx_top) */
	RXRPC_CALL_TX_LASTQ,		/* Last packet has been queued */
	RXRPC_CALL_SEND_PING,		/* A ping will need to be sent */
	RXRPC_CALL_PINGING,		/* Ping in process */
	RXRPC_CALL_RETRANS_TIMEOUT,	/* Retransmission due to timeout occurred */
};

/*
 * Events that can be raised on a call.
 */
enum rxrpc_call_event {
	RXRPC_CALL_EV_ACK,		/* need to generate ACK */
	RXRPC_CALL_EV_ABORT,		/* need to generate abort */
	RXRPC_CALL_EV_TIMER,		/* Timer expired */
	RXRPC_CALL_EV_RESEND,		/* Tx resend required */
	RXRPC_CALL_EV_PING,		/* Ping send required */
};

/*
 * The states that a call can be in.
 */
enum rxrpc_call_state {
	RXRPC_CALL_UNINITIALISED,
	RXRPC_CALL_CLIENT_AWAIT_CONN,	/* - client waiting for connection to become available */
	RXRPC_CALL_CLIENT_SEND_REQUEST,	/* - client sending request phase */
	RXRPC_CALL_CLIENT_AWAIT_REPLY,	/* - client awaiting reply */
	RXRPC_CALL_CLIENT_RECV_REPLY,	/* - client receiving reply phase */
	RXRPC_CALL_SERVER_PREALLOC,	/* - service preallocation */
	RXRPC_CALL_SERVER_SECURING,	/* - server securing request connection */
	RXRPC_CALL_SERVER_ACCEPTING,	/* - server accepting request */
	RXRPC_CALL_SERVER_RECV_REQUEST,	/* - server receiving request */
	RXRPC_CALL_SERVER_ACK_REQUEST,	/* - server pending ACK of request */
	RXRPC_CALL_SERVER_SEND_REPLY,	/* - server sending reply */
	RXRPC_CALL_SERVER_AWAIT_ACK,	/* - server awaiting final ACK */
	RXRPC_CALL_COMPLETE,		/* - call complete */
	NR__RXRPC_CALL_STATES
};

/*
 * Call Tx congestion management modes.
 */
enum rxrpc_congest_mode {
	RXRPC_CALL_SLOW_START,
	RXRPC_CALL_CONGEST_AVOIDANCE,
	RXRPC_CALL_PACKET_LOSS,
	RXRPC_CALL_FAST_RETRANSMIT,
	NR__RXRPC_CONGEST_MODES
};

/*
 * RxRPC call definition
 * - matched by { connection, call_id }
 */
struct rxrpc_call {
	struct rcu_head		rcu;
	struct rxrpc_connection	*conn;		/* connection carrying call */
	struct rxrpc_peer	*peer;		/* Peer record for remote address */
	struct rxrpc_sock __rcu	*socket;	/* socket responsible */
	struct mutex		user_mutex;	/* User access mutex */
	ktime_t			ack_at;		/* When deferred ACK needs to happen */
	ktime_t			resend_at;	/* When next resend needs to happen */
	ktime_t			ping_at;	/* When next to send a ping */
	ktime_t			expire_at;	/* When the call times out */
	struct timer_list	timer;		/* Combined event timer */
	struct work_struct	processor;	/* Event processor */
	rxrpc_notify_rx_t	notify_rx;	/* kernel service Rx notification function */
	struct list_head	link;		/* link in master call list */
	struct list_head	chan_wait_link;	/* Link in conn->waiting_calls */
	struct hlist_node	error_link;	/* link in error distribution list */
	struct list_head	accept_link;	/* Link in rx->acceptq */
	struct list_head	recvmsg_link;	/* Link in rx->recvmsg_q */
	struct list_head	sock_link;	/* Link in rx->sock_calls */
	struct rb_node		sock_node;	/* Node in rx->calls */
	struct sk_buff		*tx_pending;	/* Tx socket buffer being filled */
	wait_queue_head_t	waitq;		/* Wait queue for channel or Tx */
	s64			tx_total_len;	/* Total length left to be transmitted (or -1) */
	__be32			crypto_buf[2];	/* Temporary packet crypto buffer */
	unsigned long		user_call_ID;	/* user-defined call ID */
	unsigned long		flags;
	unsigned long		events;
	spinlock_t		lock;
	rwlock_t		state_lock;	/* lock for state transition */
	u32			abort_code;	/* Local/remote abort code */
	int			error;		/* Local error incurred */
	enum rxrpc_call_state	state;		/* current state of call */
	enum rxrpc_call_completion completion;	/* Call completion condition */
	atomic_t		usage;
	u16			service_id;	/* service ID */
	u8			security_ix;	/* Security type */
	u32			call_id;	/* call ID on connection  */
	u32			cid;		/* connection ID plus channel index */
	int			debug_id;	/* debug ID for printks */
	unsigned short		rx_pkt_offset;	/* Current recvmsg packet offset */
	unsigned short		rx_pkt_len;	/* Current recvmsg packet len */

	/* transmission-phase ACK management */
	uint8_t			acks_head;	/* offset into window of first entry */
	uint8_t			acks_tail;	/* offset into window of last entry */
	uint8_t			acks_winsz;	/* size of un-ACK'd window */
	uint8_t			acks_unacked;	/* lowest unacked packet in last ACK received */
	u8			acks_head;	/* offset into window of first entry */
	u8			acks_tail;	/* offset into window of last entry */
	u8			acks_winsz;	/* size of un-ACK'd window */
	u8			acks_unacked;	/* lowest unacked packet in last ACK received */
	int			acks_latest;	/* serial number of latest ACK received */
	rxrpc_seq_t		acks_hard;	/* highest definitively ACK'd msg seq */
	unsigned long		*acks_window;	/* sent packet window
						 * - elements are pointers with LSB set if ACK'd
	/* Rx/Tx circular buffer, depending on phase.
	 *
	 * In the Rx phase, packets are annotated with 0 or the number of the
	 * segment of a jumbo packet each buffer refers to.  There can be up to
	 * 47 segments in a maximum-size UDP packet.
	 *
	 * In the Tx phase, packets are annotated with which buffers have been
	 * acked.
	 */
#define RXRPC_RXTX_BUFF_SIZE	64
#define RXRPC_RXTX_BUFF_MASK	(RXRPC_RXTX_BUFF_SIZE - 1)
#define RXRPC_INIT_RX_WINDOW_SIZE 32
	struct sk_buff		**rxtx_buffer;
	u8			*rxtx_annotations;
#define RXRPC_TX_ANNO_ACK	0
#define RXRPC_TX_ANNO_UNACK	1
#define RXRPC_TX_ANNO_NAK	2
#define RXRPC_TX_ANNO_RETRANS	3
#define RXRPC_TX_ANNO_MASK	0x03
#define RXRPC_TX_ANNO_LAST	0x04
#define RXRPC_TX_ANNO_RESENT	0x08

#define RXRPC_RX_ANNO_JUMBO	0x3f		/* Jumbo subpacket number + 1 if not zero */
#define RXRPC_RX_ANNO_JLAST	0x40		/* Set if last element of a jumbo packet */
#define RXRPC_RX_ANNO_VERIFIED	0x80		/* Set if verified and decrypted */
	rxrpc_seq_t		tx_hard_ack;	/* Dead slot in buffer; the first transmitted but
						 * not hard-ACK'd packet follows this.
						 */
	rxrpc_seq_t		tx_top;		/* Highest Tx slot allocated. */

	/* TCP-style slow-start congestion control [RFC5681].  Since the SMSS
	 * is fixed, we keep these numbers in terms of segments (ie. DATA
	 * packets) rather than bytes.
	 */
#define RXRPC_TX_SMSS		RXRPC_JUMBO_DATALEN
	u8			cong_cwnd;	/* Congestion window size */
	u8			cong_extra;	/* Extra to send for congestion management */
	u8			cong_ssthresh;	/* Slow-start threshold */
	enum rxrpc_congest_mode	cong_mode:8;	/* Congestion management mode */
	u8			cong_dup_acks;	/* Count of ACKs showing missing packets */
	u8			cong_cumul_acks; /* Cumulative ACK count */
	ktime_t			cong_tstamp;	/* Last time cwnd was changed */

	rxrpc_seq_t		rx_hard_ack;	/* Dead slot in buffer; the first received but not
						 * consumed packet follows this.
						 */
	rxrpc_seq_t		rx_top;		/* Highest Rx slot allocated. */
	rxrpc_seq_t		rx_expect_next;	/* Expected next packet sequence number */
	u8			rx_winsize;	/* Size of Rx window */
	u8			tx_winsize;	/* Maximum size of Tx window */
	bool			tx_phase;	/* T if transmission phase, F if receive phase */
	u8			nr_jumbo_bad;	/* Number of jumbo dups/exceeds-windows */

	/* receive-phase ACK management */
	rxrpc_seq_t		rx_data_expect;	/* next data seq ID expected to be received */
	rxrpc_seq_t		rx_data_post;	/* next data seq ID expected to be posted */
	rxrpc_seq_t		rx_data_recv;	/* last data seq ID encountered by recvmsg */
	rxrpc_seq_t		rx_data_eaten;	/* last data seq ID consumed by recvmsg */
	rxrpc_seq_t		rx_first_oos;	/* first packet in rx_oos_queue (or 0) */
	rxrpc_seq_t		ackr_win_top;	/* top of ACK window (rx_data_eaten is bottom) */
	rxrpc_seq_net_t		ackr_prev_seq;	/* previous sequence number received */
	uint8_t			ackr_reason;	/* reason to ACK */
	u8			ackr_reason;	/* reason to ACK */
	u16			ackr_skew;	/* skew on packet being ACK'd */
	rxrpc_serial_t		ackr_serial;	/* serial of packet being ACK'd */
	rxrpc_seq_t		ackr_prev_seq;	/* previous sequence number received */
	rxrpc_seq_t		ackr_consumed;	/* Highest packet shown consumed */
	rxrpc_seq_t		ackr_seen;	/* Highest packet shown seen */

	/* ping management */
	rxrpc_serial_t		ping_serial;	/* Last ping sent */
	ktime_t			ping_time;	/* Time last ping sent */

	/* the following should all be in net order */
	__be32			cid;		/* connection ID + channel index  */
	__be32			call_id;	/* call ID on connection  */
};

/*
 * RxRPC key for Kerberos (type-2 security)
 */
struct rxkad_key {
	u16	security_index;		/* RxRPC header security index */
	u16	ticket_len;		/* length of ticket[] */
	u32	expiry;			/* time at which expires */
	u32	kvno;			/* key version number */
	u8	session_key[8];		/* DES session key */
	u8	ticket[0];		/* the encrypted ticket */
};

struct rxrpc_key_payload {
	struct rxkad_key k;
	struct hlist_node	hash_node;
	unsigned long		hash_key;	/* Full hash key */
	u8			in_clientflag;	/* Copy of conn->in_clientflag for hashing */
	struct rxrpc_local	*local;		/* Local endpoint. Used for hashing. */
	sa_family_t		proto;		/* Frame protocol */
	/* the following should all be in net order */
	__be32			cid;		/* connection ID + channel index  */
	__be32			call_id;	/* call ID on connection  */
	__be32			epoch;		/* epoch of this connection */
	__be16			service_id;	/* service ID */
	union {					/* Peer IP address for hashing */
		__be32	ipv4_addr;
		__u8	ipv6_addr[16];		/* Anticipates eventual IPv6 support */
	} peer_ip;
	/* transmission-phase ACK management */
	ktime_t			acks_latest_ts;	/* Timestamp of latest ACK received */
	rxrpc_serial_t		acks_latest;	/* serial number of latest ACK received */
	rxrpc_seq_t		acks_lowest_nak; /* Lowest NACK in the buffer (or ==tx_hard_ack) */
};

/*
 * Summary of a new ACK and the changes it made to the Tx buffer packet states.
 */
struct rxrpc_ack_summary {
	u8			ack_reason;
	u8			nr_acks;		/* Number of ACKs in packet */
	u8			nr_nacks;		/* Number of NACKs in packet */
	u8			nr_new_acks;		/* Number of new ACKs in packet */
	u8			nr_new_nacks;		/* Number of new NACKs in packet */
	u8			nr_rot_new_acks;	/* Number of rotated new ACKs */
	bool			new_low_nack;		/* T if new low NACK found */
	bool			retrans_timeo;		/* T if reTx due to timeout happened */
	u8			flight_size;		/* Number of unreceived transmissions */
	/* Place to stash values for tracing */
	enum rxrpc_congest_mode	mode:8;
	u8			cwnd;
	u8			ssthresh;
	u8			dup_acks;
	u8			cumulative_acks;
};

#include <trace/events/rxrpc.h>

/*
 * af_rxrpc.c
 */
extern atomic_t rxrpc_n_tx_skbs, rxrpc_n_rx_skbs;
extern atomic_t rxrpc_debug_id;
extern struct workqueue_struct *rxrpc_workqueue;

/*
 * call_accept.c
 */
extern void rxrpc_accept_incoming_calls(struct work_struct *);
extern struct rxrpc_call *rxrpc_accept_call(struct rxrpc_sock *,
					    unsigned long);
extern int rxrpc_reject_call(struct rxrpc_sock *);
void rxrpc_accept_incoming_calls(struct work_struct *);
struct rxrpc_call *rxrpc_accept_call(struct rxrpc_sock *, unsigned long);
int rxrpc_service_prealloc(struct rxrpc_sock *, gfp_t);
void rxrpc_discard_prealloc(struct rxrpc_sock *);
struct rxrpc_call *rxrpc_new_incoming_call(struct rxrpc_local *,
					   struct rxrpc_connection *,
					   struct sk_buff *);
void rxrpc_accept_incoming_calls(struct rxrpc_local *);
struct rxrpc_call *rxrpc_accept_call(struct rxrpc_sock *, unsigned long,
				     rxrpc_notify_rx_t);
int rxrpc_reject_call(struct rxrpc_sock *);

/*
 * call_event.c
 */
extern void __rxrpc_propose_ACK(struct rxrpc_call *, uint8_t, __be32, bool);
extern void rxrpc_propose_ACK(struct rxrpc_call *, uint8_t, __be32, bool);
extern void rxrpc_process_call(struct work_struct *);
extern unsigned rxrpc_requested_ack_delay;
extern unsigned rxrpc_soft_ack_delay;
extern unsigned rxrpc_idle_ack_delay;
extern unsigned rxrpc_rx_window_size;
extern unsigned rxrpc_rx_mtu;
extern unsigned rxrpc_rx_jumbo_max;

void __rxrpc_propose_ACK(struct rxrpc_call *, u8, __be32, bool);
void rxrpc_propose_ACK(struct rxrpc_call *, u8, __be32, bool);
void __rxrpc_set_timer(struct rxrpc_call *, enum rxrpc_timer_trace, ktime_t);
void rxrpc_set_timer(struct rxrpc_call *, enum rxrpc_timer_trace, ktime_t);
void rxrpc_propose_ACK(struct rxrpc_call *, u8, u16, u32, bool, bool,
		       enum rxrpc_propose_ack_trace);
void rxrpc_process_call(struct work_struct *);

/*
 * call_object.c
 */
extern const char *const rxrpc_call_states[];
extern const char *const rxrpc_call_completions[];
extern unsigned int rxrpc_max_call_lifetime;
extern struct kmem_cache *rxrpc_call_jar;

extern struct rxrpc_call *rxrpc_get_client_call(struct rxrpc_sock *,
						struct rxrpc_transport *,
						struct rxrpc_conn_bundle *,
						unsigned long, int, gfp_t);
extern struct rxrpc_call *rxrpc_incoming_call(struct rxrpc_sock *,
					      struct rxrpc_connection *,
					      struct rxrpc_header *, gfp_t);
extern struct rxrpc_call *rxrpc_find_server_call(struct rxrpc_sock *,
						 unsigned long);
extern void rxrpc_release_call(struct rxrpc_call *);
extern void rxrpc_release_calls_on_socket(struct rxrpc_sock *);
extern void __rxrpc_put_call(struct rxrpc_call *);
extern void __exit rxrpc_destroy_all_calls(void);
struct rxrpc_call *rxrpc_find_call_hash(u8,  __be32, __be32, __be32,
					__be16, void *, sa_family_t, const u8 *);
struct rxrpc_call *rxrpc_get_client_call(struct rxrpc_sock *,
					 struct rxrpc_transport *,
					 struct rxrpc_conn_bundle *,
					 unsigned long, int, gfp_t);
struct rxrpc_call *rxrpc_incoming_call(struct rxrpc_sock *,
				       struct rxrpc_connection *,
				       struct rxrpc_header *, gfp_t);
struct rxrpc_call *rxrpc_find_server_call(struct rxrpc_sock *, unsigned long);
void rxrpc_release_call(struct rxrpc_call *);
struct rxrpc_call *rxrpc_find_call_by_user_ID(struct rxrpc_sock *, unsigned long);
struct rxrpc_call *rxrpc_alloc_call(gfp_t);
struct rxrpc_call *rxrpc_new_client_call(struct rxrpc_sock *,
					 struct rxrpc_conn_parameters *,
					 struct sockaddr_rxrpc *,
					 unsigned long, s64, gfp_t);
int rxrpc_retry_client_call(struct rxrpc_sock *,
			    struct rxrpc_call *,
			    struct rxrpc_conn_parameters *,
			    struct sockaddr_rxrpc *,
			    gfp_t);
void rxrpc_incoming_call(struct rxrpc_sock *, struct rxrpc_call *,
			 struct sk_buff *);
void rxrpc_release_call(struct rxrpc_sock *, struct rxrpc_call *);
int rxrpc_prepare_call_for_retry(struct rxrpc_sock *, struct rxrpc_call *);
void rxrpc_release_calls_on_socket(struct rxrpc_sock *);
bool __rxrpc_queue_call(struct rxrpc_call *);
bool rxrpc_queue_call(struct rxrpc_call *);
void rxrpc_see_call(struct rxrpc_call *);
void rxrpc_get_call(struct rxrpc_call *, enum rxrpc_call_trace);
void rxrpc_put_call(struct rxrpc_call *, enum rxrpc_call_trace);
void rxrpc_cleanup_call(struct rxrpc_call *);
void rxrpc_destroy_all_calls(struct rxrpc_net *);

static inline bool rxrpc_is_service_call(const struct rxrpc_call *call)
{
	return test_bit(RXRPC_CALL_IS_SERVICE, &call->flags);
}

static inline bool rxrpc_is_client_call(const struct rxrpc_call *call)
{
	return !rxrpc_is_service_call(call);
}

/*
 * Transition a call to the complete state.
 */
extern struct list_head rxrpc_connections;
extern rwlock_t rxrpc_connection_lock;

extern struct rxrpc_conn_bundle *rxrpc_get_bundle(struct rxrpc_sock *,
						  struct rxrpc_transport *,
						  struct key *,
						  __be16, gfp_t);
extern void rxrpc_put_bundle(struct rxrpc_transport *,
			     struct rxrpc_conn_bundle *);
extern int rxrpc_connect_call(struct rxrpc_sock *, struct rxrpc_transport *,
			      struct rxrpc_conn_bundle *, struct rxrpc_call *,
			      gfp_t);
extern void rxrpc_put_connection(struct rxrpc_connection *);
extern void __exit rxrpc_destroy_all_connections(void);
extern struct rxrpc_connection *rxrpc_find_connection(struct rxrpc_transport *,
						      struct rxrpc_header *);
extern unsigned rxrpc_connection_expiry;
extern struct list_head rxrpc_connections;
extern rwlock_t rxrpc_connection_lock;
static inline bool __rxrpc_set_call_completion(struct rxrpc_call *call,
					       enum rxrpc_call_completion compl,
					       u32 abort_code,
					       int error)
{
	if (call->state < RXRPC_CALL_COMPLETE) {
		call->abort_code = abort_code;
		call->error = error;
		call->completion = compl,
		call->state = RXRPC_CALL_COMPLETE;
		wake_up(&call->waitq);
		return true;
	}
	return false;
}

static inline bool rxrpc_set_call_completion(struct rxrpc_call *call,
					     enum rxrpc_call_completion compl,
					     u32 abort_code,
					     int error)
{
	bool ret;

	write_lock_bh(&call->state_lock);
	ret = __rxrpc_set_call_completion(call, compl, abort_code, error);
	write_unlock_bh(&call->state_lock);
	return ret;
}

/*
 * Record that a call successfully completed.
 */
static inline bool __rxrpc_call_completed(struct rxrpc_call *call)
{
	return __rxrpc_set_call_completion(call, RXRPC_CALL_SUCCEEDED, 0, 0);
}

static inline bool rxrpc_call_completed(struct rxrpc_call *call)
{
	bool ret;

	write_lock_bh(&call->state_lock);
	ret = __rxrpc_call_completed(call);
	write_unlock_bh(&call->state_lock);
	return ret;
}

/*
 * Record that a call is locally aborted.
 */
static inline bool __rxrpc_abort_call(const char *why, struct rxrpc_call *call,
				      rxrpc_seq_t seq,
				      u32 abort_code, int error)
{
	trace_rxrpc_abort(why, call->cid, call->call_id, seq,
			  abort_code, error);
	return __rxrpc_set_call_completion(call, RXRPC_CALL_LOCALLY_ABORTED,
					   abort_code, error);
}

static inline bool rxrpc_abort_call(const char *why, struct rxrpc_call *call,
				    rxrpc_seq_t seq, u32 abort_code, int error)
{
	bool ret;

	write_lock_bh(&call->state_lock);
	ret = __rxrpc_abort_call(why, call, seq, abort_code, error);
	write_unlock_bh(&call->state_lock);
	return ret;
}

/*
 * Abort a call due to a protocol error.
 */
static inline bool __rxrpc_abort_eproto(struct rxrpc_call *call,
					struct sk_buff *skb,
					const char *eproto_why,
					const char *why,
					u32 abort_code)
{
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);

	trace_rxrpc_rx_eproto(call, sp->hdr.serial, eproto_why);
	return rxrpc_abort_call(why, call, sp->hdr.seq, abort_code, -EPROTO);
}

#define rxrpc_abort_eproto(call, skb, eproto_why, abort_why, abort_code) \
	__rxrpc_abort_eproto((call), (skb), tracepoint_string(eproto_why), \
			     (abort_why), (abort_code))

/*
 * conn_client.c
 */
extern unsigned int rxrpc_max_client_connections;
extern unsigned int rxrpc_reap_client_connections;
extern unsigned int rxrpc_conn_idle_client_expiry;
extern unsigned int rxrpc_conn_idle_client_fast_expiry;
extern struct idr rxrpc_client_conn_ids;

void rxrpc_destroy_client_conn_ids(void);
int rxrpc_connect_call(struct rxrpc_call *, struct rxrpc_conn_parameters *,
		       struct sockaddr_rxrpc *, gfp_t);
void rxrpc_expose_client_call(struct rxrpc_call *);
void rxrpc_disconnect_client_call(struct rxrpc_call *);
void rxrpc_put_client_conn(struct rxrpc_connection *);
void rxrpc_discard_expired_client_conns(struct work_struct *);
void rxrpc_destroy_all_client_connections(struct rxrpc_net *);

/*
 * conn_event.c
 */
extern void rxrpc_process_connection(struct work_struct *);
extern void rxrpc_reject_packet(struct rxrpc_local *, struct sk_buff *);
extern void rxrpc_reject_packets(struct work_struct *);
void rxrpc_process_connection(struct work_struct *);

/*
 * conn_object.c
 */
extern void rxrpc_UDP_error_report(struct sock *);
extern void rxrpc_UDP_error_handler(struct work_struct *);
void rxrpc_UDP_error_report(struct sock *);
void rxrpc_UDP_error_handler(struct work_struct *);
extern unsigned int rxrpc_connection_expiry;

struct rxrpc_connection *rxrpc_alloc_connection(gfp_t);
struct rxrpc_connection *rxrpc_find_connection_rcu(struct rxrpc_local *,
						   struct sk_buff *);
void __rxrpc_disconnect_call(struct rxrpc_connection *, struct rxrpc_call *);
void rxrpc_disconnect_call(struct rxrpc_call *);
void rxrpc_kill_connection(struct rxrpc_connection *);
bool rxrpc_queue_conn(struct rxrpc_connection *);
void rxrpc_see_connection(struct rxrpc_connection *);
void rxrpc_get_connection(struct rxrpc_connection *);
struct rxrpc_connection *rxrpc_get_connection_maybe(struct rxrpc_connection *);
void rxrpc_put_service_conn(struct rxrpc_connection *);
void rxrpc_service_connection_reaper(struct work_struct *);
void rxrpc_destroy_all_connections(struct rxrpc_net *);

static inline bool rxrpc_conn_is_client(const struct rxrpc_connection *conn)
{
	return conn->out_clientflag;
}

static inline bool rxrpc_conn_is_service(const struct rxrpc_connection *conn)
{
	return !rxrpc_conn_is_client(conn);
}

static inline void rxrpc_put_connection(struct rxrpc_connection *conn)
{
	if (!conn)
		return;

	if (rxrpc_conn_is_client(conn))
		rxrpc_put_client_conn(conn);
	else
		rxrpc_put_service_conn(conn);
}

/*
 * conn_service.c
 */
extern unsigned long rxrpc_ack_timeout;
extern const char *rxrpc_pkts[];

extern void rxrpc_data_ready(struct sock *, int);
extern int rxrpc_queue_rcv_skb(struct rxrpc_call *, struct sk_buff *, bool,
			       bool);
extern void rxrpc_fast_process_packet(struct rxrpc_call *, struct sk_buff *);
extern const char *rxrpc_pkts[];
struct rxrpc_connection *rxrpc_find_service_conn_rcu(struct rxrpc_peer *,
						     struct sk_buff *);
struct rxrpc_connection *rxrpc_prealloc_service_connection(struct rxrpc_net *, gfp_t);
void rxrpc_new_incoming_connection(struct rxrpc_sock *,
				   struct rxrpc_connection *, struct sk_buff *);
void rxrpc_unpublish_service_conn(struct rxrpc_connection *);

/*
 * input.c
 */
void rxrpc_data_ready(struct sock *);

/*
 * insecure.c
 */
extern rwlock_t rxrpc_local_lock;
extern struct rxrpc_local *rxrpc_lookup_local(struct sockaddr_rxrpc *);
extern void rxrpc_put_local(struct rxrpc_local *);
extern void __exit rxrpc_destroy_all_locals(void);

struct rxrpc_local *rxrpc_lookup_local(struct sockaddr_rxrpc *);
void rxrpc_put_local(struct rxrpc_local *);
void __exit rxrpc_destroy_all_locals(void);
extern const struct rxrpc_security rxrpc_no_security;

/*
 * key.c
 */
extern struct key_type key_type_rxrpc;
extern struct key_type key_type_rxrpc_s;

extern int rxrpc_request_key(struct rxrpc_sock *, char __user *, int);
extern int rxrpc_server_keyring(struct rxrpc_sock *, char __user *, int);
extern int rxrpc_get_server_data_key(struct rxrpc_connection *, const void *,
				     time_t, u32);
int rxrpc_request_key(struct rxrpc_sock *, char __user *, int);
int rxrpc_server_keyring(struct rxrpc_sock *, char __user *, int);
int rxrpc_get_server_data_key(struct rxrpc_connection *, const void *, time64_t,
			      u32);

/*
 * local_event.c
 */
extern int rxrpc_resend_timeout;

extern int rxrpc_send_packet(struct rxrpc_transport *, struct sk_buff *);
extern int rxrpc_client_sendmsg(struct kiocb *, struct rxrpc_sock *,
				struct rxrpc_transport *, struct msghdr *,
				size_t);
extern int rxrpc_server_sendmsg(struct kiocb *, struct rxrpc_sock *,
				struct msghdr *, size_t);
extern unsigned rxrpc_resend_timeout;

int rxrpc_send_packet(struct rxrpc_transport *, struct sk_buff *);
int rxrpc_client_sendmsg(struct rxrpc_sock *, struct rxrpc_transport *,
			 struct msghdr *, size_t);
int rxrpc_server_sendmsg(struct rxrpc_sock *, struct msghdr *, size_t);
extern void rxrpc_process_local_events(struct rxrpc_local *);

/*
 * local_object.c
 */
extern struct rxrpc_peer *rxrpc_get_peer(struct sockaddr_rxrpc *, gfp_t);
extern void rxrpc_put_peer(struct rxrpc_peer *);
extern struct rxrpc_peer *rxrpc_find_peer(struct rxrpc_local *,
					  __be32, __be16);
extern void __exit rxrpc_destroy_all_peers(void);
struct rxrpc_peer *rxrpc_get_peer(struct sockaddr_rxrpc *, gfp_t);
void rxrpc_put_peer(struct rxrpc_peer *);
struct rxrpc_peer *rxrpc_find_peer(struct rxrpc_local *, __be32, __be16);
void __exit rxrpc_destroy_all_peers(void);
struct rxrpc_local *rxrpc_lookup_local(struct net *, const struct sockaddr_rxrpc *);
void __rxrpc_put_local(struct rxrpc_local *);
void rxrpc_destroy_all_locals(struct rxrpc_net *);

static inline void rxrpc_get_local(struct rxrpc_local *local)
{
	atomic_inc(&local->usage);
}

static inline
struct rxrpc_local *rxrpc_get_local_maybe(struct rxrpc_local *local)
{
	return atomic_inc_not_zero(&local->usage) ? local : NULL;
}

static inline void rxrpc_put_local(struct rxrpc_local *local)
{
	if (local && atomic_dec_and_test(&local->usage))
		__rxrpc_put_local(local);
}

static inline void rxrpc_queue_local(struct rxrpc_local *local)
{
	rxrpc_queue_work(&local->processor);
}

/*
 * misc.c
 */
extern unsigned int rxrpc_max_backlog __read_mostly;
extern unsigned int rxrpc_requested_ack_delay;
extern unsigned int rxrpc_soft_ack_delay;
extern unsigned int rxrpc_idle_ack_delay;
extern unsigned int rxrpc_rx_window_size;
extern unsigned int rxrpc_rx_mtu;
extern unsigned int rxrpc_rx_jumbo_max;
extern unsigned int rxrpc_resend_timeout;

extern const s8 rxrpc_ack_priority[];

/*
 * net_ns.c
 */
extern unsigned int rxrpc_net_id;
extern struct pernet_operations rxrpc_net_ops;

static inline struct rxrpc_net *rxrpc_net(struct net *net)
{
	return net_generic(net, rxrpc_net_id);
}

/*
 * output.c
 */
int rxrpc_send_ack_packet(struct rxrpc_call *, bool);
int rxrpc_send_abort_packet(struct rxrpc_call *);
int rxrpc_send_data_packet(struct rxrpc_call *, struct sk_buff *, bool);
void rxrpc_reject_packets(struct rxrpc_local *);

/*
 * peer_event.c
 */
void rxrpc_error_report(struct sock *);
void rxrpc_peer_error_distributor(struct work_struct *);
void rxrpc_peer_add_rtt(struct rxrpc_call *, enum rxrpc_rtt_rx_trace,
			rxrpc_serial_t, rxrpc_serial_t, ktime_t, ktime_t);

/*
 * peer_object.c
 */
struct rxrpc_peer *rxrpc_lookup_peer_rcu(struct rxrpc_local *,
					 const struct sockaddr_rxrpc *);
struct rxrpc_peer *rxrpc_lookup_peer(struct rxrpc_local *,
				     struct sockaddr_rxrpc *, gfp_t);
struct rxrpc_peer *rxrpc_alloc_peer(struct rxrpc_local *, gfp_t);
struct rxrpc_peer *rxrpc_lookup_incoming_peer(struct rxrpc_local *,
					      struct rxrpc_peer *);

static inline struct rxrpc_peer *rxrpc_get_peer(struct rxrpc_peer *peer)
{
	atomic_inc(&peer->usage);
	return peer;
}

static inline
struct rxrpc_peer *rxrpc_get_peer_maybe(struct rxrpc_peer *peer)
{
	return atomic_inc_not_zero(&peer->usage) ? peer : NULL;
}

extern void __rxrpc_put_peer(struct rxrpc_peer *peer);
static inline void rxrpc_put_peer(struct rxrpc_peer *peer)
{
	if (peer && atomic_dec_and_test(&peer->usage))
		__rxrpc_put_peer(peer);
}

/*
 * proc.c
 */
extern const struct file_operations rxrpc_call_seq_fops;
extern const struct file_operations rxrpc_connection_seq_fops;

/*
 * recvmsg.c
 */
extern void rxrpc_remove_user_ID(struct rxrpc_sock *, struct rxrpc_call *);
extern int rxrpc_recvmsg(struct kiocb *, struct socket *, struct msghdr *,
			 size_t, int);
void rxrpc_remove_user_ID(struct rxrpc_sock *, struct rxrpc_call *);
void rxrpc_notify_socket(struct rxrpc_call *);
int rxrpc_recvmsg(struct socket *, struct msghdr *, size_t, int);

/*
 * rxkad.c
 */
extern int rxrpc_register_security(struct rxrpc_security *);
extern void rxrpc_unregister_security(struct rxrpc_security *);
extern int rxrpc_init_client_conn_security(struct rxrpc_connection *);
extern int rxrpc_init_server_conn_security(struct rxrpc_connection *);
extern int rxrpc_secure_packet(const struct rxrpc_call *, struct sk_buff *,
			       size_t, void *);
extern int rxrpc_verify_packet(const struct rxrpc_call *, struct sk_buff *,
			       u32 *);
extern void rxrpc_clear_conn_security(struct rxrpc_connection *);
int rxrpc_register_security(struct rxrpc_security *);
void rxrpc_unregister_security(struct rxrpc_security *);
#ifdef CONFIG_RXKAD
extern const struct rxrpc_security rxkad;
#endif

/*
 * security.c
 */
int __init rxrpc_init_security(void);
void rxrpc_exit_security(void);
int rxrpc_init_client_conn_security(struct rxrpc_connection *);
int rxrpc_init_server_conn_security(struct rxrpc_connection *);

/*
 * sendmsg.c
 */
extern void rxrpc_packet_destructor(struct sk_buff *);
void rxrpc_packet_destructor(struct sk_buff *);

/*
 * ar-transport.c
 */
extern struct rxrpc_transport *rxrpc_get_transport(struct rxrpc_local *,
						   struct rxrpc_peer *,
						   gfp_t);
extern void rxrpc_put_transport(struct rxrpc_transport *);
extern void __exit rxrpc_destroy_all_transports(void);
extern struct rxrpc_transport *rxrpc_find_transport(struct rxrpc_local *,
						    struct rxrpc_peer *);
extern unsigned rxrpc_transport_expiry;

struct rxrpc_transport *rxrpc_get_transport(struct rxrpc_local *,
					    struct rxrpc_peer *, gfp_t);
void rxrpc_put_transport(struct rxrpc_transport *);
void __exit rxrpc_destroy_all_transports(void);
struct rxrpc_transport *rxrpc_find_transport(struct rxrpc_local *,
					     struct rxrpc_peer *);
int rxrpc_do_sendmsg(struct rxrpc_sock *, struct msghdr *, size_t);

/*
 * skbuff.c
 */
void rxrpc_kernel_data_consumed(struct rxrpc_call *, struct sk_buff *);
void rxrpc_packet_destructor(struct sk_buff *);
void rxrpc_new_skb(struct sk_buff *, enum rxrpc_skb_trace);
void rxrpc_see_skb(struct sk_buff *, enum rxrpc_skb_trace);
void rxrpc_get_skb(struct sk_buff *, enum rxrpc_skb_trace);
void rxrpc_free_skb(struct sk_buff *, enum rxrpc_skb_trace);
void rxrpc_lose_skb(struct sk_buff *, enum rxrpc_skb_trace);
void rxrpc_purge_queue(struct sk_buff_head *);

/*
 * sysctl.c
 */
#ifdef CONFIG_SYSCTL
extern int __init rxrpc_sysctl_init(void);
extern void rxrpc_sysctl_exit(void);
#else
static inline int __init rxrpc_sysctl_init(void) { return 0; }
static inline void rxrpc_sysctl_exit(void) {}
#endif

/*
 * utils.c
 */
int rxrpc_extract_addr_from_skb(struct rxrpc_local *, struct sockaddr_rxrpc *,
				struct sk_buff *);

static inline bool before(u32 seq1, u32 seq2)
{
        return (s32)(seq1 - seq2) < 0;
}
static inline bool before_eq(u32 seq1, u32 seq2)
{
        return (s32)(seq1 - seq2) <= 0;
}
static inline bool after(u32 seq1, u32 seq2)
{
        return (s32)(seq1 - seq2) > 0;
}
static inline bool after_eq(u32 seq1, u32 seq2)
{
        return (s32)(seq1 - seq2) >= 0;
}

/*
 * debug tracing
 */
extern unsigned rxrpc_debug;
extern unsigned int rxrpc_debug;

#define dbgprintk(FMT,...) \
	printk("[%-6.6s] "FMT"\n", current->comm ,##__VA_ARGS__)

/* make sure we maintain the format strings, even when debugging is disabled */
static inline __attribute__((format(printf,1,2)))
void _dbprintk(const char *fmt, ...)
{
}

#define kenter(FMT,...)	dbgprintk("==> %s("FMT")",__func__ ,##__VA_ARGS__)
#define kleave(FMT,...)	dbgprintk("<== %s()"FMT"",__func__ ,##__VA_ARGS__)
#define kdebug(FMT,...)	dbgprintk("    "FMT ,##__VA_ARGS__)
#define kproto(FMT,...)	dbgprintk("### "FMT ,##__VA_ARGS__)
#define knet(FMT,...)	dbgprintk("@@@ "FMT ,##__VA_ARGS__)


#if defined(__KDEBUG)
#define _enter(FMT,...)	kenter(FMT,##__VA_ARGS__)
#define _leave(FMT,...)	kleave(FMT,##__VA_ARGS__)
#define _debug(FMT,...)	kdebug(FMT,##__VA_ARGS__)
#define _proto(FMT,...)	kproto(FMT,##__VA_ARGS__)
#define _net(FMT,...)	knet(FMT,##__VA_ARGS__)

#elif defined(CONFIG_AF_RXRPC_DEBUG)
#define RXRPC_DEBUG_KENTER	0x01
#define RXRPC_DEBUG_KLEAVE	0x02
#define RXRPC_DEBUG_KDEBUG	0x04
#define RXRPC_DEBUG_KPROTO	0x08
#define RXRPC_DEBUG_KNET	0x10

#define _enter(FMT,...)					\
do {							\
	if (unlikely(rxrpc_debug & RXRPC_DEBUG_KENTER))	\
		kenter(FMT,##__VA_ARGS__);		\
} while (0)

#define _leave(FMT,...)					\
do {							\
	if (unlikely(rxrpc_debug & RXRPC_DEBUG_KLEAVE))	\
		kleave(FMT,##__VA_ARGS__);		\
} while (0)

#define _debug(FMT,...)					\
do {							\
	if (unlikely(rxrpc_debug & RXRPC_DEBUG_KDEBUG))	\
		kdebug(FMT,##__VA_ARGS__);		\
} while (0)

#define _proto(FMT,...)					\
do {							\
	if (unlikely(rxrpc_debug & RXRPC_DEBUG_KPROTO))	\
		kproto(FMT,##__VA_ARGS__);		\
} while (0)

#define _net(FMT,...)					\
do {							\
	if (unlikely(rxrpc_debug & RXRPC_DEBUG_KNET))	\
		knet(FMT,##__VA_ARGS__);		\
} while (0)

#else
#define _enter(FMT,...)	_dbprintk("==> %s("FMT")",__func__ ,##__VA_ARGS__)
#define _leave(FMT,...)	_dbprintk("<== %s()"FMT"",__func__ ,##__VA_ARGS__)
#define _debug(FMT,...)	_dbprintk("    "FMT ,##__VA_ARGS__)
#define _proto(FMT,...)	_dbprintk("### "FMT ,##__VA_ARGS__)
#define _net(FMT,...)	_dbprintk("@@@ "FMT ,##__VA_ARGS__)
#define _enter(FMT,...)	no_printk("==> %s("FMT")",__func__ ,##__VA_ARGS__)
#define _leave(FMT,...)	no_printk("<== %s()"FMT"",__func__ ,##__VA_ARGS__)
#define _debug(FMT,...)	no_printk("    "FMT ,##__VA_ARGS__)
#define _proto(FMT,...)	no_printk("### "FMT ,##__VA_ARGS__)
#define _net(FMT,...)	no_printk("@@@ "FMT ,##__VA_ARGS__)
#endif

/*
 * debug assertion checking
 */
#if 1 // defined(__KDEBUGALL)

#define ASSERT(X)						\
do {								\
	if (unlikely(!(X))) {					\
		pr_err("Assertion failed\n");			\
		BUG();						\
	}							\
} while (0)

#define ASSERTCMP(X, OP, Y)						\
do {									\
	__typeof__(X) _x = (X);						\
	__typeof__(Y) _y = (__typeof__(X))(Y);				\
	if (unlikely(!(_x OP _y))) {					\
		pr_err("Assertion failed - %lu(0x%lx) %s %lu(0x%lx) is false\n", \
		       (unsigned long)_x, (unsigned long)_x, #OP,	\
		       (unsigned long)_y, (unsigned long)_y);		\
		BUG();							\
	}								\
} while (0)

#define ASSERTIF(C, X)						\
do {								\
	if (unlikely((C) && !(X))) {				\
		pr_err("Assertion failed\n");			\
		BUG();						\
	}							\
} while (0)

#define ASSERTIFCMP(C, X, OP, Y)					\
do {									\
	__typeof__(X) _x = (X);						\
	__typeof__(Y) _y = (__typeof__(X))(Y);				\
	if (unlikely((C) && !(_x OP _y))) {				\
		pr_err("Assertion failed - %lu(0x%lx) %s %lu(0x%lx) is false\n", \
		       (unsigned long)_x, (unsigned long)_x, #OP,	\
		       (unsigned long)_y, (unsigned long)_y);		\
		BUG();							\
	}								\
} while (0)

#else

#define ASSERT(X)				\
do {						\
} while (0)

#define ASSERTCMP(X, OP, Y)			\
do {						\
} while (0)

#define ASSERTIF(C, X)				\
do {						\
} while (0)

#define ASSERTIFCMP(C, X, OP, Y)		\
do {						\
} while (0)

#endif /* __KDEBUGALL */
