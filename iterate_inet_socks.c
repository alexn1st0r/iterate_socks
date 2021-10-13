#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list_nulls.h>
#include <net/inet_hashtables.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/udplite.h>

struct inet_ctx {
	void *tableinfo;
	bool (*filter)(struct sock *sk);
	void (*cb)(struct sock *sk);
};

static bool tcp_filter_wrapper(struct sock *sk)
{
	return true;
}

static void tcp_cb(struct sock *sk)
{
	printk(KERN_ERR "tcp sock [ %px ]\n", sk);
}

static bool udp_filter(struct sock *sk)
{
	return 	sk->sk_protocol == IPPROTO_UDP ||
		sk->sk_protocol == IPPROTO_UDPLITE;
}

static void udp_cb(struct sock *sk)
{
	printk(KERN_ERR "udp sock [ %px ]\n", sk);
}

static int iterate_listening_socks(struct inet_ctx *ctx)
{
	struct inet_listen_hashbucket *ilb;
	struct inet_hashinfo *hashinfo;
	struct sock *sk;
	unsigned int bucket;

	if (!ctx ) {
		printk(KERN_ERR "There is no ctx for iterate_established_tcp_socks\n");
		return -EINVAL;
	}

	hashinfo = (struct inet_hashinfo *)ctx->tableinfo;

	/*
	* NOTE(anesterenko)
	* iterate all  buckets in tcp_hashinfo listensock table
	*/
	for (bucket = 0; bucket < INET_LHTABLE_SIZE; bucket++) {
		ilb = &hashinfo->listening_hash[bucket];

		spin_lock(&ilb->lock);
		sk = sk_head(&ilb->head);

		sk_for_each_from(sk) {
			if (ctx->filter(sk)) {
				ctx->cb(sk);
			}
		}
		spin_unlock(&ilb->lock);
	}

	return 0;
}

static int iterate_established_socks(struct inet_ctx *ctx)
{
	struct inet_ehash_bucket *ehash;
	unsigned int ehash_mask;
	struct sock *sk;
	unsigned int bucket;

	if (!ctx ) {
		printk(KERN_ERR "There is no ctx for iterate_established_tcp_socks\n");
		return -EINVAL;
	}

	ehash = ((struct inet_hashinfo *)ctx->tableinfo)->ehash;
	ehash_mask = ((struct inet_hashinfo *)ctx->tableinfo)->ehash_mask;

	/*
	* NOTE(anesterenko)
	* iterate all  buckets in tcp_hashinfo ehash table
	*/
	for (bucket = 0; bucket < ehash_mask; bucket++) {
		struct hlist_nulls_node *node;
		spinlock_t *lock = inet_ehash_lockp((struct inet_hashinfo *)ctx->tableinfo, bucket);

		spin_lock_bh(lock);
		if (hlist_nulls_empty(&ehash[bucket].chain)) {
			spin_unlock_bh(lock);
			continue;
		}

		sk_nulls_for_each(sk, node, &ehash[bucket].chain) {
			if (ctx->filter(sk)) {
				ctx->cb(sk);
			}
		}
		spin_unlock_bh(lock);
	}

	return 0;
}

static int iterate_bound_socks(struct inet_ctx *ctx)
{
	struct inet_bind_hashbucket *bhash;
	struct inet_bind_bucket *tb = NULL;
	unsigned int bhash_size, bucket;
	struct sock *sk;

	if (!ctx ) {
		printk(KERN_ERR "There is no ctx for iterate_bound_socks\n");
		return -EINVAL;
	}

	bhash = ((struct inet_hashinfo *)ctx->tableinfo)->bhash;
	bhash_size = ((struct inet_hashinfo *)ctx->tableinfo)->bhash_size;

	for (bucket = 0; bucket < bhash_size; bucket++) {
		struct inet_bind_hashbucket *head = &bhash[bucket];

		spin_lock_bh(&head->lock);
		inet_bind_bucket_for_each(tb, &head->chain) {
			if (!hlist_empty(&tb->owners)) {
				sk_for_each_bound(sk, &tb->owners) {
					if (ctx->filter(sk)) {
						ctx->cb(sk);
					}
				}
			}
		}
		spin_unlock_bh(&head->lock);
	}

	return 0;
}

static int iterate_udp(struct inet_ctx *ctx)
{
	struct udp_table *udptable;
	struct sock	 *sk;
	unsigned int 	  bucket;

	if (!ctx) {
		printk(KERN_ERR "There is no ctx for iterate_udp_socks\n");
		return -EINVAL;
	}

	udptable = (struct udp_table *)ctx->tableinfo;

	for (bucket = 0; bucket <= udptable->mask; bucket++) {
		struct udp_hslot *hslot = &udptable->hash[bucket];

		spin_lock_bh(&hslot->lock);
		if (hlist_empty(&hslot->head)) {
			spin_unlock_bh(&hslot->lock);
			continue;
		}

		sk_for_each(sk, &hslot->head) {
			if (ctx->filter(sk)) {
				ctx->cb(sk);
			}
		}
		spin_unlock_bh(&hslot->lock);
	}

	return 0;
}

static int iterate_tcp_socks(void)
{
	struct inet_ctx inet_walker[] = {
		{
			.tableinfo = &tcp_hashinfo,
			.filter = tcp_filter_wrapper,
			.cb = tcp_cb
		}
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(inet_walker); i++) {
		iterate_listening_socks(&inet_walker[i]);
		iterate_established_socks(&inet_walker[i]);
		iterate_bound_socks(&inet_walker[i]);
	}

	return 0;
}

static int iterate_udp_socks(void)
{
	struct inet_ctx inet_walker[] = {
		{
			.tableinfo = &udp_table,
			.filter = udp_filter,
			.cb = udp_cb
		},
		{
			.tableinfo = &udplite_table,
			.filter = udp_filter,
			.cb = udp_cb
		}
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(inet_walker); i++) {
		iterate_udp(&inet_walker[i]);
	}

	return 0;
}

static int __init init_iterate(void)
{
	int result;

	result = iterate_tcp_socks();
	if (result)
		return result;

	result = iterate_udp_socks();

	return result;
}

static void __exit exit_iterate(void)
{
	printk(KERN_ERR "Goodbye!\n");
}

module_init(init_iterate);
module_exit(exit_iterate);
