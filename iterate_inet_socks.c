#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list_nulls.h>
#include <net/inet_hashtables.h>
#include <net/sock.h>
#include <net/tcp.h>

struct inet_ctx {
	struct inet_hashinfo *hashinfo;
	bool (*filter)(struct sock *sk);
	void (*cb)(struct sock *sk);
};

static int iterate_listening_socks(struct inet_ctx *ctx)
{
	struct inet_listen_hashbucket *ilb;
	struct inet_hashinfo *hashinfo;
	struct sock *sk;
	unsigned int i;

	if (!ctx ) {
		printk(KERN_ERR "There is no ctx for iterate_established_tcp_socks\n");
		return -EINVAL;
	}

	hashinfo = ctx->hashinfo;

	/*
	* NOTE(anesterenko)
	* iterate all  buckets in tcp_hashinfo listensock table
	*/
	for (i = 0; i < INET_LHTABLE_SIZE; i++) {
		ilb = &hashinfo->listening_hash[i];
		sk = sk_head(&ilb->head);

		sk_for_each_from(sk) {
			if (ctx->filter(sk)) {
				ctx->cb(sk);
			}
		}
	}

	return 0;
}

static int iterate_established_socks(struct inet_ctx *ctx)
{
	struct inet_ehash_bucket *ehash;
	unsigned int ehash_mask;
	struct sock *sk;
	unsigned int i;

	if (!ctx ) {
		printk(KERN_ERR "There is no ctx for iterate_established_tcp_socks\n");
		return -EINVAL;
	}

	ehash = ctx->hashinfo->ehash;
	ehash_mask = ctx->hashinfo->ehash_mask;

	/*
	* NOTE(anesterenko)
	* iterate all  buckets in tcp_hashinfo ehash table
	*/
	for (i = 0; i < ehash_mask; i++) {
		struct hlist_nulls_node *node;
		if (hlist_nulls_empty(&ehash[i].chain))
			continue;

		sk_nulls_for_each(sk, node, &ehash[i].chain) {
			if (ctx->filter(sk)) {
				ctx->cb(sk);
			}
		}
	}

	return 0;
}

static int iterate_bound_socks(struct inet_ctx *ctx)
{
	struct inet_bind_hashbucket *bhash;
	struct inet_bind_bucket *tb = NULL;
	unsigned int bhash_size, i;
	struct sock *sk;

	if (!ctx ) {
		printk(KERN_ERR "There is no ctx for iterate_bound_socks\n");
		return -EINVAL;
	}

	bhash = ctx->hashinfo->bhash;
	bhash_size = ctx->hashinfo->bhash_size;

	for (i = 0; i < bhash_size; i++) {
		struct inet_bind_hashbucket *head = &bhash[i];

		inet_bind_bucket_for_each(tb, &head->chain) {
			if (!hlist_empty(&tb->owners)) {
				sk_for_each_bound(sk, &tb->owners) {
					if (ctx->filter(sk)) {
						ctx->cb(sk);
					}
				}
			}
		}
	}

	return 0;
}

static bool tcp_filter_wrapper(struct sock *sk)
{
	return true;
}

static void tcp_cb(struct sock *sk)
{
	printk(KERN_ERR "tcp sock [ %p ]\n", sk);
}

static int __init init_iterate(void)
{
	struct inet_ctx inet_walker[] = {
		{
			.hashinfo = &tcp_hashinfo,
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

static void __exit exit_iterate(void)
{
	printk(KERN_ERR "Goodbye!\n");
}

module_init(init_iterate);
module_exit(exit_iterate);
