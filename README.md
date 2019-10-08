# TCP && UDP sockets iterator
This lkm walk throw the tcp_hashinfo and udp_table
## TCP
In linux kernel there is tcp_hashinfo hash table where all tcp socks are saved.
net/ipv4/tcp_ipv4.c
``` c
   struct inet_hashinfo tcp_hashinfo;
   EXPORT_SYMBOL(tcp_hashinfo);
```
It is struct inet_hashinfo that contain all what we realy need for our dirty hackers things!
./include/net/inet_hashtables.h
```c
 /* This is for listening sockets, thus all sockets which possess wildcards. */
 #define INET_LHTABLE_SIZE       32      /* Yes, really, this is all you need. */
 
 struct inet_hashinfo {
         /* This is for sockets with full identity only.  Sockets here will
          * always be without wildcards and will have the following invariant:
          *
          *          TCP_ESTABLISHED <= sk->sk_state < TCP_CLOSE
          *
          */
         struct inet_ehash_bucket        *ehash;
         spinlock_t                      *ehash_locks;
         unsigned int                    ehash_mask;
         unsigned int                    ehash_locks_mask;
 
         /* Ok, let's try this, I give up, we do need a local binding
          * TCP hash as well as the others for fast bind/connect.
          */
         struct inet_bind_hashbucket     *bhash;
 
         unsigned int                    bhash_size;
         /* 4 bytes hole on 64 bit */
 
         struct kmem_cache               *bind_bucket_cachep;
 
         /* All the above members are written once at bootup and
          * never written again _or_ are predominantly read-access.
          *
          * Now align to a new cache line as all the following members
          * might be often dirty.
          */
         /* All sockets in TCP_LISTEN state will be in here.  This is the only
          * table where wildcard'd TCP sockets can exist.  Hash function here
          * is just local port number.
          */
         struct inet_listen_hashbucket   listening_hash[INET_LHTABLE_SIZE]
                                         ____cacheline_aligned_in_smp;
};
```

### TCP listen sockets
firstly we have listening hash table is listening hash which type is
./include/net/inet_hashtables.h
```c
/*
 * Sockets can be hashed in established or listening table
 */
struct inet_listen_hashbucket {
     spinlock_t              lock;
     struct hlist_head       head;
};
```
This is the most small hash table of tcp_hashinfo and each bucket is described by it.

### TCP established sockets
there is another one table is ehash with bucket descriptor:
./include/net/inet_hashtables.h
```c
/* This is for all connections with a full identity, no wildcards.
 * The 'e' prefix stands for Establish, but we really put all sockets
 * but LISTEN ones.
 */
struct inet_ehash_bucket {
        struct hlist_nulls_head chain;
};
```
but established socket table is dynamically created table and size of it is ehash_mask.
There are 2 types of locks here: for ehash and ehash locks changing.

### TCP bound sockets
Bound sockets could be iterated by bhash with bucket descriptor:
./include/net/inet_hashtables.h
```c
struct inet_bind_hashbucket {
        spinlock_t              lock;
        struct hlist_head       chain;
};
```
And bound socket table is dynamically created table too and size of it is bhash_size.

## UDP
For udp iterating we have udp_table
./net/ipv4/udp.c
```c
 struct udp_table udp_table __read_mostly;
 EXPORT_SYMBOL(udp_table);
 ```
 that contain 2 dynamically hash table
 ./include/net/udp.h
 ```c
/**
 *      struct udp_table - UDP table
 *
 *      @hash:  hash table, sockets are hashed on (local port)
 *      @hash2: hash table, sockets are hashed on (local port, local address)
 *      @mask:  number of slots in hash tables, minus 1
 *      @log:   log2(number of slots in hash table)
 */
 struct udp_table {
         struct udp_hslot        *hash;
         struct udp_hslot        *hash2;
         unsigned int            mask;
         unsigned int            log;
 };
 ```
with bucket like 
./include/net/udp.h
```c
 /**
 *      struct udp_hslot - UDP hash slot
 *
 *      @head:  head of list of sockets
 *      @count: number of sockets in 'head' list
 *      @lock:  spinlock protecting changes to head/count
 */
struct udp_hslot {
        struct hlist_head       head;
        int                     count;
        spinlock_t              lock;
} __attribute__((aligned(2 * sizeof(long))));
```