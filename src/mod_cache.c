/*

Copyright (c) 2006, 2009 QUE Hongyu

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.

*/

/* mod_cache ideas:
 * idea based on squid, store cache to disk file instead of memory
 * can't cooperate with mod_deflate
 *
 * options:
 * 1) cache.bases
 * 2) cache.refresh-pattern
 * 3) cache.support-queries
 * 4) cache.enable
 * 5) cache.debug
 * 6) cache.domains
 * 7) cache.purge-host
 * 8) cache.ignore-hostname
 * 9) cache.dynamic-mode
 * 10) cache.programs-ext
 * 11) cache.support-accept-encoding
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <assert.h>
#include <stdio.h>

#if defined(HAVE_PCRE_H)
#include <pcre.h>
#endif

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "inet_ntop_cache.h"
#include "stat_cache.h"
#include "status_counter.h"
#include "joblist.h"
#include "response.h"

#include "plugin.h"

#include "version.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef UIO_MAXIOV
# ifdef __FreeBSD__
/* FreeBSD 4.7, 4.9 defined it in sys/uio.h only if _KERNEL is specified */
#  define UIO_MAXIOV 1024
# endif
#endif

#define CONFIG_CACHE_ENABLE "cache.enable"
#define CONFIG_CACHE_SUPPORT_QUERIES "cache.support-queries"
#define CONFIG_CACHE_BASES "cache.bases"
#define CONFIG_CACHE_REFRESH_PATTERN "cache.refresh-pattern"
#define CONFIG_CACHE_DEBUG "cache.debug"
#define CONFIG_CACHE_DOMAINS "cache.domains"
#define CONFIG_CACHE_PURGE_HOST "cache.purge-host"
#define CONFIG_CACHE_IGNORE_HOSTNAME "cache.ignore-hostname"
#define CONFIG_CACHE_DYNAMIC_MODE "cache.dynamic-mode"
#define CONFIG_CACHE_PROGRAMS_EXT "cache.programs-ext"
#define CONFIG_CACHE_SUPPORT_ACCEPT_ENCODING "cache.support-accept-encoding"
#define CONFIG_CACHE_MAX_MEMORY_SIZE "cache.max-memory-size"

#ifndef HAVE_PCRE_H
#error hmm, please install pcre-devel package
#endif

#ifndef LIGHTTPD_V14
/* splaytree definitions */
typedef struct tree_node
{
	struct tree_node * left, * right;
	int key;
	int size;   /* maintained to be the number of nodes rooted here */
	void *data;
} splay_tree;

splay_tree * splaytree_splay (splay_tree *t, int key);
splay_tree * splaytree_insert(splay_tree *t, int key, void *data);
splay_tree * splaytree_delete(splay_tree *t, int key);
splay_tree * splaytree_size(splay_tree *t);

#define splaytree_size(x) (((x)==NULL) ? 0 : ((x)->size))
/* This macro returns the size of a node.  Unlike "x->size", */
/* it works even if x=NULL.  The test could be avoided by using  */
/* a special version of NULL which was a real node with size 0.  */

/* splaytree definitions ends herer */
#endif

typedef struct
{
	pcre *regex;
	int type;
	time_t expires; /* in seconds */
} refresh_pattern;

typedef struct
{
	array *cache_bases;

	/* cache.domains regex array */
	pcre **domains_regex;
	/* cache.purgehost regex */
	pcre *purgehost_regex;
	/* cache.domain */
	array *domains;
	size_t domains_size;

	/* cache.refresh-pattern */
	refresh_pattern *rp;
	size_t rp_size;
	array *rp_buffer;

	/* purge host */
	buffer *purgehost;

	unsigned short support_queries;
	unsigned short enable;
	unsigned short debug;
	unsigned short ignore_hostname; /* default to disable */
	unsigned short support_accept_encoding;

	unsigned short dynamic_mode;
	array *programs_ext;

	uint32_t max_memory_size;
} plugin_config;

/* use in refresh_pattern_type */
#define CACHE_IGNORE_RELOAD BV(0)
#define CACHE_UPDATE_ON_REFRESH BV(1)
#define CACHE_FETCHALL_FOR_RANGE_REQUEST BV(2)
#define CACHE_NOCACHE BV(3)
#define CACHE_NO_EXPIRE_HEADER BV(4)
#define CACHE_OVERRIDE_EXPIRE BV(5)
#define CACHE_IGNORE_CACHE_CONTROL_HEADER BV(6)
#define CACHE_FLV_STREAMING BV(7)
#define CACHE_USE_MEMORY BV(8)

#define ASISEXT	".cachehd"

struct memory_cache
{
	int inuse;
	buffer *memoryid;
	array *headers;

	char expires[sizeof("Sat, 23 Jul 2005 21:20:01 GMT")+2];
	char max_age[20];
	time_t expires_time;

	buffer *content;

	struct memory_cache *next;
};

struct lru_info
{
	unsigned int prev, next;
};

static splay_tree **memory_store = NULL, *range_request = NULL, *cache_save = NULL;
static struct lru_info *memory_lru = NULL;
static int lrustart = 0, lruend = 0;

#define MEMCACHE_NUMBER 65536 /* 2^16 */
#define MEMCACHE_MASK (MEMCACHE_NUMBER-1)

/* variables for status report */
static int local_cache_number = 0, memory_cache_number = 0;
static uint32_t used_memory_size, reqhit, reqcount;

typedef struct {
	PLUGIN_DATA;
	plugin_config **config_storage;
	plugin_config conf;

	buffer *tmpfile;
} plugin_data;

typedef struct
{
	buffer *file;
	buffer *tmpfile;
	buffer *gzipfile;

	buffer *memoryid;
	buffer *savecontent;

	int fd; /* cache file fd */
	unsigned short error;
	unsigned short content_encoding_type; /* 1 -> gzip, 2 -> deflate */
	unsigned short accepted_encoding_type; /* 1 -> gzip, 2 -> deflate, 3 -> both */

	unsigned int is_query:1;
	unsigned int flv_streaming:1;
	/* local cache file meet */
	unsigned int local_hit:1;
	/* add expire header or not */
	unsigned int no_expire_header:1;
	/* override response's expire header */
	unsigned int override_expire:1;
	/* ignore cache-control response header */
	unsigned int ignore_cache_control_header:1;
	/* in range request mode */
	unsigned int range_request:1;
	/* flag of remove cache_save splaytree */
	unsigned int remove_cache_save:1;
	/* flag of whether to put into memory */
	unsigned int use_memory:1;

	/* response's LM timestamp */
	time_t mtime;
	/* local cache file's LM timestamp */
	time_t file_mtime;
	/* cache file's expires timestamp */
	time_t expires;
	/* cache file's expire timeout */
	int timeout;

	uint32_t hash;
	off_t offset;
} handler_ctx;

#ifndef LIGHTTPD_V14
/* splaytree implementation */
/*
	An implementation of top-down splaying with sizes
		D. Sleator <sleator@cs.cmu.edu>, January 1994.

  This extends top-down-splay.c to maintain a size field in each node.
  This is the number of nodes in the subtree rooted there.  This makes
  it possible to efficiently compute the rank of a key.  (The rank is
  the number of nodes to the left of the given key.)  It it also
  possible to quickly find the node of a given rank.  Both of these
  operations are illustrated in the code below.  The remainder of this
  introduction is taken from top-down-splay.c.

  "Splay trees", or "self-adjusting search trees" are a simple and
  efficient data structure for storing an ordered set.  The data
  structure consists of a binary tree, with no additional fields.  It
  allows searching, insertion, deletion, deletemin, deletemax,
  splitting, joining, and many other operations, all with amortized
  logarithmic performance.  Since the trees adapt to the sequence of
  requests, their performance on real access patterns is typically even
  better.  Splay trees are described in a number of texts and papers
  [1,2,3,4].

  The code here is adapted from simple top-down splay, at the bottom of
  page 669 of [2].  It can be obtained via anonymous ftp from
  spade.pc.cs.cmu.edu in directory /usr/sleator/public.

  The chief modification here is that the splay operation works even if the
  item being splayed is not in the tree, and even if the tree root of the
  tree is NULL.  So the line:

	t = splay(i, t);

  causes it to search for item with key i in the tree rooted at t.  If it's
  there, it is splayed to the root.  If it isn't there, then the node put
  at the root is the last one before NULL that would have been reached in a
  normal binary search for i.  (It's a neighbor of i in the tree.)  This
  allows many other operations to be easily implemented, as shown below.

  [1] "Data Structures and Their Algorithms", Lewis and Denenberg,
  	Harper Collins, 1991, pp 243-251.
  [2] "Self-adjusting Binary Search Trees" Sleator and Tarjan,
  	JACM Volume 32, No 3, July 1985, pp 652-686.
  [3] "Data Structure and Algorithm Analysis", Mark Weiss,
  	Benjamin Cummins, 1992, pp 119-130.
  [4] "Data Structures, Algorithms, and Performance", Derick Wood,
  	Addison-Wesley, 1993, pp 367-375
*/

#define splaytree_size(x) (((x)==NULL) ? 0 : ((x)->size))
/* This macro returns the size of a node.  Unlike "x->size", */
/* it works even if x=NULL.  The test could be avoided by using  */
/* a special version of NULL which was a real node with size 0.  */

#define node_size splaytree_size

/* Splay using the key i (which may or may not be in the tree.)
 * The starting root is t, and the tree used is defined by rat
 * size fields are maintained
 */
static splay_tree *
splaytree_splay (splay_tree *t, int i)
{
	splay_tree N, *l, *r, *y;
	int root_size, l_size, r_size;

	if (t == NULL) return t;
	N.left = N.right = NULL;
	l = r = &N;
	root_size = node_size(t);
	l_size = r_size = 0;

	while(1) {
		if (i < t->key) {
			if (t->left == NULL) break;
			if (i < t->left->key) {
				y = t->left; /* rotate right */
				t->left = y->right;
				y->right = t;
				t->size = node_size(t->left) + node_size(t->right) + 1;
				t = y;
				if (t->left == NULL) break;
			}
			r->left = t; /* link right */
			r = t;
			t = t->left;
			r_size += 1+node_size(r->right);
		} else if (i > t->key) {
			if (t->right == NULL) break;
			if (i > t->right->key) {
				y = t->right; /* rotate left */
				t->right = y->left;
				y->left = t;
				t->size = node_size(t->left) + node_size(t->right) + 1;
				t = y;
				if (t->right == NULL) break;
			}
			l->right = t; /* link left */
			l = t;
			t = t->right;
			l_size += 1+node_size(l->left);
		} else {
			break;
		}
	}
	l_size += node_size(t->left);  /* Now l_size and r_size are the sizes of */
	r_size += node_size(t->right); /* the left and right trees we just built.*/
	t->size = l_size + r_size + 1;

	l->right = r->left = NULL;

	/*
	 * The following two loops correct the size fields of the right path
	 * from the left child of the root and the right path from the left
	 * child of the root.
	 */
	for (y = N.right; y != NULL; y = y->right) {
		y->size = l_size;
		l_size -= 1+node_size(y->left);
	}
	for (y = N.left; y != NULL; y = y->left) {
		y->size = r_size;
		r_size -= 1+node_size(y->right);
	}

	l->right = t->left; /* assemble */
	r->left = t->right;
	t->left = N.right;
	t->right = N.left;

	return t;
}

static splay_tree *
splaytree_insert(splay_tree * t, int i, void *data)
{
	/*
	 * Insert key i into the tree t, if it is not already there.
	 * Return a pointer to the resulting tree.
	 */
	splay_tree * new;

	if (t != NULL) {
		t = splaytree_splay(t, i);
		if (i == t->key) {
			return t; /* it's already there */
		}
	}
	new = (splay_tree *) malloc (sizeof (splay_tree));
	if (new == NULL) /* not enough memory */
		return t;
	if (t == NULL) {
		new->left = new->right = NULL;
	} else if (i < t->key) {
		new->left = t->left;
		new->right = t;
		t->left = NULL;
		t->size = 1+node_size(t->right);
	} else {
		new->right = t->right;
		new->left = t;
		t->right = NULL;
		t->size = 1+node_size(t->left);
	}
	new->key = i;
	new->data = data;
	new->size = 1 + node_size(new->left) + node_size(new->right);
	return new;
}

static splay_tree *
splaytree_delete(splay_tree *t, int i)
{
	/*
	 * Deletes i from the tree if it's there.
	 * Return a pointer to the resulting tree.
	 */
	splay_tree * x;
	int tsize;

	if (t == NULL) return NULL;
	tsize = t->size;
	t = splaytree_splay(t, i);
	if (i == t->key) {/* found it */
		if (t->left == NULL) {
			x = t->right;
		} else {
			x = splaytree_splay(t->left, i);
			x->right = t->right;
		}
		free(t);
		if (x != NULL) {
			x->size = tsize-1;
		}
		return x;
	} else {
		return t; /* It wasn't there */
	}
}

/* splaytree implementation ends here */
#endif

static handler_ctx *
handler_ctx_init(void)
{
	handler_ctx *hctx;

	hctx = calloc(1, sizeof(*hctx));
	assert(hctx);
	memset(hctx, 0, sizeof(*hctx));
	hctx->file = buffer_init();
	hctx->tmpfile = buffer_init();
	hctx->gzipfile = buffer_init();
	hctx->memoryid = buffer_init();
	return hctx;
}

static void 
handler_ctx_free(handler_ctx *hctx)
{
	if (hctx) {
		buffer_free(hctx->file);
		buffer_free(hctx->tmpfile);
		buffer_free(hctx->gzipfile);
		buffer_free(hctx->memoryid);
		buffer_free(hctx->savecontent);
		if (hctx->fd > 0) close(hctx->fd);
		free(hctx);
	}
}

/* free cache_entry */
static void
memory_cache_free(struct memory_cache *cache)
{
	if (cache == NULL) return;
	if (cache->headers || cache->memoryid) {
		local_cache_number --;
		if (local_cache_number < 0) local_cache_number = 0;
	}
	array_free(cache->headers);
	buffer_free(cache->memoryid);
	if (cache->content) {
		if (used_memory_size <= cache->content->size)
			used_memory_size = 0;
		else
			used_memory_size -= cache->content->size;
		cache->content->ref_count --; // remove share buffer flag
		buffer_free(cache->content);
		if (cache->inuse && memory_cache_number > 0)
			memory_cache_number --;
	}
	free(cache);
}

void
free_memory_cache_chain(struct memory_cache *p)
{
	struct memory_cache *c1, *c2;

	c1 = p;
	while(c1) {
		c2 = c1->next;
		memory_cache_free(c1);
		c1 = c2;
	}

}

#define CACHE_LOCAL_ITEMS "cache.local-cached-items"
#define CACHE_MEMORY_ITEMS "cache.memory-cached-items"
#define CACHE_MEMORY "cache.used-memory-size(MB)"
#define CACHE_HIT_PERCENT "cache.hitrate(%)"

#ifndef LIGHTTPD_V14
data_integer *cache_memory;
data_integer *cache_memory_items;
data_integer *cache_items;
data_integer *cache_hit_percent;
#endif


/* init the plugin data */
INIT_FUNC(mod_cache_init)
{
	plugin_data *p;
	
#ifndef LIGHTTPD_V14
	cache_items = status_counter_get_counter(CONST_STR_LEN(CACHE_LOCAL_ITEMS));
	cache_memory = status_counter_get_counter(CONST_STR_LEN(CACHE_MEMORY));
	cache_memory_items = status_counter_get_counter(CONST_STR_LEN(CACHE_MEMORY_ITEMS));
	cache_hit_percent = status_counter_get_counter(CONST_STR_LEN(CACHE_HIT_PERCENT));	
#endif
	memory_store = (splay_tree **) calloc(MEMCACHE_NUMBER+1, sizeof(splay_tree *));
	memory_lru = (struct lru_info *)calloc(MEMCACHE_NUMBER+1, sizeof(struct lru_info));
	if (memory_store == NULL || memory_lru == NULL) return NULL;
	p = calloc(1, sizeof(*p));
	p->tmpfile = buffer_init();
	reqcount = reqhit = local_cache_number = used_memory_size = memory_cache_number = 0;
	range_request = cache_save = NULL;
	srand(getpid());

	return p;
}

/* detroy the plugin data */
FREE_FUNC(mod_cache_free)
{
	plugin_data *p = p_d;
	size_t i, j;
	
	if (!p) return HANDLER_GO_ON;
	
	if (p->config_storage) {

		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (!s) continue;
			array_free(s->cache_bases);
			array_free(s->rp_buffer);
			if (s->rp) {
				for (j = 0; j < s->rp_size; j ++)
					if (s->rp[j].regex) pcre_free(s->rp[j].regex);
				free(s->rp);
			}
			if (s->domains_regex) {
				for (j = 0; j < s->domains_size; j++) pcre_free(s->domains_regex[j]);
				free(s->domains_regex);
			}
			if (s->purgehost_regex) pcre_free(s->purgehost_regex);
			array_free(s->domains);
			array_free(s->programs_ext);
			buffer_free(s->purgehost);
			free(s);
		}
		free(p->config_storage);
	}

	buffer_free(p->tmpfile);
	free(p);
	
	for (j = 0; j <= MEMCACHE_NUMBER; j++) { 
		while(memory_store[j]) {
			free_memory_cache_chain((struct memory_cache *)(memory_store[j]->data));
			memory_store[j] = splaytree_delete(memory_store[j], memory_store[j]->key);
		}
	}
	free(memory_store);
	free(memory_lru);

	while (cache_save) { cache_save = splaytree_delete(cache_save, cache_save->key); }
	while (range_request) { range_request = splaytree_delete(range_request, range_request->key); }

	return HANDLER_GO_ON;
}

static void
free_memory_cache_by_lru(server *srv, const int num)
{
	int i, j;

	if (lrustart == 0 || lruend == 0) return;
	j = lrustart;
	for(i = 0; i < num; i++, j=lrustart) {
		lrustart = memory_lru[j].next;
		memory_lru[j].next = memory_lru[j].prev = 0;
		while(memory_store[j]) {
			free_memory_cache_chain((struct memory_cache *)(memory_store[j]->data));
			memory_store[j] = splaytree_delete(memory_store[j], memory_store[j]->key);
		}
		if (lrustart == 0) { lrustart = lruend = 0; break; }
	}

#ifdef LIGHTTPD_V14
	status_counter_set(srv, CONST_STR_LEN(CACHE_MEMORY), used_memory_size >> 20);
	status_counter_set(srv, CONST_STR_LEN(CACHE_MEMORY_ITEMS), memory_cache_number);
	status_counter_set(srv, CONST_STR_LEN(CACHE_LOCAL_ITEMS), local_cache_number);
#else
	COUNTER_SET(cache_memory, used_memory_size >> 20);
	COUNTER_SET(cache_memory_items, memory_cache_number);
	COUNTER_SET(cache_local_items, local_cache_number);
#endif
}

/* update LRU lists */
static void
update_lru(int i)
{
	int d1, d2;

	if (i == 0) return;
	if (lrustart == 0 || lruend == 0) {
		/* first item */
		memory_lru[i].prev = memory_lru[i].next = 0;
		lrustart = lruend = i;
	} else if (i != lruend && i != lrustart){
		/* re-order lru list */
		d1 = memory_lru[i].prev;
		d2 = memory_lru[i].next;
		if (d1 == 0 && d2 == 0) {
			/* new item */
			memory_lru[i].prev = lruend;
			memory_lru[i].next = 0;
			memory_lru[lruend].next = i;
			lruend = i;
		} else if (d1 == 0 || d2 == 0) {
			/* wrong lru , free all cached data and reset lru */
			memset(memory_lru, 0, sizeof(struct lru_info)*(MEMCACHE_NUMBER+1));
			lrustart = lruend = 0;
		} else {
			memory_lru[d1].next = d2;
			memory_lru[d2].prev = d1;
			/* append to end of list */
			memory_lru[lruend].next = i;
			memory_lru[i].next = 0;
			memory_lru[i].prev = lruend;
			lruend = i;
		}
	} else if (i == lruend) {
		/* end of lru, no change */
	} else if (i == lrustart) {
		/* move header to the end*/
		lrustart = memory_lru[i].next;
		memory_lru[lrustart].prev = 0;
		memory_lru[i].prev = lruend;
		memory_lru[i].next = 0;
		memory_lru[lruend].next = i;
		lruend = i;
	}
}

struct memory_cache *
get_memory_cache(handler_ctx *hctx)
{
	unsigned int i;
	struct memory_cache *c;

	if (hctx == NULL) return NULL;

	i = (hctx->hash & MEMCACHE_MASK)+1;
	memory_store[i] = splaytree_splay(memory_store[i], hctx->hash);
	if (memory_store[i] == NULL || memory_store[i]->key != hctx->hash)
		return NULL;
	c = (struct memory_cache *)memory_store[i]->data;
	while (c) {
		if (c->memoryid == NULL || !buffer_is_equal(hctx->memoryid, c->memoryid))
			c = c->next;
		else
			break;
	}
	if (c) update_lru(i);
	return c;
}

void
update_memory_cache_headers(handler_ctx *hctx, array *d)
{
	unsigned int i;
	struct memory_cache *c, *c1;

	if (hctx == NULL || d == NULL) return;

	i = (hctx->hash & MEMCACHE_MASK) + 1;
	memory_store[i] = splaytree_splay(memory_store[i], hctx->hash);
	if (memory_store[i] == NULL || memory_store[i]->key != hctx->hash) {
		/* new entry */
		c = (struct memory_cache *)calloc(1, sizeof(struct memory_cache));
		if (c == NULL) return;
		c->headers = d;
		c->memoryid = buffer_init();
		buffer_copy_string_buffer(c->memoryid, hctx->memoryid);
		memory_store[i] = splaytree_insert(memory_store[i], hctx->hash, c);
		local_cache_number ++;
	} else {
		c1 = c = (struct memory_cache *)memory_store[i]->data;
		while (c) {
			if (c->memoryid == NULL || !buffer_is_equal(hctx->memoryid, c->memoryid)) {
				c1 = c;
				c = c->next;
			} else {
				break;
			}
		}
		if (c == NULL) {
			c = (struct memory_cache *)calloc(1, sizeof(struct memory_cache));
			if (c == NULL) return;
			if (c1) c1->next = c;
			else memory_store[i]->data = (void *) c; /* memory_store[i]->data == NULL */
			c->memoryid = buffer_init();
			buffer_copy_string_buffer(c->memoryid, hctx->memoryid);
			local_cache_number ++;
		} else if (c->headers) {
			array_free(c->headers);
		}
		c->headers = d;
	}
	update_lru(i);
	return;
}

static void
update_asis_expires_cache(struct memory_cache *cc, time_t exp, int timeout)
{
	if (cc == NULL || exp == 0) return;
	if (cc->expires_time == exp) return;
	strftime(cc->expires, sizeof("Fri, 01 Jan 1990 00:00:00 GMT")+1,
			"%a, %d %b %Y %H:%M:%S GMT", gmtime(&exp));
	cc->expires_time = exp;
	if (timeout > 0) {
		snprintf(cc->max_age, 19, "max-age=%d",timeout);
	} else {
		strcpy(cc->max_age, "max-age=2592000"); /* 30 days */
	}
	return ;
}

/* return 0 if successful */
static int
delete_memory_cache(server *srv, handler_ctx *hctx)
{
	unsigned int i;
	struct memory_cache *c, *c1;

	if (hctx == NULL) return 1;
	i = (hctx->hash & MEMCACHE_MASK) + 1;
	memory_store[i] = splaytree_splay(memory_store[i], hctx->hash);
	if (memory_store[i] == NULL || memory_store[i]->key != hctx->hash)
		return 1;
 
	c = c1 = (struct memory_cache *)memory_store[i]->data;

	while(c && !buffer_is_equal(c->memoryid, hctx->memoryid)) {
		c1 = c;
		c = c->next;
	}

	if (c == NULL) return 1; /* not found */
	else if (c1 == c) {
		/* first entry */
		memory_store[i]->data = c->next;
	} else {
		c1->next = c->next;
	}

	update_lru(i);
	if ((c->headers || c->memoryid) && local_cache_number > 0)
		local_cache_number --;
	if (c->headers) array_free(c->headers);
	if (c->memoryid) buffer_free(c->memoryid);
	if (c->content) {
		if (used_memory_size <= c->content->size)
			used_memory_size = 0;
		else
			used_memory_size -= c->content->size;
		if (c->inuse && memory_cache_number > 0)
			memory_cache_number --;
		c->content->ref_count --; // remove share buffer flag
		buffer_free(c->content);
	}
	free(c);

#ifdef LIGHTTPD_V14
	status_counter_set(srv, CONST_STR_LEN(CACHE_MEMORY), used_memory_size >> 20);
	status_counter_set(srv, CONST_STR_LEN(CACHE_MEMORY_ITEMS), memory_cache_number);
	status_counter_set(srv, CONST_STR_LEN(CACHE_LOCAL_ITEMS), local_cache_number);
#else
	COUNTER_SET(cache_memory, used_memory_size >> 20);
	COUNTER_SET(cache_memory_items, memory_cache_number);
	COUNTER_SET(cache_local_items, local_cache_number);
#endif
	return 0;
}

SETDEFAULTS_FUNC(mod_cache_set_defaults)
{
	plugin_data *p = p_d;
	size_t i = 0;
	data_unset *du;
	
	config_values_t cv[] = {
		{ CONFIG_CACHE_SUPPORT_QUERIES, NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
		{ CONFIG_CACHE_ENABLE, NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 1 */
		{ CONFIG_CACHE_BASES, NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION }, /* 2 */
		{ CONFIG_CACHE_REFRESH_PATTERN, NULL, T_CONFIG_LOCAL, T_CONFIG_SCOPE_CONNECTION }, /* 3 */
		{ CONFIG_CACHE_DEBUG, NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 4 */
		{ CONFIG_CACHE_DOMAINS, NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION }, /* 5 */
		{ CONFIG_CACHE_PURGE_HOST, NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 6 */
		{ CONFIG_CACHE_IGNORE_HOSTNAME, NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 7 */
		{ CONFIG_CACHE_DYNAMIC_MODE, NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 8 */
		{ CONFIG_CACHE_PROGRAMS_EXT, NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION }, /* 9 */
		{ CONFIG_CACHE_SUPPORT_ACCEPT_ENCODING, NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION }, /* 10 */
		{ CONFIG_CACHE_MAX_MEMORY_SIZE, NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION }, /* 11 */
		{ NULL, NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	if (!p) return HANDLER_ERROR;
	
	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		data_array *da = (data_array *)du;
		array *ca;
		size_t m;
	   	const char *errptr;
	   	int erroff;
		pcre *pcregex;
		char *p3, *p2, *p6;
		data_string *ds;

		s = calloc(1, sizeof(plugin_config));
		s->support_queries = 0;
		s->enable = 1;
		s->debug = 0;
		s->cache_bases = array_init();
		s->rp_buffer = array_init();
		s->domains = array_init();
		s->domains_size = 0;
		s->purgehost = buffer_init();
		s->rp = NULL;
		s->rp_size = 0;
		s->ignore_hostname = 0;
		s->domains_regex = NULL;
		s->purgehost_regex = NULL;
		s->programs_ext = array_init();
		s->dynamic_mode = 0;
		s->support_accept_encoding = 0;
		s->max_memory_size = 256; /* default is 256M */

		cv[0].destination = &(s->support_queries);
		cv[1].destination = &(s->enable);
		cv[2].destination = s->cache_bases;
		cv[3].destination = s->rp_buffer;
		cv[4].destination = &(s->debug);
		cv[5].destination = s->domains;
		cv[6].destination = s->purgehost;
		cv[7].destination = &(s->ignore_hostname);
		cv[8].destination = &(s->dynamic_mode);
		cv[9].destination = s->programs_ext;
		cv[10].destination = &(s->support_accept_encoding);
		cv[11].destination = &(s->max_memory_size);

		p->config_storage[i] = s;
		ca = ((data_config *)srv->config_context->data[i])->value;

		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}

		if (s->max_memory_size <= 0) s->max_memory_size = 256;
		s->max_memory_size *= 1024*1024;

		if (s->domains->used) {
			/* parse domains */

			s->domains_regex = (pcre **) malloc(s->domains->used * sizeof(pcre *));
			if (s->domains_regex == NULL) {
				log_error_write(srv, __FILE__, __LINE__, "s", "can't alloc memory for domains_regex, exiting");
				return HANDLER_ERROR;
			}
			s->domains_size = s->domains->used;

			for (m = 0; m < s->domains->used; m ++) {
				ds = (data_string *)(s->domains->data[m]);
				pcregex = pcre_compile(ds->value->ptr, 0, &errptr, &erroff, NULL);
				if (pcregex == NULL) {
					log_error_write(srv, __FILE__, __LINE__, "sbss",
							"compiling regex for domains failed:", ds->value, "pos:", erroff);
					return HANDLER_ERROR;
				}
				s->domains_regex[m] = pcregex;
			}
		}

		if (s->purgehost->used) {
			s->purgehost_regex = pcre_compile(s->purgehost->ptr, 0, &errptr, &erroff, NULL);
			if (s->purgehost_regex == NULL) {
				log_error_write(srv, __FILE__, __LINE__, "sbss", "compiling regex for purge-host failed:",
						s->purgehost, "pos:", erroff);
				return HANDLER_ERROR;
			}
		}

#ifdef LIGHTTPD_V14
		if (NULL == (du = array_get_element(ca, "cache.refresh-pattern"))) {
#else
		if (NULL == (du = array_get_element(ca, CONST_STR_LEN("cache.refresh-pattern")))) {
#endif
			/* no cache.refresh-pattern defined */
			continue;
		}
		
		/* parse cache.refresh-pattern */
		if (du->type != TYPE_ARRAY) {
			log_error_write(srv, __FILE__, __LINE__, "s", "unexpected type for cache.refresh-pattern");
			return HANDLER_ERROR;
		}
		
		da = (data_array *)du;
		s->rp_size = da->value->used;
		s->rp = (refresh_pattern *) malloc(sizeof(refresh_pattern)* s->rp_size);
		if (s->rp == NULL) {
			log_error_write(srv, __FILE__, __LINE__, "s", "can't alloc memory for refresh-pattern");
			return HANDLER_ERROR;
		}
		for (m = 0; m < da->value->used; m++) {
			if (da->value->data[m]->type != TYPE_STRING) {
				log_error_write(srv, __FILE__, __LINE__, "sbs",
						"unexpected type for key: cache.refresh-pattern [", da->value->data[m]->key, "](string)");
				return HANDLER_ERROR;
			}

			ds = (data_string *)da->value->data[m];

			/* key => value */
			pcregex = pcre_compile(ds->key->ptr, 0, &errptr, &erroff, NULL);
			if (pcregex == NULL) {
				log_error_write(srv, __FILE__, __LINE__, "sbss",
						"compiling regex for refresh_pattern failed:", ds->key, "pos:", erroff);
				return HANDLER_ERROR;
			}
			s->rp[m].regex = pcregex;

			/* value
			 * format: "minutes options"
			 */
			p2 = strdup(ds->value->ptr);
			p3 = strchr(p2, ' ');
			s->rp[m].type = 0;
			if (p3) {
				p3[0] = '\0';
				p3 ++;
			}
			while (p3) {
				p6 = strchr(p3, ' ');
				if (p6) *p6 = '\0';
				if (strncmp(p3, "ignore-reload", sizeof("ignore-reload")) == 0)
					s->rp[m].type |= CACHE_IGNORE_RELOAD;
				else if (strncmp(p3, "update-on-refresh",  sizeof("update-on-refresh")) == 0 ||
					 strncmp(p3, "update-on-nocache",  sizeof("update-on-nocache")) == 0)
					s->rp[m].type |= CACHE_UPDATE_ON_REFRESH;
				else if (strncmp(p3, "no-expire-header", sizeof("no-expire-header")) == 0)
					s->rp[m].type |= CACHE_NO_EXPIRE_HEADER;
				else if (strncmp(p3, "override-expire", sizeof("override-expire")) == 0)
					s->rp[m].type |= CACHE_OVERRIDE_EXPIRE;
				else if (strncmp(p3, "flv-streaming", sizeof("flv-streaming")) == 0)
					s->rp[m].type |= CACHE_FLV_STREAMING;
				else if (strncmp(p3, "use-memory", sizeof("use-memory")) == 0)
					s->rp[m].type |= CACHE_USE_MEMORY;
				else if (strncmp(p3, "ignore-cache-control-header", sizeof("ignore-cache-control-header")) == 0)
					s->rp[m].type |= CACHE_IGNORE_CACHE_CONTROL_HEADER;
				else if (strncmp(p3, "nocache",  sizeof("nocache")) == 0 || strncmp(p3, "no-cache", sizeof("no-cache")) == 0)
					s->rp[m].type |= CACHE_NOCACHE;
				else if (strncmp(p3, "fetchall-for-range-request", sizeof("fetchall-for-range-request")) == 0)
					s->rp[m].type |= CACHE_FETCHALL_FOR_RANGE_REQUEST;
				if (p6) p3 = p6+1;
				else break;
			}
			s->rp[m].expires = strtoul(p2, NULL,10)*60;
			free(p2);
		}
	}
	
	return HANDLER_GO_ON;
}

#ifdef LIGHTTPD_V14
#define PATCH_OPTION(x) \
	p->conf.x = s->x;
#endif

static int
mod_cache_patch_connection(server *srv, connection *con, plugin_data *p)
{
	size_t i, j;
	plugin_config *s = p->config_storage[0];
	
	PATCH_OPTION(rp);
	PATCH_OPTION(rp_size);
	PATCH_OPTION(cache_bases);
	PATCH_OPTION(domains_size);
	PATCH_OPTION(support_queries);
	PATCH_OPTION(enable);
	PATCH_OPTION(debug);
	PATCH_OPTION(ignore_hostname);
	PATCH_OPTION(domains_regex);
	PATCH_OPTION(purgehost_regex);
	PATCH_OPTION(dynamic_mode);
	PATCH_OPTION(programs_ext);
	PATCH_OPTION(support_accept_encoding);
	PATCH_OPTION(max_memory_size);
	
	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];
		
		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;
		
		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_CACHE_ENABLE))) {
				PATCH_OPTION(enable);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_CACHE_REFRESH_PATTERN))) {
				PATCH_OPTION(rp);
				PATCH_OPTION(rp_size);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_CACHE_SUPPORT_QUERIES))) {
				PATCH_OPTION(support_queries);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_CACHE_BASES))) {
				PATCH_OPTION(cache_bases);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_CACHE_DOMAINS))) {
				PATCH_OPTION(domains_regex);
				PATCH_OPTION(domains_size);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_CACHE_DEBUG))) {
				PATCH_OPTION(debug);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_CACHE_IGNORE_HOSTNAME))) {
				PATCH_OPTION(ignore_hostname);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_CACHE_PURGE_HOST))) {
				PATCH_OPTION(purgehost_regex);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_CACHE_DYNAMIC_MODE))) {
				PATCH_OPTION(dynamic_mode);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_CACHE_SUPPORT_ACCEPT_ENCODING))) {
				PATCH_OPTION(support_accept_encoding);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_CACHE_MAX_MEMORY_SIZE))) {
				PATCH_OPTION(max_memory_size);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_CACHE_PROGRAMS_EXT))) {
				PATCH_OPTION(programs_ext);
			}
		}
	}
	
	return 0;
}

#ifdef LIGHTTPD_V14
#undef PATCH_OPTION
#endif

#define DEFAULT_INDEX_FILENAME "index_mod_cache.html"

/* generate filename after cache_bases/cache_domain */
static void
get_cache_uri_pattern(connection *con, plugin_data *p, buffer *dst)
{
	handler_ctx *hctx = con->plugin_ctx[p->id];
	buffer *src;
	char *p1, *p2;
	size_t i;

	if (hctx == NULL) return;
	src = con->uri.path;

	if (hctx->is_query == 0 || p->conf.dynamic_mode == 0) {
		buffer_append_string_buffer(dst, src);
	} else {
		/*uri-pattern path */
		p1 = strrchr(src->ptr, '/');
		if (p1) buffer_append_string_len(dst, src->ptr, abs(p1-src->ptr));
		buffer_append_string_len(dst, CONST_STR_LEN("/"));

		if (hctx->is_query == 0 || p->conf.dynamic_mode == 0) {
			p1 = strrchr(src->ptr, '/');
			if (p1 == NULL) buffer_append_string_buffer(dst, src);
			else {
				p1++;
				if (*p1) buffer_append_string(dst, p1);
			}
		} else {
			/* /uri_key.js(css) */
			if (src->ptr[src->used-2] == '/') {
				/* last char is '/' */
				buffer_append_string_buffer(dst, src);
				buffer_append_string(dst, "index_mod_cache_");

				/* append _+hash */
				buffer_append_long(dst, (unsigned int)hctx->hash);
				buffer_append_string_len(dst, CONST_STR_LEN(".html"));
			} else {
				/* find last '/' */
				p1 = strrchr(src->ptr, '/');
				if (p1 == NULL) p1 = src->ptr;
				else p1++;
				/* find last '.' from / */
				p2 = strrchr(p1, '.');

				/* append string from / to . */
				if (p2) buffer_append_string_len(dst, p1, abs(p2-p1));
				else buffer_append_string(dst, p1);

				/* append _+hash */
				buffer_append_string_len(dst, CONST_STR_LEN("_"));
				buffer_append_long(dst, (unsigned int)hctx->hash);

				/* append file ext */
				if (p2) buffer_append_string(dst, p2);
				else buffer_append_string_len(dst, CONST_STR_LEN(".html"));
			}
		}
	}
	
	/* check cache.programs-ext*/
	for (i = 0; i < p->conf.programs_ext->used; i ++) {
		data_string *ds = (data_string *)p->conf.programs_ext->data[i];
		if (buffer_is_equal_right_len(dst, ds->value, ds->value->used-1)) {
			/* remove programs-ext, append .cache.html as extension */
			src = buffer_init();
			buffer_copy_string_len(src, dst->ptr, dst->used - ds->value->used);
			buffer_append_string_len(src, CONST_STR_LEN(".cache.html"));
			buffer_copy_string_buffer(dst, src);
			buffer_free(src);
			break;
		}
	}
}

static void
get_cache_filename(connection *con, plugin_data *p, buffer *b)
{
	size_t i;
	data_string *ds;
	handler_ctx *hctx = con->plugin_ctx[p->id];

	if (p->conf.cache_bases->used == 0 || hctx == NULL) return;

	if (p->conf.cache_bases->used == 1) i = 0;
	else i = (hctx->hash&0xff) % p->conf.cache_bases->used;

	ds = (data_string *) p->conf.cache_bases->data[i];
	hctx->offset = ds->value->used-1;
	buffer_copy_string_buffer(b, ds->value);

	if (!p->conf.ignore_hostname && !buffer_is_empty(con->uri.authority)) {
		buffer_append_string(b, "/");
		buffer_append_string_buffer(b, con->uri.authority);
	}

	/* get the local path */
	get_cache_uri_pattern(con, p, b);

	if (b->ptr[b->used-2] == '/')
		buffer_append_string(b, DEFAULT_INDEX_FILENAME);
}

static int
copy_chunkqueue_to_memory(server *srv, handler_ctx *hctx, chunkqueue *cq)
{
	chunk *c;
	size_t k;
	int result = 0;
	off_t *save_offset;

	if (hctx == NULL) return 0;

	for (c=cq->first, k = 0; c; c = c->next, k ++) ;
	if (k == 0) return 0;

	save_offset = (off_t *) calloc(k, sizeof(off_t));
	if (save_offset == NULL) return -1;

	/* backup chunkqueue's offset */
	for (c=cq->first, k = 0; c; c = c->next, k++) save_offset[k] = c->offset;
	
	for(c = cq->first; result == 0 && c; c = c->next) {
		
		switch(c->type) {
		case MEM_CHUNK: 
			if (c->mem)
				buffer_append_string_buffer(hctx->savecontent, c->mem);
			break;
		case FILE_CHUNK:
			/* we don't local cache FILE_CHUNK */
			result = -1;
			break;
		default:
			log_error_write(srv, __FILE__, __LINE__, "ds", c, "type not known");
			result = -1;
			break;
		}
	}

	for (c=cq->first, k = 0; c; c = c->next, k++)
		c->offset = save_offset[k];

	free(save_offset);
	return result;
}
/* ugly hack on network_freebsd_sendfile.c code
 * just save chunkqueue->offset before save
 * and restore them after chunk saved
 */
static int
save_chunkqueue(int fd, chunkqueue *cq)
{
	chunk *c;
	size_t chunks_written = 0, k;
	int result = 0;
	off_t bytes_out = 0, *save_offset;

	for (c=cq->first, k = 0; c; c = c->next, k ++) ;

	if (k == 0) return 0;

	save_offset = (off_t *) calloc(sizeof(off_t), k);

	if (save_offset == NULL) return -1;

	/* backup chunkqueue's offset */
	for (c=cq->first, k = 0; c; c = c->next, k++) save_offset[k] = c->offset;
	
	for(c = cq->first; c; c = c->next, chunks_written++) {
		int chunk_finished = 0;
		
		switch(c->type) {
		case MEM_CHUNK: {
			char * offset;
			size_t toSend;
			ssize_t r;
			
			size_t num_chunks, i;
			struct iovec chunks[UIO_MAXIOV];
			chunk *tc;
			size_t num_bytes = 0;
			
			/* we can't send more then SSIZE_MAX bytes in one chunk */
			
			/* build writev list
			 *
			 * 1. limit: num_chunks < UIO_MAXIOV
			 * 2. limit: num_bytes < SSIZE_MAX
			 */
			for(num_chunks = 0, tc = c; tc && tc->type == MEM_CHUNK && num_chunks < UIO_MAXIOV; num_chunks++, tc = tc->next);
			
			for(tc = c, i = 0; i < num_chunks; tc = tc->next, i++) {
				if (tc->mem->used == 0) {
					chunks[i].iov_base = tc->mem->ptr;
					chunks[i].iov_len  = 0;
				} else {
					offset = tc->mem->ptr + tc->offset;
					toSend = tc->mem->used - 1 - tc->offset;
					
					chunks[i].iov_base = offset;
					
					/* protect the return value of writev() */
					if (toSend > SSIZE_MAX || num_bytes + toSend > SSIZE_MAX) {
						chunks[i].iov_len = SSIZE_MAX - num_bytes;
						num_chunks = i + 1;
						break;
					} else {
						chunks[i].iov_len = toSend;
					}
				
					num_bytes += toSend;
				}
			}
			
			if ((r = writev(fd, chunks, num_chunks)) < 0) {
				switch (errno) {
				case EAGAIN:
				case EINTR:
					r = 0;
					break;
				case EPIPE:
				case ECONNRESET:
					result = -2;
					goto restore_offset;
				default:
					result = -1;
					goto restore_offset;
					
				}

				r = 0;
			}
			
			/* check which chunks have been written */
			bytes_out += r;
			
			for(i = 0, tc = c; i < num_chunks; i++, tc = tc->next) {
				if (r >= (ssize_t)chunks[i].iov_len) {
					/* written */
					r -= chunks[i].iov_len;
					tc->offset += chunks[i].iov_len;
					
					if (chunk_finished) {
						/* skip the chunks from further touches */
						chunks_written++;
						c = c->next;
					} else {
						/* chunks_written + c = c->next is done in the for()*/
						chunk_finished++;
					}
				} else {
					/* partially written */
					
					tc->offset += r;
					chunk_finished = 0;
					
					break;
				}
			}
			
			break;
		}
		case FILE_CHUNK:
			/* we don't local cache FILE_CHUNK */
			result = -1;
			goto restore_offset;
			break;

		default:
			
			result = -1;
			goto restore_offset;
			
		}
		
		if (!chunk_finished) {
			/* not finished yet */
			break;
		}
	}
restore_offset:
	for (c=cq->first, k = 0; c; c = c->next, k++)
		c->offset = save_offset[k];

	free(save_offset);

	if (result < 0) return result;
	else return chunks_written;
}

/* update cache file's stat time */
static void
update_cache_change_time(char *file, time_t mtime, time_t now)
{
	struct timeval cachetime[2];
	buffer *b;

	if (file == NULL) return;

	/* don't use srv->cur_ts because
	 * it may talk long time to process
	 */
	cachetime[0].tv_usec = cachetime[1].tv_usec = 0;
	cachetime[0].tv_sec = now;
	cachetime[1].tv_sec = mtime ? mtime:now;
	utimes(file, cachetime);
	/* update ASIS header file too*/
	b = buffer_init();
	buffer_copy_string(b, file);
	buffer_append_string(b, ASISEXT);
	utimes(b->ptr, cachetime);
	buffer_free(b);
	return;
}

static int
check_response_iscachable(server *srv, connection *con, plugin_data *p, handler_ctx *hctx)
{
	data_string *ds;
	struct tm etime;
	time_t etime_t = 0;

	if (con->http_status != 200) return 0;

	/* Check if response has a Content-Encoding.
	 * Don't cache response with gzip/deflate content-encoding
	 */

	if (
#ifdef LIGHTTPD_V14
		(NULL != (ds = (data_string *)array_get_element(con->response.headers, "Content-Encoding")))
#else
		(NULL != (ds = (data_string *)array_get_element(con->response.headers, CONST_STR_LEN("Content-Encoding"))))
#endif
		 ) {
		if (p->conf.support_accept_encoding == 0 ) {
			if (p->conf.debug)
				log_error_write(srv, __FILE__, __LINE__, "sb", "ignore response uri with CE", con->uri.path);
			return 0;
		} else {
			if (strcasecmp(ds->value->ptr, "gzip") == 0) {
				hctx->content_encoding_type = 1;
			} else if (strcasecmp(ds->value->ptr, "deflate") == 0) {
				hctx->content_encoding_type = 2;
			}
		}
	}

	/* don't save response with 'Set-Cookie' */
#ifdef LIGHTTPD_V14
	if (NULL != (ds = (data_string *)array_get_element(con->response.headers, "Set-Cookie"))) {
#else
	if (NULL != (ds = (data_string *)array_get_element(con->response.headers, CONST_STR_LEN("Set-Cookie")))) {
#endif
		if (p->conf.debug)
			log_error_write(srv, __FILE__, __LINE__, "sbb", "ignore response with Set-Cookie:", ds->value, con->uri.path);
		return 0;
	}

	if ((p->conf.support_accept_encoding == 0 || hctx->use_memory == 1) &&
#ifdef LIGHTTPD_V14
		(NULL != (ds = (data_string *)array_get_element(con->response.headers, "Vary")))
#else
		(NULL != (ds = (data_string *)array_get_element(con->response.headers, CONST_STR_LEN("Vary"))))
#endif
		) {
		if (p->conf.debug)
			log_error_write(srv, __FILE__, __LINE__, "sbb", "ignore response with Vary:", ds->value, con->uri.path);
		return 0;
	}

	if (hctx->ignore_cache_control_header == 0) {
		/* no-cache check */
		if (
#ifdef LIGHTTPD_V14
			NULL != (ds = (data_string *)array_get_element(con->response.headers, "Pragma")) &&
#else
			NULL != (ds = (data_string *)array_get_element(con->response.headers, CONST_STR_LEN("Pragma"))) &&
#endif
			buffer_is_equal_string(ds->value, CONST_STR_LEN("no-cache"))) {
			if (p->conf.debug)
				log_error_write(srv, __FILE__, __LINE__, "sb", "ignore response uri with Pragma: no-cache ", con->uri.path);
			return 0;
		}

		if (
#ifdef LIGHTTPD_V14
			NULL != (ds = (data_string *)array_get_element(con->response.headers, "Cache-Control")) &&
#else
			NULL != (ds = (data_string *)array_get_element(con->response.headers, CONST_STR_LEN("Cache-Control"))) &&
#endif
			(buffer_is_equal_string(ds->value, CONST_STR_LEN("private")) ||
			 buffer_is_equal_string(ds->value, CONST_STR_LEN("no-cache, must-revalidate")) ||
			 buffer_is_equal_string(ds->value, CONST_STR_LEN("no-cache")))) {
			if (p->conf.debug)
				log_error_write(srv, __FILE__, __LINE__, "sb", "ignore response uri with Cache-Control: private/no-cache ", con->uri.path);
			return 0;
		}
	}

	if (hctx->override_expire == 0 &&
#ifdef LIGHTTPD_V14
		(NULL != (ds = (data_string *)array_get_element(con->response.headers, "Expires")))
#else
		(NULL != (ds = (data_string *)array_get_element(con->response.headers, CONST_STR_LEN("Expires"))))
#endif
		) {
		if (strptime(ds->value->ptr, "%a, %d %b %Y %H:%M:%S GMT", &etime)) {
			etime_t = timegm(&etime);
			if (etime_t <= srv->cur_ts) {
				if (p->conf.debug)
					log_error_write(srv, __FILE__, __LINE__, "sb",
							"ignore response uri that Expires is sometime before now: ", con->uri.path);
				return 0;
			}
		}
	}

	if ((con->request.http_version == HTTP_VERSION_1_1) &&
			(con->response.content_length < 0) &&
		!(con->response.transfer_encoding & HTTP_TRANSFER_ENCODING_CHUNKED)) {
		/* don't cache no 'Content-Length' and no "chunked-encoding" HTTP/1.1 response */
		log_error_write(srv, __FILE__, __LINE__, "sb", "ignore no content-length and no chunked transfer-encoding uri", con->uri.path);
		return 0;
	}

	/* don't cache local file, meaningless */
#ifdef LIGHTTPD_V14
	if (con->write_queue->first == NULL || con->write_queue->first->type == FILE_CHUNK)
#else
	if (con->send->first && con->send->first->type == FILE_CHUNK)
#endif
		return 0;
	return 1;
}

/*
 * following code is taken from mod_compress.c
 */

static int
mkdir_recursive(char *p, off_t offset)
{
	char *dir, *nextdir;

	for (dir = p + offset; NULL != (nextdir = strchr(dir, '/')); dir = nextdir + 1) {
		*nextdir = '\0';
			
		if (-1 == mkdir(p, 0755)) {
			if (errno != EEXIST) {
				*nextdir = '/';
				return 1;
			}
		}
		*nextdir = '/';
	}
	return 0;
}

/*
 * success return new malloced array, otherwise return NULL
 */
static array *
read_cache_header_file(handler_ctx *hctx)
{
	int fd;
	buffer *f;
	off_t len;
	array *da;
	char *b, *pos, *pos2;
	data_string *ds;

	if (hctx == NULL) return NULL;
	f = buffer_init();
	buffer_copy_string_buffer(f, hctx->file);
	buffer_append_string(f, ASISEXT);

	/* read all content of asis file into buffer *b */
	fd = open(f->ptr, O_RDONLY);
	buffer_free(f);
	if(fd == -1) return NULL;

	len = lseek(fd, 0, SEEK_END);
	if (len == -1) { close(fd); return NULL; }

	b = malloc(len+1);
	if (b == NULL) { close(fd); return NULL; }

	lseek(fd, 0, SEEK_SET);
	len = read(fd, b, len);
	close(fd);
	b[len] = '\0';
	/* process buffer b */
	da = array_init();
	/* process asis buffer.
	 * asis file format:
	 * header1:value1
	 * header2:value2
	 * ...
	 * X-Powered-By:PHP/4.4.2
	 * Content-type:text/html
	 */
	pos = b;
	while(*pos) {
		for (pos2 = pos, len = 0; *pos2 && *pos2 != ':'; *pos2++) len++;
		if (*pos2 == '\0') break;
		ds = data_string_init();
		buffer_copy_string_len(ds->key, pos, len);
		pos = pos2+1;
		for (pos2 = pos, len = 0; *pos2 && *pos2 != '\n'; *pos2++) len ++;
		if (*pos2) {
			buffer_copy_string_len(ds->value, pos, len);
			pos = pos2 + 1;
		} else {
			buffer_copy_string_len(ds->value, pos, len);
			pos = pos2;
		}
		array_insert_unique(da,(data_unset *)ds);
	}
	free(b);
	return da;
}

static void
update_memory_cache_file(connection *con, handler_ctx *hctx)
{
	int fd = -1, copy_header;
	buffer *f;
	size_t i;
	data_string *ds, *ds2;
	array *headers;
		
	if (con->http_status != 200 || con->response.headers->used == 0) return;

	if (hctx->use_memory == 0) {
		/* open fd of asis file */
		f = buffer_init();
		buffer_copy_string_buffer(f, hctx->file);
		buffer_append_string(f, ASISEXT);

		fd = open(f->ptr, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0644);
		if (fd == -1) {
			if (errno == ENOTDIR || errno == ENOENT) {
				if (mkdir_recursive(hctx->file->ptr, hctx->offset) == 0) {
					fd = open(f->ptr, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0644);
				} else {
					buffer_free(f);
					return;
				}
			} else {
				buffer_free(f);
				return;
			}
		}
		buffer_free(f);
	}

	/* going to update struct memory_cache and asis file */
	headers = array_init();
	for (i = 0; i < con->response.headers->used; i++) {
		/* skip
		 * Date Content-Length Last-Modified
		 * X-Cache Transfer-Encoding Expires
		 * Connection Server for all content
		 * Cache-Control Age Via
		 * Content-Encoding Vary
		 * headers
		 */
		ds = (data_string *)con->response.headers->data[i];
		copy_header = 1;
		switch(ds->key->used) {
		case 4:
			if (0 == strncasecmp(ds->key->ptr, "Via", 3)) copy_header = 0;
			if (0 == strncasecmp(ds->key->ptr, "Age", 3)) copy_header = 0;
			break;
		case 5:
			if (0 == strncasecmp(ds->key->ptr, "Date", 4)) copy_header = 0;
			if (0 == strncasecmp(ds->key->ptr, "Vary", 4)) copy_header = 0;
			break;
		case 7:
			if (0 == strncasecmp(ds->key->ptr, "Server", 6)) copy_header = 0;
			break;
		case 8:
			if (0 == strncasecmp(ds->key->ptr, "Expires", 7)) copy_header = 0;
			else if (0 == strncasecmp(ds->key->ptr, "X-Cache", 7)) copy_header = 0;
			break;
		case 11:
			if (0 == strncasecmp(ds->key->ptr, "Connection", 10)) copy_header = 0;
			else if (0 == strncasecmp(ds->key->ptr, "Set-Cookie", 10)) copy_header = 0;
			break;
		case 14:
			if (0 == strncasecmp(ds->key->ptr, "Cache-Control", 13)) copy_header = 0;
			else if (0 == strncasecmp(ds->key->ptr, "Accept-Ranges", 13)) copy_header = 0;
			break;
		case 15:
			if (0 == strncasecmp(ds->key->ptr, "Content-Length", 14)) copy_header = 0;
			break;
		case 17:
			if (0 == strncasecmp(ds->key->ptr, "Content-Encoding", 16)) copy_header = 0;
			break;
		case 18:
			if (0 == strncasecmp(ds->key->ptr, "Transfer-Encoding", 17)) copy_header = 0;
			break;
		default:
			break;
		}

		if (copy_header) {
			ds2 = data_string_init();
			buffer_copy_string_buffer(ds2->key, ds->key);
			buffer_copy_string_buffer(ds2->value, ds->value);
			array_insert_unique(headers, (data_unset *)ds2);
			if (fd > 0) {
				write(fd, CONST_BUF_LEN(ds->key));
				write(fd, ":", 1);
				write(fd, CONST_BUF_LEN(ds->value));
				write(fd, "\n", 1);
			}
		}
	}

	update_memory_cache_headers(hctx, headers);
	if (fd > 0) close(fd);
	return;
}

static void
delete_memory_cache_file(handler_ctx *hctx)
{
	/*delete header cache file*/
	buffer *f;

	if (hctx == NULL) return;
	f = buffer_init();
	buffer_copy_string_buffer(f, hctx->file);
	buffer_append_string(f, ASISEXT);
	unlink(f->ptr);

	buffer_free(f);
	return;
}

/* check cache header or local cache header file.
 * return 0 when there has cache header
 */
static int
check_memory_cache_existness(server *srv, connection *con, handler_ctx *hctx)
{
	buffer *b;
	int status = 0;
	stat_cache_entry *sce = NULL;

	if (hctx == NULL) return 1;
	if (get_memory_cache(hctx)) return 0;

	b = buffer_init();
	buffer_copy_string_buffer(b, hctx->file);
	buffer_append_string(b, ASISEXT);

	if (HANDLER_ERROR == stat_cache_get_entry(srv, con, b, &sce)) status = 1;

	buffer_free(b);
	return status;
	
}

static void
update_response_header(server *srv, connection *con, handler_ctx *hctx)
{
	data_string *ds;
	array *b;
	size_t i;
	struct memory_cache *node;

	if (hctx == NULL) return ;
	node = get_memory_cache(hctx);
	if (node == NULL) {
		if ((b = read_cache_header_file(hctx)) == NULL) return;
		/* put asis into cache */
		update_memory_cache_headers(hctx, b);
		node = get_memory_cache(hctx);
	} else {
		b = node->headers;
	}

	for (i = 0; i < b->used; i++) {
		ds = (data_string *) b->data[i];
		response_header_overwrite(srv, con, CONST_BUF_LEN(ds->key), CONST_BUF_LEN(ds->value));
	}

	if (con->http_status == 200 && hctx->no_expire_header == 0) {
		if (hctx->expires > 0 && (node->expires_time != hctx->expires))
			update_asis_expires_cache(node, hctx->expires, hctx->timeout);
		if (node->expires[0] != '\0')
			response_header_overwrite(srv, con, CONST_STR_LEN("Expires"), node->expires, strlen(node->expires));
		if (node->max_age[0] != '\0')
			response_header_overwrite(srv, con, CONST_STR_LEN("Cache-Control"), node->max_age, strlen(node->max_age));
	}
	return;
}

/* check header and setup con->use_cache_file, write_cache_file
 * handle procedure:
 * 1) handle PURGE
 * 2) is_query check
 * 3) refresh pattern check
 */

handler_t
mod_cache_uri_handler(server *srv, connection *con, void *p_d)
{
	plugin_data *p = p_d;
	handler_ctx *hctx = con->plugin_ctx[p->id];
	stat_cache_entry *sce = NULL;
	int expires = -1;
	size_t i=0;
	int type;
	unsigned short fetchall_for_range_request = 0, is_query = 0;
	int n;
	data_string *ds;
# define N 10
	int ovec[N * 3];
	
	if (con->uri.path->used == 0) return HANDLER_GO_ON;
	
	mod_cache_patch_connection(srv, con, p);

	if (p->conf.enable == 0 || p->conf.cache_bases->used == 0) return HANDLER_GO_ON;

	/* we only handle GET, PURGE and HEAD */
	switch(con->request.http_method) {
	case HTTP_METHOD_GET:
	case HTTP_METHOD_HEAD:
	case HTTP_METHOD_PURGE:
		break;
	default:
		return HANDLER_GO_ON;
	}

	reqcount++;

	if (strchr(con->request.uri->ptr, '?')) is_query = 1;
	if (!p->conf.support_queries && is_query) return HANDLER_GO_ON;
	
	if (con->conf.log_request_handling)
		log_error_write(srv, __FILE__, __LINE__, "s", "-- mod_cache_uri_handler called");

	if (hctx == NULL) {
		hctx = handler_ctx_init();
		con->plugin_ctx[p->id] = hctx;
	}

	if (p->conf.ignore_hostname) {
		if (p->conf.dynamic_mode)
			buffer_copy_string_buffer(p->tmpfile, con->request.uri);
		else
			buffer_copy_string_buffer(p->tmpfile, con->uri.path);
	} else {
		buffer_copy_string_buffer(p->tmpfile, con->uri.authority);
		if (p->conf.dynamic_mode)
			buffer_append_string_buffer(p->tmpfile, con->request.uri);
		else
			buffer_append_string_buffer(p->tmpfile, con->uri.path);
	}
	hctx->hash = hashme(p->tmpfile);
	buffer_copy_string_buffer(hctx->memoryid, p->tmpfile);

	hctx->is_query = is_query;

	if (con->request.http_method == HTTP_METHOD_PURGE) {
		/* handle PURGE command
		 * PURGE http://www.xxx.com/abc HTTP/1.0
		 * or PURGE /abc HTTP/1.1\r\nHOST: www.xxx.com\r\n\r\n
		 */
		
		char *remote_ip = (char *) inet_ntop_cache_get_ip(srv, &(con->dst_addr));

		/* hardcoded 10.0.0.0/8 and 127.0.0.1/32 allow host */
		if (strncmp(remote_ip, "10.", 3) == 0 || strcmp(remote_ip, "127.0.0.1")
		   || (p->conf.purgehost_regex &&
			   pcre_exec(p->conf.purgehost_regex, NULL, remote_ip, strlen(remote_ip), 0, 0, ovec, 3 * N) > 0)
		   ) {
			/* try local memory storage first */
			if (delete_memory_cache(srv, hctx)) {
				get_cache_filename(con, p, hctx->file);
				if (unlink(hctx->file->ptr) == 0) con->http_status = 200;
				else if (errno == ENOENT) con->http_status = 404;
				else con->http_status = 403; /* EACCESS or other error */
				buffer_append_string(hctx->file, ASISEXT);
				unlink(hctx->file->ptr);
			} else {
				con->http_status = 200;
			}
		} else {
			log_error_write(srv, __FILE__,__LINE__, "ss","don't allow PURGE from ip", remote_ip);
			con->http_status = 403;
		}
#ifdef LIGHTTPD_V14
		con->file_finished = 1;
#else
		con->send->is_closed = 1;
#endif
		return HANDLER_FINISHED;
	}

	if (p->conf.domains_size) {
		if (buffer_is_empty(con->uri.authority)) {
			con->plugin_ctx[p->id] = NULL;
			handler_ctx_free(hctx);
			return HANDLER_GO_ON;
		}

		for( i = 0; i < p->conf.domains_size; i ++) {
			if ((n = pcre_exec(p->conf.domains_regex[i], NULL,
					con->uri.authority->ptr, con->uri.authority->used - 1, 0, 0, ovec, 3 * N)) < 0) {
				if (n != PCRE_ERROR_NOMATCH) {
					log_error_write(srv, __FILE__, __LINE__, "sbd",
							"execution error while matching domains:", con->uri.authority, n);
					return HANDLER_ERROR;
				}
			} else break;
		}
		if (i == p->conf.domains_size) {
			con->plugin_ctx[p->id] = NULL;
			handler_ctx_free(hctx);
			if (p->conf.debug)
				log_error_write(srv, __FILE__, __LINE__, "sb", "don't cache for domain", con->uri.authority);
			return HANDLER_GO_ON;
		}
	}


	/* default to use local cache file since now*/
	con->use_cache_file = 1;

	if (p->conf.rp_size && p->conf.rp) {
		/* check refresh_pattern */
		for (i = 0 ; i < p->conf.rp_size; i++) {
			if ((n = pcre_exec(p->conf.rp[i].regex, NULL, con->uri.path->ptr, con->uri.path->used - 1, 0, 0, ovec, 3 * N)) < 0) {
				if (n != PCRE_ERROR_NOMATCH) {
					log_error_write(srv, __FILE__, __LINE__, "sbd",
							"execution error while matching refresh-pattern url:", con->uri.path, n);
					con->plugin_ctx[p->id] = NULL;
					handler_ctx_free(hctx);
					return HANDLER_ERROR;
				}
			} else {
				expires = p->conf.rp[i].expires;
				/* default to use IGNORE_RELOAD */
				type = p->conf.rp[i].type;
				if (type & CACHE_NOCACHE) {
					con->plugin_ctx[p->id] = NULL;
					con->use_cache_file = 0;
					handler_ctx_free(hctx);
					return HANDLER_GO_ON;
				}

				if (type & CACHE_FLV_STREAMING) {
					/* backend use flv streaming technology
					 * don't save backend's flv streaming output
					 */
					if (is_query)
						hctx->flv_streaming = 1;
				}

				if (type & CACHE_FETCHALL_FOR_RANGE_REQUEST)
					fetchall_for_range_request = 1;

				if (type & CACHE_NO_EXPIRE_HEADER) {
					hctx->no_expire_header = 1;
				}

				if (type & CACHE_OVERRIDE_EXPIRE) {
					hctx->override_expire = 1;
				}

				if (type & CACHE_USE_MEMORY) {
					hctx->use_memory = 1;
				}

				if (type & CACHE_IGNORE_CACHE_CONTROL_HEADER) {
					hctx->ignore_cache_control_header = 1;
				}

				if (type & CACHE_UPDATE_ON_REFRESH) {
					/* check request header */
					if (
#ifdef LIGHTTPD_V14
						(NULL != (ds = (data_string *)array_get_element(con->request.headers, "Pragma")) &&
						 buffer_is_equal_string(ds->value, CONST_STR_LEN("no-cache")))
							||
						(NULL != (ds = (data_string *)array_get_element(con->request.headers, "Cache-Control")) &&
						 buffer_is_equal_string(ds->value, CONST_STR_LEN("no-cache")))
#else
						(NULL != (ds = (data_string *)array_get_element(con->request.headers, CONST_STR_LEN("Pragma"))) &&
						 buffer_is_equal_string(ds->value, CONST_STR_LEN("no-cache")))
							||
						(NULL != (ds = (data_string *)array_get_element(con->request.headers, CONST_STR_LEN("Cache-Control"))) &&
						 buffer_is_equal_string(ds->value, CONST_STR_LEN("no-cache")))
#endif
					) {
						/* when user press F5:
						 * IE send:
						 * 	If-Modified-Since: Sun, 21 Nov 2004 14:35:21 GMT
						 * 	If-None-Match: "14f598-916-a64a7c40"
						 * Firefox send:
						 * 	Cache-Control: max-age=0
						 * when user press CTRL+F5
						 * IE send:
						 * 	Cache-Control: no-cache
						 * Firefox send:
						 * 	Pragma: no-cache
						 * 	Cache-Control: no-cache
						 */
						con->use_cache_file = 0;
					}
				}
				break;
			}
		}
	}

	if (expires == -1) con->use_cache_file = 0;

	if (hctx->use_memory == 0) {
		get_cache_filename(con, p, hctx->file);
		if (con->use_cache_file) {
			/* check local cache file existence */
			if (p->conf.support_accept_encoding) {
				hctx->accepted_encoding_type = 0;
				if (
#ifdef LIGHTTPD_V14
					(NULL != (ds = (data_string *)array_get_element(con->request.headers, "Accept-Encoding")))
#else
					(NULL != (ds = (data_string *)array_get_element(con->request.headers, CONST_STR_LEN("Accept-Encoding"))))
#endif
				) {
					if (strstr(ds->value->ptr, "gzip")) {
						buffer_copy_string_buffer(hctx->gzipfile, hctx->file);
						buffer_append_string_len(hctx->gzipfile, CONST_STR_LEN(".gzip"));
						if (HANDLER_ERROR != stat_cache_get_entry(srv, con, hctx->gzipfile, &sce)) {
							hctx->accepted_encoding_type = 1;
						}
					} else if (strstr(ds->value->ptr, "deflate")) {
						buffer_copy_string_buffer(hctx->gzipfile, hctx->file);
						buffer_append_string_len(hctx->gzipfile, CONST_STR_LEN(".deflate"));
						if (HANDLER_ERROR != stat_cache_get_entry(srv, con, hctx->gzipfile, &sce)) {
							hctx->accepted_encoding_type = 2;
						}
					}
				}
			}

			if (hctx->accepted_encoding_type == 0 && (HANDLER_ERROR == stat_cache_get_entry(srv, con, hctx->file, &sce)))
				con->use_cache_file = 0;

			if (con->use_cache_file && check_memory_cache_existness(srv, con, hctx)) {
				con->use_cache_file = 0;
				hctx->accepted_encoding_type = 0;
			}

			if (con->use_cache_file == 1) {
				hctx->local_hit = 1;
				hctx->file_mtime = sce->st.st_mtime;
				if (!S_ISREG(sce->st.st_mode)) {
					if (p->conf.debug)
						log_error_write(srv, __FILE__, __LINE__, "bs", hctx->file, "isn't regular cache file:");
					con->use_cache_file = 0;
				} else if (expires > 0 && (srv->cur_ts - sce->st.st_ctime) > expires) {
					con->use_cache_file = 0;
					if (p->conf.debug)
						log_error_write(srv, __FILE__, __LINE__, "bs", hctx->file, "expired:");
				} else {
					/* use local cache now */
					if (hctx->no_expire_header == 0) {
						if (expires == 0) {
							/* never expires */
							hctx->expires = 0x7fffffff;
							hctx->timeout = 0;
						} else {
							hctx->expires = sce->st.st_ctime + expires;
							hctx->timeout = hctx->expires - srv->cur_ts;
						}
					} else {
						hctx->expires = -1;
					}
				}
			}
		}
	} else if (con->use_cache_file == 1) {
		/* use memory storage */
		struct memory_cache *mc;
		mc = get_memory_cache(hctx);
		if (mc == NULL || mc->inuse == 0) {
			con->use_cache_file = 0;
		} else {
			con->mode = p->id;
			if (hctx->no_expire_header == 0) {
				if (expires == 0) {
					/* never expires */
					hctx->expires = 0x7fffffff;
					hctx->timeout = 0;
				} else {
					hctx->expires = srv->cur_ts + expires;
					hctx->timeout = expires;
				}
			} else {
				hctx->expires = -1;
			}
		}
	}

	if (con->use_cache_file == 0 && hctx->flv_streaming ) {
		if (p->conf.debug)
			log_error_write(srv, __FILE__, __LINE__, "sb", "ignore flv streaming", con->request.uri);
		/* don't save backend's flv stream output */
		con->plugin_ctx[p->id] = NULL;
		handler_ctx_free(hctx);
		return HANDLER_GO_ON;
	}

	if ( fetchall_for_range_request && (con->use_cache_file == 0) &&
#ifdef LIGHTTPD_V14
		(NULL != array_get_element(con->request.headers, "Range"))
#else
		(NULL != array_get_element(con->request.headers, CONST_STR_LEN("Range")))
#endif
		) {
		/* check Range: bytes=xxx- request header */
		range_request = splaytree_splay(range_request, hctx->hash);
		if ((hctx->use_memory == 0) && (range_request == NULL || range_request->key != (int)hctx->hash)) {
			/* tell mod_proxy to remove Range: bytes=xxx header */
			con->remove_range_request_header = 1;
			range_request = splaytree_insert(range_request, hctx->hash, NULL);
			hctx->range_request = 1;
		} else {
			con->plugin_ctx[p->id] = NULL;
			handler_ctx_free(hctx);
			return HANDLER_GO_ON;
		}
	}

	if (con->use_cache_file)
		reqhit++;

#ifdef LIGHTTPD_V14
	status_counter_set(srv, CONST_STR_LEN(CACHE_HIT_PERCENT), ((float)reqhit/(float)reqcount)*100);
#else
	COUNTER_SET(cache_hit_percent, ((float)reqhit/(float)reqcount)*100);
#endif
	return HANDLER_GO_ON;
}

handler_t
mod_cache_docroot_handler(server *srv, connection *con, void *p_d)
{
	plugin_data *p = p_d;
	size_t i;
	data_string *ds;
	handler_ctx *hctx = con->plugin_ctx[p->id];

	if (con->uri.path->used == 0) return HANDLER_GO_ON;
	
	mod_cache_patch_connection(srv, con, p);

	if (p->conf.enable == 0 || p->conf.cache_bases->used == 0 || hctx == NULL) return HANDLER_GO_ON;

	/* we only handle GET and HEAD
	 * PURGE already handled by uri_handler
	 */
	switch(con->request.http_method) {
	case HTTP_METHOD_GET:
	case HTTP_METHOD_HEAD:
		break;
	default:
		return HANDLER_GO_ON;
	}

	if (con->use_cache_file && hctx->use_memory == 0) {
		buffer *b;
		/* set doc root here */
		if (p->conf.cache_bases->used == 1) i = 0;
		else i = (hctx->hash&0xff) % p->conf.cache_bases->used;

		ds = (data_string *) p->conf.cache_bases->data[i];
		buffer_copy_string_buffer(con->physical.doc_root, ds->value);

		b = buffer_init();
		get_cache_uri_pattern(con, p, b);
		if (!p->conf.ignore_hostname && !buffer_is_empty(con->uri.authority)) {
			buffer_copy_string(con->physical.rel_path, "/");
			buffer_append_string_buffer(con->physical.rel_path, con->uri.authority);
		} else {
			buffer_reset(con->physical.rel_path);
		}
		buffer_append_string_buffer(con->physical.rel_path, b);
		buffer_free(b);
		/* append DEFAULT_INDEXFILENAME if needed */
		if (con->physical.rel_path->used >= 2 && con->physical.rel_path->ptr[con->physical.rel_path->used-2] == '/')
			buffer_append_string(con->physical.rel_path, DEFAULT_INDEX_FILENAME);

		if (hctx->accepted_encoding_type == 1) /* append ".gzip" */
			buffer_append_string_len(con->physical.rel_path, CONST_STR_LEN(".gzip"));
		else if (hctx->accepted_encoding_type == 2) /* append ".deflate" */
			buffer_append_string_len(con->physical.rel_path, CONST_STR_LEN(".deflate"));

		con->mode = DIRECT;
	}

	return HANDLER_GO_ON;
}

handler_t
mod_cache_handle_memory_storage(server *srv, connection *con, void *p_d)
{
	plugin_data *p = p_d;
	handler_ctx *hctx = con->plugin_ctx[p->id];
	struct memory_cache *mc;

	if (con->uri.path->used == 0) return HANDLER_GO_ON;

	/* someone else has handled this request */
	if (con->mode != p->id || con->use_cache_file == 0 || hctx == NULL || hctx->use_memory == 0) return HANDLER_GO_ON;

#ifdef LIGHTTPD_V14
	if (con->file_finished) return HANDLER_GO_ON;
#else
	if (con->send->is_closed) return HANDLER_GO_ON;
#endif
	/* we only handle GET, POST and HEAD */
	switch(con->request.http_method) {
	case HTTP_METHOD_GET:
	case HTTP_METHOD_HEAD:
		break;
	default:
		return HANDLER_GO_ON;
	}
	
	mod_cache_patch_connection(srv, con, p);

	if (p->conf.debug)
		log_error_write(srv, __FILE__, __LINE__, "s", "-- mod_cache_handle_memory_storage called");

	if (used_memory_size > p->conf.max_memory_size)
		free_memory_cache_by_lru(srv, 100);

	mc = get_memory_cache(hctx);
	if (mc && mc->inuse && mc->content != NULL) {
#ifdef LIGHTTPD_V14
		chunkqueue_append_shared_buffer(con->write_queue, mc->content); // use shared buffer
		con->file_finished = 1;
#else
		chunkqueue_append_shared_buffer(con->send, mc->content); // use shared buffer
		con->send->is_closed = 1;
#endif
		return HANDLER_FINISHED;
	}
	return HANDLER_GO_ON;
}

handler_t
mod_cache_handle_response_start(server *srv, connection *con, void *p_d)
{
	plugin_data *p = p_d;
	data_string *ds;
	stat_cache_entry *sce = NULL;
	struct tm mtime;
	handler_ctx *hctx = con->plugin_ctx[p->id];
	buffer *file;
	
	if (con->uri.path->used == 0) return HANDLER_GO_ON;

	/* we only write GET response to cache*/
	if(con->request.http_method != HTTP_METHOD_GET || hctx == NULL ||
	   (con->http_status != 200 && con->http_status != 304 && con->http_status != 404))
		return HANDLER_GO_ON;

	mod_cache_patch_connection(srv, con, p);

	if (p->conf.enable == 0 || p->conf.cache_bases->used == 0) return HANDLER_GO_ON;

	/* update ETag and other things */
	if (con->use_cache_file) {
		if (con->http_status == 200 || con->http_status == 304 ||
			con->http_status == 206) {
			update_response_header(srv, con, hctx);
			/* add "X-Cache" header */
#ifdef LIGHTTPD_V14
			if (NULL == array_get_element(con->response.headers, "X-Cache")) {
#else
			if (NULL == array_get_element(con->response.headers, CONST_STR_LEN("X-Cache"))) {
#endif
				response_header_insert(srv, con, CONST_STR_LEN("X-Cache"), CONST_STR_LEN("HIT"));
			}

			if (hctx->accepted_encoding_type > 0) {
				/* add "Vary" response header */
#ifdef LIGHTTPD_V14
				if (NULL == array_get_element(con->response.headers, "Vary")) {
#else
				if (NULL == array_get_element(con->response.headers, CONST_STR_LEN("Vary"))) {
#endif
					response_header_insert(srv, con, CONST_STR_LEN("Vary"), CONST_STR_LEN("Accept-Encoding"));
				}
				
#ifdef LIGHTTPD_V14
				if (NULL == array_get_element(con->response.headers, "Content-Encoding")) {
#else
				if (NULL == array_get_element(con->response.headers, CONST_STR_LEN("Content-Encoding"))) {
#endif
					if (hctx->accepted_encoding_type == 1)
						response_header_insert(srv, con, CONST_STR_LEN("Content-Encoding"), CONST_STR_LEN("gzip"));
					else
						response_header_insert(srv, con, CONST_STR_LEN("Content-Encoding"), CONST_STR_LEN("deflate"));
				}
			}
		}
		return HANDLER_GO_ON;
	}
	
	if (con->write_cache_file == 0 || (hctx->use_memory == 0 && hctx->file->used == 0))  return HANDLER_GO_ON;

	if (con->http_status == 404) {
		/* delete cache file */
		if (hctx->use_memory == 0) {
			if (unlink(hctx->file->ptr) == 0 && p->conf.debug)
				log_error_write(srv, __FILE__, __LINE__, "sb", "backend return 404 to delete cache file", hctx->file);

			delete_memory_cache_file(hctx);
		}
		delete_memory_cache(srv, hctx);
		return HANDLER_GO_ON;
	}

#ifdef LIGHTTPD_V14
	if (NULL != (ds = (data_string *)array_get_element(con->response.headers, "Last-Modified"))) {
#else
	if (NULL != (ds = (data_string *)array_get_element(con->response.headers, CONST_STR_LEN("Last-Modified")))) {
#endif
		/* Last-Modified: Thu, 23 Feb 2006 13:44:02 GMT */
		if (strptime(ds->value->ptr, "%a, %d %b %Y %H:%M:%S GMT", &mtime)) {
			hctx->mtime = timegm(&mtime);
		}
	}

	if (con->http_status == 304) {
		if (hctx->local_hit)
			update_cache_change_time(hctx->file->ptr, hctx->file_mtime, srv->cur_ts);
		return HANDLER_GO_ON;
	}

	/* only http status 200 now */
	if (check_response_iscachable(srv, con, p, hctx) == 0) return HANDLER_GO_ON;

	if (hctx->use_memory == 0 && p->conf.support_accept_encoding) {
#ifdef LIGHTTPD_V14
		if (NULL != (ds = (data_string *)array_get_element(con->response.headers, "Content-Encoding"))) {
#else
		if (NULL != (ds = (data_string *)array_get_element(con->response.headers, CONST_STR_LEN("Content-Encoding")))) {
#endif
			if (strstr(ds->value->ptr, "gzip")) {
				buffer_copy_string_buffer(hctx->gzipfile, hctx->file);
				buffer_append_string_len(hctx->gzipfile, CONST_STR_LEN(".gzip"));
				hctx->accepted_encoding_type = 1;
			} else if (strstr(ds->value->ptr, "deflate")) {
				buffer_copy_string_buffer(hctx->gzipfile, hctx->file);
				buffer_append_string_len(hctx->gzipfile, CONST_STR_LEN(".deflate"));
				hctx->accepted_encoding_type = 2;
			} else {
				/* unknow 'Content-Encoding' */
				return HANDLER_GO_ON;
			}
		}
	} else {
		hctx->accepted_encoding_type = 0;
	}

	cache_save = splaytree_splay(cache_save, hctx->hash);
	if (cache_save && (cache_save->key == (int) hctx->hash)) {
		if (p->conf.debug)
			log_error_write(srv, __FILE__, __LINE__, "sb", "somebody is handling", hctx->file);
		return HANDLER_GO_ON; /* sb is writing same cache file */
	}

	cache_save = splaytree_insert(cache_save, hctx->hash, NULL);
	hctx->remove_cache_save = 1;

	if (hctx->use_memory == 1) {
		hctx->savecontent = buffer_init();
		update_memory_cache_file(con, hctx);
		return HANDLER_GO_ON;
	}

	if (hctx->accepted_encoding_type > 0)
		file = hctx->gzipfile;
	else
		file = hctx->file;

	/* create directory if needed */
	if (HANDLER_ERROR != stat_cache_get_entry(srv, con, file, &sce)) {
 		/* file exists */
		if (0 == check_memory_cache_existness(srv, con, hctx) && hctx->mtime && (hctx->mtime <= sce->st.st_mtime)) {
			/*
			 * update local copy's change time only
			 */
			update_cache_change_time(file->ptr, sce->st.st_mtime, srv->cur_ts);
			if (p->conf.debug)
				log_error_write(srv, __FILE__, __LINE__, "sb", "backend return 200 to update last-access time of ", file);

			if (hctx->remove_cache_save) {
				cache_save = splaytree_delete(cache_save, hctx->hash);
				hctx->remove_cache_save = 0;
			}

			return HANDLER_GO_ON;
		} else {
			if (unlink(file->ptr) && errno != ENOENT) {
				log_error_write(srv, __FILE__, __LINE__, "sbss", "failed to delete old cache file",
						hctx->file, "before update", strerror(errno));
				if (hctx->remove_cache_save) {
					cache_save = splaytree_delete(cache_save, hctx->hash);
					hctx->remove_cache_save = 0;
				}

				return HANDLER_GO_ON;
			}
			if (p->conf.debug)
				log_error_write(srv, __FILE__, __LINE__, "sbs", "delete old cache file", file, "before update");
		}
	}

	/* create tmp file */
	buffer_copy_string_buffer(hctx->tmpfile, file);
 	buffer_append_string(hctx->tmpfile, ".");
 	buffer_append_long(hctx->tmpfile, random());

	if (-1 == (hctx->fd = open(hctx->tmpfile->ptr, O_WRONLY|O_EXCL|O_CREAT|O_BINARY, 0644))) {
		/* make sure directory existed */
		if (errno == ENOTDIR || errno == ENOENT) {
			if (mkdir_recursive(hctx->tmpfile->ptr, hctx->offset))
				return HANDLER_GO_ON;
			if (-1 == (hctx->fd = open(hctx->tmpfile->ptr, O_WRONLY|O_EXCL|O_CREAT|O_BINARY, 0644)))
				return HANDLER_GO_ON;
		} else return HANDLER_GO_ON;
	}

	update_memory_cache_file(con, hctx);

	return HANDLER_GO_ON;
}

handler_t
mod_cache_handle_response_filter(server *srv, connection *con, void *p_d)
{
	plugin_data *p = p_d;
	handler_ctx *hctx = con->plugin_ctx[p->id];

	if (hctx == NULL) return HANDLER_GO_ON;

	if (con->request.http_method == HTTP_METHOD_GET && hctx->error == 0) {
		if (hctx->use_memory && hctx->savecontent != NULL) {
#ifdef LIGHTTPD_V14
			if (copy_chunkqueue_to_memory(srv, hctx, con->write_queue) < 0) {
#else
			if (copy_chunkqueue_to_memory(srv, hctx, con->send) < 0) {
#endif
				log_error_write(srv, __FILE__, __LINE__, "s", "failed to save to memory storage");
				hctx->error = -1;
			}
		} else if(hctx->fd > 0) {
#ifdef LIGHTTPD_V14
			if (save_chunkqueue(hctx->fd, con->write_queue) < 0) {
#else
			if (save_chunkqueue(hctx->fd, con->send) < 0) {
#endif
				log_error_write(srv, __FILE__, __LINE__, "sbss", "failed to save cache file ",
						hctx->file, ":", strerror(errno));
				hctx->error = errno;
			}
		}
	}
	return HANDLER_GO_ON;
}

handler_t
mod_cache_cleanup(server *srv, connection *con, void *p_d)
{
	plugin_data *p = p_d;
	handler_ctx *hctx = con->plugin_ctx[p->id];
	off_t len;

	con->use_cache_file = 0;
	con->write_cache_file = 0;
	con->remove_range_request_header = 0;

	mod_cache_patch_connection(srv, con, p);

	if(hctx) {
		con->plugin_ctx[p->id] = NULL;
		if (hctx->use_memory == 1 && hctx->savecontent) {
			struct memory_cache *mc;
			if (hctx->error == 0 && con->state != CON_STATE_ERROR && 
				((hctx->savecontent->used == (con->response.content_length+1) || con->response.content_length == -1))) {
				mc = get_memory_cache(hctx);
				if (mc) {
					if (mc->content) {
						if (used_memory_size <= mc->content->size)
							used_memory_size = 0;
						else
							used_memory_size -= mc->content->size;
						mc->content->ref_count --; // remove share buffer flag
						buffer_free(mc->content);
						if (mc->inuse && memory_cache_number > 0)
							memory_cache_number --;
					}
					if (p->conf.debug)
						log_error_write(srv, __FILE__, __LINE__, "sbbs", "save http://", con->uri.authority, con->uri.path, "to memory");
					mc->content = hctx->savecontent;
					hctx->savecontent = NULL;
					mc->inuse = 1;
					memory_cache_number ++;
					mc->content->ref_count = 1; /* setup shared flag */
					used_memory_size += mc->content->size;
#ifdef LIGHTTPD_V14
					status_counter_set(srv, CONST_STR_LEN(CACHE_MEMORY), used_memory_size >> 20);
					status_counter_set(srv, CONST_STR_LEN(CACHE_MEMORY_ITEMS), memory_cache_number);
					status_counter_set(srv, CONST_STR_LEN(CACHE_LOCAL_ITEMS), local_cache_number);
#else
					COUNTER_SET(cache_memory, used_memory_size >> 20);
					COUNTER_SET(cache_memory_items, memory_cache_number);
					COUNTER_SET(cache_local_items, local_cache_number);
#endif
				}
			}
		} else if (hctx->fd > 0) {
			len = lseek(hctx->fd, 0, SEEK_CUR);
			close(hctx->fd);
			hctx->fd = 0;
			if (hctx->accepted_encoding_type > 0)
				buffer_copy_string_buffer(hctx->file, hctx->gzipfile);
			if (hctx->error == 0 && con->state != CON_STATE_ERROR &&
				((len == con->response.content_length) || con->response.content_length == -1)) {
				if (rename(hctx->tmpfile->ptr, hctx->file->ptr)) {
					log_error_write(srv, __FILE__, __LINE__, "sbsbs",
							"fail to rename", hctx->tmpfile, "to", hctx->file, strerror(errno));
					unlink(hctx->tmpfile->ptr);
					buffer_append_string(hctx->file, ASISEXT);
					unlink(hctx->file->ptr);
				} else {
					update_cache_change_time(hctx->file->ptr, hctx->mtime, srv->cur_ts);
					if (p->conf.debug)
						log_error_write(srv, __FILE__, __LINE__, "sb", "cache file saved successfully:", hctx->file);
				}
			} else {
				unlink(hctx->tmpfile->ptr);
				if (hctx->error)
					log_error_write(srv, __FILE__, __LINE__, "sbs",
							"sth is wrong while saving cache file, delete temporary file", hctx->tmpfile, strerror(hctx->error));
				else
					if(p->conf.debug)
						log_error_write(srv, __FILE__, __LINE__, "sb",
								"user or backend server terminates connection before finish, delete temporary file",
								hctx->tmpfile);
				buffer_append_string(hctx->file, ASISEXT);
				unlink(hctx->file->ptr);
			}
		}
		
		if (hctx->range_request && range_request)
			range_request = splaytree_delete(range_request, hctx->hash);
		if (hctx->remove_cache_save)
			cache_save = splaytree_delete(cache_save, hctx->hash);

		handler_ctx_free(hctx);
	}

	return HANDLER_GO_ON;
}

/* this function is called at dlopen() time and inits the callbacks */

int mod_cache_plugin_init(plugin *p) {
	p->version = LIGHTTPD_VERSION_ID;
	p->name = buffer_init_string("cache");
	
	p->init = mod_cache_init;
	p->handle_uri_clean = mod_cache_uri_handler;
	p->handle_docroot = mod_cache_docroot_handler;
#ifdef LIGHTTPD_V14
	p->handle_response_start = mod_cache_handle_response_start;
	p->handle_response_filter = mod_cache_handle_response_filter;
	p->handle_subrequest = mod_cache_handle_memory_storage;
#else
	p->handle_response_header = mod_cache_handle_response_start;
	p->handle_filter_response_content = mod_cache_handle_response_filter;
	p->handle_start_backend = mod_cache_handle_memory_storage;
#endif
	p->handle_connection_close = mod_cache_cleanup;
	p->connection_reset = mod_cache_cleanup;
	p->set_defaults  = mod_cache_set_defaults;
	p->cleanup = mod_cache_free;
	
	p->data = NULL;

	return 0;
}
