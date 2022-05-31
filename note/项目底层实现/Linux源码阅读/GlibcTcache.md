---
title: "Tcache"
date: 2019-08-20T18:14:38+08:00
tags: [""]
categories: ["项目底层实现", "Linux源码阅读"]
---

> 参考资料：
>
> - <http://p4nda.top/2018/03/20/tcache/>
> - <https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/tcache_attack-zh/>


## 介绍

`tcache`，全称是 `thread local caching`，是 `libc 2.26` 版本中新增加的内存管理机制，属于一种用于加速 `malloc` 分配的缓存机制。

它由 64 个链表组成，处理逻辑位于 `malloc` 函数和 `free` 函数中，优先级较高，会先于全部的 `bin` 来处理，当缓存链表装满时，分配方式就与之前版本的 `malloc` 相同。

## 源码分析

### `tcache_entry` && `tcache_perthread_struct`

在 `tcache` 中新增了两个数据结构，它们的定义源码如下：

```c
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;
} tcache_entry;

/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  uint16_t counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

static __thread bool tcache_shutting_down = false;
static __thread tcache_perthread_struct *tcache = NULL;
```

可见源码中直接定义了一个后者的一个对象 `tcache`，假设前者有两个垃圾对象，其内存布局大致如下：

```
                                                                                       
     tcache_perthread_struct *tcache                                                   
                               |                                                       
                               |                                                       
                               v                                                       
      +---------------------------+---+                                                
 2*64 |    uint16_t counts[64]    | 0 |<----------------------------------------------+
      +--------------------------------                                               |
                                  | 2 |                                               |
                                  -----                                               |
                                  |...|                                               |
                                  -----                                               |
                                  | 0 |                                               |
                                  -----                                               |
                                  | 0 |                                               |
      +---------------------------+------+                                            |
 4*64 | tcache_entry *entries[64] | null |                                            |
      +-----------------------------------     +------------------------------+       |
                                  | ptr  |---->|      tcache_entry *next      |-+     |
                                  --------     -------------------------------- |     |
                                  | ...  |     | tcache_perthread_struct *key |-|-----+
                                  --------     +------------------------------+ |     |
                                  | null |  +-----------------------------------+     |
                                  --------  |  +------------------------------+       |
                                  | null |  +->|      tcache_entry *next      |->null |
                                  +------+     --------------------------------       |
                                               | tcache_perthread_struct *key |-------+
                                               +------------------------------+        
```

### `tcache_get` && `tcache_put`

两个比较重要的函数，`tcache_get()` 与 `tcache_put()`：

```c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  e->key = NULL;
  return (void *) e;
}
```

- 前者将一个元素插入了单向链表的头部，并且将对应位置的 `counts` 大小自增一；
- 后者单向链表头部节点取出并返回，并且将对应位置的 `counts` 大小自减一。

### `_int_free`

在内存释放的 `free` 函数中，对 `tcache` 的相关调用只有以下的一处，该处在函数的最开始执行：

```c
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
	/* Check to see if it's already in the tcache.  */
	tcache_entry *e = (tcache_entry *) chunk2mem (p);

	/* This test succeeds on double free.  However, we don't 100%
	   trust it (it also matches random payload data at a 1 in
	   2^<size_t> chance), so verify it's not an unlikely
	   coincidence before aborting.  */
	if (__glibc_unlikely (e->key == tcache))
	  {
	    tcache_entry *tmp;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = tmp->next)
	      if (tmp == e)
		malloc_printerr ("free(): double free detected in tcache 2");
	    /* If we get here, it was a coincidence.  We've wasted a
	       few cycles, but don't abort.  */
	  }

	if (tcache->counts[tc_idx] < mp_.tcache_count)
	  {
	    tcache_put (p, tc_idx);
	    return;
	  }
      }
  }
#endif
```

可见，在执行 `tcache_put` 操作之前，函数主要进行了三个检测：

1. 当前的 `tcache` 存在，并且目标块的大小在范围内；
2. 目标块的 `key` 是否指向了 `tcache`，若已经指向了目标地址，则有可能是 `Double Free`；
3. 目标的垃圾箱链表长度是否已经达到上限（源码中将上限定义为 7）。

### `_int_malloc`

而在内存分配的 `malloc` 函数中，对 `tcache` 的调用有五处，根据 `ctf-wiki` 中的介绍，主要有以下的几点：

1. 首先，申请的内存块符合 `fastbin` 大小时并且找到在 `fastbin` 内找到可用的空闲块时，会把该 `fastbin` 链上的其他内存块放入 `tcache` 中。

2. 其次，申请的内存块符合 `smallbin` 大小时并且找到在 `smallbin` 内找到可用的空闲块时，会把该 `smallbin` 链上的其他内存块放入 `tcache` 中。
3. 当在 `unsorted bin` 链上循环处理时，当找到大小合适的链时，并不直接返回，而是先放到 `tcache` 中，继续处理。
