> 参考：长亭科技堆的概念

# 堆基础

堆的一些特点：

- 堆是可以根据运行时的需要进行动态分配和释放的内存，大小可变；
- 堆的实现重点关注内存块的组织和管理方式（尤其时空闲的内存块）：
  - 如何提高分配和释放的时间效率；
  - 如何降低碎片化，提高空间利用率；

常见堆的实现：

- `dlmalloc`：通用分配器；
- **`ptmalloc2`：`glibc` 函数，基于 `dlmalloc`，支持多线程**；
- `jemalloc`：`FreeBSD`、`FireFox`、`Android`；
- `tcmalloc`：`Google Chrome`；
- `libumem`：`Solaris`；
- `Windows 10`：`segment heap`。

# glibc heap

## 相关结构

下面介绍管理 `glic` 堆的各种数据结构：

### `arena`

`arena` 指的是内存区域本身，并非一个结构：

1. 主线程的堆由 `sbrk` 创建，称为 **`main arena`**；
2. 其他线程的堆由 `mmap` 创建，称为 **`per thread arena`**；

`arena` 的数量受 CPU 核数的限制：

- 对于 32 位系统：`数量上限 = 2 * 核数`
- 对于 64 位系统：`数量上限 = 8 * 核数`

### `malloc_state`

它是管理 `arena` 的核心结构，其定义在 `glibc`  源码的 `/malloc/malloc.c` 这个文件中：

```c
struct malloc_state
{
  /* Serialize access.  */
  __libc_lock_define (, mutex);

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Set if the fastbin chunks contain recently inserted free blocks.  */
  /* Note this is a bool but not all targets support atomics on booleans.  */
  int have_fastchunks;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};
```

同样在文件 `/malloc/malloc.c` 中，定义了全局变量 `main_arena` 管理主线程的 `malloc_state`：

```c
static struct malloc_state main_arena =
{
  .mutex = _LIBC_LOCK_INITIALIZER,
  .next = &main_arena,
  .attached_threads = 1
};
```

### `malloc_chunks`

内存块的结构，`glibc` 源码的 `./malloc/malloc.c` 这个文件中定义：

```c
struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

空闲内存块的结构大致如下（字段右侧为32 位平台下的比特位长）：

<img src="./free_chunk.jpg" width=50% >

1. 第一个字段 `prev_size` 存储了，物理地址上的前一个 `chunk` 的大小。
2. 第二个字段 `size` 记录了当前 `chunk` 的大小。最后三个比特位被用作其他含义：
   1. `P` 代表 `PREV_INUSE`，指明前一个 `chunk` 是否被使用；
   2. `M` 代表 `IS_MAPPED`，代表当前的 `chunk` 是否通过 `mmap` 方式创建出来的；
   3. `N` 代表 `NON_MAIN_ARENA`，代表当前 `chunk` 是否属于其他线程堆（主线程值为 0）；
3. 第三四个字段为前向指针与后向指针，这两个字段用于 `bin` 链表中。

已分配内存块的结构大致如下：

<img src="./allocated_chunk.jpg" width=70% >

1. 前两个字段与空闲的内存块大致相同；
2. 用户可用的数据是第三个字段开始一直到下一个 `chunk` 的第一个字段。这是因为：
   - `prev_size` 只有当前一个字段是空闲的时候才有意义，如果前一个字段已经分配，堆管理器不关心；
3. 在 32 位平台下，`chunk` 的大小一定是 8 字节的整数倍（所以 `size` 的最低三个比特位是无用的）。`malloc` 返回地址指针为 `data` 的起始位置。

### `fastbins`

`bins` 是根据 `chunk` 的大小和状态，用来管理和组织空闲块的，链表的数组结构。

`fastbins` 用于管理最小的 `chunk`。他存储在了 `malloc_state` 中的数组变量 `fastbinsY` 中。它同样定义在 `/malloc/malloc.c` 这个文件中：

```c
/*
   Fastbins

    An array of lists holding recently freed small chunks.  Fastbins
    are not doubly linked.  It is faster to single-link them, and
    since chunks are never removed from the middles of these lists,
    double linking is not necessary. Also, unlike regular bins, they
    are not even processed in FIFO order (they use faster LIFO) since
    ordering doesn't much matter in the transient contexts in which
    fastbins are normally used.

    Chunks in fastbins keep their inuse bit set, so they cannot
    be consolidated with other free chunks. malloc_consolidate
    releases all chunks in fastbins and consolidates them with
    other free chunks.
 */

typedef struct malloc_chunk *mfastbinptr;
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])
```

可以得出它有以下这些特点：

1. 它是一个单向链表（因为从来不会需要从中间移除元素的操作，不需要双向链表）；
2. 后进先出（其他的垃圾回收结构是先进先出）；
3. `chunk` 被清理时，`PREV_INUSE` 标志位不会被清零；
4. 32 位系统中，`fastbin` 中默认支持最大的 chunk 的数据空间大小为 64 字节。但是 `glibc` 可以支持的 chunk 的数据空间最大为 80 字节。
5. 一共有十个 `fastbins`；
6. 相邻的空闲的 `fastbin chunk` 不会被合并。

下面是一个 32 位程序在运行时的 `fastbins` 示例图：

<img src="./fastbins_example.jpg">

### `bins` (`small & large & unsorted`)

源码中有一段注释解释这些 `bins`：

```c
/*
   Bins

    An array of bin headers for free chunks. Each bin is doubly
    linked.  The bins are approximately proportionally (log) spaced.
    There are a lot of these bins (128). This may look excessive, but
    works very well in practice.  Most bins hold sizes that are
    unusual as malloc request sizes, but are more usual for fragments
    and consolidated sets of chunks, which is what these bins hold, so
    they can be found quickly.  All procedures maintain the invariant
    that no consolidated chunk physically borders another one, so each
    chunk in a list is known to be preceeded and followed by either
    inuse chunks or the ends of memory.

    Chunks in bins are kept in size order, with ties going to the
    approximately least recently used chunk. Ordering isn't needed
    for the small bins, which all contain the same-sized chunks, but
    facilitates best-fit allocation for larger chunks. These lists
    are just sequential. Keeping them in order almost never requires
    enough traversal to warrant using fancier ordered data
    structures.

    Chunks of the same size are linked with the most
    recently freed at the front, and allocations are taken from the
    back.  This results in LRU (FIFO) allocation order, which tends
    to give each chunk an equal opportunity to be consolidated with
    adjacent freed chunks, resulting in larger free chunks and less
    fragmentation.

    To simplify use in double-linked lists, each bin header acts
    as a malloc_chunk. This avoids special-casing for headers.
    But to conserve space and improve locality, we allocate
    only the fd/bk pointers of bins, and then use repositioning tricks
    to treat these as the fields of a malloc_chunk*.
 */
```

其中 `small bins` 有以下的特点：

1. `chunk` 的大小小于 512 字节；
2. 共有 62 个双向循环链表，每个链表中存储着相同大小的 `chunk`；
3. 先进先出；
4. 当有相邻的空闲内存块时，`chunk` 会被合并成一个更大的 `chunk`。

`large bins` 有以下的特点：

1. `chunk` 的大小大于 512 字节；
2. 共有 63 个双向循环链表，大小相近的 `chunk` 放在同一个 `bin` 中；
3. `chunk` 按照大小从大到小排序；
4. 先进先出；
5. 当有相邻的空闲内存块时，`chunk` 会被合并成一个更大的 `chunk`。

`unsorted bins` 有以下的特点：

1. `chunk` 的大小大于 64 个字节；
2. 只有唯一一个双向循环链表；
3. 当一个非 `fastbin` 的 `chunk` 被释放之后，它首先被放入 `unsorted bin` 等后续整理时，才会放入对应的 `small bin/fast bin`。

这三个 `bins` 共享一个 `malloc_state` 中的变量：

```c
/* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];
```

其中三种 `bins` 的排列大致如下图所示：

<img src ="./arena.bins_structure.jpg" />

## 相关函数

### `malloc()`

工作流程：

1. 在 `fast bins` 中寻找 `fast chunk`，如果找到则结束；
2. 在 `small bins` 中寻找 `small chunk`，如果找到则结束；
3. 循环：
   1. 检查 `unsorted bin` 中的 `last_remainder`。如果它足够大大则分配这个 `chunk`，并将剩余的 `chunk` 标记为新的 `last_remainer`；
   2. 在 `unsorted bin` 中搜索，同时进行整理。如果遇到精确大小则返回，否则将 `chunk` 整理到它对应大小的 `small/large bins` 中去；
   3. 在 `small bin` 和 `large bin` 中搜索最合适的 `chunk`（不一定精确）；
4. 使用 `top chunk`。

### `free()`

工作流程：

1. 如果是 `fast chunk`，则放入 `fast bin`；
2. 如果前一个 `chunk` 是空闲的：
   1. `unlink` 前面的 `chunk`；
   2. 合并两个 `chunk`，并且放入 `unsorted bin`；
3. 如果后一个 `chunk` 是 `top chunk`，则将当前 `chunk` 并入 `top chunk`；
4. 如果后一个 `chunk` 是空闲的：
   1. `unlink` 后面的 `chunk`；
   2. 合并两个 `chunk`，并且放入 `unsorted bin`；
5. 前后两个 `chunk` 都不是空闲的，直接放入 `unsorted bin`；

