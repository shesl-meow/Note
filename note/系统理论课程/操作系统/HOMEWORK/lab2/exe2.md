---
title: "exe2"
date: 2019-11-24T22:24:42+08:00
tags: [""]
categories: ["系统理论课程", "操作系统"]
---


## 概述

> 通过设置页表和对应的页表项，可建立虚拟内存地址和物理内存地址的对应关系。其中的 `get_pte` 函数是设置页表项环节中的一个重要步骤。此函数找到一个虚地址对应的二级页表项 的内核虚地址，如果此二级页表项不存在，则分配一个包含此项的二级页表。
>
> 本练习需要补全`kern/mm/pmm.c` 文件中的 `get_pte` 函数，实现其功能。请仔细查看和理解 `get_pte` 函数中的注释。 

函数原型如下：

```c
pte_t *get_pte(pde_t *pgdir, uintptr_t la, bool create);
```

~~我们先来翻译一下这个函数的注释~~：

函数 `get_pte` 的相关注释：

- 作用：通过页目录项和逻辑地址，取得对应的页表；如果页表不存在则会分配这个页表；
- 参数：`pgdir`：页目录项；`la`：逻辑地址；`create`：是否创建新的页表；
- 返回值：内核对应页表的虚拟地址。

在对应的头文件 `pmm.h` 与 `mmu.h` 中，定义了一些你可能会用到宏和函数：

- `PDX(la)`：通过一个进程的虚拟逻辑地址，求得一个页目录项的索引；
- `PTX(la)`：通过一个进程的虚拟逻辑地址，求得一个页表项的索引；
- `KADDR(pa)`：通过一个物理地址，返回一个对应的内核虚拟地址；
- `set_page_ref(page, 1)`：将页的引用计数加一；
- `page2pa(page)`：通过一个页表项，得到它实际的物理地址；
- `struct Page * alloc_page()`：分配一个内存页；
- `memset(void *s, char c, size_t n)`：将指针 `s` 之后的 `n` 个区域的内容设置为 `c`；
- `PTE_P`：存在；`PTE_W`：写；`PTE_U`：读。

## 问题一

> 请描述页目录项 (Page Directory Entry) 和页表 (Page Table Entry) 中每个组成部分的含义和以及对 ucore 而言的潜在用处。

因为页目录项、页表、物理地址对应的起始地址都要求按照 4096 比特对齐。因此：

- 页目录项的高 20 位用于存储页表的实际物理地址；

  页表项的高 20 位用于存储虚拟地址对应的真实物理地址；

- 页目录项和页表项的低 12 位都用于存储一些标志位，详细的内容列举在了 `./kern/mm/mmu.h` 这个文件中。

## 问题二

> 如果 ucore 执行过程中访问内存，出现了页访问异常，请问硬件要做哪些事情？

进行换页操作：

- 首先 CPU 将产生页访问异常的线性地址放到 cr2 寄存器中
- 然后就是和普通的中断一样保护现场，将寄存器的值压入栈中，然后压入 `error_code` 中断服务例程将外存的数据换到内存中来
- 最后退出中断，回到进入中断前的状态

## 代码


