---
title: "exe2"
date: 2019-12-03T13:41:00+08:00
tags: [""]
categories: ["系统理论课程", "操作系统"]
---


## 代码

### `_fifo_map_swappable`

FIFA 算法需要将最近使用过的页链接在链表的头部。

看注释，这个函数是要将刚刚使用过的 page 放在链表的第二个元素。程序已经将链表和元素都选取出来了：

```c
list_entry_t *head=(list_entry_t*) mm->sm_priv;
list_entry_t *entry=&(page->pra_page_link);
```

因此我们只需要调用 `list_entry_t` 中的方法即可：

```c
list_add(head, entry);
```

### `_fifo_swap_out_victim`

FIFA 算法需要将最长时间未使用过的页从链表的尾部去除。

看注释我们需要做的事情是删除尾部，并且用 `ptr_page` 这个参数指向被替换的页：

```c
static int
_fifo_swap_out_victim(struct mm_struct *mm, struct Page ** ptr_page, int in_tick)
{
    list_entry_t *head=(list_entry_t*) mm->sm_priv;
    assert(head != NULL && in_tick==0);
    list_entry_t *tail = head->prev;            // Select the victim
    assert(tail != head);                       // this isn't a one-element-list
    *ptr_page = le2page(tail, pra_page_link);   // (2)  assign the value of *ptr_page to the addr of this page
    list_del(tail);                             // (1)  unlink the  earliest arrival page in front of pra_list_head qeueue
    assert(*ptr_page != NULL);
    return 0;
}
```

### `do_pgfault`

~~惯例先翻译注释~~：

- 经过 exe1 的流程，我们可以认为变量 `ptep` 是一个待替换的页表项。
- 现在我们需要把这个页表项对应磁盘中的内容加载到内存中来，然后将逻辑地址映射到这个页表项中，同时触发之前更改的 FIFO 的页表替换逻辑。

## 问题

> 如果要在ucore上实现"extended clock页替换算法"请给你的设计方案，现有的 swap_manager框架是否足以支持在ucore中实现此算法?如果是，请给你的设计方案。 如果不是，请给出你的新的扩展和基此扩展的设计方案。并需要回答如下问题：

> 需要被换出的页的特征是什么? 

访问标志位和修改标志位都为 0 时；

> 在 ucore 中如何判断具有这样特征的页? 

访问标志位：PTE_A；修改标志位：PTE_D；

> 何时进行换入和换出操作? 

换入是在缺页异常的时候，换出是在物理页帧满的时候
