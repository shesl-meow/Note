---
title: "Use After Free"
date: 2019-08-26T23:35:49+08:00
tags: [""]
categories: ["工具使用接口", "CTF-WriteUp"]
---

> 题目：Hitcon Training lab10


## 文件信息

检查文件安全性：

```bash
$ checksec ./hacknote
[*] '/mnt/d/program/ctf/ctf-wiki/useafterfree/hacknote'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

程序没有开启地址随机化，有栈保护和堆栈不可执行。

## 程序逻辑

这个可执行文件中存在函数的调式信息，`main` 函数就是打印菜单，然后执行几个选项的常规套路。

### `menu`

```c
int menu()
{
  puts("----------------------");
  puts("       HackNote       ");
  puts("----------------------");
  puts(" 1. Add note          ");
  puts(" 2. Delete note       ");
  puts(" 3. Print note        ");
  puts(" 4. Exit              ");
  puts("----------------------");
  return printf("Your choice :");
}
```

可见输出四个数字对应的功能。

### `add_note`

简单的分配地址的功能。通过阅读源码实现逻辑，存储结构大致如下：

```c
struct Note{
    void (*func_ptr)(int);	// 指向了 `print_note_content` 的函数地址
    char *buffer;			// 用户通过指定一个 `size` 读入的内容
};

Note notlist[5];
```

### `del_note`

删除笔记：

```c
unsigned int del_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( notelist[v1] )
  {
    free(*((void **)notelist[v1] + 1));
    free(notelist[v1]);
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

需要注意的是，这里的笔记内存被释放后，并没有清空指针。这有可能导致 `UAF` 漏洞或 `Double Free` 漏洞。

### `print_note`

因为没有清空指针会导致的 `UAF` 漏洞即在此处发生。

```c
unsigned int print_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( notelist[v1] )
    (*(void (__cdecl **)(void *))notelist[v1])(notelist[v1]);
  return __readgsdword(0x14u) ^ v3;
}
```

它的程序逻辑是读入一个 `index`，调用对应位置第一个内容存储的 `print_note_content` 函数，将内容打印出来。

### `magic`

比较有意思的是从函数表中还可以看到这样一个没有被调用的函数：

```c
int magic()
{
  return system("cat flag");
}
```

据此我们就大概可以猜测到，破解的思路应该是执行 `magic` 函数即可。

### 漏洞利用

根据之前的阅读源码很显然这是一个 `UAF` 漏洞。我们


