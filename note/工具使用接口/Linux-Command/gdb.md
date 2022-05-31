---
title: "gdb"
date: 2022-05-31T12:50:56+08:00
tags: [""]
categories: ["工具使用接口", "Linux-Command"]
---


## Quick Manual

常用命令:

1. 列出程序中的所有变量名（`gdb`）：

   ```bashs
   (gdb) info variables
   ```

2. 列出程序中的所有函数名（`gdb`）：

   ```bash
   (gdb) info functions
   ```

3. 列出一个函数的汇编代码（`gdb`）：

   ```bash
   (gdb) disas main
   ```

4. 查看指定地址内的字符串（`gdb`）：

   ```bash
   (gdb) x /s <memory_address>
   ```

5. 查看各个程序段的读写执行权限（`gdb`：`gef` 插件或 `peda` 插件都支持）

   ```bash
   (gdb-peda) vmmap
   ```

6. 查看堆的信息以及按结构解析堆：

   ```
   (gdb-peda) heapinfo
   
   (gdb-peda) parseheap
   ```

## PEDA

插件 `PEDA`（Python Exploit Development Assistance for GDB）

使用以下命令安装：

```bash
$ git clone https://github.com/longld/peda

$ echo "souce `pwd`/peda/peda.py" >> ~/.gdbinit
```

这个插件将会在开启 `gdb` 之后注入一些命令，以下是一些常用命令：

| 命令                    | 功能                                                         |
| ----------------------- | ------------------------------------------------------------ |
| `aslr`                  | 检测程序地址随机化是否开启/设置地址随机化                    |
| `checksec`              | 检测程序开启的安全保护                                       |
| `dumpargs`              | 显示执行程序是的命令行参数                                   |
| `elfheader`/`readelf`   | 检测 ELF 文件的文件头信息                                    |
| `elfsymbol`             | 显示文件中包含的所有非调式信息                               |
| `lookup`                | 查找一个给定地址范围内中，所有被引用的信息                   |
| `patch`                 | 在一段地址之前通过 `字符串/十六进制/整数` 的方式，添加一段数据 |
| `pattern`               | 在内存中，生成/查找/写入 一个循环模式                        |
| `procinfo`              | 显示从 `/proc/pid` 中得到的信息                              |
| `pshow`/`pset`          | 显示/设置 `peda` 的属性参数                                  |
| `ropgadget`/`ropsearch` | 显示所有的 `ROP` 链/查找给定的 `ROP` 链                      |
| `searchmem`/`find`      | 在二进制文件中，查找一个指定的正则表达式                     |
| `shellcode`             | 生成或下载常用的 `shellcode`                                 |
| `xormem`                | 对一段给定的地址范围进行异或操作                             |
