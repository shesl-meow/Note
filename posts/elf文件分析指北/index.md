---
title: ":moyai:Elf文件分析指北"
date: 2019-08-29T22:27:32+08:00
tags: ["Linux", "服务端", "信息安全", "C++"]
---

> 参考：
>
> - <https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/>
> - <https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/>
> - <https://lief.quarkslab.com/doc/stable/tutorials/05_elf_infect_plt_got.html>
> - <http://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-v.html>
> - <http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html>
> - <https://stackoverflow.com/questions/34966097/what-functions-does-gcc-add-to-the-linux-elf>

## 文件格式

ELF is the abbreviation for **Executable and Linkable Format** and defines the structure for binaries, libraries, and core files. 

The formal specification allows the operating system to interpreter its underlying machine instructions correctly. ELF files are typically the output of a compiler or linker and are a binary format. With the right tools, such file can be analyzed and better understood.

Due to the extensible design of ELF files, the structure differs per file. An ELF file consists of:

1. ELF header

2. File data which consist of three parts:

   1. Program Headers or `Segments (9)`

   2. Section Headers or `Sections (28)`

   3. Data



## ELF Header

With the `readelf` command, we can look at the structure of a file and it will look something like this:

```bash
$ readelf -h ret2dlresolve
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           Intel 80386
  Version:                           0x1
  Entry point address:               0x4b0
  Start of program headers:          52 (bytes into file)
  Start of section headers:          6216 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         9
  Size of section headers:           40 (bytes)
  Number of section headers:         29
  Section header string table index: 28
```

下面依次解释上面从 `readelf` 中读取出来的信息：

### Magic

As can be seen in this screenshot, the ELF header starts with some magic. 

This ELF header magic provides information about the file. The first 4 hexadecimal parts define that this is an ELF file (45=`E`, 4c=`L`, 46=`F`), prefixed with the **7f** value.

This ELF header is mandatory. It ensures that data is correctly interpreted during linking or execution. To better understand the inner working of an ELF file, it is useful to know this header information is used.

### Class

After the ELF type declaration, there is a Class field defined. This value determines the architecture for the file. It can a **32-bit** (=01) or **64-bit** (=02) architecture.

The magic shows a 01, which is translated by the `readelf` command as an `ELF32` file. In other words, an ELF file using the 32-bit architecture. Not surprising, as this particular machine contains a modern CPU.

### Data

Next part is the data field. It knows two options: 01 for **LSB** ([Least Significant Bit](https://en.wikipedia.org/wiki/Least_significant_bit)), also known as little-endian. Then there is the value 02, for **MSB** (Most Significant Bit, big-endian). 

This particular value helps to interpret the remaining objects correctly within the file. This is important, as different types of processors deal differently with the incoming instructions and data structures. In this case, LSB is used, which is common for AMD64 type processors.

### Version

Currently, there is only 1 version type: currently, which is the value “01”. So nothing interesting to remember.

### OS/ABI

Each operating system has a big overlap in common functions. In addition, each of them has specific ones, or at least minor differences between them. The definition of the right set is done with an **Application Binary Interface** ([ABI](https://en.wikipedia.org/wiki/Application_binary_interface)). This way the operating system and applications both know what to expect and functions are correctly forwarded. These two fields describe what ABI is used and the related version.

In this case, the value is 00, which means no specific extension is used.

### ABI version

When needed, a version for the ABI can be specified.

### Machine

We can also find the expected machine type (AMD64) in the header.

### Type

The **type** field tells us what the purpose of the file is. There are a few common file types.

- CORE (value 4)
- DYN (Shared object file), for libraries (value 3)
- EXEC (Executable file), for binaries (value 2)
- REL (Relocatable file), before linked into an executable file (value 1)

## File Data

Before we dive into these headers, it is good to know that ELF has two complementary “views”:

1. One is to be used for the linker to allow execution (segments). 

2. The other one for categorizing instructions and data (sections).

So depending on the goal, the related header types are used. Let’s start with program headers, which we find on ELF binaries.

### Segments (Program Headers)

An ELF file consists of zero or more segments, and describe how to create a process/memory image for runtime execution. 

When the kernel sees these segments, it uses them to map them into virtual address space, using the `mmap(2)` system call. In other words, it converts predefined instructions into a memory image. If your ELF file is a normal binary, it requires these program headers. Otherwise, it simply won’t run. It uses these headers, with the underlying data structure, to form a process. This process is similar for shared libraries.

可以用 `readelf` 命令 `--segments` 参数或者 `--program-headers` 参数查看程序头信息：

```bash
$ readelf --segments ./ret2dlresolve

Elf file type is DYN (Shared object file)
Entry point 0x4b0
There are 9 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x00000034 0x00000034 0x00120 0x00120 R   0x4
  INTERP         0x000154 0x00000154 0x00000154 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x00000000 0x00000000 0x008b0 0x008b0 R E 0x1000
  LOAD           0x000ec4 0x00001ec4 0x00001ec4 0x00144 0x00148 RW  0x1000
  DYNAMIC        0x000ecc 0x00001ecc 0x00001ecc 0x000f8 0x000f8 RW  0x4
  NOTE           0x000168 0x00000168 0x00000168 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x000760 0x00000760 0x00000760 0x0003c 0x0003c R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
  GNU_RELRO      0x000ec4 0x00001ec4 0x00001ec4 0x0013c 0x0013c R   0x1

 Section to Segment mapping:
  Segment Sections...
   00
   01     .interp
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rel.dyn .rel.plt .init .plt .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame
   03     .init_array .fini_array .dynamic .got .data .bss
   04     .dynamic
   05     .note.ABI-tag .note.gnu.build-id
   06     .eh_frame_hdr
   07
   08     .init_array .fini_array .dynamic .got
```

我们看到上面一共有九个程序头，我们只看其中的两个比较重要的信息：

1. `GNU_EH_FRAME`：这里存储着  `gcc` 的一个队列，它里面存储的是处理程序异常的句柄。程序异常时，这个区域会正确处理这些异常；
2. `GNU_STACK`：这里时程序的栈区信息。可以看到栈区时只是可读可写的。

### Sections (Sections Headers)

Sections can be found in an ELF binary after the GNU C compiler transformed C code into assembly, followed by the GNU assembler, which creates objects of it.

同样的我们也可以用 `readelf` 命令的 `--sections` 参数或 `--sections-headers` 参数查看程序的节头信息：

```bash
$ readelf --sections ./ret2dlresolve
There are 29 section headers, starting at offset 0x1848:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        00000154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            00000168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            00000188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        000001ac 0001ac 000020 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          000001cc 0001cc 0000d0 10   A  6   1  4
  [ 6] .dynstr           STRTAB          0000029c 00029c 0000bc 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          00000358 000358 00001a 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         00000374 000374 000030 00   A  6   1  4
  [ 9] .rel.dyn          REL             000003a4 0003a4 000050 08   A  5   0  4
  [10] .rel.plt          REL             000003f4 0003f4 000028 08  AI  5  22  4
  [11] .init             PROGBITS        0000041c 00041c 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        00000440 000440 000060 04  AX  0   0 16
  [13] .plt.got          PROGBITS        000004a0 0004a0 000010 08  AX  0   0  8
  [14] .text             PROGBITS        000004b0 0004b0 000292 00  AX  0   0 16
  [15] .fini             PROGBITS        00000744 000744 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        00000758 000758 000008 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        00000760 000760 00003c 00   A  0   0  4
  [18] .eh_frame         PROGBITS        0000079c 00079c 000114 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      00001ec4 000ec4 000004 04  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      00001ec8 000ec8 000004 04  WA  0   0  4
  [21] .dynamic          DYNAMIC         00001ecc 000ecc 0000f8 08  WA  6   0  4
  [22] .got              PROGBITS        00001fc4 000fc4 00003c 04  WA  0   0  4
  [23] .data             PROGBITS        00002000 001000 000008 00  WA  0   0  4
  [24] .bss              NOBITS          00002008 001008 000004 00  WA  0   0  1
  [25] .comment          PROGBITS        00000000 001008 00002b 01  MS  0   0  1
  [26] .symtab           SYMTAB          00000000 001034 000480 10     27  43  4
  [27] .strtab           STRTAB          00000000 0014b4 000297 00      0   0  1
  [28] .shstrtab         STRTAB          00000000 00174b 0000fc 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)
```

我们分析时可能关心以下几个比较重要的节头：

1. `.text`：该段包含的是可执行代码，该段中的数据只可读不可写，该段中的数据只加载一次。
2. `.data`：已被初始化的数据，可读可写。
3. `.rodata`：已被初始化的数据，只可读不可写。
4. `.bss`：未初始化数据，可读可写。

## Elf如何加载文件外的系统链接库

### 动态链接过程

此处详解以下动态链接过程中最重要的部分，`libc` 函数的链接过程。`libc` 中的函数，若使用动态链接，则关键的两个表项时 `.got` 表与 `.plt` 表，这种绑定方式又称为延迟绑定。

比如我们在某一个函数中进行了 `puts` 系统调用，在调用之前表结构大致如下：

```
                                                         
  .text sections       .plt table         .got table      
                                                          
 +--------------+    +---------------+   +------------------+   
 | [my_func]    |    | [puts@plt]    |   | [puts@got]       |   
 |              |    |               |   |                  |   
 | jmp 0x400480 ---->| jmp 0x601028  --->| 0x601028:0x400486--+  
 |              |    |               |   |                  | |  
 | ...          | +->| push 0x2      |   | ...              | |  
 +--------------+ |  |               |   +------------------+ |  
                  |  | jmp 0x400450  --+                      |  
                  |  |               | |                      |  
                  |  | ...           | |                      |  
                  |  +---------------+ |                      |  
                  +--------------------|----------------------+  
                +----------------------+                   
                |   +------------------+                  
                +-->|[_dl_resolve@plt] |                  
                    +------------------+                       
```

可见：

1. `.text` 段中任何对 `libc` 函数得调用，编译是只会将程序执行权交给 `.plt` 表；
2. `.plt` 表实际上是一段代码，`.got` 表实际上只是地址到地址的映射；
3. 一个函数对应的 `.plt` 表代码由三行组成：
   1. `.plt` 表的第一行指向 `.got` 表对应的位置；
   2. 如果函数第一次调用，`.got` 默认会指向 `.plt` 表的第二行；
   3. `.plt` 表的第二三行调用 `_dl_runtime_resolve` 函数，将实际的地址导入 `.got` 表中

也就是说，调用了之后，这三段结构会变成下面的结构：

```
                                                         
  .text sections      .plt table         .got table      
                                                         
 +--------------+   +---------------+   +--------------+ 
 | [my_func]    |   | [puts@plt]    |   | [puts@got]   | 
 |              |   |               |   |              | 
 | jmp 0x400480 --->| jmp 0x601028  --->| 0x601028:puts----->puts 
 |              |   |               |   |              | 
 | ...          |   | push 0x2      |   | ...          | 
 +--------------+   |               |   +--------------+ 
                    | jmp 0x400450  --+                  
                    |               | |                  
                    | ...           | |                  
                    +---------------+ |                  
                                      |                  
               +----------------------v                  
               |   +------------------+                  
               --->|[_dl_resolve@plt] |                  
                   +------------------+                  
```

### 动态链接节

在使用 `readelf` 命令查看一个程序的节列表时，类型为 `REL` 的节区包含重定位表项：

1. `.got` 节保存全局变量偏移表，`.got.plt` 节保存全局函数偏移表；`.plt` 节是过程链接表。过程链接表把位置独立的函数调用重定向到绝对位置。

2. `.rel.dyn` 节是用于变量重定位，`.rel.plt` 节是用于函数重定位。

   可以使用 `readelf` 命令的 `--relocs` 参数查看这两个节区的内容：

   ```bash
   $ readelf -r ./ret2dlresolve
   
   重定位节 '.rel.dyn' at offset 0x3a4 contains 10 entries:
    偏移量     信息    类型              符号值      符号名称
   00001ec4  00000008 R_386_RELATIVE   
   00001ec8  00000008 R_386_RELATIVE   
   00001ff8  00000008 R_386_RELATIVE   
   00002004  00000008 R_386_RELATIVE   
   00001fe4  00000306 R_386_GLOB_DAT    00000000   _ITM_deregisterTMClone
   00001fe8  00000406 R_386_GLOB_DAT    00000000   __cxa_finalize@GLIBC_2.1.3
   00001fec  00000506 R_386_GLOB_DAT    00000000   __gmon_start__
   00001ff0  00000906 R_386_GLOB_DAT    00000000   stdin@GLIBC_2.0
   00001ff4  00000a06 R_386_GLOB_DAT    00000000   stdout@GLIBC_2.0
   00001ffc  00000b06 R_386_GLOB_DAT    00000000   _ITM_registerTMCloneTa
   
   重定位节 '.rel.plt' at offset 0x3f4 contains 5 entries:
    偏移量     信息    类型              符号值      符号名称
   00001fd0  00000107 R_386_JUMP_SLOT   00000000   setbuf@GLIBC_2.0
   00001fd4  00000207 R_386_JUMP_SLOT   00000000   read@GLIBC_2.0
   00001fd8  00000607 R_386_JUMP_SLOT   00000000   strlen@GLIBC_2.0
   00001fdc  00000707 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
   00001fe0  00000807 R_386_JUMP_SLOT   00000000   write@GLIBC_2.0
   ```

3. `.dynsym` 节包含了动态链接符号表。可以用 `readelf` 命令的 `--symbols` 参数查看：

   ```bash
   $ readelf --symbols ./ret2dlresolve
   
   Symbol table '.dynsym' contains 13 entries:
      Num:    Value  Size Type    Bind   Vis      Ndx Name
        0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND 
        1: 00000000     0 FUNC    GLOBAL DEFAULT  UND setbuf@GLIBC_2.0 (2)
        2: 00000000     0 FUNC    GLOBAL DEFAULT  UND read@GLIBC_2.0 (2)
        3: 00000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTab
        4: 00000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.1.3 (3)
        5: 00000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
        6: 00000000     0 FUNC    GLOBAL DEFAULT  UND strlen@GLIBC_2.0 (2)
        7: 00000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.0 (2)
        8: 00000000     0 FUNC    GLOBAL DEFAULT  UND write@GLIBC_2.0 (2)
        9: 00000000     0 OBJECT  GLOBAL DEFAULT  UND stdin@GLIBC_2.0 (2)
       10: 00000000     0 OBJECT  GLOBAL DEFAULT  UND stdout@GLIBC_2.0 (2)
       11: 00000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
       12: 0000075c     4 OBJECT  GLOBAL DEFAULT   16 _IO_stdin_used
   ....
   ```

4. `.dynstr` 节包含了动态链接的字符串。这个节以 `\x00` 作为开始和结尾，中间每个字符串也以 `\x00` 间隔。

## `main` 函数是如何执行的

### `__libc_start_main` 函数流程

在介绍这一节之前可以需要先了解以下 Linux 程序是如何启动一个程序的。以下是 loader 的调用图：

![start_callgraph](./start_callgraph.png)

下面我们依次介绍以下整个程序运行的流程：

1. 在 `_start` 函数之前，Linux 进行了 `execuve()` 系统调用，在栈上布置好了 `argc`、`argv` 与 `envp` 参数，并且设置好了 `stdin`、`stdout`、`stderr`。

2. 在 `_start` 函数中，传入数个参数执行了 `__libc_start_main`，这个函数的原型如下：

   ```c
   int __libc_start_main(  int (*main) (int, char * *, char * *),
   			    int argc, char * * ubp_av,
   			    void (*init) (void),
   			    void (*fini) (void),
   			    void (*rtld_fini) (void),
   			    void (* stack_end));
   ```

   这些参数的含义分别是：

   1. `main`：程序的主进程，它的返回值最终会传递给 `exit` 函数，之后退出进程；
   2. `arcg`、`ubp_av`：`main` 函数传入的两个参数 `argc` 与 `argv`；
   3. `init`：`__libc_csu_init` 的地址，在 `main` 函数之前调用，程序的构造函数；
   4. `fini`：`__libc_csu_fini` 的地址，程序的析构函数；通过 `__cxat_exit` 函数注册；
   5. `rtld_fini`：动态链接段的析构函数；通过 `__cxat_exit` 函数注册；
   6. `stack_end`：栈的尾指针；

3. 然后程序在程序中按照上图的次序依次调用各个函数（这里先不细说了，详见 [LinuxProgramStart](http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html)）。

### `__libc_start_main` 节作用

那么这个过程中主要创建了哪些个节呢？

- 主要有三个：`preinit_array`、`init_array` 与 `fini_array`。
- 这三个节的本质都是一个**函数指针的数组**。它们存储的函数，会在程序运行的特定时刻，被执行。

下面分别介绍这三个节：

1. `.preinit_array`：其中的函数，会在程序的构造函数（一般指 `__libc_csu_init`）执行之前，被调用；
2. `.init_array`：其中的函数，会在程序构造函数执行之后，`main` 函数执行之前被执行。这个数组有一个默认就存在的函数 `frame_dummy`，它用于保护栈的运行与安全。
3. `.fini_array`：其中的函数，会在 `main` 函数执行之后被执行。glibc 中定义了一个函数 `__do_global_dtors_aux` 会在这个节未被定义时被默认执行，详见 [Stack Overflow](<https://stackoverflow.com/questions/34966097/what-functions-does-gcc-add-to-the-linux-elf>)。

当然，程序员在写 c 程序时可以自己向数组中添加元素：

```c
void init(int argc, char **argv, char **envp) {
 printf("%s\n", __FUNCTION__);
}

__attribute__((section(".init_array"))) typeof(init) *__init = init;
```


## PostScript: 分析工具

### `elfutils`

- /usr/bin/eu-addr2line
- /usr/bin/eu-ar – alternative to ar, to create, manipulate archive files
- /usr/bin/eu-elfcmp
- /usr/bin/eu-elflint – compliance check against gABI and psABI specifications
- /usr/bin/eu-findtextrel – find text relocations
- /usr/bin/eu-ld – combining object and archive files
- /usr/bin/eu-make-debug-archive
- /usr/bin/eu-nm – display symbols from object/executable files
- /usr/bin/eu-objdump – show information of object files
- /usr/bin/eu-ranlib – create index for archives for performance
- /usr/bin/eu-readelf – human-readable display of ELF files
- /usr/bin/eu-size – display size of each section (text, data, bss, etc)
- /usr/bin/eu-stack – show the stack of a running process, or coredump
- /usr/bin/eu-strings – display textual strings (similar to strings utility)
- /usr/bin/eu-strip – strip ELF file from symbol tables
- /usr/bin/eu-unstrip – add symbols and debug information to stripped binary

*Notes: the elfutils package is a great start, as it contains most utilities to perform analysis.*

### `elfkickers`

- /usr/bin/ebfc – compiler for [Brainfuck](https://en.wikipedia.org/wiki/Brainfuck) programming language
- /usr/bin/elfls – shows program headers and section headers with flags
- /usr/bin/elftoc – converts a binary into a C program
- /usr/bin/infect – tool to inject a dropper, which creates setuid file in /tmp
- /usr/bin/objres – creates an object from ordinary or binary data
- /usr/bin/rebind – changes bindings/visibility of symbols in ELF file
- /usr/bin/sstrip – strips unneeded components from ELF file

*Notes: the author of the ELFKickers package focuses on manipulation of ELF files, which might be great to learn more when you find malformed ELF binaries.*

### `pax-utils`

- /usr/bin/dumpelf – dump internal ELF structure
- /usr/bin/lddtree – like ldd, with levels to show dependencies
- /usr/bin/pspax – list ELF/PaX information about running processes
- /usr/bin/scanelf – wide range of information, including PaX details
- /usr/bin/scanmacho – shows details for Mach-O binaries (Mac OS X)
- /usr/bin/symtree – displays a leveled output for symbols

### 我习惯用的

```bash
# 查看文件头
$ readelf --file-header <program>

# 查看程序头
$ readelf --program-headers <program>

# 查看节头
$ readelf --section-headers <program>

# 查看动态链接的依赖
$ lddtree <program>
```

