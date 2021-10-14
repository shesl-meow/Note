# ElfSections

> 参考：
>
> * [https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/](https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/)
> * [https://lief.quarkslab.com/doc/stable/tutorials/05\_elf_infect_plt_got.html](https://lief.quarkslab.com/doc/stable/tutorials/05\_elf_infect_plt_got.html)
> * [http://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-v.html](http://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-v.html)
> * [http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html](http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html)
> * [https://stackoverflow.com/questions/34966097/what-functions-does-gcc-add-to-the-linux-elf](https://stackoverflow.com/questions/34966097/what-functions-does-gcc-add-to-the-linux-elf)

## Elf Sections

### 常见节

我们分析以下几个比较重要的节头：

1. `.text`：该段包含的是可执行代码，该段中的数据只可读不可写，该段中的数据只加载一次。
2. `.data`：已被初始化的数据，可读可写。
3. `.rodata`：已被初始化的数据，只可读不可写。
4. `.bss`：未初始化数据，可读可写。

### 链接相关

#### 动态链接过程

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

#### 动态链接节

在使用 `readelf` 命令查看一个程序的节列表时，类型为 `REL` 的节区包含重定位表项：

1. `.got` 节保存全局变量偏移表，`.got.plt` 节保存全局函数偏移表；`.plt` 节是过程链接表。过程链接表把位置独立的函数调用重定向到绝对位置。
2.  `.rel.dyn` 节是用于变量重定位，`.rel.plt` 节是用于函数重定位。

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
3.  `.dynsym` 节包含了动态链接符号表。可以用 `readelf` 命令的 `--symbols` 参数查看：

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

### `_start` 相关

#### `__libc_start_main` 函数流程

在介绍这一节之前可以需要先了解以下 Linux 程序是如何启动一个程序的。以下是 loader 的调用图：

![\_start_callgraph](../../.gitbook/assets/\_start_callgraph.png)

下面我们依次介绍以下整个程序运行的流程：

1. 在 `_start` 函数之前，Linux 进行了 `execuve()` 系统调用，在栈上布置好了 `argc`、`argv` 与 `envp` 参数，并且设置好了 `stdin`、`stdout`、`stderr`。
2.  在 `_start` 函数中，传入数个参数执行了 `__libc_start_main`，这个函数的原型如下：

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

#### `__libc_start_main` 节作用

那么这个过程中主要创建了哪些个节呢？

* 主要有三个：`preinit_array`、`init_array` 与 `fini_array`。
* 这三个节的本质都是一个**函数指针的数组**。它们存储的函数，会在程序运行的特定时刻，被执行。

下面分别介绍这三个节：

1. `.preinit_array`：其中的函数，会在程序的构造函数（一般指 `__libc_csu_init`）执行之前，被调用；
2. `.init_array`：其中的函数，会在程序构造函数执行之后，`main` 函数执行之前被执行。这个数组有一个默认就存在的函数 `frame_dummy`，它用于保护栈的运行与安全。
3. `.fini_array`：其中的函数，会在 `main` 函数执行之后被执行。glibc 中定义了一个函数 `__do_global_dtors_aux` 会在这个节未被定义时被默认执行，详见 [Stack Overflow](https://stackoverflow.com/questions/34966097/what-functions-does-gcc-add-to-the-linux-elf%3E)。

当然，程序员在写 c 程序时可以自己向数组中添加元素：

```c
void init(int argc, char **argv, char **envp) {
 printf("%s\n", __FUNCTION__);
}

__attribute__((section(".init_array"))) typeof(init) *__init = init;
```
