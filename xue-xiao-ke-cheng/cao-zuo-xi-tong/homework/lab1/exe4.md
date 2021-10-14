# exe4

> 分析 bootloader 加载 ELF 格式的 OS 的过程

## `bootmian.c`

~~让我们简单地翻译一下这个文件的注释：~~

磁盘内存布局：

* 这个程序是一个启动加载器 (`bootloader`)，它应该在磁盘的第一个扇区上；
* 紧接着的第二个扇区存储着内核的镜像，它必须是一个 ELF 格式的文件。

启动的流程：

1. 当 CPU 启动时，它首先将 BIOS 加载进内存中，然后执行它；
2. 然后 BIOS 会初始化中断周期，然后取出启动程序的第一个选区然后跳转到它；
3. 如果启动加载器存储在第一个扇区，控制权就转移到了这个文件中的代码（具体是在 `bootasm.S` 这个文件中调用的 `bootmain()` 这个函数）；
4. 当这个文件中的函数执行完毕之后，内核会被读入，控制权会被转移给内核。

## 问题一

> Boot loader 如何读取硬盘扇区的？

我们看文件中函数 `readsect` 的注释，就知道用来读取硬盘扇区的是这个函数，我们来逐行解释这个函数：

```c
/* readsect - read a single sector at @secno into @dst */
static void
readsect(void *dst, uint32_t secno) {
    // wait for disk to be ready
    waitdisk();

    outb(0x1F2, 1);                         // count = 1
    outb(0x1F3, secno & 0xFF);
    outb(0x1F4, (secno >> 8) & 0xFF);
    outb(0x1F5, (secno >> 16) & 0xFF);
    outb(0x1F6, ((secno >> 24) & 0xF) | 0xE0);
    outb(0x1F7, 0x20);                      // cmd 0x20 - read sectors

    // wait for disk to be ready
    waitdisk();

    // read a sector
    insl(0x1F0, dst, SECTSIZE / 4);
}
```

* 看文件前的注释可知，函数两个参数的含义：`dst` 是目标句柄，`secno` 是扇区标示；
* 根据[参考资料](https://blog.csdn.net/henrykobe/article/details/7483530)，后面的几行是通过 24-bit LBA 的方式读取磁盘（下面进行详细解析）；
* 后面的 `insl` 函数则是读取四个字节到 `dst` 这个句柄中；

那么 `outb` 那几行的具体原理是什么呢，首先我们在 [Linux manual](http://man7.org/linux/man-pages/man2/outb.2.html) 上找到了函数原型：

```c
void outb(unsigned char value, unsigned short int port);
```

它通过 port 这个 IO 技术与磁盘进行通信，这个技术被简称为 **PIO**。关于这个技术我找到一个中文的相关博客：[网络 IO 与磁盘 IO 详解](https://www.cnblogs.com/sunsky303/p/8962628.html)，其中是这样描述的：

* PIO：我们拿磁盘来说，很早以前，磁盘和内存之间的数据传输是需要 CPU 控制的，也就是说如果我们读取磁盘文件到内存中，数据要经过 CPU 存储转发，这种方式称为 PIO。显然这种方式非常不合理，需要占用大量的 CPU 时间来读取文件，造成文件访问时系统几乎停止响应。
* DMA：后来，DMA（直接内存访问，Direct Memory Access）取代了 PIO，它可以不经过 CPU 而直接进行磁盘和内存的数据交换。在 DMA 模式下，CPU 只需要向 DMA 控制器下达指令，让 DMA 控制器来处理数据的传送即可，DMA 控制器通过系统总线来传输数据，传送完毕再通知 CPU，这样就在很大程度上降低了 CPU占有率，大大节省了系统资源，而它的传输速度与 PIO 的差异其实并不十分明显，因为这主要取决于慢速设备的速度。
* 可以肯定的是，PIO 模式的计算机我们现在已经很少见到了。

在 [Stanford 的课件](http://www.scs.stanford.edu/15wi-cs140/notes/devices.pdf)中，我们找到了 24-bit LBA 模式读取磁盘，有更完整注释的代码：

```
IDE_ReadSector(int disk, int off, void *buf) {
  outb(0x1F6, disk == 0 ? 0xE0 : 0xF0);     // Select Drive
  IDEWait();
  outb(0x1F2, 512);                                             // Read length (512 B)
  outb(0x1F3, off);                                             // LBA Low
  outb(0x1F4, off >> 8);                                     // LBA Mid
  outb(0x1F5, off >> 16);                                 // LBA High
  outb(0x1F7, 0x20);                                             // Read Command
  insw(0x1F0, buf, 256);                                     // Read 256 Words
}
```

## 问题二

> Boot loader 是如何加载 ELF 格式的 OS？

略读代码发现，读取并解析 ELF 文件字节的是 `bootmain` 函数在进行的工作：

```c
/* bootmain - the entry of bootloader */
void
bootmain(void) {
    // read the 1st page off disk
    readseg((uintptr_t)ELFHDR, SECTSIZE * 8, 0);

    // is this a valid ELF?
    if (ELFHDR->e_magic != ELF_MAGIC) {
        goto bad;
    }

    struct proghdr *ph, *eph;

    // load each program segment (ignores ph flags)
    ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
    eph = ph + ELFHDR->e_phnum;
    for (; ph < eph; ph ++) {
        readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
    }

    // call the entry point from the ELF header
    // note: does not return
    ((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();

bad:
    outw(0x8A00, 0x8A00);
    outw(0x8A00, 0x8E00);

    /* do nothing */
    while (1);
}
```

* 它首先将磁盘的第一页读取了进来，然后通过文件幻数检查它是否为一个合法的 ELF 文件；
* 程序循环性地调用 `readseg` 函数，通过 `proghdr` 结构的参数读取 ELF 文件的内容（此处涉及到 `resadseg` 函数的具体实现与 `proghdr` 的结构）；
* 然后程序调用 ELF 的入口函数；

在 [Stack Overflow](https://stackoverflow.com/questions/29320615/reading-the-program-header-contents-of-an-elf-file) 上可以找到结构的具体实现（没什么特别的）：

```c
struct Proghdr {
        uint32_t p_type;
        uint32_t p_offset;
        uint32_t p_va;
        uint32_t p_pa;
        uint32_t p_filesz;
        uint32_t p_memsz;
        uint32_t p_flags; 
        uint32_t p_align;
};
```

而 `readseg` 函数具体实现就是同一个文件中：

```c
/* *
 * readseg - read @count bytes at @offset from kernel into virtual address @va,
 * might copy more than asked.
 * */
static void
readseg(uintptr_t va, uint32_t count, uint32_t offset) {
    uintptr_t end_va = va + count;

    // round down to sector boundary
    va -= offset % SECTSIZE;

    // translate from bytes to sectors; kernel starts at sector 1
    uint32_t secno = (offset / SECTSIZE) + 1;

    // If this is too slow, we could read lots of sectors at a time.
    // We'd write more to memory than asked, but it doesn't matter --
    // we load in increasing order.
    for (; va < end_va; va += SECTSIZE, secno ++) {
        readsect((void *)va, secno);
    }
}
```

逻辑也相当清晰，注释也很完整，这里就不解释了。
