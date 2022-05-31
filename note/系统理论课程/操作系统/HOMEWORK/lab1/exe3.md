---
title: "exe3"
date: 2019-10-06T23:25:31+08:00
tags: [""]
categories: ["系统理论课程", "操作系统"]
---


## 问题1

> 为何开启 A20,以及如何开启 A20

为了与早期的pc机兼容，物理地址线20(实模式)置于低位不能使用。所以超过1MB的地址，默认就会返回到地址0。寻址空间只有1MB。

开启A20：

```assembly
seta20.1:
    inb $0x64, %al                                  # Wait for not busy(8042 input buffer empty).
    testb $0x2, %al
    jnz seta20.1

    movb $0xd1, %al                                 # 0xd1 -> port 0x64
    outb %al, $0x64                                 # 0xd1 means: write data to 8042's P2 port
```

从0x64端口读入一个字节的数据到al中，如果a1第二位不为0，则跳转到seta20.1接着执行检查a1的第二位是不是0。将0xd1写入到al中，再将al中的数据写入到端口0x64中。

```assembly
seta20.2:
    inb $0x64, %al                                  # Wait for not busy(8042 input buffer empty).
    testb $0x2, %al
    jnz seta20.2

    movb $0xdf, %al                                 # 0xdf -> port 0x60
    outb %al, $0x60                                 # 0xdf = 11011111, means set P2's A20 bit(the 1 bit) to 1
```

从0x64端口读入一个字节的数据到al中，如果a1第二位不为0，则跳转到seta20.2接着执行检查a1的第二位是不是0。将0xdf写入到al中，再将al中的数据写入到端口0x60中。

> 如何初始化GDT表

```assembly
#define SEG_NULLASM                                             \
    .word 0, 0;                                                 \
    .byte 0, 0, 0, 0

#define SEG_ASM(type,base,lim)                                  \
    .word (((lim) >> 12) & 0xffff), ((base) & 0xffff);          \
    .byte (((base) >> 16) & 0xff), (0x90 | (type)),             \
        (0xC0 | (((lim) >> 28) & 0xf)), (((base) >> 24) & 0xff)
 
 
 gdt:
    SEG_NULLASM                                     # null seg
    SEG_ASM(STA_X|STA_R, 0x0, 0xffffffff)           # code seg for bootloader and kernel
    SEG_ASM(STA_W, 0x0, 0xffffffff)                 # data seg for bootloader and kernel
#初始化空段，代码段和数据段
gdtdesc:
    .word 0x17                                      # sizeof(gdt) - 1
    .long gdt                                       # address gdt
#gdt大小和地址
```



在该文件的第十行定义了  CR0_PE_ON 变量等于 1 ,加载全局描述符寄存器gdtr，通过lgdt指令将全局描述符入口地址装入gdtr寄存器中。然后将控制寄存器cr0的值装载入eax中，将eax的值设置为1，然后将eax的值装载入cr0中，cr0为1时代表进入保护模式。

> 如何使能和进入保护模式

~~翻译下面代码注释得到以下结论~~

```assembly
lgdt gdtdesc
    movl %cr0, %eax
    orl $CR0_PE_ON, %eax
    movl %eax, %cr0
```



先将A20开启进入32位寻址模式，然后初始化GDT表，然后设置cr0控制寄存器为1，表示进入保护模式，然后跳转到32位模式中的下一条指令将处理器切换为32位工作模式，设置数据段寄存器，设置栈指针，并且调用bootmain函数。

```assembly
 # Jump to next instruction, but in 32-bit code segment.
    # Switches processor into 32-bit mode.
    ljmp $PROT_MODE_CSEG, $protcseg

.code32                                             # Assemble for 32-bit mode
protcseg:
    # Set up the protected-mode data segment registers
    movw $PROT_MODE_DSEG, %ax                       # Our data segment selector
    movw %ax, %ds                                   # -> DS: Data Segment
    movw %ax, %es                                   # -> ES: Extra Segment
    movw %ax, %fs                                   # -> FS
    movw %ax, %gs                                   # -> GS
    movw %ax, %ss                                   # -> SS: Stack Segment

    # Set up the stack pointer and call into C. The stack region is from 0--start(0x7c00)
    movl $0x0, %ebp
    movl $start, %esp
    call bootmain
```


