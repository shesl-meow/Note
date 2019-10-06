# exe2

使用 `qemu` 执行并调试 lab1 中的软件。

为了更加简易地对 gdb 进行调试，我们应该安装 [peda](https://notes.shesl.top/an-quan-ji-shu/gong-ju/gdb/peda#peda)。但是我发现这个内核调试的版本并不能显示颜色，很多乱码，所以并没有什么卵用。

## STEP-1

> 从 CPU 加电后执行的第一条指令开始，单步跟踪 BIOS 的执行

可以在 `Makefile` 的第 219-222 行看到 make 列举的命令中，有一个叫做 `debug` 的命令：
```makefile
debug: $(UCOREIMG)
	$(V)$(QEMU) -S -s -parallel stdio -hda $< -serial null &
	$(V)sleep 2
	$(V)$(TERMINAL) -e "gdb -q -tui -x tools/gdbinit"
```

这三行命令分别执行：

1. 使用 `qemu` 运行 32 位程序的虚拟机，这个变量值在 Makefile 的 27 行进行赋值，在我的 Ubuntu 中这个变量的最终赋值是 `qemu-system-i386`。要查看上面各个命令的含义使用 manual 即可：

   ```bash
   $ qemu-system-i386 --help
   ```

   使用到的选项含义如下：

   1. `-S`： 在启动时不启动 CPU， 需要在 monitor 中输入 `c`，才能让 qemu 继续模拟工作。
   2. `-s`：等待 gdb 连接到端口 1234；
   3. `-hda $<`：使用 `$<`  作为硬盘0、1、2、3镜像。其中 `$<` 指第一个依赖，也就是 `$(UCOREIMG)`；
   4. `-parallel stdio`：重定向虚拟**并口**到主机设备 studio 中；
   5. `-serial null`：不重定向虚拟**串口**到主机设备。

2. `sleep 2`：程序休眠两秒钟；

3. 第三行以执行 `gdb` 的方式，打开一个终端，其中使用 `tools/gdbinit` 作为初始化配置。

根据附录中的内容，一顿瞎操作，我们需要把 `./tools/gdbinit` 改成下面的样子：

```bash
# ./tools/gdbinit
set architecture i8086
target remote :1234

define hook-stop
x /i (($cs << 4) + $pc)
end
```

1. 前面两行的意思是：告诉 `gdb` 设置 32 位程序，并且把 `gdb` 通过 1234 网络端口链接到 `qemu`；

2. 后面三行的意思是：加入一个停止的钩子，也就是说每次停止时会执行中间的语句；
3. 原本的题目中给出的语句是 `x /i $pc`。但是根据附录中的提示，真实的执行位置是虚拟得到的，也就是通过 `$cs`. 寄存器与 `$pc` 寄存器计算而来，因此我们得到了上面的语句。

最后我们在 bash 中执行下面的命令就可以了：

```bash
$ make debug
```

我也不知道为什么第一次没有 hook 到 stop，需要手动显示：

```bash
0x0000fff0 in ?? ()
(gdb) x /i (($cs << 4) + $pc)
   0xffff0:     ljmp   $0xf000,$0xe05b
```

可以看到 CPU 加电后的第一条指令是 `ljmp` 长转移指令，也就是说第一条指令是 `0xfe05b` 位置的指令。

## STEP-2 & STEP-3

> 在初始化位置 `0x7c00` 设置实地址断点,测试断点正常。
>
> 从 `0x7c00` 开始跟踪代码运行,将单步跟踪反汇编得到的代码与 `bootasm.S`. 和 `bootblock.asm` 进行比较。

更改 `./tools/gdbinit` 为下面的形式：

```bash
# ./tools/gdbinit
set architecture i8086
target remote :1234

define hook-stop
x /10i (($cs << 4) + $pc)
end

break *0x7c00
continue
```

可以看到它得到的反汇编代码：

```assembly
=> 0x7c00:      cli
   0x7c01:      cld
   0x7c02:      xor    %ax,%ax
   0x7c04:      mov    %ax,%ds
   0x7c06:      mov    %ax,%es
   0x7c08:      mov    %ax,%ss
   0x7c0a:      in     $0x64,%al
   0x7c0c:      test   $0x2,%al
   0x7c0e:      jne    0x7c0a
   0x7c10:      mov    $0xd1,%al
   0x7c12:      out    %al,$0x64
   0x7c14:      in     $0x64,%al
   0x7c16:      test   $0x2,%al
   0x7c18:      jne    0x7c14
   0x7c1a:      mov    $0xdf,%al
   0x7c1c:      out    %al,$0x60
   0x7c1e:      lgdtw  0x7c6c
   0x7c23:      mov    %cr0,%eax
   0x7c26:      or     $0x1,%eax
   0x7c2a:      mov    %eax,%cr0
```

`boot/bootasm.S` 的文件内容如下：

```assembly
#include <asm.h>

# Start the CPU: switch to 32-bit protected mode, jump into C.
# The BIOS loads this code from the first sector of the hard disk into
# memory at physical address 0x7c00 and starts executing in real mode
# with %cs=0 %ip=7c00.

.set PROT_MODE_CSEG,        0x8                     # kernel code segment selector
.set PROT_MODE_DSEG,        0x10                    # kernel data segment selector
.set CR0_PE_ON,             0x1                     # protected mode enable flag

# start address should be 0:7c00, in real mode, the beginning address of the running bootloader
.globl start
start:
.code16                                             # Assemble for 16-bit mode
    cli                                             # Disable interrupts
    cld                                             # String operations increment

    # Set up the important data segment registers (DS, ES, SS).
    xorw %ax, %ax                                   # Segment number zero
    movw %ax, %ds                                   # -> Data Segment
    movw %ax, %es                                   # -> Extra Segment
    movw %ax, %ss                                   # -> Stack Segment

    # Enable A20:
    #  For backwards compatibility with the earliest PCs, physical
    #  address line 20 is tied low, so that addresses higher than
    #  1MB wrap around to zero by default. This code undoes this.
seta20.1:
    inb $0x64, %al                                  # Wait for not busy(8042 input buffer empty).
    testb $0x2, %al
    jnz seta20.1

    movb $0xd1, %al                                 # 0xd1 -> port 0x64
    outb %al, $0x64                                 # 0xd1 means: write data to 8042's P2 port

seta20.2:
    inb $0x64, %al                                  # Wait for not busy(8042 input buffer empty).
    testb $0x2, %al
    jnz seta20.2

    movb $0xdf, %al                                 # 0xdf -> port 0x60
    outb %al, $0x60                                 # 0xdf = 11011111, means set P2's A20 bit(the 1 bit) to 1

    # Switch from real to protected mode, using a bootstrap GDT
    # and segment translation that makes virtual addresses
    # identical to physical addresses, so that the
    # effective memory map does not change during the switch.
    lgdt gdtdesc
    movl %cr0, %eax
    orl $CR0_PE_ON, %eax
    movl %eax, %cr0

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

    # If bootmain returns (it shouldn't), loop.
spin:
    jmp spin

# Bootstrap GDT
.p2align 2                                          # force 4 byte alignment
gdt:
    SEG_NULLASM                                     # null seg
    SEG_ASM(STA_X|STA_R, 0x0, 0xffffffff)           # code seg for bootloader and kernel
    SEG_ASM(STA_W, 0x0, 0xffffffff)                 # data seg for bootloader and kernel

gdtdesc:
    .word 0x17                                      # sizeof(gdt) - 1
    .long gdt                                       # address gdt
```

二者是相同的，与 `./obj/bootblock.asm` 中的代码也是相同的。

从 `boot/bootasm.S` 可以看到这段代码的主要功能是：

1. 初始化数据段、额外段、栈区等；
2. 进行与早期 PC 兼容的操作，如果地址线超过总线长，高位会被清零；
3. 从实模式切换到保护模式，使得物理地址表示转换为虚拟地址表示。

## STEP-4

> 自己找一个bootloader或内核中的代码位置，设置断点并进行测试。

参考 git 版本仓库中 HEAD 的 `gdbinit` 版本：

```bash
file bin/kernel
target remote :1234
break kern_init
continue
```

这个版本 break 在了 `kern_init` 这个函数，并且有源码进行 `debug`。

