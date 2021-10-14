# exe6

## 写在前面：

阅读源码时，发现了一个之前没有遇到过的 c 语言语法：

```c
struct struct_name {
  unsigned field1: 16;
  unsigned field2: 16;
};
```

这个结构声明表示声明了一个名为 `struct_name`，同时有 `field1`、`field2` 这两个 16 位字段的结构。（同时发现 64 位计算器的结构大小一定是 4 个字节的整数倍，不足则向上 padding）

## 问题一

> 中断描述表（保护模式下的中断向量表）中，一个表项占多少个字节？其中哪几位代表中断处理代码的入口？

中断描述表定义在 `kern/trap/trap.c` 这个文件中：

```c
/* *
 * Interrupt descriptor table:
 *
 * Must be built at run time because shifted function addresses can't
 * be represented in relocation records.
 * */
static struct gatedesc idt[256] = {{0}};
```

其中 `gatedesc` 这个结构定义在 `kern/mm/mmu.h` 这个文件中：

```c
/* Gate descriptors for interrupts and traps */
struct gatedesc {
    unsigned gd_off_15_0 : 16;        // low 16 bits of offset in segment
    unsigned gd_ss : 16;            // segment selector
    unsigned gd_args : 5;            // # args, 0 for interrupt/trap gates
    unsigned gd_rsv1 : 3;            // reserved(should be zero I guess)
    unsigned gd_type : 4;            // type(STS_{TG,IG32,TG32})
    unsigned gd_s : 1;                // must be 0 (system)
    unsigned gd_dpl : 2;            // descriptor(meaning new) privilege level
    unsigned gd_p : 1;                // Present
    unsigned gd_off_31_16 : 16;        // high bits of offset in segment
};
```

计算之后可以发现这个结构一共占 64bits = 8bytes，也就是说表项占 8 个字节。

决定处理代码入口的是逻辑地址，也就是段选择子与段偏移这两个字端，看名称与注释知道逻辑地址是 `gd_off_15_0`、`gd_ss`、`gd_off_31_16` 这三个字段决定的。也就是最开始的 32 位与最后的 16 位。

## 问题二

> 请编程完善 `kern/trap/trap.c` 中对中断向量表进行初始化的函数 `idt_init`。在 `idt_init` 函数中，依次对所有中断入口进行初始化。使用 `mmu.h` 中的 `SETGATE` 宏，填充 `idt` 数组内容。
>
> 每个中断的入口由 `tools/vectors.c` 生成，使用 `trap.c` 中声明的 `vectors` 数组即可。

~~首先我们简单翻译一下这个文件的注释：~~

1.  所有的 ISR 入口地址都存储在 `__vectors` 这个变量中，而这个变量是由 `tools/vector.c` 这个文件生成 `kern/trap/vector.S` 这个汇编代码得来的。

    你可以在代码中引入下面这一行来声明这个外部变量：

    ```c
    extern uintptr_t __vectors[];
    ```
2. 接下来就可以使用 ISR 的入口初始化 IDT 了，也就是 `kern/trap/trap.c` 文件中的 `idt` 变量；
3. 之后，你就需要用 `lidt` 这个指令告诉 CPU 中断向量表的地址了。

第二步中，设置需要用到 `SETGATE` 这个宏：

```c
/* *
 * Set up a normal interrupt/trap gate descriptor
 *   - istrap: 1 for a trap (= exception) gate, 0 for an interrupt gate
 *   - sel: Code segment selector for interrupt/trap handler
 *   - off: Offset in code segment for interrupt/trap handler
 *   - dpl: Descriptor Privilege Level - the privilege level required
 *          for software to invoke this interrupt/trap gate explicitly
 *          using an int instruction.
 * */
#define SETGATE(gate, istrap, sel, off, dpl) {            \
    (gate).gd_off_15_0 = (uint32_t)(off) & 0xffff;        \
    (gate).gd_ss = (sel);                                \
    (gate).gd_args = 0;                                    \
    (gate).gd_rsv1 = 0;                                    \
    (gate).gd_type = (istrap) ? STS_TG32 : STS_IG32;    \
    (gate).gd_s = 0;                                    \
    (gate).gd_dpl = (dpl);                                \
    (gate).gd_p = 1;                                    \
    (gate).gd_off_31_16 = (uint32_t)(off) >> 16;        \
}
```

简单的说呢，这个宏定义了五个参数：

1. 第一个参数是中断描述符，就是前一个问题中 `gatedesc` 这个结构的对象；
2. 第二个参数是一个布尔型变量，1 表示 Trap Gate，0 表示 Interrupt Gate；
3. 第三个参数是_段选择子_；第四个参数是_段偏移_。这两个参数构成一个逻辑地址；
4. 第五个参数是段描述符的优先级；

段选择子应该如何选择呢，在 `kern/mm/memlayout.h` 这个文件中有提到：

```c
/* global descriptor numbers */
#define GD_KTEXT    ((SEG_KTEXT) << 3)        // kernel text
#define GD_KDATA    ((SEG_KDATA) << 3)        // kernel data
#define GD_UTEXT    ((SEG_UTEXT) << 3)        // user text
#define GD_UDATA    ((SEG_UDATA) << 3)        // user data
#define GD_TSS        ((SEG_TSS) << 3)        // task segment selector
```

也就是说，内核的代码段是 `GD_KTEXT` 这个宏。

## 问题三

> 请编程完善 trap.c 中的中断处理函数 trap，在对时钟中断进行处理的部分填写 trap 函数中处理时钟中断的部分，使操作系统每遇到 100 次时钟中断后，调用 `print_ticks` 子程序，向屏幕上打印一行文字 "100 ticks”。

这个相当简单，我就不说了。
