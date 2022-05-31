---
title: "exe1"
date: 2019-09-19T21:36:09+08:00
tags: [""]
categories: ["系统理论课程", "操作系统"]
---


### make

make命令执行需要一个makefile文件，以告诉make命令需要如何去编译和链接程序。

- 如果工程没有被编译过，所有的c文件都要编译并被链接。
- 如果某几个c文件被修改，那么只编译被修改的c文件，并链接目标程序。
- 如果工程的头文件被修改了，那么需要编译引用了这几个头文件的c文件，并链接目标程序

```
target... : prerequisites...
    command
    ...
    ...
```

target也就是一个目标文件，可以是object file,也可以是执行文件。还可以是一个label。prerequisites就是要生成target所需要的文件或是目标。command就是make需要执行的命令。target这一个或多个的目标文件依赖于prerequisites中的文件，其生成规则定义在command中。如果prerequisites中有一个以上的文件比target文件要新，那么command所定义的命令就会被执行。

## 问题 1

> 操作系统镜像文件ucore.img是如何一步一步生成的?(需要比较详细地解释Makefile中每
> 一条相关命令和命令参数的含义,以及说明命令导致的结果)

### ucore.img

makefile中生成ucore.img的代码为：

```bash
UCOREIMG	:= $(call totarget,ucore.img)

$(UCOREIMG): $(kernel) $(bootblock)
	$(V)dd if=/dev/zero of=$@ count=10000
	$(V)dd if=$(bootblock) of=$@ conv=notrunc
	$(V)dd if=$(kernel) of=$@ seek=1 conv=notrunc

$(call create_target,ucore.img)

```

将ucore.img传入totarget表达式调用call函数结果赋值给变量UCOREIMG，UCOREIMG作为target，其依赖于两个文件，一个是kernel，一个是bootblock。接下来给出make需要执行的命令。首先从/dev/zero中读了10000*512块的空字节，生成空文件，接着将bootlock中的内容拷贝到目标文件，然后从输文件的512字节后继续写入kernel的内容。makefile的第六行`V       := @`将@赋值给变量V，所以$(V)代指@,表示命令不回显。conv=notrunc代表不截断输出文件，count=n’ 代表从输入文件中拷贝n个大小为ibs byte的块，ibs默认为512字节。seek=n代表在拷贝前输出文件时跳过n 个‘obs’-byte的块。obs默认为512字节。所以seek=1代表跳过输出文件的512个字节。

kenel：

```bash
kernel = $(call totarget,kernel)

$(kernel): tools/kernel.ld

$(kernel): $(KOBJS)
	@echo + ld $@
	$(V)$(LD) $(LDFLAGS) -T tools/kernel.ld -o $@ $(KOBJS)
	@$(OBJDUMP) -S $@ > $(call asmfile,kernel)
	@$(OBJDUMP) -t $@ | $(SED) '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $(call symfile,kernel)

$(call create_target,kernel)

```

kernel的生成依赖于KOBJS和tools/kernel.ld，生成命令依赖于i386-elf-objdump 、ld和objdump等。

第五行链接各种文件输出给目标文件，第六行反汇编目标文件输出给asmfile这个变量。第七行输出目标文件的符号表并进行文本替换。最后写入symfile这个变量。

### bootblock

```bash
bootfiles = $(call listf_cc,boot)
$(foreach f,$(bootfiles),$(call cc_compile,$(f),$(CC),$(CFLAGS) -Os -nostdinc))
bootblock = $(call totarget,bootblock)
$(bootblock): $(call toobj,$(bootfiles)) | $(call totarget,sign)
    @echo + ld $@
    $(V)$(LD) $(LDFLAGS) -N -e start -Ttext 0x7C00 $^ -o $(call toobj,bootblock)
    @$(OBJDUMP) -S $(call objfile,bootblock) > $(call asmfile,bootblock)
    @$(OBJCOPY) -S -O binary $(call objfile,bootblock) $(call outfile,bootblock)
    @$(call totarget,sign) $(call outfile,bootblock) $(bootblock)
$(call create_target,bootblock)

```

bootblock 依赖于bootasm.o、bootmain.o、sign生成bootblock的编译指令为：

```
ld -m    elf_i386 -nostdlib -N -e start -Ttext 0x7C00 obj/boot/bootasm.o obj/boot/bootmain.o -o obj/bootblock.o
```

- -m   模拟为i386上的连接器
- -nostdlib  不使用标准库
- -N  设置代码段和数据段均可读写
- -e   指定入口
- -Ttext  制定代码段开始位置
- -fno-builtin:除非用__builtin_前缀，否则不进行builtin函数的优化

## 问题 2

> 一个被系统认为是符合规范的硬盘主引导扇区的特征是什么?

sign:外部执行程序,用来生成虚拟的硬盘主引导扇区

从sign.c代码中：

```c
if (st.st_size > 510) {
    fprintf(stderr, "%lld >> 510!!\n", (long long)st.st_size);
    return -1;
}
...
buf[510] = 0x55;
buf[511] = 0xAA;
```

主引导扇区有512个字节，第511字节写入0x55，第512字节写入0xAA。
