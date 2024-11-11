---
title: ":pager:C++ CoreDump 案例分析"
date: 2023-08-09T12:00:00+08:00
tags: ["服务端", "C++", "运维", "搜广推系统", "Linux", "字节跳动"]
---

## 背景

为了避免过于冗长的前置介绍，本次介绍分享将不会介绍以下的内容：
1. CPU、内存、磁盘、寄存器等概念是什么；
2. 编译器将 C++ 等高级语言编译成机器语言的完整流程，和中间概念等；
3. Elf 的文件结构和内存分段（参考：[Elf 文件分析指北](https://shesl-meow.github.io/posts/elf%E6%96%87%E4%BB%B6%E5%88%86%E6%9E%90%E6%8C%87%E5%8C%97/)）
4. Gdb、Objdump 等指令或工具的使用，包括如何获得汇编代码，如何查看内存内容等。可以参考：[常见 Gdb 命令](https://shesl-meow.github.io/note/%E5%B7%A5%E5%85%B7%E4%BD%BF%E7%94%A8%E6%8E%A5%E5%8F%A3/linux-command/gdb/)；
5. Gdb 工具的展示优化，或功能加强插件，比如 gdb-dashboard、gef、peda、voltron 等；
关于以上的问题可以问 ChatGPT。

## 前置知识介绍

### 常见寄存器的含义

寄存器是 CPU 上的存储单元，可以认为是整个机器上最快的存储单元。下面是 x86_64 系统架构里常见的寄存器：
|寄存器名称|一般用处|
|:--|:--|
|\$rip|指向内存中一段可执行代码的地址，表示当前 CPU 正在处理的指令|
|\$rsp|指向当前函数栈的栈顶。<br />当 CPU 执行 push \$ 指令时，会将指令的操作数赋值给 \$rsp 指向的地址，并令 \$rsp 自减一个地址。|
|\$rbp|指向当前函数栈的栈底，里面的内容存储的是前一个函数栈的栈底。<br />线程正在执行的所有函数 \$rbp 构成一个单向链表，它从当前正在执行的函数开始，指向线程的第一个函数。|


x86_64 系统架构中函数的传递方式：

|参数序号|左一|左二|左三|左四|左五|左六|
|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
|使用寄存器|\$rdi|\$rsi|\$rdx|\$rcx|\$r8|\$r9|

### call 指令, 如何操作函数栈？

当一个线程被创建之后，操作系统会在栈区为这个线程分配一段空间，作为这个线程的函数栈，栈区的主要作用是“存储函数局部变量”和“进行函数调用”。

函数调用发生时，表现在汇编代码上就是 call 指令，该指令的前后一般会发生以下的事情：
1. 将下一个函数需要的参数传入对应的寄存器中；
2. call 指令本身会在栈顶（$rsp 寄存器指向的位置）推入 $rip 的当前值，并将 $rip 指向目标地址；
3. 调用 push 指令推入当前的 $rbp；
4. 将 $rsp 赋值给 $rbp，栈底调整完成；
5. 通过 sub 命令或其他数值计算指令调整 $rsp，中间的区域就是当前函数的局部变量区；

比如下面的 two_sum 代码，和他们的汇编代码：

|源代码| main 函数汇编代码 | two_sum 函数汇编代码|
|:-:|:-:|:-:|
|[two_sum.cpp](./two_sum.cpp)|[main.asm](./main.asm)|[two_sum.asm](./two_sum.asm)|


当程序运行到 `two_sum:20` 行时，运行时的栈区内容是：

```shell
(gdb) x /32xg 0x7fffffffcf00

0x7fffffffcf00: 0x00000069ffffcfa0      0x00007fffffffcfa0
0x7fffffffcf10: 0x000055555556fea4      0x000055555556fe70
0x7fffffffcf20: 0x00007fffffffcf70      0x0000555555555ca6
0x7fffffffcf30: 0x00007fffffffcf80      0x00007fffffffcfa0
0x7fffffffcf40: 0x00007fffffffcf9f      0x00007fffffffcf9f
0x7fffffffcf50: 0x00007fffffffcf70      0x000000000000000d
0x7fffffffcf60: 0x0000555555559040      0x000000000000000d
0x7fffffffcf70: 0x00007fffffffcfe0      0x00005555555553c1
0x7fffffffcf80: 0x000055555556fe70      0x000055555556fea4
0x7fffffffcf90: 0x000055555556fea4      0x0000555555555810
0x7fffffffcfa0: 0x000055555556feb0      0x000055555556fee4
0x7fffffffcfb0: 0x000055555556fee4      0x0000000000000000
0x7fffffffcfc0: 0x0000555555558240      0x0000000000000000
0x7fffffffcfd0: 0x0000555555555120      0x00007fffffffd0c0
0x7fffffffcfe0: 0x0000555555558240      0x00007ffff7b0b09b
0x7fffffffcff0: 0xffffffffffffff90      0x00007fffffffd0c8
0x7fffffffd000: 0x00000001f7eff9e0      0x0000555555555346
```

> :bulb:为什么有的 call 函数指向的地址区域不一样？比如函数 `_ZdlPv@plt`，它的地址比一般的函数地址更高
>
> :speech_balloon:见：[Elf如何加载文件外的系统链接库](https://shesl-meow.github.io/posts/elf%E6%96%87%E4%BB%B6%E5%88%86%E6%9E%90%E6%8C%87%E5%8C%97/#elf%E5%A6%82%E4%BD%95%E5%8A%A0%E8%BD%BD%E6%96%87%E4%BB%B6%E5%A4%96%E7%9A%84%E7%B3%BB%E7%BB%9F%E9%93%BE%E6%8E%A5%E5%BA%93)

### 堆区如何进行内存分配？

参考博客：[堆区如何进行内存分配？](https://shesl-meow.github.io/posts/%E5%A0%86%E5%8C%BA%E5%A6%82%E4%BD%95%E8%BF%9B%E8%A1%8C%E5%86%85%E5%AD%98%E5%88%86%E9%85%8D/)



为什么多线程同时写一个变量会导致 CoreDump 呢？下面给一个同步写 demo 原因留由读者自行思考：

|                     源代码                     |    函数 EditElement 汇编代码     |
| :--------------------------------------------: | :------------------------------: |
| [concurrent_write.cpp](./concurrent_write.cpp) | [EditElement](./EditElement.asm) |



## CoreDump 案例分析

> 2023-07-31 下午，一个 c++ 调度中枢服务出现大面积 coredump。虽然通过暂停实验解决了问题，但是实验根因未找到，问题需要进一步定位。本文档旨在通过恢复 coredump 文件，分析 coredump 堆栈还原现场以定位到根本原因。

### 恢复 Tce 和 Coredump 文件

CoreDump 采样：

- 找了多个发生 coredump 的机器，都没有找到 coredump 文件。
- 后发现由于原始的 coredump 文件大小很大，大部分的公司都会采取 coredump 文件的采样策略；

失败的容器过期：

- 被恢复失败容器会被中台在过期 4 天后物理删除，需要用 `SimpleHttpServer` 拉到自己的机器里面来；
- PostScript：在本地分析的时候可以安装 [Peda 插件](https://shesl-meow.github.io/note/%E5%B7%A5%E5%85%B7%E4%BD%BF%E7%94%A8%E6%8E%A5%E5%8F%A3/linux-command/gdb/#peda)

更新 gdb 版本：

- 自己下载手动编译了一个 gdb 10.0 安装在了 `/usr/local/bin/gdb` 目录中；
- 启动命令：`/usr/local/bin/gdb -x ~/.gdbinit elf_file core_file`

### Thread-1: CoreDump 线程

#### frame rbp+rsp 计算恢复

加载 core 文件后，当前的 thread 和 stack-frame 会直接定位到发生 core 的位置，可以看看该位置的 backtraces：

```Plain
(gdb-peda) bt

......
#26 std::vector<idl::ad::aio::search_title_rewrite::AbstractInfo, std::allocator<idl::ad::aio::search_title_rewrite::AbstractInfo> >::_M_move_assign (
    this=0x0, __x=...)
    at /opt/tiger/typhoon-blade/gccs/x86_64-x86_64-gcc-830/lib/gcc/x86_64-linux-gnu/8.3.0/../../../../include/c++/8.3.0/bits/stl_vector.h:1683
#27 std::vector<idl::ad::aio::search_title_rewrite::AbstractInfo, std::allocator<idl::ad::aio::search_title_rewrite::AbstractInfo> >::operator= (this=0x0, 
    __x=...) at /opt/tiger/typhoon-blade/gccs/x86_64-x86_64-gcc-830/lib/gcc/x86_64-linux-gnu/8.3.0/../../../../include/c++/8.3.0/bits/stl_vector.h:601
#28 idl::ad::aio::search_title_rewrite::CreativeAbstractData::set_kv_abstract<std::vector<idl::ad::aio::search_title_rewrite::AbstractInfo, std::allocator<idl::ad::aio::search_title_rewrite::AbstractInfo> > > (this=0x0, kv_abstract_=...) at build64_release/idl/ad/aio/search_title_rewrite_types.h:11390
#29 admix::dag::SearchInspireRspModifyOp::set_to_abstract (this=<optimized out>, idl_type=<optimized out>, abstract_infos=..., abstract=...)
    at admix/src/dag_op/search_dag_op/inspire_rsp_modify_op.cpp:805
#30 0x00007ff8ccb93100 in ?? ()
#31 0x00007ff840000000 in ?? ()
#32 0x00007ff8ccb1c800 in ?? ()
#33 0x00007ff880000000 in ?? ()
.....
```

可以看到栈在 第29个 frame 断链了，这说明这个堆栈上的内容也因为 coredump 被改坏了。但是我们发现 `set_to_abstract` 这个函数被正确地发现，说明栈区存储的 `$rip` 大概率没有被改坏，尝试以此为线索，找到核心的第29个、第30个 frame 正确的栈帧。

先 dump 出 `set_to_abstract` 和 `deal_aweme_abstract` 的汇编代码（代码泄漏安全问题，此处不展示真实 asm 文件）

他们在 `.text` 段的地址都是 0x0933 开头的，那么可以在当前线程的栈区上反向地找到引用这个特征的位置：

- `(0x7ff42eec7aa8) => 0x0000000009eeafc8`，存储着 `set_to_abstract` 某一行的地址；
- `(0x7ff42eec7ad8) => 0x0000000009eef20c`，存储着 `deal_aweme_abstract` 某一行的地址；

按照汇编的执行流程，#29 `set_to_abstract` 的真实栈底是：

- `set_to_abstract$rbp = deal_aweme_abstract$rip - 0x8 = 0x7ff42eec7ad0`



#### #29 frame: `set_to_abstract`

那么由上可以知道 #29 号的栈底为 `0x7ff42eec7ad0`，它的栈区内容为：

```text
/*
    saved:
        $rbp = 0x7ff42eeca9f0
        $rsp = 0x7ff42eec7ab0
        $rbx = 0x7ff5e2c52b00

    但这些 value 可能被改坏了，是有一些问题的。但是我们可以根据确定的 $rip 值域区间，恢复 frame
    在附近的内存中查找可以找到栈区存储的两个 $rip，分别在地址：
        (0x7ff42eec7aa8) => 0x0000000009eeafc8
        (0x7ff42eec7ad8) => 0x0000000009eef20c
    按照汇编的执行流程: frame-$rbp = address(saved prev $rip) - 0x8
    所以 frame29-$rbp = 0x7ff42eec7ad8 - 0x8 = 0x7ff42eec7ad0
*/
$rbp=0x7ff42eec7ad0


address                                                                content
		|	0x7ff42eec7960:	0x0000000000000000	0x0000000000000000	|
		|	0x7ff42eec7970:	0x0000000000000000	0x0000000000000000	|
		|	0x7ff42eec7980:	0x00007ff755555554	0x00007ff446505845	|
		|	0x7ff42eec7990:	0x0000000000000020	0x0000000000000002	|
		|	0x7ff42eec79a0:	0x000000000000183a	0x0000000000000004	|
		|	0x7ff42eec79b0:	0x00007ff42eeca9c0	0x00007ff42eecabc0	|
		|	0x7ff42eec79c0:	0x0000000000000015	0x00007ff8f1dc87eb	|
		|	0x7ff42eec79d0:	0x00007ff42eeca901	0x00007ff42eecabc0	|
		|	0x7ff42eec79e0:	0x000000000000001b	0x0000000000000000	|
		|	0x7ff42eec79f0:	0x00007ff60831dfe0	0x00007ff8f1e3b969	|
		|	0x7ff42eec7a00:	0x00007ff42eec7a98	0x0000000007091b09	|
		|	0x7ff42eec7a10:	0x00007ff42eec9b20	0x0000000000000006	|
		|	0x7ff42eec7a20:	0x00007ff7d5bca580	0x00007ff8f1dd2e18	|
		|	0x7ff42eec7a30:	0x00007ff42eecaa30	0x00007ff42eecabc0	|
		|	0x7ff42eec7a40:	0x0000000000000008	0x0000000000000004	|
		|	0x7ff42eec7a50:	0x00007ff7d5bca4d0	0x00007ff84c80f050	|
		|	0x7ff42eec7a60:	0x00007ff7a8b7c700	0x00007ff5e2c52b00	|
		|	0x7ff42eec7a70:	0x00007ff5e2c52cc0	0x00007ff84c80f058	|
		|	0x7ff42eec7a80:	0x00007ff5e2c52800	0x00007ff8c62d3028	|
		|	0x7ff42eec7a90:	0x00007ff42eec7ad0	0x0000000007d8775a	|
		|	0x7ff42eec7aa0:	0x00007ff5e2c52b00	0x0000000009eeafc8	|   frame29-$rbx    frame29-$rip
		|	0x7ff42eec7ab0:	0x00007ff42eec9af0	0x00007ff84c80f058	|   frame30-$rbx    frame30-$r12
		|	0x7ff42eec7ac0:	0x00007ff8c62d3028	0x0000000000000003	|   frame30-$r14    frame30-$r15
$rbp=>	|	0x7ff42eec7ad0:	0x00007ff42eec9e20	0x0000000009eef20c	|   frame30-$rbp    frame30-$rip
		|	0x7ff42eec7ae0:	0x0000000000000000	0x0000000000000000	|
		|	0x7ff42eec7af0:	0x0000000000000000	0x0000000000000000	|
		|	0x7ff42eec7b00:	0x0000000000000000	0x0000000000000000	|
```



#### #30 frame: `deal_aweme_abstract`

可以根据 #29 的存储数据同样推算出 #30 的栈帧：

- `$rbp = 0x7ff42eec9e20`
- `$rsp = 0x7ff42eec7ad8`

另外这个函数的源代码签名为：

```C++
int SearchInspireRspModifyOp::deal_aweme_abstract(const IdlSearchNewCommonData& common_data,
                                                  const IdlSearchNewTupleData& ori_tuple_data, int64_t cid,
                                                  CreativeAbstractData& abstract)
```

通过阅读 `deal_aweme_abstract` 的反汇编代码，可以得到它的这些参数在栈上的存储位置（参考 x86_64 架构函数调用时，参数的传递方式：https://abcdxyzk.github.io/blog/2012/11/23/assembly-args/）：

| **C++** **参数**                   | **栈区存储位置** | **变量值**         | **解释**                                                     |
| ---------------------------------- | ---------------- | ------------------ | ------------------------------------------------------------ |
| `this`                             |                  |                    | 因为函数没有用到这个参数，所以被编译器优化掉了；             |
| `common_data`                      | 0x7ff42eec9da0   | 0x00007ff7d59ed928 | 第二个参数通过寄存器 `$rsi` 传入，阅读 asm，被存储到了 `$rbp-0x80` |
| `ori_tuple_data.material_info_map` | 0x7ff42eec9d38   | 0x00007ff7a8f82208 | 第三个参数通过寄存器 `$rdx` 传入，因为函数只用到了其中的唯一一个成员变量，因此栈区上只存储了 `ori_tuple_data` 的成员变量地址，原始地址可以直接通过成员变量地址 `-0x8` 得到 |
| `cid`                              | 0x7ff42eec9d78   | 0x00064c7440ece878 | 通过寄存器 `$rcx` 传入，十进制 `cid=1772912049449080`        |
| `abstract`                         | 0x7ff42eec9d50   | 0x00007ff8c62d3028 | 通过寄存器 `$r8` 传入，这个变量的跨线程共享也是导致本次 coredump 的原因 |

因为本线程没有任何请求维度的参数，并且 `this` 还被优化了，所以需要正向地通过查找主线程所在的位置来查看完整的请求上下文。



### Thread-612: SearchInspireRspModifyOp 主线程堆栈

#### 找到创建 Thread-1 的线程

方法简单粗暴：

- 通过 `thread apply all bt` 命令打印出所有线程的 `backtraces`；
- 在所有的线程中只有一个线程还跑在 `inspire_rsp_modify_op` 这个文件，大概率他就是创建 Thread-1 的主线程，它被挂起在了 `std::move(all_ret).get()` 这一行，在等待 Thread-1 完成；
- *PostScript*：这行命令跑完大概需要半天，记录到文件中随时查看已经跑出来的线程；

Thread-612 的堆栈没有被破坏，完整 backtraces 如下：

```
Thread 612 (LWP 684297):
......
#12 folly::Future<std::vector<folly::Try<int>, std::allocator<folly::Try<int> > > >::get() && (this=0x7ff5fe86ec50) at cpp3rdlib/folly/include/folly/futures/Future-inl.h:2196
#13 0x0000000009eee99f in admix::dag::SearchInspireRspModifyOp::deal_aweme_info (this=this@entry=0x7ff7a1116c10, rsp=..., search_res_ctx=...) at admix/src/dag_op/search_dag_op/inspire_rsp_modify_op.cpp:230
#14 0x0000000009eed517 in admix::dag::SearchInspireRspModifyOp::deal_new_resp (this=this@entry=0x7ff7a1116c10, op_context=...) at admix/src/dag_op/search_dag_op/inspire_rsp_modify_op.cpp:118
#15 0x0000000009ee8e35 in admix::dag::SearchInspireRspModifyOp::exec (this=0x7ff7a1116c10, op_context=...) at admix/src/dag_op/search_dag_op/inspire_rsp_modify_op.cpp:45
#16 0x0000000009ef9549 in std::__invoke_impl<folly::Future<int>, folly::Future<int> (admix::dag::SearchInspireRspModifyOp::*&)(std::shared_ptr<admix::dag::SearchInspireRspModifyOp::OpContext>), admix::dag::SearchInspireRspModifyOp*&, std::shared_ptr<admix::dag::SearchInspireRspModifyOp::OpContext> > (__f=<optimized out>, __t=<optimized out>, __args=...) at /opt/tiger/typhoon-blade/gccs/x86_64-x86_64-gcc-830/lib/gcc/x86_64-linux-gnu/8.3.0/../../../../include/c++/8.3.0/bits/invoke.h:73
#17 0x0000000009ef9478 in std::__invoke<folly::Future<int> (admix::dag::SearchInspireRspModifyOp::*&)(std::shared_ptr<admix::dag::SearchInspireRspModifyOp::OpContext>), admix::dag::SearchInspireRspModifyOp*&, std::shared_ptr<admix::dag::SearchInspireRspModifyOp::OpContext> > (__fn=<error reading variable>, __args=..., __args=...) at /opt/tiger/typhoon-blade/gccs/x86_64-x86_64-gcc-830/lib/gcc/x86_64-linux-gnu/8.3.0/../../../../include/c++/8.3.0/bits/invoke.h:95
#18 std::_Bind<folly::Future<int> (admix::dag::SearchInspireRspModifyOp::*(admix::dag::SearchInspireRspModifyOp*, std::_Placeholder<1>))(std::shared_ptr<admix::dag::SearchInspireRspModifyOp::OpContext>)>::__call<folly::Future<int>, std::shared_ptr<admix::dag::SearchInspireRspModifyOp::OpContext>&&, 0ul, 1ul>(std::tuple<std::shared_ptr<admix::dag::SearchInspireRspModifyOp::OpContext>&&>&&, std::_Index_tuple<0ul, 1ul>) (this=0x89, __args=...) at /opt/tiger/typhoon-blade/gccs/x86_64-x86_64-gcc-830/lib/gcc/x86_64-linux-gnu/8.3.0/../../../../include/c++/8.3.0/functional:400
......
```

有了这些信息，我们可以：

1. 通过阅读 assembly 代码找到变量的存储位置，获取完整请求上下文；
2. 通过比对 abstract 等变量的存储地址，确定 Thread-1 和 Thread-612 是不是同一个请求；



#### #15 frame: `SearchInspireRspModifyOp::exec`

`exec` 函数的参数为 `op_context`，把它解析出来就有了整个完整的上下文。

直接通过 `frame 15` 切换到 这个栈帧，然后 `print` 出寄存器的值：

- `$rbp=0x7ff5fe872830`
- `$rsp=0x7ff5fe872800`
- `$rip=0x9ee8e35`

然后阅读 asm，发现 op_context 存储在 `$rbp-0x30` 的位置：

| **C++** **参数** | **栈区存储位置** | **变量值**         | **解释**                                                     |
| ---------------- | ---------------- | ------------------ | ------------------------------------------------------------ |
| `op_context`     | 0x7ff5fe872800   | 0x00007ff79cb36c10 | 在调用函数 `deal_new_resp` 时，发现汇编从 `$rbp-0x30` 这个位置取出数据赋值给 `rsi`，因此认为这个位置存储着 `op_context` |

有了 `op_context`，几乎可以完整地打出当次请求的所有的堆区变量。



#### 堆区变量: `search_res_ctx`

用 gdb 的 p 直接打印出这个变量。

核心关心的是其中的 `local_cids` 这个变量有重复的 `cid=1772912049449080`，也就是 Thread-1 发生重复的 cid：

```text
0x7ff6e32d8000:	1772912049449080	1772912049449080
0x7ff6e32d8010:	1772912049449080	1760510634593283
0x7ff6e32d8020:	1760511427911687	1760510634589187
0x7ff6e32d8030:	1760510634581027	7255514027525177402
0x7ff6e32d8040:	1760511427896359	1760510634591267
0x7ff6e32d8050:	1760510633723955	7255514027525161018
0x7ff6e32d8060:	1760510633719891	7257961100132761657
0x7ff6e32d8070:	7255513894658457658	1760510634591283
0x7ff6e32d8080:	7255514027525144634	1760510633730051
0x7ff6e32d8090:	7246930068398932024	7261469851183693885
0x7ff6e32d80a0:	1772851126451283	1760848843448504
0x7ff6e32d80b0:	7254115995273478204	1760848847006782
0x7ff6e32d80c0:	1760848847025214	1760848847017998
0x7ff6e32d80d0:	7256503565378748472	1772292198980621
0x7ff6e32d80e0:	1772292198980669	1772292198979613
0x7ff6e32d80f0:	1772292196287565	1772292201230509
0x7ff6e32d8100:	7260213576806187066	7260213353321381947
```



#### 堆区变量: `inner_req`

用 gdb 的 p 直接打印出这个变量。

核心关心的变量是其中的 `abtest_parameters`，发现它确实命中了最开始关闭的实验。

另外还可以看到这个请求 `logid=20230731141810F9A6B0B65EDD8E82246D`；



#### 堆区变量: `cypher_ctx.new_rsp`

因为 `search_res_ctx.local_cids` 中有重复 cid，它的构造来自这个 rpc 返回值。

它其中的 `creative_infos` 是一个 `seraph::ad::CreativeMeta` 结构的数组，用 gdb 插件中 [stl 容器打印的方法](https://sourceware.org/gdb/wiki/STLSupport?action=AttachFile&do=view&target=stl-views-1.0.3.gdb)打印出这个变量，或者可以写一个简单的 python 完整地打印出里面的内容：

```Bash
(gdb) p sizeof(seraph::ad::CreativeMeta)
0x7a0

(gdb) python [gdb.execute('p *(seraph::ad::CreativeMeta *)' + hex(addr)) for addr in range(0x7ff7a8fc0000, 0x7ff7a8fcf400, 0x7a0)]
```

可以看到 `0x64c7440ece878` 这个 cid 确实重复出现了三次，分别是：

- recall_type = seraph::ad::RecallType::NORMAL, **id=0x64c74418c1c87**, creative_id = 0x64c7440ece878,aid = 0x6153d08ca6837,
- recall_type = seraph::ad::RecallType::NORMAL,**id=0x64c7440ecec98**,creative_id = 0x64c7440ece878,aid = 0x6153d08ca6837,
- recall_type = seraph::ad::RecallType::NORMAL,**id=0x64c7440ece878**,creative_id = 0x64c7440ece878,aid = 0x6153d08ca6837,



### 根因小结

`idl::ad::inspire::SortedInspireSearchRsp` 这个返回值中包含重复的 cid；



## 免责声明

本文仅供学习使用，“案例分析”虽然涉及到源代码分析和二进制存储内容，但是已经是一年前的源代码，并且因为 STE 团队的编译优化等原因，其中的堆区地址和栈区地址的真实值泄漏不会导致机器的漏洞泄漏。