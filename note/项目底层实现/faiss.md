---
title: "faiss"
date: 2022-05-29T00:00:49+08:00
tags: [""]
categories: ["项目底层实现"]
---


## 1. 项目目的、框架、文件结构、接口

简介：

- `faiss` 全称 Facebook AI Similarity Search；
- 它用于对海量高维数据，在很短的时间内进行邻近点的计算；
- 它的 Github 开源地址：https://github.com/facebookresearch/faiss，Docker 地址：https://hub.docker.com/r/plippe/faiss-docker/#!

基础知识和框架：

- 开发语言：C++，开放 API 语言：C++ 或 Python；
- C++ 中均匀分布：`std::uniform_real_distribution`；
- kmeans：一种聚类方法，将 n 组同维度的向量聚类为 k 类；
- `omp`：Open Muti-Process，可扩展、跨平台的多线程框架，官网使用例子：https://www.openmp.org/wp-content/uploads/openmp-examples-5.1.pdf。omp 提供编译层面的指令式 API：
  - pragma 可以指定对应指令：`#pragma omp directive-specification`；
  - C++ 可以用 attribute 的方式指定：`[[omp :: directive( directive-specification )]]`
- 编译框架：CMake
- 单元测试框架：`gtest`

接口：`demo` 和 `tutorial` 中调用的都是 `faiss` 中以 Index 开头的文件（比如 `IndexFlat.h`），它们都继承于 `Index` 这个定义于 `Index.h` 这个文件的类。

一些贯穿这个文件定义的概念和类型定义：

- `d`：内部指示向量纬度的一个成员变量；
- `MetricType`：距离计算方式，`METRIC_L2` 是最常见的欧式距离；
- `idx_t`：用于计量向量数量或下标的类型，当一组向量作为参数传入时通常是一个 `n * d` 长度的线性浮点数；

它的核心接口定义如下：

| 函数名                                                       | 作用                                                         |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `train`                                                      | 训练 n 个 d 维的向量，向量用一个长度为 n * d 的线性数组表示  |
| `add`/`add_with_ids`                                         | 动态添加向量的 API                                           |
| `search`/`range_search`/`assign`                             | 执行搜索操作的相关 API，ANN 问题的核心算法，传入一组向量，搜索指定数量或半径内的向量。 |
| `reset`/ `remove_ids`/ `reconstruct`/ `reconstruct_n`/ `search_and_reconstruct` | 重建、删除相关的 API。                                       |
| `compute_residual`/ `compute_residual_n`                     | 计算剩余向量。                                               |

## 2. 通读代码，梳理调用逻辑

从 `tutorial` 中的代码开始，分别梳理 `cpp/` 下的各个文件调用逻辑。

### `Flat`

`flat` 的含义是最朴素的实现：它全量地存储所有的向量数据，并且执行暴力搜索。

`tutorial` 中构建的具体类型是 `faiss::IndexFlatL2`，核心调用的两个 API 是 `add` 与 `search`，它的具体实现文件为 `faiss/IndexFlat`。

从基类 `Index` 开始，继承衍生出的以下的类型：

- `IndexFlatCodes: Index`：用最简单的固定长度编码和数组存储，实现了 `add` 相关的方法；
- `IndexFlat : IndexFlatCodes`：用最简单的暴力搜索实现了 `search`/`reconstruct` 相关的方法；
- `IndexFlatIP: IndexFlat`/`IndexFlatL2 : IndexFlat`：基于内积距离和基于欧氏距离的两个分类方法；
- `IndexFlat1D : IndexFlatL2`：一维向量的特化优化方法；

也就是 `Flat` 中包含的核心逻辑是 `IndexFlatCodes` 中的简单存储逻辑，和 `IndexFlat` 中的简单搜索逻辑。

### `IndexIVFFlat`

`IndexIVF` 定义的核心文件是 `faiss/IndexIVF.h`，在文件中可以看到 `IndexIVF` 的含义是 "index based on a inverted file"，即“基于倒排文件的索引”，也就是倒排索引：

- 在添加时，量化器（quantizer）为输入向量提供了一个量化索引（quantization index），类的实现中会存储着这个索引到某个列表的映射，这个列表就是原始向量集合；
- 在搜索时，被搜索向量首先会被量化计算出一个索引，类实现中的映射列表就是搜索结果；
- *PostScript*：量化结果可以用多路搜索（multi-probe search）泛化，从而访问得到多个列表（`nprobe`）；

这个核心文件中定义了结构 `IndexIVF`，它有 `Index`/`Level1Quantizer` 两个父类。在 `tutorial` 中构建的核心类是 `IndexFlatL2`/`IndexIVFFlat`，前者构建后作为 `quantizer` 传入后者的构造函数，调用的核心 API 是后者的 `train`/`add`/`search`。

下面讨论一下涉及到的一些核心类：

- `Level1Quantizer`：`IndexIVF` 的父类，抽象封装了独立于存储的逻辑。暂时没有特别理解这个类的作用；
- `IndexIVF : Index, Lvel1Quantizer`：核心结构，注释都写在这个结构上。
  - `InvertedLists`：`InvertedLists.invlists` 的数据类型，存储着真实的数据，结构实现了并发 RU；
  - `DirectMap`：`InvertedLists.direct_map` 的数据结构，可选变量，将 ids 映射回倒排列表的方式；
  - `InvertedListScanner`：处理 `IVF` 搜索的封装结构，核心方法是 `distance_to_code`、`scan_codes`，这两个方法实现了多线程安全调用。
- `IndexIVFStats indexIVF_stats`：一个全局变量，存储着 `IVF` 正在查询的数量、堆更新次数等信息；
- `IndexIVFFlat : IndexIVF`：简单地用向量存储倒排文件；

### `IndexIVFPQ`

核心文件是 `faiss/IndexIVFPQ.h`，其中的 PQ 指 "product quantizer"，一种编码存储向量的方式。

`tutorial` 中的使用与“平凡倒排索引”类似，先构造了一个 `IndexFlatL2` 作为量化器，以此作为构造函数的参数构造 `IndexIVFPQ` 类型的变量。与前面的类似，这个 `tutorial` 的 demo 中调用的核心 API 仍然是 `add`/`train`/`search` 三个函数。

涉及到的核心结构：

- `IndexIVFPQ : IndexIVF`：核心结构，向量用 PQ 的方式存储。
  - `ProductQuantizer`：`IndexIVFPQ.pq` 的类型，封装了 PQ 编码的实现；
  - `AlignedTable`：`IndexIVFPQ.precomputed_table` 的类型；
- `ndexIVFPQStats indexIVFPQ_stats`：一个全局变量，存储一些工程统计数据；

### `GPU`/`Multiple-GPUs`

GPU 相关的实现与 CPU 的 api 定义与调用流程看起来是类似的，在 API 上额外实现了 "copy from IndexFlat"/"copy to IndexFlat" 等函数。

### 总结

faiss 通过实现不同的类结构解耦不同的逻辑，以 Index 为根结点对不同的新增逻辑派生了不同的子类，自顶向下大致分为“搜索方式”、“存储方式”、“计算硬件”三个分支：

1. “搜索方式”指的是海量向量中搜索对应临近对的逻辑，它是 ANN 问题的核心逻辑，faiss 给出的方案是"index based on a inverted file"；就是 `Index` 结构中三个核心方法的具体实现 `add`/`search`/`train`；
2. “存储方式”指的是向量以什么方式存储在内存中，faiss 给出的方案是叫做"product quantizer"的编码方式；
3. “计算硬件”指的是计算单元使用 CPU 或 GPU 进行计算，这块逻辑我不太关心；
4. *PostScript*：其他公共的函数逻辑与结构封装，比如 `InvertedLists`；

## 3. 深入了解项目核心逻辑

### 朴素基类 Index

几乎所有的封装结构的公共祖先，看下它的朴素实现 `IndexFlat`/`IndexFlatCodes` 功能与具体实现。

`Index::train`：没有实现，do nothing；

`IndexFlatCodes::add`：`resize` 向量 `codec` 的大小，并调用 `sa_encode` 方法对新的位置进行赋值；

`IndexFlat::sa_encode`：朴素地直接将对应向量拷贝到目标内存中；

`IndexFlat::search`：输入 `n` 个向量，在已经存储在 Index 的数据库中为 `n` 个向量分别都找到找到 `k` 个临近向量，通过 `metric_type` 分流调用暴力搜索；

总结：

1. `Index` 作为基类可以视作为一个提供了默认实现的父类；

2. `Index` 作为变量或者参数可以视作为一个内存级别的索引数据库，或者一个“正排”；

3. `Index` 还可以视作仅承载编码方法的纯函数封装类，此时的核心方法是 `sa_encode` 与 `sa_decode`；

### 搜索方法 IVF

以 `2-IVFFlat.cpp` 中的 `tutorial` 调用为例，向量维度 d 为 64、数据库大小 nb 100000。

在这个例子中，它先构造了 `faiss::IndexFlatL2 quantizer`，然后构造了 `fails::IndexIVFFlat index`，随后先后调用了方法 `train`、`add`、`search`。

`IndexIVF::train`

- 核心调用 `Level1Quantizer::train_q1`，内部通过 `quantizer_trains_alone` 分流，定义处有相关的注释，感觉不太看得懂，我选择直接看它们的实现：
  - `quantizer_trains_alone = 0`：构造了 `Cluster` 后调用它的 `train` 方法，`Cluster` 是 kmeans 实现的结构封装，核心方法 `train`，输入一个待训练的向量数组和一个索引（暂时还不知道是什么意思），返回若干个质心点；
  - `quantizer_trains_alone = 1`：只直接调用 `quantizer->train`；
  - `quantizer_trains_alone = 2`：与 `=0` 时类似，有不同的传入和调用逻辑，暂时没怎么看懂；
- 综上 `Cluster::train` 是一个核心方法，这个方法又转发逻辑到了 `train_encoded`。
  - 参数与常用变量解释：
    - 成员变量 `d`：向量维度；
    - 成员变量 `k`：质心的数量；
    - 成员变量 `centorids`：质心向量，以 `k * d` 一维数组表示，核心输出结果；
    - 成员变量 `iteration_stats`：一个列表，每个元素都是 kmeans 方法中某次迭代的状态记录；
    - 参数 `nx`：向量的数量；
    - 参数 `x_in`：向量的值，以一个 `nx * d` 一维数组形式传入，表示一个矩阵；
    - 参数 `codec`：输入向量数据的编码方式，`Index` 类承载前一节“总结3”的功能；
    - 参数 `index`：“质心”到“链表”的倒排索引，`Index` 类承载前一节“总结2”的功能；
    - 参数 `weights`：用于计算质心的权重数组，长度 `nx`；
  - 运行流程：参数合法性校验、对 `nx` 过大时进行采样、处理边界情况、打印日志、循环迭代；
  - `nredo` 次循环逻辑是算法的核心流程：
    - 从 `x[0:k]` 中取 `k` 个质心，做随机排列并解码后赋值给 `centroids` ；
    - 调用倒排索引 `index` 的 `train` 方法与 `add` 方法，此时该索引存储了 k 个质心并能执行快速搜索；
    - 执行 `niter` 次迭代，kmeans 方法的核心流程：
      - 在质心索引 `index` 中，为 `nx` 个向量中每一个都搜索一个最近的向量，返回结果在局部变量 `assign` 中、距离在 `dis` 中；加和所有 `dis` 作为分类衡量指标；
      - 调用计算质心方法 `compute_centroids`，调用处理空分类方法 `split_clusters`，记录当前迭代状态 `iteration_stats`；
      - 将本次迭代计算得到的 `k` 个质心存入索引 `index`；
    - 如果本次循环得到的质心更好，则记录为 `best_centroids`；
  - 结束循环后将 `best_centroids` 设置到质心索引 `index` 中，并返回函数；
- 上面的 kmeans 迭代中引用了一个核心方法 `compute_centroids`，它的实现：
  - `#pragma omp parallel` 新起了若干个线程异步处理这段逻辑（线程数量在其他位置指定）：
    - 对于 “当前线程号/总线程数量“=”r/nt“，当前线程将处理 `k * r / nt` 到 `k * (r + 1) / nt` 这些质心的计算逻辑；
    - 具体的循环体逻辑，即对于每一个输入的点 x，对它先解码而后执行累加逻辑；总结下来这段多线程代码的执行效果是：$$\displaystyle \vec{c}_k = \sum_{assign[i] = k}^{}{\vec{x_{i}} * w_i}, hassign_k = \sum_{assign[i] = k}{w_i}$$
  - `#pragma omp parallel for` 用多线程的方式处理下面这段 for 循环逻辑：
    - 对于每个质心，应用传入的 `hassign` 进行正规化，即 $$\displaystyle \vec{c}_{norm} = \frac{\vec{c}}{hassign}$$
  - 这个方法是一个很简单地利用传入 `assign` 数组计算质心的方法，由前面的逻辑可以得知，`assign` 是在每次迭代开始，通过在质心索引 `index` 中执行 search 方法得到的；
- 总结：
  - `train` 的执行流程是迭代计算：
    1. 得到 k 个质心（初始化时用全量数据的 k 个随机组合）；
    2. 对 n 个全量数据，通过质心索引 index 查到离他最近的质心；
    3. 得到构建 k 个质心到若干个数据的倒排索引 assign，构成对 n 个全量数据形成划分；
    4. 通过 assign 的链表 compute_centroids 重新计算 k 个质心；
    5. 得到 k 个质心；
  - `train` 函数的输出是：k 个质心 `centroids`、倒排索引 `assign`；

`IndexIVF::add`

- 代理调用 `IndexIVF::add_with_ids`，先找到输入向量 x 最近的向量 `coarse_idx` 后调用 `IndexIVF::add_core`.
- `IndexIVF::add_core` 参数与常见变量：
  - 参数 `n`：三个函数透传的参数，待添加的向量数量；
  - 参数 `x`：向量的值，以 `n * d` 长度的一维数组表示一个矩阵；
  - 参数 `xids`：提前指定的 n 个向量的 ID，上述链路的调用会传入 `nullptr`
  - 参数 `coarse_idx`：调用函数 `quantizer->assign` 的返回值，一个长度为 n 的数组，每一个元素都指向一个离参数 x 最近的一个倒排链编号；
  - 成员变量 `InvertedLists* invlists`：存储数据的倒排链表
  - 成员变量 `DirectMap direct_map`：将向量的 ID 反向索引到存储它的倒排链。
  - 局部变量 `DirectMapAdd dm_adder`：通过 `direct_map` 构造，线程安全地封装了向 `DirectMap` 类型的添加操作函数逻辑。
- `IndexIVF::add_core` 函数的执行逻辑：
  - 执行边界检查与参数合法性校验，对 x 编码，构造 `dm_adder`；
  - 运行 `omp` 并行逻辑，每一个并行线程都循环遍历 n 个向量，通过分片策略保证每个向量只被一个线程执行。对于倒排链编号存在的向量，先后调用 `invlists.add_entry`/`dm_adder_add.add`；对于不存在的给定默认值调用 `dm_adder.add(i, -1, 0)`
- 上述梳理表明，函数的核心执行逻辑在 omp 的 for 循环并行代码中，它包含了三个部分：
  1. 按线程数量 `nt` 与当前线程号 `rank` 进行分片：对于某个应该被添加到编号为 `list_no` 倒排链的向量，它会由第 `list_no % nt` 个线程负责执行添加调用。这样的分片方法：
     - 好处：要添加到相同倒排链的向量一定是在同一个线程执行的，不会发生访问冲突，不需要加锁；
     - 坏处：每一个线程都需要遍历所有的输入向量以判断是否为当前线程需要负责的向量；非聚合的方式向倒排链逐一添加对应的向量，在每次添加时都会需要重新分配内存并拷贝内容。
  2. 方法 `InvertedLists::add_entry` 代理调用 `ArrayInvertedLists::add_entries`，该函数对 `ids`/`codes` 进行扩容，然后直接将传入的向量 ID 和编码值设置到这两个变量的末尾处。
  3. 方法 `DirectMapAdd::add` 主要解决了 `DirectMap` 在以 `unordered_map` 为存储结构时，无法写并发的问题。该函数的解决方案是调用时先用一个数组存储对应的调用结果，在 `DirectMapAdd` 析构时串行地设置到 `unordered_map` 上。

`IndexIVF::search`

- 函数注释：这是一个理论实现上相当简单的函数，但是因为工程上需要考虑到“并发”、“异常处理”、“收集统计数据”、“统计最大最小值”等问题，导致这个函数变得非常复杂，简单的 MVP 版本可以参考参数 `parallel_mode = 0` 的分支。
- 函数参数与常见变量：
  - 局部变量 `nprobe`：执行多线程搜索的多路线程数量。
- 函数执行流程：
  1. 先定义一个函数变量 `sub_search_func`，它与 `IndexIVF::search` 有一致的函数签名，是对称的内部串行实现；
  2. 之后函数根据成员变量 `parallel_mode` 的特征分流：
     - 分支：对 `n` 个输入的向量分片（分片方式：随机按顺序将 `n` 个向量平均拆成 `omp_max_thread` 个平均的桶），执行串行子函数 `sub_search_func`；
     - 分支：直接代理调用 `IndexIVF::sub_search_func`；
- 子函数 `sub_search_func` 的实现：

## 4. 梳理通用公共框架逻辑、提出疑问和建议


