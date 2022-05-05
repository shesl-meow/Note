# faiss

## 1. 项目目的、框架、文件结构、接口

简介：

- `faiss` 全称 Facebook AI Similarity Search；
- 它用于对海量高维数据，在很短的时间内进行邻近点的计算；
- 它的 Github 开源地址：https://github.com/facebookresearch/faiss，Docker 地址：https://hub.docker.com/r/plippe/faiss-docker/#!

语言基础和框架：

- 开发语言：C++，开放 API 语言：C++ 或 Python；
- C++ 中均匀分布：`std::uniform_real_distribution`；
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
- `IndexFlat1D : IndexFlatL2`：一维向量的特化优化方法；

