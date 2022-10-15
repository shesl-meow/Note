---
title: "archon"
date: 2022-04-30T21:33:23+08:00
tags: [""]
categories: ["项目底层实现"]
---


## 线程模型

四个独立线程池：

1. `Accept` 线程池：接受网络请求、`accept` 方法的线程；
2. `IO` 线程池：每个线程对应一个 `folly::Eventbase`，所有与IO相关的操作都在IO线程中以非阻塞的方式执行；
3. `worker` 线程池：执行 CPU 任务，计算密集任务的线程；除此之外，`fbthrift` 还会额外为其他四种优先级分别建立两个线程；
4. `Async Dispatcher` 线程池：Archon 为异步 Client 创建的线程类型，本质上是 IO 线程的一种；

设计概念 IOBuf：

- 背景：在数据生产消费的时候，通常不是连续的过程，但是在内存使用过程中我们却通常需要申请一块连续的内存；
- 性能：`fbthrift` 宣称这一概念带来了很大收益，减少了内存拷贝（Zero Copy），传递指针进行解析，对非连续内存友好（流式序列化和反序列化）；

## 常见问题与优化思路

Client Fast Retry 策略与 Server Loadingshedding 策略。

优化思路：少用“异步”、“Buffered”客户端：

- `Buffered` 与 `Framed` 协议：两者都是 Thrift 的传输协议。Framed 协议有一个四字节的长度指示消息长度；Buffered 协议则通过不断尝试 fid 来探测包传输的边界，探索结束后交给 worker 线程进行序列化；

- 问题：在请求大包时，Buffered 协议会反复进行序列化探测，CPU 浪费严重；
- 解决方案：使用“同步 Buffered”的异步接口；

ArchonOptimizedServer 优化：

- 背景业务场景：QPS 较高，且请求较短，无需进行 `io/worker` 切换的场景；
- 弊端：没有 post calls 需求，没有多 accept 需求；

提前释放 worker（大约可以提升 30% 的吞吐量）：

- 背景业务场景：在 worker 的最后一个业务场景需要等待 IO 任务时，因为 worker 持有请求的 socket 信息导致 worker 一直无法释放，但是在最后这段时间内 worker 却没有做任何事情；
- 解决方案：`fbthrift` 中提供了 [`HandlerCallback`](https://github.com/facebook/fbthrift/blob/main/thrift/lib/cpp2/async/AsyncProcessor.h) 可以提前释放 worker 的能力，在 worker 代码结束时，将需要返回后需要执行的代码通过 callback 统一存放在某个位置；建议与 batch 一起使用；
- 弊端：无法统计 latency 的 Metrics，worker 的语义发生变化；

精细化线程池的数量：根据业务场景精细化地配置每个线程池的数量；

善用 `folly::future`：对于 10w*5 次的调用，每减少 1 个 `then` 的调用，能减少千分之一的 CPU 使用；

优化 IO、精简拓扑：关注长链接和拓扑的复杂度；
