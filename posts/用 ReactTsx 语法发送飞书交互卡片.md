---
title: "用 ReactTsx 语法发送飞书交互卡片"
date: 2023-08-10T13:49:44+08:00
tags: ["前端", "后端", "TypeScript", "字节跳动"]
---

# 用 ReactTsx 语法发送飞书交互卡片

> 本文有同步到掘金：https://juejin.cn/post/7129942982760857613


## 最终效果 Demo


## 背景

飞书卡片是一个功能非常丰富的组件，对于希望构建精美的纯样式或者简单跳转按钮的卡片，飞书提供了解决方案：[如何快速搭建精美的消息卡片？ ](https://bytedance.feishu.cn/wiki/V4mPw7nkUiZySSkyok2cUinjnIh)

但是有时我们希望发送的飞书卡片：内容动态化地根据网络请求、配置、状态等信息渲染。
同时又希望它拥有比较丰富的交互功能：点击了某一个按钮后，执行某个特定的行为，然后将卡片重新渲染成不同的样式。

飞书的卡片交互 API 是提供了以下的两个能力，使得我们实现上面的功能成为可能：
1. 卡片点击时，可以携带自定义的 value 值到服务器；
2. 我们的服务器可以响应卡片的 head/body 信息重新渲染对应的消息卡片；
基于上面的两个基础能力，我们可以在飞书卡片上实现一个完整的前端系统。

## 总体系统设计

先看传统的前端代码运行模式，浏览器运行的 React.js 代码，其运行流程可以大致地通过下图表示：

![traditional_fe_system](./traditional_fe_system.svg)

而在现在面对的 Lark 交互系统，上图中的 show 阶段和 deliver 阶段是通过网络请求异步完成的：

![lark_card_interact_system](./lark_card_interact_system.svg)

对比上面两个流程图发现以下的不同点：

1. Lark 的流程中缺失了事件监听的流程，无法准确的分发对应的事件；
2. Lark 的事件分发和渲染流程是割裂的，对应 Teamo 的服务器来说是两个独立的请求；

Teamo 可以引入 React 的 VirtualDOM 概念解决了上面的两个问题，同时以它为中间结果，将系统解耦成 SDK/Runtime 两个部分：

![decoupling_runtime](./decoupling_runtime.svg)

## SDK 系统实现

> SDK 部分的核心功能是以 tsx 源代码为输入，产出一个 larkNativeDOM 的树状结构。

### Tsx 代码编译

众所周知，一个 Tsx 的代码的会被编译为 React.createElement：

- `(<Comp prop="nihao" />)`
- `React.createElement(Comp, {prop: "nihao"})`
- 或者在 React17 之后：`_jsxRuntime.jsxs(Comp, {prop: "nihao"})`

我们是不是可以将 createElement 替换成一个自己的函数 tlmCreateElement 呢，经过几天的研究，用 babel 进行以下的配置就可以实现这个功能，这里就不加赘述：

![babel_compile_sequence](./babel_compile_sequence.svg)

### 重新造一个 React 的轮子

上面的 tlmCreateElement 这个函数就相当于重新造了一个 React.createElement 的破轮子，同样是使用 Component/Element 两层结构，具体的简陋实现参见 gitlab 仓库：

> gitlab: (内部链接，邮箱联系)

总之这一步的输出是一个 TlmElement 的树状结构，将它作为 TlmNativeDOM 中 render 方法的参数，可以得到一个 TlmNativeDOM 的实例，这个实例将参与后续 Runtime 的流程。

### 不同形状的轮子

这里需要重新写一个 tlmCreateElement 而不是重新实现一个 ReactDOM 并不是没有原因的，在这个问题中，我们需要的代码有以下的本质区别：
1. 浏览器代码需要将 UI 迅速的渲染到屏幕上，然后在后台异步地执行网络请求，当网络请求结束时用更新的方式重新渲染对应的前端页面；
2. 在当前系统中，UI 是通过网络请求“一次性渲染”的，“更新”操作在这个模型中是没有意义的。因此我们需要等待所有异步请求完成后，执行一次性渲染。

也就是下图呈现的两个模式的区别：

![dom_design_difference](./dom_design_difference.svg)

要实现下面的统一等待，只需要为每个 Component 维护一个“线程池”就可以了。因为这个“线程池”的存在，tlmNativeDOM 的核心方法 nativeLocalJSON/nativeGlobalJSON 都是异步方法。

## Runtime 系统实现

Runtime 部分的核心功能是，承接与 lark 服务器的所有网络交互、与数据库相关的持久化工作，使得上层 SDK 部分可以像运行在单机浏览器上的纯前端系统一样，进行事件处理、UI 渲染等工作。

### 无状态服务模型

有了 SDK 部分输出的 larkNativeDOM，我们还需要设计将这个 DOM 展示到飞书上的流程，并且设计相应的事件处理、监听机制。

发送的流程大致如下（忽略用户与 Lark 服务器交互的部分，将 Lark-Server 视作一个黑盒）：

![stateless_design_1](./stateless_design_1.svg)

交互的逻辑要更复杂一些，简单的来说就是通过一些变量重建了 DOM 场景，然后在重建的场景中分发对应的点击事件：

![stateless_design_2](./stateless_design_2.svg)


### 有状态服务模型

Teamo 完整地落地了上面的结构，但是上面架构是一个“单请求”、“无状态”服务，落地的过程中遇到了一些问题：
- 在每次请求中都在 Server 端重新构建一次卡片的 DOM，感官上这是相当损耗性能的，相当于“在玩游戏，玩家的每次操作到服务端时，服务端都从头重新渲染一次游戏场景”。
- 实际应用的过程这一感官确实是正确的，上面的方案在 Teamo 落地时平均响应时长在 5-10s。
- 致命的是：如果 lark 的一次交互请求耗时过长，Lark 会主动断开连接给客户端抛出错误。
- 经过分析：其主要的性能损耗就是在上图中 3.Compile 与 4.Set clientState 这两步中。

解决方案：
- 参考“游戏房间”的概念，我们可以在服务端缓存每个消息的 DOM 树；
- 如果缓存的 DOM 树是正确合理的话，我们就可以直接跳过 2-4 这最耗时的三步；

命中缓存时的交互逻辑是这样的：

![stateful_service_design](./stateful_service_design.svg)

Teamo 落地使用了简单的 Lru 内存缓存卡片的 DOM 树，平均响应时长基本降低为 1ms-500ms，提升了 10 倍的性能；

## 遗留的问题

因为时间问题，本系统还有大量的遗留问题没有解决。

1. 单元测试运行问题 
2. IDE 代码补全问题
3. 有状态服务的多客户端问题

其中第三个，对消息 DOM 树进行缓存，我们的服务就变成了一个“有状态服务”，这时就不得不考虑多客户端发起请求、多客户端卡片是否共享、服务本身是分布式部署的问题。

总的来说就是我们需要考虑下面的拓扑图：

![multi_client_problem](./multi_client_problem.svg)

解决这个问题有一些简单的思路：
- 对每个客户端展示的卡片给予一个 version 版本号，每次交互请求后版本号加一；
- 为避免多个服务端缓存了同一个卡片的信息，在获取内存缓存之前应该通过 ZooKeeper 等系统实现一个分布式锁；