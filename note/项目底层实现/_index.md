---
bookFlatSection: true
weight: 20
title: "项目底层实现"
---

# 项目底层实现

> 最近转岗到了字节跳动搜索广告组，接触到了大量没有接触过的项目代码，觉得有必要整理一下大型项目代码的方法论，打算在此总结一些自己的想法，并最近拿一个开源项目代码练练手。


## 基本方法论

带着问题读代码，好于枚举式读代码：

- 比如：这个项目是为了解决什么问题（读代码前先明确“我为什么要读这个项目代码”，之后对不同的步骤有倾向地侧重）？实现 xxx 逻辑的代码在哪里？这个项目是按照什么逻辑组织的？

应用 OKR 的思想，带着"产出"的思维读代码：

- 经过了一段迷茫时间的感悟，没有明确的产出目标很容易走神、注意力不集中、代码看着看着就看手机去了。

- 比如：这个"产出"可以是一篇可以分享到朋友圈的笔记、一个可以在周报上写上的文档；

广度优先遍历读代码，“读完”优先级高于“深入理解”：

- 看了网上很多人交流的方法论，有人更倾向于“广度”、有人更倾向于“深度”，我都有尝试。我个人觉得对于一个完全陌生的项目，“广度”是“必选项”而不是“个人喜好”。

- “深度”发生的两个场景：

    1. 刚开始读就希望了解全部的代码底层逻辑：这样的阅读方式会把大量的时间浪费在不重要的细枝末节上；

    2. 看到一个方法名、注释、变量名非常符合我们期待的目的：没有全局视角时这样的判断正确率不会很高，当我们判断失败时，因为人的思维组织模式，想要回到上次的位置继续阅读会非常困难。可以先将这个位置记下，有全局视角后深入阅读将是 ROI 很高的事情。


没有完美的代码架构，带着质疑的心态读代码，不要怀疑自己；


## 步骤

0. 前置和准备条件：了解代码的基本编程语言，项目的目的，代码库产生的历史背景等；基本概念、术语、相关领域的常见词汇（比如广告代码的 RIT、投放、品牌广告、竞价广告等）；

1. 了解项目代码目的、出入口、基本框架。项目相关文档、项目的 idl 接口定义。

2. 通读代码，了解大概调用链路，找出核心逻辑模块。业务层的逻辑调用、通用代码的文件组织结构，比如 `rpc`、`io` 等；

3. 按优先级深入了解核心模块逻辑

4. 整理运行流程图、提出建议。上手运行这个代码，比如一个 benchmark、一个 issue、一个需求；

