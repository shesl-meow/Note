---
title: ":ambulance:概念学习与面试题"
date: 2018-12-30T00:00:00+08:00
tags: ["持续更新", "算法", "服务端"]
---

## 常见算法小记

Fisher–Yates shuffle 洗牌算法：https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle

Boyer-Moore 多数投票算法：https://en.wikipedia.org/wiki/Boyer%E2%80%93Moore_majority_vote_algorithm

```golang
func majorityElement(nums []int) int {
    iter, most := 0, 0
    for _,num := range nums {
        if iter == 0 { most, iter = num, iter+1 } 
      	else if most == num { iter += 1 } 
      	else { iter -= 1 }
    }
    count, sz := 0, len(nums)
    for _,num := range nums {
        if num == most { count += 1 }
        if count * 2 > sz { return most }
    }
    return -1
}
```

素性检测算法：关于一些素性检测的底层算法，在学校时，[信息安全数学基础课](../../book/系统理论课程/信息安全数学基础/8.数论应用)上讲过。

素数数量计算，`Sieve of Eratosthenes`，筛法：

```pseudocode
algorithm Sieve of Eratosthenes is
    input: an integer n > 1.
    output: all prime numbers from 2 through n.

    let A be an array of Boolean values, indexed by integers 2 to n,
    initially all set to true.
    
    for i = 2, 3, 4, ..., not exceeding √n do
        if A[i] is true
            for j = i2, i2+i, i2+2i, i2+3i, ..., not exceeding n do
                A[j] := false

    return all i such that A[i] is true.
```


## 时序数据库 TSDB

时序数据的特点：

- 数据按照时间严格单调排序；
- Append Only：只能向后插入数据，不能更新；
- 写数量远大于读数量：大于 90% 的数据从未被读取；
- 数据量级特别大，但是相对比较稳定；
- 随着时间的推移，数据的价值减小，最近数据的价值高于历史数据；
- 通常与 `tag` 聚合在一起，根据时间范围进行查询；

Metrics 是字节跳动实现 tsdb 的解决方案，很多平台的数据源都来自 Metrics：

- `alarm`、`grafana`、`metro-fe`、`argos`；

Metrics 系统架构分为三级：

1. SDK 侧：通过 SDK 将日志信息发送到 `agent`，`agent` 通过 `producer` 发送到消息队列中；
2. 核心逻辑：`consimer`/`preshuffle` 两个消费逻辑链路，分别将数据存储到冷热存储的两个不同数据库中；
3. 数据存储：速度快的“热存储”TSDC、速度较慢的“冷存储”mstore；

Open Source：

- 在业界有很多开源的解决方案：`Influxdb`、`Opentsdb`、`Druid`、`Elasticsearch`、`Beringei` 等；

## RESTful

> For TypeScript: https://github.com/thiagobustamante/typescript-rest

REST: Representational state transfer.

RESTful 是一种面向资源的过时 API 设计理念，他基于 http 协议，没有单独定义自己的一套协议，只是一种 API 设计范式。

它提供了四个指导原则：

1. Resource-Base 基于资源的：一个 uri 单独对应于一个资源；
2. Manipulation Through Representations 动作表示：对资源的不同动作通过方法或参数表示；
3. Self-Descriptive Message 自描述信息：每条请求都能没有上下文地无状态地，唯一执行一个动作；
4. Hypermedia as the Engine of Application State (HATEOAS)：用高级的请求体来表示状态；

## GraphQL

> For TypeScript: https://github.com/MichalLytek/type-graphql,  https://typegraphql.com/
>
> Official Website: https://graphql.org/

GraphQL: Graph Query Language.

- 介绍：GraphQL 是 Facebook 为了解决 RESTful 设计模式在系统庞大之后出现的各种问题应运而生的接口描述语言。

- 在 API 设计这个问题上：Graph API 对外只暴露一个接口（比如：https://leetcode.com/graphql），资源通过图的方式关联式地设计在这个接口中。
- 与 RESTful：在系统中，GraphQL 与 RESTful 通常是同时存在的关系而不是完全取代。 

*PS*: 许多诸如 GraphQL 与 RESTful 的区别等问题可以查看官方的文档：https://graphql.org/faq/#does-graphql-use-http

## Thrift-RPC

> 官方：https://thrift.apache.org/、
>
> IDL 文档：https://thrift.apache.org/docs/idl.html

Thrift 是什么，Apache 提供的一个 API 序列化框架：

- Apache Thrift 是一个跨语音的可扩展服务器开发框架，可以在语言间无缝高效地迁移。


## Session Base Authentication

> 参考：
>
> - https://sherryhsu.medium.com/session-vs-token-based-authentication-11a6c5ac45e4
> - https://jwt.io/introduction
> - https://stackoverflow.com/questions/43452896/authentication-jwt-usage-vs-session
> - https://en.wikipedia.org/wiki/OAuth

### 流程简介

最传统的用户系统，django 的默认实现，用户登陆时后服务端会为当前会话创建一个 `session` 并且将 `sessionID` 作为 cookie 设置到客户端上，用户每次需要访问敏感资源时需要带上 `sessionID`，服务端通过 session 判断用户是否登陆成功。简单流程如下：

![session_base_authentication](./session_base_authentication.png)

## JWT (Json Web Token)

### 格式

JWT 是一种被写入 [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519) 的协议标准。一个 JWT 的格式由 Base64 加密的 “Header”、“Payload”、“Signature” 三个部分由 `.` 字符拼接而成：

![jwt_format](./jwt_format.png)

上图中可以看出三部分的作用：

1. `header` 部分表示当前 JWT 的算法；
2. `playload` 则存储了当前登陆用户的信息（在传统基于 `session` 的登陆系统下，这一信息一般是存储在服务端），`Playload` 分为 `Registered claims`/`Public claims`/`Private claims` 三个类型；
3. `signature` 用服务端的私钥进行 HMAC 确保 `playload` 中的信息没有被修改过；

### 工作流

在认证成功后，服务器会返回给客户端一个 JWT。当客户端需要访问任何敏感资源时，需要设置 `Authorization` 的请求头：

```
Authorization: Bearer <token>
```

图例：

![jwt_authentication](./jwt_authentication.png)

值得注意的是，因为 Token 是在请求头的 `Authorization` 中带上的，所以并不会被浏览器的跨域策略（CORS, Cross-Origin Resource Sharing）影响。**Token 不是 Cookie**。

### 优点与缺点

 JWT(Json Web Token) 相对 SWT(Simple Web Token) 与 SMAL(Security Assertion Markup Language Tokens) 的好处：

- JWT 相对于 SMAL 有更小的体积，相对于解析 xml 解析 json 更加简单，更适合在 http 协议于 html 文件的场景下进行传输；
- JWT 相对于 SWT 更加安全。SWT 只能解析基于共享密钥的对称加密算法，而 JWT（SMAL 也支持）则支持 `X.509` 格式的公私钥签名；

相比传统使用 `sessionID` 的 cookie 进行身份校验的好处：

1. Scalability（可扩展性）：传统的 `sessionID` 策略如果将用户信息持久化存储在数据库中，每次请求数据库都会执行一次数据库查询；如果存储在内存中则存在分布式系统的横向扩展问题。jwt 将信息存储在客户端，并且服务端做鉴权，就不存在这个问题；
2. Multiple Devices：可以用于设计 SSO 单点登录系统，因为 JWT Token 被设置在 http 请求头中，可以规避浏览器跨域问题；

JWT 也有一些缺点，在 RFC 的标准协议中没有指定解决方案：

- 客户端存储信息的安全性、JWT 信息传输的安全性、JWT Token 难以被控制失效、客户端信息信任问题；

### nodejs 生态

[jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken) 可以用于在服务端创建一个 JWT，[express-jwt](https://github.com/auth0/express-jwt) 中间件可以用于对 jwt 进行鉴权。

## OAuth (Open Authorization)

OAuth 是一种第三方授权协议，现在讨论的版本通常是 OAuth2.0，也是 RFC 的标准协议 [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749)。

OAuth 的大致工作流程在 RFC 的文档中有详细解释：

```
     +--------+                               +---------------+
     |        |--(A)- Authorization Request ->|   Resource    |
     |        |                               |     Owner     |
     |        |<-(B)-- Authorization Grant ---|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(C)-- Authorization Grant -->| Authorization |
     | Client |                               |     Server    |
     |        |<-(D)----- Access Token -------|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(E)----- Access Token ------>|    Resource   |
     |        |                               |     Server    |
     |        |<-(F)--- Protected Resource ---|               |
     +--------+                               +---------------+
```

在标准文档更关于不同授权模式的介绍，不详细赘述。

值得注意的是 OAuth 与 JWT 并不是并列的关系，OAuth 中的 Access Token 可以用 JWT 实现，它们应该是一个嵌套的关系。

## 服务发现

> https://zhuanlan.zhihu.com/p/161277955

使用一个名字服务器进行服务发现。解决分布式微服务的网络调用结构问题。

## 服务限流

> https://zhuanlan.zhihu.com/p/65900436

服务限流算法：

- 计数器算法、漏桶算法、令牌算法

## 服务雪崩降级熔断

服务雪崩：

- 一个服务失败，导致整条链路的服务都失败的情形，我们称之为服务雪崩。

服务熔断：

- 当下游的服务因为某种原因突然**变得不可用**或**响应过慢**，上游服务为了保证自己整体服务的可用性，不再继续调用目标服务，直接返回，快速释放资源。

服务降级：

- 当下游的服务因为某种原因**响应过慢**，下游服务主动停掉一些不太重要的业务，释放出服务器资源，增加响应速度。

## 版本控制

现在流行的版本系统主要分为集中式版本系统、分布式版本系统 2 大类。

### 集中式版本系统

主要的集中式版本控制系统：

- `CVS` (Concurrent Versions System) free software，以 GNU 版权发行，许多老的 GNU 项目都用 CVS，2008 年后更新不活跃。
- `Subversion` (Apache Subversion) Apache License，top-level Apache project，兼容 CVS。
- `SVN` 则是最著名的集中式版本控制系统。

`SVN` 的主要特点：

- `SVN` 需要一个**中心服务器**，用来保存所有文件的所有修订版本。

- 客户端只保存最新的版本或者设置为检出某一个历史版本，客户端必须在连接到中心服务器之后才能做出检出某个版本、查询文件修改历史、提交更新等操作。

- 每一次 `commit` 之前，都需要连接中心服务器获取最新的文件版本，如果中心服务器宕机，则你无法提交任何更新，也无法将项目回溯到历史版本。

- 如果中心服务器发生磁盘故障，而你又没有做任何备份，你将会丢失当前和历史的所有数据。

- 对 分支 的支持较弱，SVN 的分支就是一个完整、独立的文件夹，分支的创建和合并代价都非常高（实际可能会通过硬连接的方式节省空间）；

- 无法追踪目录文件的变化，变更目录需要使用 SVN 命令。
- 管理员能够轻松掌握每一个开发者的权限（Git 自身不支持分支保护）。

### 分布式版本系统

主要的分布式管理系统：

- Git 第一个版本由 Linus Torvalds 编写，GNU GPL v2
- Mercurial 基本用 python 实现，目前 GNU GPL v2。仍在用它管理的[项目](https://www.mercurial-scm.org/wiki/ProjectsUsingMercurial)

Git 和 Mercurial 都是为了管理 Linux kernel 而开发的，只不过最后社区选择了 Git。

对于 Git，中心服务器是可选的，客户端不仅仅提取最新版本的文件快照，而是把整个代码仓库完整地镜像下来。这样你在版本控制系统中做出任何提交、检出，比较等操作都是在本地进行，如果用来协同工作的中心服务器发生故障，事后可以用任何一个镜像来恢复代码仓库。


### Git 文件系统

我们在一个 `git init` 结果的空仓库中，简述一下各个部分的作用：

```bash
.git
├── HEAD 				// 指示当前被检出的分支
├── branches 		// 废弃
├── config 			// 项目内的配置文件
├── description // 供GitWeb程序使用
├── hooks 			// 存储钩子脚本
│   ├── applypatch-msg.sample
│  ...
├── info 				// 目录包含一个全局性排除(global exclude)文件，
│   └── exclude	// 用以放置那些不希望被记录在 .gitignore 文件中的忽略模式(ignored patterns)
├── objects 		// 存储所有数据内容
│   ├── info 		// 仓库的额外信息
│   └── pack 		// 压缩后的包文件
└── refs // 存储指向分支的提交对象的指针
    ├── heads 	// 分支
    └── tags 		// 标签
```

执行以下命令可以查看 Git 目录结构说明：

```bash
git help gitrepository-layout
```

当 Git 存储一个文件时：

1. 首先会根据文件内容计算出文件的哈希值 (使用 SHA-1 算法)，结果是 40 位的十六进制字符串。
2. 取前 2 个字符作为目录名，后 38 个字符作为文件名，存储在 `.git/objects` 文件夹下。

这样给定文件的哈希值，就能在文件系统中直接定位到文件。这种计算方式遍布于 Git 的各种操作中，包括分支、提交记录、tag 等都可以用哈希值来表示。

以下命令可以查看，一个指定哈希值，对应的文件：

```bash
git cat-file -p <hash>
```


## ACID 理论

关系型数据库有事务（transaction）的概念，事务遵循 ACID 原则：

- A (Atomicity 原子性)：事务里的所有操作要么全部做完，要么都不做，事务成功的条件是事务里的所有操作都成功，只要有一个操作失败，整个事务就失败，需要回滚。
- C (Consistency 一致性)：
- I (Isolation 独立性)：
- D (Durability 持久性)：

## 分布式系统

什么是分布式系统？

- 简单的来说，**一个分布式系统是一组计算机系统一起工作，在终端用户看来，就像一台计算机在工作一样**。这组一起工作的计算机，拥有**共享的状态**，他们同时运行，独立机器的故障不会影响整个系统的正常运行。

分布式系统的优点：

- **可靠性（容错） ：**分布式计算系统中的一个重要的优点是可靠性。一台服务器的系统崩溃并不影响到其余的服务器。

- **可扩展性：**在分布式计算系统可以根据需要增加更多的机器。

- **资源共享：**共享数据是必不可少的应用，如银行，预订系统。

- **灵活性：**由于该系统是非常灵活的，它很容易安装，实施和调试新的服务。

- **更快的速度：**分布式计算系统可以有多台计算机的计算能力，使得它比其他系统有更快的处理速度。

- **开放系统：**由于它是开放的系统，本地或者远程都可以访问到该服务。

- **更高的性能：**相较于集中式计算机网络集群可以提供更高的性能（及更好的性价比）。

分布式系统的缺点：

- **故障排除：**故障排除和诊断问题。

- **软件：**更少的软件支持是分布式计算系统的主要缺点。

- **网络：**网络基础设施的问题，包括：传输问题，高负载，信息丢失等。

- **安全性：**开放系统的特性让分布式计算系统存在着数据的安全性和共享的风险等问题。

## CAP 理论

在计算机科学中, CAP定理（CAP theorem）, 又被称作 布鲁尔定理（Brewer's theorem）, 它指出对于一个分布式计算系统来说，不可能同时满足以下三点:

- 一致性(Consistency)：所有节点在同一时间具有相同的数据；
- 可用性(Availability)：保证每个请求不管成功或者失败都有响应；
- 分隔容忍(Partition tolerance)：系统中任意信息的丢失或失败不会影响系统的继续运作；

因为三者无法同时满足，所以分布式系统可以被分为 CA、CP、AP 三大类，因为 CA 系统本质只是单点集群，所以无法满足 P 的系统在分布式系统中是没有意义的，因此我们通常只讨论 AP 或 CP 系统。

## BASE 理论

BASE：Basically Available, Soft-state, Eventually Consistent。 由 Eric Brewer 定义。

相对于 CAP 理论，BASE 理论则强调可用性超过一致性，通常用于描述 NoSQL 数据库的特性。

- Basically Available：基本可用
- Soft-State：软状态/柔性事务。即在没有任何输入的情况下，状态也会发生变更。
- Eventually Consistency：最终一致性。系统会随着时间的变化最终达到一致性的要求。

## Roaring Bitmap

### 背景

官网：http://roaringbitmap.org/

开源代码：https://github.com/RoaringBitmap/RoaringBitmap

论文：

- 《Better bitmap performance with Roaring bitmaps》：https://arxiv.org/abs/1402.6407，https://arxiv.org/pdf/1402.6407.pdf
- 《Consistently faster and smaller compressed bitmaps with Roaring》：https://arxiv.org/abs/1603.06549，https://arxiv.org/pdf/1603.06549.pdf

相关文章：https://cloud.tencent.com/developer/article/1136054

### 竞品解决方案

Roaring Bitmap 是对 Bitmap 的优化，是“压缩位图索引”的一种，同样的方案还有：

-  RLE（Run-Length Encoding）；
-  WAH (Word Aligned Hybrid Compression Scheme) ；
-  Concise (Compressed ‘n’ Composable Integer Set)

### 空间复杂度分析

假设我们的系统主线是 64 位，我们需要存储类型为 `uint32_t` 的索引到一个对象地址。

传统的 Bitmap 对应的空间复杂度为：

- $2^{32} * 64 bit = 4G * 8byte = 32 GByte$，是一个不论数据分布如何的常数。

而 Roaring Bitmap 对应的空间复杂度为：

- 一级索引的内容是二级索引的地址指针：$2^{16} * 64bit = 2^{22} = 512KByte$

- 而二级索引是一个随数据分布而变化的量：
  - 空标记位 0Byte，只需要标记存储地址的指针；
  - 在数据稀疏时通过数组存储对应的数据，每个数据需要存储剩余的低 16 位索引以及数据本身，对于一个桶中有 n 个数据：$n * (2^{16} + 2^{64})$
  - 对于稠密的数据，将通过 bitmap 存储该桶中的数据，空间退化为常数 $2^{16} * 2^{64}$，这主要是出于查询时间复杂度的考虑而非空间的考虑。
