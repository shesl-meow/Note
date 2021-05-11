# API 设计

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

*PostScript*：概念学习：

- 微服务：
- 服务发现：
- 服务限流：
- 服务熔断：
- 负载均衡：

## gRPC

