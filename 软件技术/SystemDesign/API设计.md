# API 设计

## RESTful

> https://github.com/thiagobustamante/typescript-rest

REST: Representational state transfer.

 RESTfu 是一种面向资源的过时 API 设计理念，他基于 http 协议，没有单独定义自己的一套协议，只是一种设计范式，它提供了四个指导原则：

1. Resource-Base 基于资源的：一个 uri 单独对应于一个资源；
2. Manipulation Through Representations 动作表示：对资源的不同动作通过方法或参数表示；
3. Self-Descriptive Message 自描述信息：每条请求都能没有上下文地无状态地，唯一执行一个动作；
4. Hypermedia as the Engine of Application State (HATEOAS)：用高级的请求体来表示状态；

