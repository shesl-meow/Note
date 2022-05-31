---
title: "Go Modules"
date: 2022-05-05T23:35:00+08:00
tags: [""]
categories: ["工具使用接口", "Golang"]
---

> 参考资料：https://mp.weixin.qq.com/s/zo7zmEVXvxgr80n6H_49Mg


什么是 Go Modules？

- Golang 的依赖库解决方案，于 Go1.14 推荐在生产环境上使用；

## 关于 GOPATH

GOPATH 是一个 golang 的语言环境变量，输入以下命令，可以查看本机的值：

```bash
$ go env
```

GOPATH 指向一个绝对路径，这个路径下，应该有 `bin/`、`pkg/`、`src/` 三个文件夹。

在 GOPATH 模式下：

1. 应用的代码应该存放在固定的目录 `$GOPATH/src` 下；
2. 如果执行 `go get` 拉取外部的依赖，会将其自动下载并安装到 `$GOPATH` 目录下；

GOPATH 模式的致命缺陷：没有版本控制的概念。

在 GOPATH 模式下诞生了许多依赖解决方案：vendor 目录模式，依赖工具 dep，Go 1.11 释放出 Go Modules 前身 vgo。

## 基本使用

在 Go modules 中，我们能够使用如下命令进行操作：

| 命令            | 作用                             |
| :-------------- | :------------------------------- |
| go mod init     | 生成 go.mod 文件                 |
| go mod download | 下载 go.mod 文件中指明的所有依赖 |
| go mod tidy     | 整理现有的依赖                   |
| go mod graph    | 查看现有的依赖结构               |
| go mod edit     | 编辑 go.mod 文件                 |
| go mod vendor   | 导出项目所有的依赖到vendor目录   |
| go mod verify   | 校验一个模块是否被篡改过         |
| go mod why      | 查看为什么需要依赖某模块         |

在 Go Modules 中有如下常用的环境变量（同样可以用 `go env` 命令查看）：

1. `GO111MODULE`：是否开启 Go Modules 的开关，有三个值。`auto` 表示通过是否存在文件 `go.mod` 文件判断，`on` 表示启用，`off` 表示禁用；

2. `GOPROXY`：用于使 Go 在后续拉取模块版本时能够脱离传统的 VCS 方式，直接通过镜像站点来快速拉取。它的默认值是 `https://proxy.golang.org,direct`；可以用以下命令切换成国内源：

   ```bash
   $ go env -w GOPROXY=https://goproxy.cn,direct
   ```

3. `GOSUMDB`：一个远程的 checksum 数据库，默认指向 `sum.golang.org`，它在国内也是无法访问的，但是它可以被 GOPROXY 所代理；

4. `GONOPROXY/GONOSUMDB/GOPRIVATE`：功能与前三者类似，一般用于当前项目的依赖了私有模块。一般建议直接设置 GOPRIVATE，它的值将作为 GONOPROXY 和 GONOSUMDB 的默认值：

   ```bash
   $ go env -w GOPRIVATE="git.example.com,github.com/eddycjy/mquote"
   ```

## `go.mod` 文件

这个文件描述了当前项目（也就是当前模块）的元信息，每一行都以一个动词开头。

一般常用的动词有：

- `module`：用于定义当前项目的模块路径。比如：

  ```go
  module github.com/eddycjy/module-repo
  ```

- `go`：用于标识当前模块的 Go 语言版本，值为初始化模块时的版本。比如：

  ```go
  go 1.13
  ```

- `require`：用于设置一个特定的模块版本。比如：

  ```go
  require (
      example.com/apple v0.1.2
      example.com/banana v1.2.3
      example.com/banana/v2 v2.3.4
      example.com/pear // indirect
      example.com/strawberry // incompatible
  )

- `exclude`：用于从使用中排除一个特定的模块版本。比如：

  ```go
  exclude example.com/banana v1.2.4

- `replace`：用于将一个模块版本替换为另外一个模块版本。比如：

  ```go
  replace example.com/apple v0.1.2 => example.com/fried v0.1.0 
  replace example.com/banana => example.com/fish

*PostScript*：

- `go.sum` 文件：存储着拉取模块依赖后，这些模块的哈希值防止它们被篡改。

## go get 行为

拉取的过程大致分为三步：finding 发现、downloading 下载、extracting 提取。

常用的 `go get` 命令：

| 命令               | 作用                                                         |
| :----------------- | :----------------------------------------------------------- |
| go get             | 拉取依赖，会进行指定性拉取（更新），并不会更新所依赖的其它模块。 |
| go get -u          | 更新现有的依赖，会强制更新它所依赖的其它全部模块，不包括自身。 |
| go get -u -t ./... | 更新所有直接依赖和间接依赖的模块版本，包括单元测试中用到的。 |

指定版本的方式有以下这些：

- `xxx@latest` 最新版本，`xxx@master` 对应分支的最新 commit，`xxx@v0.3.0` 仓库 tag 对应的版本，`xxx@342b2e` commit 的哈希值；
