---
title: ":santa:C++ 杂技大全"
date: 2018-12-30T00:00:00+08:00
tags: ["持续更新", "服务端", "C++"]
---

## 关键字

### `__builtin_expect`

`__builtin_expect`：一个 if 分支极大可能不会执行，使用这个编译，附近的，编译器会将极大概率连续执行的代码编译为连续的二进制。


### `__attribute__`

更多相关信息可以查看 [GNU 官方文档](https://gcc.gnu.org/onlinedocs/gcc-4.3.0/gcc/Function-Attributes.html) ：

1. `unused`: 显式地指定一个变量不会被使用，-Wall 编译时不会抛出警告，比如：`int main(int argc __attribute__((unused)), char **argv)`；
2. `format`: 传递 `printf` 类似的参数时进行参数校验，比如：`extern void printfBy(int flag, const char *format, ...) __attribute__((format(printf, 2, 3)));`
3. `noreturn`: 显式地告诉编译器对应的函数不会调用 `exit` 或 `abort` 等函数；

## 内存分配与 Runtime

> 参考：https://github.com/huihut/interview

### 在 main 函数前执行的函数

定义一个类 A 以 `static` 的方式持有一个 类 B 的实例。

类 B 的静态初始化方法会在整个程序的 `main` 函数前执行。

### 控制对象分配

如何定义一个只能分配在栈（堆）上的类（参考[博客](https://www.nowcoder.com/questionTerminal/0a584aa13f804f3ea72b442a065a7618)）：

1. 将析构函数定义为私有函数，编译器无法在栈分配时调用析构方法。对象将只能被定义在堆上；

2. 重载 `new()` 与 `delete()`，对象无法被动态分配。对象将只能被定义在栈上；

### 虚函数表

用纯 C 实现 C++ 类继承中的动态虚函数特性（参考[博客](https://blog.twofei.com/496/)），实现虚函数表。

### `struct` 字节对齐

定义结构体编译对齐方法，比如按四字节对齐：

```c++
#pragma pack(push)
#pragma pack(4)
...
#pragma pack(pop)
```

### 强制类型转化

![ForceCast](./cpp-cast.svg)

## 插件与三方库

### `Deque`

`Deque` 的全称是 double ended queue，两端结束队列；

它是 `stack` 与 `queque` 的底层存储结构，它的实现基于 `vector` 的实现，它结构大致如下：

![DequeStructure](./cpp-DequeStructure.png)

可以看到这样存储的优点是：

1. 仍然可以通过接近与 O(1) 常数级别的时间复杂度进行访问；
2. 在两端的插入删除复杂度仍然为 O(1)；

对于 `stack` 与 `queue` 这样的仅仅在双端有插入删除访问操作的数据结构，是一个合适的基类；

### 智能指针

智能指针定义在头文件 `memory` 中。

![cpp-smartpointer.svg](./cpp-smartpointer.svg)


