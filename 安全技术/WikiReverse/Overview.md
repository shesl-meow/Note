# Reverse Overview

## Introduction

What is **reverse engineering** (逆向工程)?

> [Wikipedia](https://en.wikipedia.org/wiki/Reverse_engineering): Reverse engineering, also called back engineering, is the process by which a man-made object is deconstructed to reveal its designs, architecture, or to extract knowledge from the object.
>
> RE 或 BE 是一个通过解构人造对象来获取其设计方式、组织结构、或分离信息的过程。

### 常规逆向流程

1. 使用 `strings/file/binwalk/IDA` 等静态分析工具收集信息，并根据这些静态信息进行 `google/github` 搜索
2. 研究程序的保护方法，如代码混淆，保护壳及反调试等技术，并设法破除或绕过保护
3. 反汇编目标软件，快速**定位到关键代码**进行分析
   - TIPS：分析控制流 &rarr; 控制流可以参见IDA生成的控制流程图 (CFG, Control Flow Graph)，沿着分支循环和函数调用，逐块地阅读反汇编代码进行分析；利用数据、代码交叉引用。
4. 结合动态调试，验证自己的初期猜想，在分析的过程中理清程序功能
5. 针对程序功能，写出对应脚本，求解出flag