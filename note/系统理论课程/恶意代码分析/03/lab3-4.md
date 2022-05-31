---
title: "lab 3-4"
date: 2019-05-16T15:42:26+08:00
tags: [""]
categories: ["系统理论课程", "恶意代码分析"]
---


## QUESTION 1

> What happens when you run this file?

拿到病毒首先分析是否加壳：

![04.exe.PEiD](../04.exe.PEiD.png)

同样的这个文件也是 `Microsoft Visual C++ 6.0`，同样理论上也可以直接分析反汇编代码。对于本题我们只需要双击运行即可。

双击运行结果：病毒闪退，然后把自己删掉了。

## QUESTION 2

> What is causing the roadblock in dynamic analysis?

这个病毒会检测自己是否被正确执行，然后闪退把自己删除。

## QUESTION 3

> Are there other ways to run this program?

分析反汇编代码应该可以观察这个程序需要什么手段才可以正确执行，但是我懒，不想继续分析了。


