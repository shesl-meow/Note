---
title: "exe0"
date: 2019-12-03T13:41:00+08:00
tags: [""]
categories: ["系统理论课程", "操作系统"]
---


同 [lab2](../lab2/exe0.md)：

1. 导出 change：

   ```bash
   $ git diff 776bc9ece6f0f887962603c0eadf779d1443ecbd HEAD labcodes/lab3/ | sed 's/lab3/lab4/g' > lab4/exe0.patch
   ```

2. 进行 merge：

   ```bash
   $ git apply lab4/exe0.patch
   ```


