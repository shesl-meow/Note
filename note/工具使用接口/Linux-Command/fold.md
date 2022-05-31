---
title: "`Fold`"
date: 2019-02-25T15:16:23+08:00
tags: [""]
categories: ["工具使用接口", "Linux-Command"]
---


`fold`:

- manual:

  > Usage: fold [OPTION]... [FILE]...
  > Wrap input lines in each FILE, writing to standard output.

- example:

  ```bash
  $ echo "Hello" > t1
  
  $ echo "World" > t2
  
  $ fold t1 t2
  Hello
  World
  ```

