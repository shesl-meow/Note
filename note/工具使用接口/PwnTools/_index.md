---
bookCollapseSection: true
weight: 1
title: "PwnTools"
---

# PwnTools


Quick Manual:

1. 检查安全性（已经安装了 `pwntools`，在 `peda` 等 `gdb` 插件中也支持）：

   ```bash
   $ checksec <program>
   ```

2. 代码段全部汇编代码（`objdump`）：

   ```bash
   $ objdump -d <program>
   ```

3. `ROPgadget` 得到指定的指令链或字符串：

   ```bash
   # pop-ret 指令链
   $ ROPgadget --binary <program> --only 'pop|ret'
   
   # /bin/sh 字符串
   $ ROPgadget --binary <program> --string '/bin/sh'
   ```