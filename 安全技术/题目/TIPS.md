# TIPS

## PWN

记录一些命令：

1. 检查安全性（已经安装了 `pwntools`）：

   ```bash
   $ checksec <program>
   ```

2. 代码段全部汇编代码（`objdump`）：

   ```bash
   $ objdump -d <program>
   ```

3. 列出程序中的所有变量名（`gdb`）：

   ```gdb
   (gdb) info variables
   ```

4. 列出程序中的所有函数名（`gdb`）：

   ```gdb
   (gdb) info functions
   ```

5. 列出一个函数的汇编代码（`gdb`）：

   ```bash
   (gdb) disas main
   ```

6. 查看指定地址内的字符串（`gdb`）：

   ```gdb
   (gdb) x /s <memory_address>
   ```

7. 

