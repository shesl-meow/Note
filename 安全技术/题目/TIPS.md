# TIPS

## PWN

记录一些命令：

### 命令行工具

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

4. 

### `gdb`

1. 列出程序中的所有变量名（`gdb`）：

   ```bashs
   (gdb) info variables
   ```

2. 列出程序中的所有函数名（`gdb`）：

   ```bash
   (gdb) info functions
   ```

3. 列出一个函数的汇编代码（`gdb`）：

   ```bash
   (gdb) disas main
   ```

4. 查看指定地址内的字符串（`gdb`）：

   ```bash
   (gdb) x /s <memory_address>
   ```

5. 查看各个程序段的读写执行权限（`gdb`：`gef` 插件或 `peda` 插件都支持）

   ```bash
   (gdb-peda) vmmap
   ```

6. 

