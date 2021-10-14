# peda

> 源项目地址：[https://github.com/longld/peda](https://github.com/longld/peda)

## PEDA

`PEDA` - Python Exploit Development Assistance for GDB

### 安装教程

使用以下命令安装：

```bash
$ git clone https://github.com/longld/peda

$ echo "souce `pwd`/peda/peda.py" >> ~/.gdbinit
```

### 使用教程

这个插件将会在开启 `gdb` 之后注入一些命令，以下是一些常用命令：

| 命令                      | 功能                                 |
| ----------------------- | ---------------------------------- |
| `aslr`                  | 检测程序地址随机化是否开启/设置地址随机化              |
| `checksec`              | 检测程序开启的安全保护                        |
| `dumpargs`              | 显示执行程序是的命令行参数                      |
| `elfheader`/`readelf`   | 检测 ELF 文件的文件头信息                    |
| `elfsymbol`             | 显示文件中包含的所有非调式信息                    |
| `lookup`                | 查找一个给定地址范围内中，所有被引用的信息              |
| `patch`                 | 在一段地址之前通过 `字符串/十六进制/整数` 的方式，添加一段数据 |
| `pattern`               | 在内存中，生成/查找/写入 一个循环模式               |
| `procinfo`              | 显示从 `/proc/pid` 中得到的信息             |
| `pshow`/`pset`          | 显示/设置 `peda` 的属性参数                 |
| `ropgadget`/`ropsearch` | 显示所有的 `ROP` 链/查找给定的 `ROP` 链        |
| `searchmem`/`find`      | 在二进制文件中，查找一个指定的正则表达式               |
| `shellcode`             | 生成或下载常用的 `shellcode`               |
| `xormem`                | 对一段给定的地址范围进行异或操作                   |
