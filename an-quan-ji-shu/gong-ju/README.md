# 工具

关于各种工具的用途总结：

## WEB 工具

[shodan](https://github.com/shesl-meow/Note/tree/687b2064a0a6a9909107f1bc42f10d61e939dc26/%E5%AE%89%E5%85%A8%E6%8A%80%E6%9C%AF/%E5%B7%A5%E5%85%B7/%3Chttps:/cli.shodan.io/%3E/README.md)：

```bash
# 安装
$ pip install shodan

# 初始化
$ shodan init <API KEY>

# 详细见：https://cli.shodan.io/
```

[sqlmap](https://github.com/shesl-meow/Note/tree/687b2064a0a6a9909107f1bc42f10d61e939dc26/%E5%AE%89%E5%85%A8%E6%8A%80%E6%9C%AF/%E5%B7%A5%E5%85%B7/%3Chttps:/github.com/sqlmapproject/sqlmap%3E/README.md)：

```bash
# 安装
$ pip install sqlmap

# 使用
$ sqlmap -u <target website>
```

## 密码学工具

`z3`，`pycrypto`，`sagemath`

## PE Portable Executable

1. [VirusTotal](http://www.virustotal.com)：一个分析病毒文件的在线网站。
2. `pefile`：一个静态分析 PE 文件的 python 库。[源代码](https://github.com/erocarrera/pefile)
3. `capstone`、`keystone-enginne`：一个处理反汇编程序的库和一个处理汇编程序的库，可以使用 python、c++ 等语言编写。[源代码](https://github.com/aquynh/capstone)
