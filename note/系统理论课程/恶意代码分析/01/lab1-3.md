---
title: "lab 1-3"
date: 2019-05-01T12:56:05+08:00
tags: [""]
categories: ["系统理论课程", "恶意代码分析"]
---


## QUESTION 1

> Upload the Lab01-03.exe file to http://www.VirusTotal.com/. Does it match any existing antivirus definitions?

文件的 sha256 哈希值：

```bash
$ sha256sum Lab01-03.exe
7983a582939924c70e3da2da80fd3352ebc90de7b8c4c427d484ff4f050f0aec  Lab01-03.exe
```

因此上传的 `url` 为：https://www.virustotal.com/#/file/7983a582939924c70e3da2da80fd3352ebc90de7b8c4c427d484ff4f050f0aec/detection

可以看到这同样是一个被 59 个引擎检测出来的木马。

## QUESTION 2

> Are there any indications that this file is packed or obfuscated? If so, what are these indicators? If the file is packed, unpack it if possible.

可以在 Windows 上通过 `PEiD` 这个软件检验壳：

![03.exe.PEiD](../03.exe.PEiD.png)

我们发现，这个可执行文件通过 `FSG 1.0` 加壳了。我们通过一个[52poejie 教程](https://www.52pojie.cn/thread-886615-1-1.html?tdsourcetag=s_pctim_aiomsg) 可以实现手动脱壳。

但是我懒不想手动脱壳，在吾爱破解上找到了[一个工具](https://www.52pojie.cn/thread-153693-1-1.html)：

![03.exe.PackerBreaker](../03.exe.PackerBreaker.png)

把同文件夹下的 `./Lab01-03.pb.1.exe` 更名为 `./Lab01-03.unpack.exe` 然后再用 `PEiD` 分析，发现成功脱壳：

![03.exe.PEiD.unpack](../03.exe.PEiD.unpack.png)

## QUESTION 3

> Do any imports hint at this program’s functionality? If so, which imports are they and what do they tell you?

我们使用 `malscan` 这个工具，检测脱壳之后的文件：

```bash
$ malscan /tmp/BinaryCollection/Chapter_1L/Lab01-03.unpack.exe
...
[Imports Overview]

MSVCRT.dll
        0x402000 __getmainargs
        0x402004 _controlfp
        0x402008 _except_handler3
        0x40200c __set_app_type
        0x402010 __p__fmode
        0x402014 __p__commode
        0x402018 _exit
        0x40201c _XcptFilter
        0x402020 exit
        0x402024 __p___initenv
        0x402028 _initterm
        0x40202c __setusermatherr
        0x402030 _adjust_fdiv

OLEAUT32.dll
        0x402038 None
        0x40203c SysAllocString
        0x402040 None

OLE32.dll
        0x402048 OleInitialize
        0x40204c CoCreateInstance
        0x402050 OleUninitialize
...
```

不知道这是干什么的，可能下载的脱壳机有问题。

## QUESTION 4

> What host- or network-based indicators could be used to identify this malware on infected machines?

因为脱壳失败了，所以读取的字段也有问题。
