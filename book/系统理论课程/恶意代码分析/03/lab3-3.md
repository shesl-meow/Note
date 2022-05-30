# lab 3-3

## QUESTION 1

> What do you notice when monitoring this malware with Process Explorer?

拿到病毒首先分析是否加壳：

![03.exe.PEiD](../03.exe.PEiD.png)

可见其 `packer` 就是 `Visual C++ 6.0`，没有进行任何加壳，理论上可以直接分析反汇编代码，但是题目让我们进行动态分析，于是我们再虚拟机中运行这个病毒。

我们首先打开 `Procexp` 与 `Procmon`，然后运行 `Lab03-03.exe` 这个程序：

![03.exe.procmon](../03.exe.procmon.png)

我们发现 `Lab03-03.exe` 这个应程序再运行时创建了一个 `svchost.exe` 的子进程。

另外我们尝试通过 `procmon` 中过滤 `Process Name =is= Lab03-03.exe` 进程观察这个进程调用的 API。我们发现这个病毒尝试创建这样一个敏感文件 `C:/Windows/System32/svchost.exe`：

![03.exe.procexp](../03.exe.procexp.png)

我们猜测这个病毒可能尝试替换电脑中的 `svchost.exe` 文件，并且替换电脑的服务进程。

## QUESTION 2

> Can you identify any live memory modifications?

同样的我们再 `procmon` 中添加以下的两条过滤条件：

```sql
"Process Name" is "Lab03-03.exe"
"Operations" contains "Create"
```

![03.exe.procexp.contains.create](../03.exe.procexp.contains.create.png)

通过上面的分析，这个恶意代码主要尝试创建以下的几个文件：`svchost.exe`、`apphelp.dll`、`systest.db` 等，其中大部分文件由于权限问题创建失败，因此我们也有理由相信它因为权限问题无法写入文件。

所以大致猜测，该恶意代码尝试替换主机上的 `svchost.exe` 文件，但因为权限问题无法写入。但是通过第一问的分析，恶意代码可能已经替换了正运行在内存中的 `svchost.exe` 文件。

另外进一步观察这里调用的 API，发现这个病毒还在同级目录下创建了文件 `practicalmalwareanalysis.log`，这个文件。

## QUESTION 3

> What are the malware’s host-based indicators?

如同前面两节搭建网络测试环境：`Windows XP` 运行病毒、`Windows 7` 搭建 DNS 服务、`Kali Linux` 搭建 WEB、SSH 等应用层服务。

运行病毒后，我们并没有再 `Windows 7` 上看到来自 `Windows XP` 的任何 DNS 请求，再在 `Kali Linux` 上再使用 `wireshark` 捕获整个网卡上的所有流量信息，并没有任何相关信息。

因此综上所述，可以唯一观察到的主机迹象是创建了同目录下的文件 `practicalmalwareanalysis.log`。

## QUESTION 4

> What is the purpose of this program?

经过前面的分析，这个程序主要替换了一个 `svchost.exe` 文件。但是并没有发起任何网络请求，另外还在同级目录下的文件 `practicalmalwareanalysis.log` 中记录了一些东西：

```log
[Window:  C:\Documents and Settings\Administrator\桌面\Practical Malware Analysis Labs\BinaryCollection\Cha]
 
[Window:  practicalmalwareanalysis.log 属性]
 c
[Window:  C:\Documents and Settings\Administrator\桌面\Practical Malware Analysis Labs\BinaryCollection\Cha]
 
[Window:  C:\Documents and Settings\Administrator\桌面\Practical Malware Analysis Labs\BinaryCollection\Chapter_3L\practicalmalwareanalysis.log - EverEdit]
 ac
```

暂时还不知道这个记录的内容是什么。