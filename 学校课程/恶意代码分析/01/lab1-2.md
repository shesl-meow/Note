# lab 1-2

## QUESTION 1

> Upload the Lab01-02.exe file to http://www.VirusTotal.com/. Does it match
> any existing antivirus definitions?

文件的 sha256 哈希值：

```bash
$ sha256sum Lab01-02.exe
c876a332d7dd8da331cb8eee7ab7bf32752834d4b2b54eaa362674a2a48f64a6  Lab01-02.exe
```

因此上传的 `url` 为：https://www.virustotal.com/#/file/c876a332d7dd8da331cb8eee7ab7bf32752834d4b2b54eaa362674a2a48f64a6/detection

可以看到这同样是一个木马。

## QUESTION 2

> Are there any indications that this file is packed or obfuscated? If so, what are these indicators? If the file is packed, unpack it if possible.

使用 `blackarch` 的工具 `packerid` 来检测第二个可执行文件的壳：

```bash
$ packerid Lab01-02.exe
['UPX v0.89.6 - v1.02 / v1.05 -v1.24 -> Markus & Laszlo [overlay]']
```

可以看到这是一个用 `UPX` 简单加壳的程序。

我们安装 `upx` 这个程序之后，简单地脱壳即可：

```bash
$ sudo pacman -S upx

$ upx -d Lab01-02.exe -o Lab01-02.unpack.exe
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2018
UPX 3.95        Markus Oberhumer, Laszlo Molnar & John Reiser   Aug 26th 2018

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     16384 <-      3072   18.75%    win32/pe     Lab01-02.unpack.exe

Unpacked 1 file.

$ packerid Lab01-02.unpack.exe 
['Microsoft Visual C++ v5.0/v6.0 (MFC)']
```

可以看到打包程序是 `MFC`，因此我们将这个程序成功脱壳。

## QUESTION 3

> Do any imports hint at this program’s functionality? If so, which imports are they and what do they tell you?

我们同样可以使用 `blackarch` 下的静态分析工具 `malscan` 分析导入表：

```bash
$ malscan /tmp/BinaryCollection/Chapter_1L/Lab01-02.unpack.exe
...
KERNEL32.DLL
	0x402010 SystemTimeToFileTime
	0x402014 GetModuleFileNameA
	0x402018 CreateWaitableTimerA
	0x40201c ExitProcess
	0x402020 OpenMutexA
	0x402024 SetWaitableTimer
	0x402028 WaitForSingleObject
	0x40202c CreateMutexA
	0x402030 CreateThread

ADVAPI32.dll
	0x402000 CreateServiceA
	0x402004 StartServiceCtrlDispatcherA
	0x402008 OpenSCManagerA

MSVCRT.dll
	0x402038 _exit
	0x40203c _XcptFilter
	0x402040 exit
	0x402044 __p___initenv
	0x402048 __getmainargs
	0x40204c _initterm
	0x402050 __setusermatherr
	0x402054 _adjust_fdiv
	0x402058 __p__commode
	0x40205c __p__fmode
	0x402060 __set_app_type
	0x402064 _except_handler3
	0x402068 _controlfp

WININET.dll
	0x402070 InternetOpenUrlA
	0x402074 InternetOpenA
...
```

可见这个可执行文件主要调用了与进程线程有关的函数、打开 `URL` 连接的函数。

## QUESTION 4

> What host- or network-based indicators could be used to identify this malware on infected machines?

我们分析脱壳之后的文件，发现其 `.data` 段中有 `http://www.malwareanalysis.com` 这个字符串：

![02.exe.PEexplorer.data](./02.exe.PEexplorer.data.png)

再用 `ida pro` 查找调用这个字符串的位置，我们找到以下的伪代码：

```c
  for ( i = InternetOpenA(szAgent, 1u, 0, 0, 0); ; InternetOpenUrlA(i, szUrl, 0, 0, 0x80000000, 0) );
```

这其中 `szAgent` 这个字符串变量指的就是 `Internet Explorer 8.0`，而后的 `szUrl` 指的就是 `http://www.malwareanalysisbook.com`，这是一个不会停止的循环，意味着这个病毒会不断得使用 `IE` 浏览器打开后面的网址。

因此我们可以通过 `wireshark` 抓取所有访问这个网址的流量即可。

