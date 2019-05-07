# lab 3-2

## QUESTION 1

> How can you get this malware to install itself?

首先查看文件类型：

```cmd
$ file Lab03-02.dll
Lab03-02.dll: PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
```

因此使用程序 `rundll32.exe` 安装动态链接库，[msdn 使用教程](<https://support.microsoft.com/en-us/help/164787/info-windows-rundll-and-rundll32-interface>)。

我们进一步查看这个动态链接库的导出内容，以查看应该运行哪个函数安装：

![02.dll.PEexplorer](./02.dll.PEexplorer.png)

因此从名字来判断，有可能是 `Install` 也有可能是 `installA`，我们发现前者运行不了，因此安装这个动态链接库的指令为：

```bash
$ rundll32.exe Lab03-02.dll, installA
```

