---
title: "lab 6-3"
date: 2019-06-10T04:41:10+08:00
tags: [""]
categories: ["系统理论课程", "恶意代码分析"]
---


## QUESTION 1

> Compare the calls in main to Lab 6-2’s main method. What is the new function called from main?

后面多出了 `sub_401130` 这个函数。

## QUESTION 2

> What parameters does this new function take?

`Ida Pro` 将函数声明生成了以下的伪代码：

```c
int __cdecl sub_401130(char, LPCSTR lpExistingFileName)
```

其传入的参数是一个字符型的变量，一个指向文件名的字符指针。

## QUESTION 3

> What major code construct does this function contain?

主要是一个 `switch case` 语句：

```c
void __cdecl sub_401130(char a1, LPCSTR lpExistingFileName)
{
  HKEY phkResult; // [sp+4h] [bp-4h]@5

  switch ( a1 )
  {
    case 97:
      CreateDirectoryA(PathName, 0);
      break;
    case 98:
      CopyFileA(lpExistingFileName, (LPCSTR)Data, 1);
      break;
    case 99:
      DeleteFileA((LPCSTR)Data);
      break;
    case 100:
      RegOpenKeyExA(HKEY_LOCAL_MACHINE, SubKey, 0, 0xF003Fu, &phkResult);
      if ( RegSetValueExA(phkResult, ValueName, 0, 1u, Data, 0xFu) )
        sub_401271(aError3_1CouldN);
      break;
    case 101:
      Sleep(0x186A0u);
      break;
    default:
      sub_401271(aError3_2NotAVa);
      break;
  }
}
```

## QUESTION 4

> What can this function do?

观察上面的伪代码容易的到这个函数的逻辑：

| 传入的第一个字符参数 |                          执行的动作                          |
| :------------------: | :----------------------------------------------------------: |
|   `chr(97)` = `a`    |              创建文件夹 `PathName` = `C:\Temp`               |
|   `chr(98)` = `b`    | 复制文件 `lpExistingFileName`（传入的参数）到 `Data` = `C:\Temp\cc.exe` |
|   `chr(99)` = `c`    |              删除文件 `Data` = `C:\Temp\cc.exe`              |
|   `chr(100)` = `d`   | 打开注册表项 `Software\Microsoft\Windows\CurrentVersion\Run`，<br />并且将其值设置为 `ValueName` = `Malware` |
|   `chr(101)` = `e`   |            睡眠 `0x186A0` = `100 000ms` = `100s`             |
|         默认         |        报错 `Error 3.2: Not a valid command provided`        |

## QUESTION 5

> Are there any host-based indicators for this malware?

一个注册表的更改和一个文件的创建 `C:\Temp\cc.exe`。

## QUESTION 6	

> What is the purpose of this malware?

这个程序的大致内容与之前的一个程序内容类似。另外，他添加了了的函数（之前分析的带 `switch case` 语句的函数），增加了删除的功能。


