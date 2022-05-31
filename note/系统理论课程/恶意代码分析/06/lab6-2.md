---
title: "lab 6-2"
date: 2019-06-10T04:41:10+08:00
tags: [""]
categories: ["系统理论课程", "恶意代码分析"]
---


## QUESTION 1

> What operation does the first subroutine called by main perform?

查看 `_main` 的汇编代码：

```assembly
.text:00401130 ; =============== S U B R O U T I N E =======================================
.text:00401130
.text:00401130 ; Attributes: bp-based frame
.text:00401130
.text:00401130 ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:00401130 _main           proc near               ; CODE XREF: start+AFp
.text:00401130
.text:00401130 var_8           = byte ptr -8
.text:00401130 var_4           = dword ptr -4
.text:00401130 argc            = dword ptr  8
.text:00401130 argv            = dword ptr  0Ch
.text:00401130 envp            = dword ptr  10h
.text:00401130
.text:00401130                 push    ebp
.text:00401131                 mov     ebp, esp
.text:00401133                 sub     esp, 8
.text:00401136                 call    sub_401000
......
```

可见这个汇编代码调用的第一个子过程是 `sub_401000`，同样的查看它的伪代码：

```pseudocode
signed int sub_401000()
{
  signed int result; // eax@2

  if ( InternetGetConnectedState(0, 0) )
  {
    sub_40117F(aSuccessInterne);
    result = 1;
  }
  else
  {
    sub_40117F(aError1_1NoInte);
    result = 0;
  }
  return result;
}
```

这也是一个判断网络连接状态的函数。

## QUESTION 2

> What is the subroutine located at `0x40117F`?

跳转到这个地址之后查看这个子过程的伪代码：

```c
int sub_40117F(const char *a1, ...)
{
  int v1; // edi@1
  int v2; // ebx@1
  va_list va; // [sp+14h] [bp+8h]@1

  va_start(va, a1);
  v1 = _stbuf(&stru_407160);
  v2 = sub_4013A2(&stru_407160, (int)a1, (int)va);
  _ftbuf(v1, &stru_407160);
  return v2;
}
```

这个跟前面一题的 `printf` 内容是类似的。应该也是一个 `printf` 函数。

## QUESTION 3

> What does the second subroutine called by main do?

先找到 `main` 函数的调用的第二个子过程，是在 `.text:401148` 位置调用的函数 `sub_401040`。

```c
char sub_401040()
{
  char result; // al@2
  char Buffer; // [sp+0h] [bp-210h]@3
  char v2; // [sp+1h] [bp-20Fh]@6
  char v3; // [sp+2h] [bp-20Eh]@7
  char v4; // [sp+3h] [bp-20Dh]@8
  char v5; // [sp+4h] [bp-20Ch]@9
  HINTERNET hFile; // [sp+200h] [bp-10h]@1
  HINTERNET hInternet; // [sp+204h] [bp-Ch]@1
  DWORD dwNumberOfBytesRead; // [sp+208h] [bp-8h]@3
  int v9; // [sp+20Ch] [bp-4h]@3

  hInternet = InternetOpenA(szAgent, 0, 0, 0, 0);
  hFile = InternetOpenUrlA(hInternet, szUrl, 0, 0, 0, 0);
  if ( hFile )
  {
    v9 = InternetReadFile(hFile, &Buffer, 0x200u, &dwNumberOfBytesRead);
    if ( v9 )
    {
      if ( Buffer != 60 || v2 != 33 || v3 != 45 || v4 != 45 )
      {
        sub_40117F(aError2_3FailTo);
        result = 0;
      }
      else
      {
        result = v5;
      }
    }
    else
    {
      sub_40117F(aError2_2FailTo);
      InternetCloseHandle(hInternet);
      InternetCloseHandle(hFile);
      result = 0;
    }
  }
  else
  {
    sub_40117F(aError2_1FailTo);
    InternetCloseHandle(hInternet);
    result = 0;
  }
  return result;
}
```

我们逐个分析，对于：

```c
hInternet = InternetOpenA(szAgent, 0, 0, 0, 0);
// szAgent ==> 字符常量 Internet Explorer 7.5/pma
```

这一行代码通过 `Internet Explorer 7.5`  打开了一个浏览器。

对于：

```c
hFile = InternetOpenUrlA(hInternet, szUrl, 0, 0, 0, 0);
// szUrl ==> 字符常量 http://www.practicalmalwareanalysis.com/cc.htm
```

这一行代码在之前打开的浏览器中打开了一个链接 `http://www.practicalmalwareanalysis.com/cc.htm`。

对于：

```c
v9 = InternetReadFile(hFile, &Buffer, 0x200u, &dwNumberOfBytesRead);
```

这一行代码将打开的网页读入变量中。

对于：

```c
sub_40117F(aError2_3FailTo);
// aError2_3FailTo ==> 字符常量 Error 2.3: Fail to get command
......
sub_40117F(aError2_2FailTo);
// aError2_3FailTo ==> 字符常量 Error 2.2: Fail to ReadFile
......
sub_40117F(aError2_1FailTo);
// aError2_1FailTo ==> 字符常量 Error 2.1: Fail to OpenUrl
```

都是用于抛出异常、错误的函数。

**结论**：综上所述，这个函数用于读取 `http://www.practicalmalwareanalysis.com/cc.htm` 的内容，并且将其作为函数的返回结果返回。读取失败会抛出异常。

## QUESTION 4

> What type of code construct is used in this subroutine?

主要是 `if` 语句。

## QUESTION 5

> Are there any network-based indicators for this program?

有。主要有以下三点：

1. 静态分析这个应用程序引用的动态链接库，有调用网络相关的 API 函数；
2. 动态分析这个应用程序，运行这个应用程序将检测到 DNS 请求。
3. 这个应用应用程序的全局变量（字符串）区有 `http://www.practicalmalwareanalysis.com/cc.htm` 这样的字符串。

## QUESTION 6

> What is the purpose of this malware?

我们尝试把网页尝试下载的内容下载下来：

```bash
$ wget http://www.practicalmalwareanalysis.com/cc.htm
--2019-06-05 15:00:49--  http://www.practicalmalwareanalysis.com/cc.htm
Resolving www.practicalmalwareanalysis.com (www.practicalmalwareanalysis.com)... 192.0.78.24, 192.0.78.25
Connecting to www.practicalmalwareanalysis.com (www.practicalmalwareanalysis.com)|192.0.78.24|:80... connected.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: https://www.practicalmalwareanalysis.com/cc.htm [following]   
--2019-06-05 15:00:50--  https://www.practicalmalwareanalysis.com/cc.htm
Connecting to www.practicalmalwareanalysis.com (www.practicalmalwareanalysis.com)|192.0.78.24|:443... connected.
```

一直卡在了这个位置。我们直接用 `Chrome` 访问发现出现了 404 错误。

暂时不清楚这个恶意代码的作用。
