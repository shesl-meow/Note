# lab 6-4

## QUESTION 1

> What is the difference between the calls made from the main method in Labs 6-3 and 6-4?

分别考虑下面的函数：

1. `sub_401000`：这个函数在两个 lab 中是相同的，都是用于检测网络的连通性；
2. `sub_401040`：也是相同的，下载网页的文件然后解析其中的内容；
3. `sub_401050`：就是在 `lab3` 中的 `sub_401130` 这个函数，通过传入一个字符执行不同的命令；
4. `sub_4012B5`：在 `lab2` 中分析的可能是 `printf` 的函数。

## QUESTION 2

> What new code construct has been added to main?

在检测了网络的连通性之后，添加了一个 `for` 循环。其代码结构是 `cmp` 和 `jge` 组成的：

```assembly
loc_40125A:
cmp     [ebp+var_C], 5A0h
jge     short loc_4012AF
```

另外还在 `for` 循环结束添加了 `sleep` 函数：

```assembly
push    0EA60h          ; dwMilliseconds
call    ds:Sleep
```

## QUESTION 3

> What is the difference between this lab’s parse HTML function and those of the previous labs?

在第一问中分析过了，解析的函数是 `sub_401040`，我们查看它的伪代码：

```c
char __cdecl sub_401040(int a1)
{
  char result; // al@2
  int Buffer; // [sp+0h] [bp-230h]@3
  char v3; // [sp+4h] [bp-22Ch]@9
  HINTERNET hFile; // [sp+200h] [bp-30h]@1
  HINTERNET hInternet; // [sp+204h] [bp-2Ch]@1
  CHAR szAgent; // [sp+208h] [bp-28h]@1
  DWORD dwNumberOfBytesRead; // [sp+228h] [bp-8h]@3
  int v8; // [sp+22Ch] [bp-4h]@3

  sprintf(&szAgent, aInternetExplor, a1);
  hInternet = InternetOpenA(&szAgent, 0, 0, 0, 0);
  hFile = InternetOpenUrlA(hInternet, szUrl, 0, 0, 0, 0);
  if ( hFile )
  {
    v8 = InternetReadFile(hFile, &Buffer, 0x200u, &dwNumberOfBytesRead);
    if ( v8 )
    {
      if ( (char)Buffer != 60 || SBYTE1(Buffer) != 33 || SBYTE2(Buffer) != 45 || SBYTE3(Buffer) != 45 )
      {
        sub_4012B5(aError2_3FailTo);
        result = 0;
      }
      else
      {
        result = v3;
      }
    }
    else
    {
      sub_4012B5(aError2_2FailTo);
      InternetCloseHandle(hInternet);
      InternetCloseHandle(hFile);
      result = 0;
    }
  }
  else
  {
    sub_4012B5(aError2_1FailTo);
    InternetCloseHandle(hInternet);
    result = 0;
  }
  return result;
}
```

主要的区别是在函数 `InternetOpenA()` 这个函数之前添加了这样的一行代码：

```c
sprintf(&szAgent, aInternetExplor, a1);
```

这一行的代码的作用是拼接字符串 `aInternetExplor` 与 `a1` 并且将结果赋值给 `szAgent`。

## QUESTION 4

> How long will this program run? (Assume that it is connected to the Internet.)

`for` 循环的次数：（`0x5A0` = `1440`）

```assembly
.text:0040125A                 cmp     [ebp+var_C], 5A0h
```

如果不考虑各种子函数的执行时间，仅考虑在 `_main` 中执行的 `sleep` 函数的时间占用。每次睡眠的时间为：

```assembly
push    0EA60h          ; dwMilliseconds
call    ds:Sleep
```

所以总的程序运行时间为 `0xEA60 ms * 1440` = `60000 ms * 1440` = `1 min * 1440` = `24 h`

所以如果不考虑网络的链接状况和各种子函数的调用次数，这个程序大约会运行一天。

## QUESTION 5

> Are there any new network-based indicators for this malware?

每次使用的浏览器客户端都不同（在第三问中分析过）。

## QUESTION 6

> What is the purpose of this malware?

先检查 `Internet` 连接，使用随时间可变的 `user-agent` 下载网页，解析HTML，程序运行 `24h` 终止。

