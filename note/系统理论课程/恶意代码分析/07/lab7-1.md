---
title: "lab 7-1"
date: 2019-06-10T04:41:10+08:00
tags: [""]
categories: ["系统理论课程", "恶意代码分析"]
---


## QUESTION 1

> How does this program ensure that it continues running (achieves persistence) when the computer is restarted?

我们先分析这个程序的结构，查看 `_main` 函数的伪代码：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  SERVICE_TABLE_ENTRYA ServiceStartTable; // [sp+0h] [bp-10h]@1
  int v5; // [sp+8h] [bp-8h]@1
  int v6; // [sp+Ch] [bp-4h]@1

  ServiceStartTable.lpServiceName = aMalservice;
  ServiceStartTable.lpServiceProc = (LPSERVICE_MAIN_FUNCTIONA)sub_401040;
  v5 = 0;
  v6 = 0;
  StartServiceCtrlDispatcherA(&ServiceStartTable);
  return sub_401040(0, 0, ServiceStartTable.lpServiceName, ServiceStartTable.lpServiceProc, v5, v6);
}
```

其中创建了一个 `SERVICE_TABLE_ENTRYA` 类型的变量，将 `sub_401040` 这个函数赋值给 `lpServerceProc` 这个子变量，并通过调用 `StartServiceCtrlDispatcherA` 这个函数注册这个服务。

并且通过 `sub_401040(0, 0, ServiceStartTable.lpServiceName, ServiceStartTable.lpServiceProc, v5, v6)` 的方式调用了这个函数，所以我们进一步分析这个关键的函数 `sub_401040()`：

```c
int sub_401040()
{
  SC_HANDLE v0; // esi@3
  HANDLE v1; // esi@3
  signed int v2; // esi@4
  SYSTEMTIME SystemTime; // [sp+0h] [bp-400h]@3
  struct _FILETIME FileTime; // [sp+10h] [bp-3F0h]@3
  CHAR Filename; // [sp+18h] [bp-3E8h]@3

  if ( OpenMutexA(0x1F0001u, 0, Name) )
    ExitProcess(0);
  CreateMutexA(0, 0, Name);
  v0 = OpenSCManagerA(0, 0, 3u);
  GetCurrentProcess();
  GetModuleFileNameA(0, &Filename, 0x3E8u);
  CreateServiceA(v0, DisplayName, DisplayName, 2u, 0x10u, 2u, 0, &Filename, 0, 0, 0, 0, 0);
  *(_DWORD *)&SystemTime.wYear = 0;
  *(_DWORD *)&SystemTime.wDayOfWeek = 0;
  *(_DWORD *)&SystemTime.wHour = 0;
  *(_DWORD *)&SystemTime.wSecond = 0;
  SystemTime.wYear = 2100;
  SystemTimeToFileTime(&SystemTime, &FileTime);
  v1 = CreateWaitableTimerA(0, 0, 0);
  SetWaitableTimer(v1, (const LARGE_INTEGER *)&FileTime, 0, 0, 0, 0);
  if ( !WaitForSingleObject(v1, 0xFFFFFFFF) )
  {
    v2 = 20;
    do
    {
      CreateThread(0, 0, StartAddress, 0, 0, 0);
      --v2;
    }
    while ( v2 );
  }
  Sleep(0xFFFFFFFF);
  return 0;
}
```

我们发现其中的一个关键的函数 `CreateServiceA(v0, DisplayName, DisplayName, 2u, 0x10u, 2u, 0, &Filename, 0, 0, 0, 0, 0);`，这个函数用于创建了一个服务，我们查看这个函数的原型：

```c
SC_HANDLE __stdcall CreateServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword);
```

这个函数的第六个参数，调用时传入的参数是 `2u`，可以在 `MSDN` 中查找到具体的各个参数的含义：

| Value                                 | Meaning                                                      |
| :------------------------------------ | :----------------------------------------------------------- |
| **SERVICE_AUTO_START** `0x00000002`   | A service started automatically by the service control manager during system startup. For more information, see [Automatically Starting Services](https://msdn.microsoft.com/8aa60e96-a35e-4670-832c-c045d0903618). |
| **SERVICE_BOOT_START** `0x00000000`   | A device driver started by the system loader. This value is valid only for driver services. |
| **SERVICE_DEMAND_START** `0x00000003` | A service started by the service control manager when a process calls the [StartService](https://msdn.microsoft.com/f185a878-e1c3-4fe5-8ec9-c5296d27f985) function. For more information, see [Starting Services on Demand](https://msdn.microsoft.com/72f51b38-d62c-4400-a38d-b9a0e90e9db4). |
| **SERVICE_DISABLED** `0x00000004`     | A service that cannot be started. Attempts to start the service result in the error code **ERROR_SERVICE_DISABLED**. |
| **SERVICE_SYSTEM_START** `0x00000001` | A device driver started by the **IoInitSystem** function. This value is valid only for driver services. |

所以这个程序通过创建一个服务，并且将其第六个参数 `DWORD dwServiceType` 设置为 `SERVICE_AUTO_START 0x02` 来设置程序的自启动。

## QUESTION 2

> Why does this program use a mutex?

在上面的伪代码分析中，我们发现程序在执行 `sub_401040()` 这个函数之前首先使用 `CreateMutexA(0, 0, Name);` 这个函数创建了一个互斥量。如果通过 `OpenMutexA(0x1F0001u, 0, Name)` 这个方法检测到互斥量的存在，则程序直接退出。

其目的应该是确保后面对进程、系统时间、文件或者服务的访问，只有一个进程在使用。

## QUESTION 3

> What is a good host-based signature to use for detecting this program?

根据第一问对伪代码的分析我们可以得到：

1. 被这个程序感染的机器会创建一个服务，其名称为 `DisplayName` = `Malservice`

2. 被这个感染的机器，如果程序正在运行，则会创建一个互斥量 `Name` = `HGL345`

## QUESTION 4

> What is a good network-based signature for detecting this malware?

我们进一步分析伪代码，发现这个程序通过 `do while` 循环创建线程执行以下的函数 20 次：

```c
CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartAddress, 0, 0, 0);
```

于是我们查看 `StartAddress` 中的函数伪代码：

```c
void __stdcall __noreturn StartAddress(LPVOID lpThreadParameter)
{
  void *i; // esi@1

  for ( i = InternetOpenA(szAgent, 1u, 0, 0, 0); ; InternetOpenUrlA(i, szUrl, 0, 0, 0x80000000, 0) )
    ;
}
```

其中：

1. 字符串 `szAgent` = `Internet Explorer 8.0`
2. 字符串 `szUrl` = `http://www.malwareanalysisbook.com`

这个函数的功能是打开一个浏览器 `Internet Explorer 8.0`，并且不断地在这个浏览器中打开网址 `http://www.malwareanalysisbook.com`。

## QUESTION 5

> What is the purpose of this program?

我们进一步分析函数 `sub_401040` 的逻辑，发现在 `do while` 循环之前 `SystemTime` 的值被设置为了 `2100 年 1 月 1 日 00:00`，结合我们在第四问中分析的逻辑。

我们知道这个程序的目的是在 `2100 年 1 月 1 日 00:00` 这个时间打开 `20` 个线程不断打开网页 `http://www.malwareanalysisbook.com`。猜测其目的是在这个时间点联合多台感染主机对目标发起 `DDoS` 攻击。

## QUESTION 6

> When will this program finish executing?

根据之前的分析，程序创建了 20 个不会停止的线程之后会 `Sleep(0xFFFFFFFF);`，这是一个 `unsigned int` 类型的最大值，以毫秒为单位计算之后这个程序 `sleep` 的时间，得到 `49 天 ` 的结果。

所以这个程序的主控线程会在执行了 49 天之后停止，但是很显然这个恶意代码的作者并不想让他停止，之所以为 49 天只是因为并不能休眠更长的时间了。


