# lab 9-1

## QUESTION 1

> How can you get this malware to install itself?

在 `BinaryCollection/` 文件夹下运行 `diff` 命令可以查看两个文件之间的差异：

```bash
$ diff Chapter_9L/Lab09-01.exe Chapter_3L/Lab03-04.exe
# 没有返回值说明这两个文件没有任何不同
```

我们发现 `Lab09-01.exe` 与 `Lab03-04.exe` 是同一个文件。在 `Lab03-04` 中，我们的分析结果是这个文件运行起来就直接闪退并且把自己删除了。

我们先用 `PE Explorer` 查看这个函数的导入表内容：

![01.exe.PEexplorer.Import.png](./01.exe.PEexplorer.Import.png)

可见它导入的动态链接库以及其中调用的函数都非常敏感：

1. `KERNEL32.dll` 中的 `CopyFileA()`、`WriteFile()` 等操作文件的函数， `CreateProcess()` 等操作进程、互斥量等相关的函数；
2. `ADVAPI32.dll` 中的 `RegSetValueExA()` 等操作注册表的函数，`CreateService()`、`DeleteService()` 等控制系统服务的函数；
3. `SHELL32.dll` 动态链接库仅导入了一个函数，但非常敏感：`ShellExecuteA()`；
4. `WS2_32.dll` 则是 Windows Socket 编程中最常用的动态链接库，这说明这个程序会有网络请求。

然后我们用 `Ida Pro` 打开这个文件，查看其中的 `main` 函数伪代码，发现其中的主要代码结构是一个如下的 `if` 语句结构：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  // ... // 此处定义了局部变量
  if ( argc == 1 )
  {
    if ( !sub_401000() )
      sub_402410();
    sub_402360();
  }
  else
  {
    //.....
  }
  return 0;
}
```

我们对以上的伪代码逐行分析：

1. 可以看到主函数的第一个条件分支语句就是判断命令行参数是否为 1，根据我们之前对病毒分析的经验知道 `sub_402360()` 这个函数的功能应该是删除可执行文件本身。而 `sub_401000()` 是一个判断函数，`sub_402410()` 则应该是进行报错的函数。
2. 在条件分支的 `else` 分支中调用了更多的函数，我们进一步分析其中的逻辑。

`sub_402510()`：在命令行参数多于一个时，以命令行参数的最后一个字符串作为传入值的函数：

```c
int __cdecl sub_402510(int a1)
{
  //.....
  if ( strlen((const char *)a1) == 4 )
  {
    if ( *(_BYTE *)a1 == 97 )
    {
      v2 = *(_BYTE *)(a1 + 1) - *(_BYTE *)a1;
      if ( v2 == 1 )
      {
        v3 = 99 * v2;
        if ( v3 == *(_BYTE *)(a1 + 2) )
          result = (char)(v3 + 1) == *(_BYTE *)(a1 + 3);
        else
          result = 0;
      }
      else
      {
        result = 0;
      }
    }
    else
    {
      result = 0;
    }
  }
  else
  {
    result = 0;
  }
  return result;
}
```

分析以上的伪代码，发现如果传入的字符串为 `chr(97) + chr(97 + 1) + chr(99 * 1) + chr(97 + 3)` = `abcd` 时返回真，否则返回 0。

| 命令行参数 |                          执行的分支                          |
| :--------: | :----------------------------------------------------------: |
| `./程序名` | 可能调用 `sub_402410()`，<br />一定调用 `sub_402360()`<br />（这两个函数可能是报错与删除自己的函数，后面直接用报错/删除代替） |
| `./程序名` |                                                              |



## QUESTION 2

> What are the command-line options for this program? What is the password requirement?