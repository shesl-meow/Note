# lab4-4

又是用 `IDA pro` 分析文件，得到：

```cpp
signed int __cdecl main_0(int a1, const char **a2)
{
  signed int result; // eax

  if ( a1 == 2 )
  {
    if ( !j_strcmp(*a2, "game3.exe") )
    {
      if ( !j_strcmp(a2[1], "dromedary") )
        printf("Congratulations!  You solved the crackme puzzle!\n");
      else
        printf("Incorrect password!\n");
      result = 0;
    }
    else
    {
      printf("Fail!\n");
      result = 0;
    }
  }
  else
  {
    printf("Usage: game3.exe password\n");
    result = 1;
  }
  return result;
}
```

这里可以看出首先需要将文件名改为 `game3.exe` 然后再进行输入 `game3.exe dromedary`

当然也可以通过更改对应汇编代码的形式实现随机输入的认证。

**这里要注意的问题是：改完文件名之后，运行文件的命令行界面用 `cmd` 界面，不要使用 `./` 命令，因为使用 `./` 命令后传入的字符串为文件的绝对地址，会导致 `strcmp` 函数的返回非0**
