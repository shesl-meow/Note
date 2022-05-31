---
title: "Lab 4-2"
date: 2019-06-10T04:41:10+08:00
tags: [""]
categories: ["系统理论课程", "恶意代码分析"]
---


用 `IDA pro` 打开文件，分析伪代码：

```c++
int __cdecl main_0(int argc, const char **argv)
{
  int result; // eax

  if ( argc == 2 )
  {
    if ( !j_strcmp(argv[1], "alligator") )
      printf("You found the password!  Congratulations!\n");
    else
      printf("Fail!\n");
    result = 0;
  }
  else
  {
    printf("Usage: crackme-123-2 password\n");
    result = 1;
  }
  return result;
}
```

发现与前一个一样，所以同样修改对应的汇编即可。
