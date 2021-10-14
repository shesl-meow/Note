# lab7-2

## QUESTION 1

> How does this program achieve persistence?

我们同样的通过 `_main` 函数开始分析：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  OLECHAR *v3; // esi@3
  LPVOID ppv; // [sp+0h] [bp-24h]@2
  VARIANTARG pvarg; // [sp+4h] [bp-20h]@3
  __int16 v7; // [sp+14h] [bp-10h]@3
  int v8; // [sp+1Ch] [bp-8h]@3

  if ( OleInitialize(0) >= 0 )
  {
    CoCreateInstance(&rclsid, 0, 4u, &riid, &ppv);
    if ( ppv )
    {
      VariantInit(&pvarg);
      v7 = 3;
      v8 = 1;
      v3 = SysAllocString(psz);
      (*(void (__stdcall **)(LPVOID, OLECHAR *, __int16 *, VARIANTARG *, VARIANTARG *, VARIANTARG *))(*(_DWORD *)ppv + 44))(
        ppv,
        v3,
        &v7,
        &pvarg,
        &pvarg,
        &pvarg);
      SysFreeString(v3);
    }
    OleUninitialize();
  }
  return 0;
}
```

查看被调用的所有函数，这个程序似乎并没有尝试永久地运行。

## QUESTION 2

> What is the purpose of this program?

根据之前对 `main` 函数的分析，这个程序的作用是仅仅是打开 `http://www.malwareanalysisbook.com/ad.html`

## QUESTION 3

> When will this program finish executing?

并没有任何延时函数，直接退出。
