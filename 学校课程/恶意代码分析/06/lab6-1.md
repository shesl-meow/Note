# lab 6-1

## QUESTION 1

> What is the major code construct found in the only subroutine called by main?

在左侧的函数列表中选择 `_main` ，然后在右侧可以看到 `_main` 函数的汇编代码：

```assembly
.text:00401040 ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:00401040 _main           proc near               ; CODE XREF: start+AFp
.text:00401040
.text:00401040 var_4           = dword ptr -4
.text:00401040 argc            = dword ptr  8
.text:00401040 argv            = dword ptr  0Ch
.text:00401040 envp            = dword ptr  10h
.text:00401040
.text:00401040                 push    ebp
.text:00401041                 mov     ebp, esp
.text:00401043                 push    ecx
.text:00401044                 call    sub_401000
.text:00401049                 mov     [ebp+var_4], eax
.text:0040104C                 cmp     [ebp+var_4], 0
.text:00401050                 jnz     short loc_401056
.text:00401052                 xor     eax, eax
.text:00401054                 jmp     short loc_40105B
.text:00401056 ; ---------------------------------------------------------------------------
.text:00401056
.text:00401056 loc_401056:                             ; CODE XREF: _main+10j
.text:00401056                 mov     eax, 1
.text:0040105B
.text:0040105B loc_40105B:                             ; CODE XREF: _main+14j
.text:0040105B                 mov     esp, ebp
.text:0040105D                 pop     ebp
.text:0040105E                 retn
.text:0040105E _main           endp
```

我们发现 `main` 函数调用的唯一子过程是在 `.text:00401044` 这个位置的调用 `sub_401000` 这个函数，我们查看这个函数的伪代码：

```assembly
.text:00401000 ; =============== S U B R O U T I N E =======================================
.text:00401000
.text:00401000 ; Attributes: bp-based frame
.text:00401000
.text:00401000 sub_401000      proc near               ; CODE XREF: _main+4p
.text:00401000
.text:00401000 var_4           = dword ptr -4
.text:00401000
.text:00401000                 push    ebp
.text:00401001                 mov     ebp, esp
.text:00401003                 push    ecx
.text:00401004                 push    0               ; dwReserved
.text:00401006                 push    0               ; lpdwFlags
.text:00401008                 call    ds:InternetGetConnectedState
.text:0040100E                 mov     [ebp+var_4], eax
.text:00401011                 cmp     [ebp+var_4], 0
.text:00401015                 jz      short loc_40102B
.text:00401017                 push    offset aSuccessInterne ; "Success: Internet Connection\n"
.text:0040101C                 call    sub_40105F
.text:00401021                 add     esp, 4
.text:00401024                 mov     eax, 1
.text:00401029                 jmp     short loc_40103A
.text:0040102B ; ---------------------------------------------------------------------------
.text:0040102B
.text:0040102B loc_40102B:                             ; CODE XREF: sub_401000+15j
.text:0040102B                 push    offset aError1_1NoInte ; "Error 1.1: No Internet\n"
.text:00401030                 call    sub_40105F
.text:00401035                 add     esp, 4
.text:00401038                 xor     eax, eax
.text:0040103A
.text:0040103A loc_40103A:                             ; CODE XREF: sub_401000+29j
.text:0040103A                 mov     esp, ebp
.text:0040103C                 pop     ebp
.text:0040103D                 retn
.text:0040103D sub_401000      endp
```

主要的代码结构是 `.text:00401011` 与 `.text:00401015` 这两行构成的 `if` 语句的汇编代码。按空格键查看 `cfg` 更加直观。

## QUESTION 2

> What is the subroutine located at `0x40105F`?

`0x40105F` 是一个子过程的入口地址，也是在第一问中得到的 `main` 函数调用唯一子过程中，如果 `InternateGetConnectedState` 函数的返回值如果不为 0 的调用函数，可以看到其伪代码为：

```pseudocode
int __cdecl sub_40105F(int a1, int a2)
{
  int v2; // edi@1
  int v3; // ebx@1

  v2 = _stbuf(&stru_407098);
  v3 = sub_401282(&stru_407098, a1, (int)&a2);
  _ftbuf(v2, &stru_407098);
  return v3;
}
```

其中，定义在 `stru_407098` 的结构是文件：

```assembly
.data:00407098 ; FILE stru_407098
.data:00407098 stru_407098     FILE <0, 0, 0, 2, 1, 0, 0, 0> ; DATA XREF: sub_40105F+2o
.data:00407098                                         ; __stbuf+12o ...
```

函数 `sub_401282` 是一个很长的函数。

我们尝试寻找调用 `sub_40105F` 这个函数的位置传入的参数是什么，我们发现传入的是 `Success: Internet Connection` 与 `Error 1.1: No Internet` 这两个字符串的地址，

## QUESTION 3

> What is the purpose of this program?

因为 `sub_401282` 这个程序的结构过于复杂不予研究的话，根据函数行为判断，这个程序仅仅通过 `InternateGetConnectedState()` 这个函数检测是否有有网络连接。

