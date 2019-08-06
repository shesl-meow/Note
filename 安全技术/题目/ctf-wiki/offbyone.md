# Off By One

## 文件信息

首先检查保护等级：

```bash
$ checksec ./b00ks
[*] '/mnt/d/program/ctf/ctf-wiki/offbyone/b00ks'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

程序没有开启栈保护。查看各个段的权限：

```bash
gdb-peda$ vmmap 
Warning: not running
Start              End                Perm      Name
0x00000808         0x0000135d         rx-p      /mnt/d/program/ctf/ctf-wiki/offbyone/b00ks
0x00000238         0x00001914         r--p      /mnt/d/program/ctf/ctf-wiki/offbyone/b00ks
0x00201d58         0x00202100         rw-p      /mnt/d/program/ctf/ctf-wiki/offbyone/b00ks
```

各个段的地址如下：

```bash
$ readelf --section-headers ./b00ks
There are 27 section headers, starting at offset 0x2160:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000000238  00000238
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.ABI-tag     NOTE             0000000000000254  00000254
       0000000000000020  0000000000000000   A       0     0     4
  [ 3] .note.gnu.build-i NOTE             0000000000000274  00000274
       0000000000000024  0000000000000000   A       0     0     4
  [ 4] .gnu.hash         GNU_HASH         0000000000000298  00000298
       0000000000000030  0000000000000000   A       5     0     8
  [ 5] .dynsym           DYNSYM           00000000000002c8  000002c8
       00000000000001e0  0000000000000018   A       6     2     8
  [ 6] .dynstr           STRTAB           00000000000004a8  000004a8
       00000000000000f4  0000000000000000   A       0     0     1
  [ 7] .gnu.version      VERSYM           000000000000059c  0000059c
       0000000000000028  0000000000000002   A       5     0     2
  [ 8] .gnu.version_r    VERNEED          00000000000005c8  000005c8
       0000000000000030  0000000000000000   A       6     1     8
  [ 9] .rela.dyn         RELA             00000000000005f8  000005f8
       0000000000000120  0000000000000018   A       5     0     8
  [10] .rela.plt         RELA             0000000000000718  00000718
       00000000000000f0  0000000000000018   A       5    12     8
  [11] .init             PROGBITS         0000000000000808  00000808
       000000000000001a  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         0000000000000830  00000830
       00000000000000b0  0000000000000010  AX       0     0     16
  [13] .text             PROGBITS         00000000000008e0  000008e0
       0000000000000a72  0000000000000000  AX       0     0     16
  [14] .fini             PROGBITS         0000000000001354  00001354
       0000000000000009  0000000000000000  AX       0     0     4
  [15] .rodata           PROGBITS         0000000000001360  00001360
       0000000000000324  0000000000000000   A       0     0     8
  [16] .eh_frame_hdr     PROGBITS         0000000000001684  00001684
       000000000000007c  0000000000000000   A       0     0     4
  [17] .eh_frame         PROGBITS         0000000000001700  00001700
       0000000000000214  0000000000000000   A       0     0     8
  [18] .init_array       INIT_ARRAY       0000000000201d58  00001d58
       0000000000000008  0000000000000000  WA       0     0     8
  [19] .fini_array       FINI_ARRAY       0000000000201d60  00001d60
       0000000000000008  0000000000000000  WA       0     0     8
  [20] .jcr              PROGBITS         0000000000201d68  00001d68
       0000000000000008  0000000000000000  WA       0     0     8
  [21] .dynamic          DYNAMIC          0000000000201d70  00001d70
       00000000000001f0  0000000000000010  WA       6     0     8
  [22] .got              PROGBITS         0000000000201f60  00001f60
       00000000000000a0  0000000000000008  WA       0     0     8
  [23] .data             PROGBITS         0000000000202000  00002000
       0000000000000020  0000000000000000  WA       0     0     8
  [24] .bss              NOBITS           0000000000202020  00002020
       00000000000000e0  0000000000000000  WA       0     0     32
  [25] .comment          PROGBITS         0000000000000000  00002020
       000000000000004f  0000000000000001  MS       0     0     1
  [26] .shstrtab         STRTAB           0000000000000000  0000206f
       00000000000000ef  0000000000000000           0     0     1
```

## 程序逻辑

首先看 `main` 函数：

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 savedregs; // [rsp+20h] [rbp+0h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  print_welcome();
  read_author_name();
  while ( (unsigned int)menu() != 6 )
  {
    switch ( (unsigned int)&savedregs )
    {
      case 1u: create(); break;
      case 2u: delete(); break;
      case 3u: edit(); break;
      case 4u: detail(); break;
      case 5u: read_author_name(); break;
      default:
        puts("Wrong option");
        break;
    }
  }
  puts("Thanks to use our library software");
  return 0LL;
}
```

我们略去漏洞发现的过程。

在 `read_auther_name()` 这个函数中，调用了一个自己实现的读取字符串的函数 `read_str()`：

```c
signed __int64 __fastcall read_str(_BYTE *a1, int a2)
{
  int i; // [rsp+14h] [rbp-Ch]
  _BYTE *buf; // [rsp+18h] [rbp-8h]

  if ( a2 <= 0 )
    return 0LL;
  buf = a1;
  for ( i = 0; ; ++i )
  {
    if ( (unsigned int)read(0, buf, 1uLL) != 1 )
      return 1LL;
    if ( *buf == '\n' )
      break;
    ++buf;
    if ( i == a2 )
      break;
  }
  *buf = 0;
  return 0LL;
}
```

这个函数是存在 `off-by-one` 漏洞的。