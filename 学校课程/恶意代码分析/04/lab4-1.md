# lab 4-1

用 `IDA pro` 打开文件：

```c++
int __cdecl main_0(int argc, const char **argv)
{
  int result; // eax

  if ( argc == 2 )
  {
    if ( !j_strcmp(argv[1], "topsecret") )
      printf("You found the password!  Congratulations!\n");
    else
      printf("Fail!\n");
    result = 0;
  }
  else
  {
    printf("Usage: crackme-123-1 password\n");
    result = 1;
  }
  return result;
}
```

```asm
.text:004113C2                 push    offset Str2     ; "topsecret"
.text:004113C7                 mov     eax, [ebp+arg_4]
.text:004113CA                 mov     ecx, [eax+4]
.text:004113CD                 push    ecx             ; Str1
.text:004113CE                 call    j_strcmp
.text:004113D3                 add     esp, 8
.text:004113D6                 test    eax, eax
.text:004113D8                 jnz     short loc_4113F5
.text:004113DA                 mov     esi, esp
.text:004113DC                 push    offset aYouFoundThePas ; "You found the password!  Congratulation"...
.text:004113E1                 call    ds:printf
.text:004113E7                 add     esp, 4
.text:004113EA                 cmp     esi, esp
.text:004113EC                 call    j___RTC_CheckEsp
.text:004113F1                 xor     eax, eax
.text:004113F3                 jmp     short loc_41140E
```

通过查看汇编代码，发现只要将第8行的 `jnz short loc_4113F5` 改为 `jz short loc_4113F5` 即把判断条件反转即可做到输入随机字符串可通过认证。




