# lab4-3

还是用 `IDA pro` 分析，得到伪代码：

```cpp
signed int __cdecl main_0(int a1, int a2)
{
  signed int result; // eax

  if ( a1 == 3 )
  {
    if ( !j_strcmp(*(const char **)(a2 + 4), "suffering") )
    {
      if ( !j_strcmp(*(const char **)(a2 + 8), "succotash") )
        printf("Congratulations!  You found the passwords!\n");
      else
        printf("Fail!  Second word was wrong!\n");
      result = 0;
    }
    else
    {
      printf("Fail!  First word was wrong!\n");
      result = 0;
    }
  }
  else
  {
    printf("Usage: crackme-123-3 password1 password2\n");
    result = 1;
  }
  return result;
}
```

这个是要输入两个密码的，就改两个条件判断就可以了。

```
.text:004113D2                 push    offset Str2     ; "suffering"
.text:004113D7                 mov     eax, [ebp+arg_4]
.text:004113DA                 mov     ecx, [eax+4]
.text:004113DD                 push    ecx             ; Str1
.text:004113DE                 call    j_strcmp
.text:004113E3                 add     esp, 8
.text:004113E6                 test    eax, eax
.text:004113E8                 jz      short loc_411405
.text:004113EA                 mov     esi, esp
.text:004113EC                 push    offset aFailFirstWordW ; "Fail!  First word was wrong!\n"
.text:004113F1                 call    ds:printf
.text:004113F7                 add     esp, 4
.text:004113FA                 cmp     esi, esp
.text:004113FC                 call    j___RTC_CheckEsp
.text:00411401                 xor     eax, eax
.text:00411403                 jmp     short loc_411451

.text:00411405 loc_411405:                             ; CODE XREF: _main_0+58↑j
.text:00411405                 push    offset aSuccotash ; "succotash"
.text:0041140A                 mov     eax, [ebp+arg_4]
.text:0041140D                 mov     ecx, [eax+8]
.text:00411410                 push    ecx             ; Str1
.text:00411411                 call    j_strcmp
.text:00411416                 add     esp, 8
.text:00411419                 test    eax, eax
.text:0041141B                 jz      short loc_411438
```

将第 8 行和第 26 行的 `jz` 命令改为 `jnz` 即可。
