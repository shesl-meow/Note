# DoIt

## 文件流程

### `choice_one`

```c
__int64 choice_one()
{
  int size; // [rsp+8h] [rbp-18h]
  int index; // [rsp+Ch] [rbp-14h]
  void *weapon_ptr; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("wlecome input your size of weapon: ");
  _isoc99_scanf("%d", &size);
  if ( size <= 0 || size > 96 )
  {
    printf("The size of weapon is too dangers!!", &size);
    exit(0);
  }
  printf("input index: ", &size);
  index = read_number();
  if ( index < 0 && index > 9 )
  {
    printf("error");
    exit(0);
  }
  weapon_ptr = malloc(size);
  if ( !weapon_ptr )
  {
    printf("malloc error");
    exit(0);
  }
  GLOBAL_WEAPONSIZE_ARRAY[4 * index] = size;
  *((_QWORD *)&GLOBAL_WEAPONPTR_ARRAY + 2 * index) = weapon_ptr;
  puts("input your name:");
  read_str(*((void **)&GLOBAL_WEAPONPTR_ARRAY + 2 * index), size);
  return 0LL;
}
```

