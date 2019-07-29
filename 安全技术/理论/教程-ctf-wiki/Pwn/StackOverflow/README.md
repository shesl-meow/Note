> 参考：<https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/stack-intro-zh/>

# Stack Overflow

对于程序的栈区，以下几点需要注意：

1. 程序的栈是从高地址向低地址增长的
2. `x86` 的函数参数在函数返回地址的上面；`x64` 程序的前六个整型或指针型参数依次保存在 `RDI`、`RSI`、`RDX`、`RCX`、`R8`、`R9` 六个寄存器中（`Linux`、`FreeFSD`、`macOS` 采用），更多参数则会保存在栈上。
3. `x64` 的地址长度不能超过 `0x0000 7FFF FFFF FFFF` 六个字节长度，否则会抛出异常。

