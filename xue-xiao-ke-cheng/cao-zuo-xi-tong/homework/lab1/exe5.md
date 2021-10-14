# exe5

程序思路：函数`kern/debug/kdebug.c::print_stackframe`的注释写的很清楚了，先调用`read_ebp()`,`read_eip()`读出 ebp 和 eip 的指并打印出来。然后输出四个参数的值，由 ebp 开始向上找两位所保存的值是第一个参数，以此类推。然后找到下一个函数栈的 eip 和 ebp,下一个函数的 eip 就是压入栈的返回地址，也就是当前 ebp 向上找一位所保存的值，下一个函数的 ebp 就是当前 ebp 保存的地址所指向的地方。
