# cpp 杂技

`__builtin_expect`：一个 if 分支极大可能不会执行，使用这个编译，附近的，编译器会将极大概率连续执行的代码编译为连续的二进制。

`__attribute__` 相关（查看 [GNU 官方文档](https://gcc.gnu.org/onlinedocs/gcc-4.3.0/gcc/Function-Attributes.html) ）：

1. `unused`: 显式地指定一个变量不会被使用，-Wall 编译时不会抛出警告，比如：`int main(int argc __attribute__((unused)), char **argv)`；

2. `format`: 传递 `printf` 类似的参数时进行参数校验，比如：`extern void printfBy(int flag, const char *format, ...) __attribute__((format(printf, 2, 3)));`

3. `noreturn`: 显式地告诉编译器对应的函数不会调用 `exit` 或 `abort` 等函数；

如何定义一个只能分配在栈（堆）上的类（参考[博客](https://www.nowcoder.com/questionTerminal/0a584aa13f804f3ea72b442a065a7618)）：

1. 将析构函数定义为私有函数，编译器无法在栈分配时调用析构方法。对象将只能被定义在堆上；

2. 重载 `new()` 与 `delete()`，对象无法被动态分配。对象将只能被定义在栈上；

用纯 C 实现 C++ 类继承中的动态虚函数特性（参考[博客](https://blog.twofei.com/496/)），实现虚函数表。

定义结构体编译对齐方法，比如按四字节对齐：

```c++
#pragma pack(push)
#pragma pack(4)
...
#pragma pack(pop)
```