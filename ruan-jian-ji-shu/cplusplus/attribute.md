# attribute

C++ 中的 `__attribute__` 是 GNU 为 C 语言提供的一项机制，它允许开发者向函数、变量添加一些特征以方便错误检查。下面是几个使用 `__attribute__` 的例子，更完整的使用示例可以查看 [GNU 官方文档](https://gcc.gnu.org/onlinedocs/gcc-4.3.0/gcc/Function-Attributes.html)

## `unused`

Gcc 编译器有一个特性，如果在编译时加入 `-Wall`（显示所有的警告）这个参数，则会将没有使用过的变量、函数作为警告抛出。

但是有时我们需要故意地，声明一个变量不会被使用，于是我们可以使用 `unused`。一个被标记了 `unused` 属性的变量或者函数，不会抛出未使用警告。

比如我们有时会用到 main 函数中的 `argv` 参数，不会用到 `argc` 参数所以我们可以把它们标记为 `unused`：

```c
int main(int argc __attribute__((unused)), char **argv)
{
   /* code that uses argv, but not argc */
}
```

## `format`

像 `printf` 与 `scanf` 这样的函数，需要格式化字符串与动态参数，我们有时需要确定参数的合法性。

比如我们定义了一个函数：

```c
#include<stdarg.h>
void printfBy(int flag, const char *format, ...)
{
  if(flag){
    va_list args;
      va_start(args, format);
    vprintf(format, args);
      va_end(args);
  }
}
```

我们希望编译器可以在编译的时候告诉我们参数是否传递错误，我们可以在引用这个函数时，给函数添加一个 `format` 属性：

```c
extern void printfBy(int flag, const char *format, ...) __attribute__((format(printf, 2, 3)));
```

*   指定 `format` 有以下两种格式：

    ```c
    __attribute__((format(printf, m, n)));

    __attribute__((format(scanf, m, n)));
    ```
* 其中 m 这个参数表示格式化字符串所在的位置，n 表示动态参数开始的位置。

## `noreturn`

这个属性告诉编译器，指定一个函数不会返回。典型地比如 C 标准库中的 `exit()` 与 `abort()` 函数：

```c
extern void exit(int)   __attribute__((noreturn));
extern void abort(void) __attribute__((noreturn));
```

如果编译器编译时，检测到了返回的路径，则会抛出警告。
