>参考资料：
>
>- `Objective-C` 官方文档：https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ObjectiveC/Introduction/introObjectiveC.html
>- 苹果 API：https://developer.apple.com/documentation/
>- 菜鸟教程简单介绍：https://www.runoob.com/w3cnote/objective-c-tutorial.html

# Objective-C

`Objective-C` 的入口函数是 `main.m` 文件中的 `main` 函数，它的传入参数与 C 中也是类似的。

比如一个 `HelloWorld` 程序应该通过以下的方式编写：

```objective-c
#import <UIKit/UIKit.h>

int main(int argc, char * argv[]) {
    NSLog(@"Hello World!");
		return 0;
}
```

