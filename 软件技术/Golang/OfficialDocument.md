# Official Document

## Get Start

### hello world

mod 初始化：

```bash
$ go mod init example.com/hello
```

golang 的 hello world 程序如下，将它写入 `hello.go` 文件中：

```go
package main

import "fmt"

func main() {
    fmt.Println("Hello, World!")
}
```

编译并运行 hello world 程序：

```bash
$ go run .
```

