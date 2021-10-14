# Socket

> 学习网址：
>
> * [https://www.geeksforgeeks.org/socket-programming-cc/](https://www.geeksforgeeks.org/socket-programming-cc/)

## Socket Programming

什么是 socket 编程？

Socket programming is a way of connecting two nodes on a network to communicate with each other. One socket(node) listens on a particular port at an IP, while other socket reaches out to the other to form a connection. Server forms the listener socket while client reaches out to the server.

### 服务端

#### 示例代码

```cpp
// Server side C/C++ program to demonstrate Socket programming 
#include <unistd.h>
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#define PORT 8080 
int main(int argc, char const *argv[]) 
{ 
    int server_fd, new_socket, valread; 
    struct sockaddr_in address; 
    int opt = 1; 
    int addrlen = sizeof(address); 
    char buffer[1024] = {0}; 
    char *hello = "Hello from server"; 

    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 

    // Forcefully attaching socket to the port 8080 
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) 
    { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    } 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( PORT ); 

    // Forcefully attaching socket to the port 8080 
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    if (listen(server_fd, 3) < 0) 
    { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    }
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) 
    { 
        perror("accept"); 
        exit(EXIT_FAILURE); 
    } 
    valread = read( new_socket , buffer, 1024); 
    printf("%s\n",buffer ); 
    send(new_socket , hello , strlen(hello) , 0 ); 
    printf("Hello message sent\n"); 
    return 0; 
}
```

#### 接口的创建

```cpp
int socketfd = socket(domain, type, protocol);
```

* **sockfd:** socket 描述符，一个整数。
* **domain:** 整数，网络层区域。比如：
  * `AF_INET` (IPv4 协议) 
  * `AF_INET6` (IPv6 协议)
* **type:** 交流方式，传输层协议。
  * `SOCK_STREAM`: TCP（可信，建立连接）
  * `SOCK_DGRAM`: UDP（不可信，不建立连接）
* **protocol:** 网络层协议的值（IP），该值通常设置为 0，意味我们使用默认的协议。

#### 绑定

```cpp
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

创建接口之后，上面的 `bind` 函数会将 `sockfd` 这个接口绑定到 `addr` 这个自定义数据结构对象中指定的地址和端口。

在上面的示例代码中我们使用 `INADDR_ANY` 来指定 IP 地址，因为我们将服务绑定到了本地的端口。

#### 监听

```cpp
int listen(int sockfd, int backlog);
```

该语句令服务器接口处于被动接收消息的模式，也就是说，它开始等待客户端向服务器建立连接。

`backlog` 定义了 `socket` 在连接时，连接等待队列中可以增长到的最大长度。如果有客户端在最大长度时连接到服务器时，客户端会收到一个 `ECONNREFUSED` 的错误信息。

#### 接收

```cpp
int new_socket= accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

它将 `sockfd` 等待队列中最靠前的连接请求解压出来，创建一个新的 `socket` 连接，返回一个新的描述符。

到此为止，服务器和和客户端已经建立了连接，可以传送数据。

### 客户端

#### 示例代码

```cpp
// Client side C/C++ program to demonstrate Socket programming 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#define PORT 8080 

int main(int argc, char const *argv[]) 
{ 
    struct sockaddr_in address; 
    int sock = 0, valread; 
    struct sockaddr_in serv_addr; 
    char *hello = "Hello from client"; 
    char buffer[1024] = {0};
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 

    memset(&serv_addr, '0', sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(PORT); 

    // Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) 
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    } 

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        return -1; 
    } 
    send(sock , hello , strlen(hello) , 0 ); 
    printf("Hello message sent\n"); 
    valread = read( sock , buffer, 1024); 
    printf("%s\n",buffer );
    return 0; 
}
```

#### 接口的创建

与服务器端接口的创建过程相同。

#### 连接的建立

```cpp
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

`connect` 这个系统函数调用，将描述符 `sockfd` 与由 `addr` 参数确定的地址和端口连接起来。

### 总结

`TCP-IP` 协议下流程大致如下：

![TCP-IP](../../../.gitbook/assets/TCP_IP_socket_diagram.png)
