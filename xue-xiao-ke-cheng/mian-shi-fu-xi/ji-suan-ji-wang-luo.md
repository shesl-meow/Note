# 计算机网络

三种工作方式：

> 单工：数据只能在一个方向上传输
>
> 半双工：数据可以在两个方向上传输，但是一次只允许数据在一个方向传输
>
> 全双工：允许数据同时在两个方向上传输

IPv4 三类地址：

> 见：[https://tools.ietf.org/html/rfc3330](https://tools.ietf.org/html/rfc3330)
>
> A类地址 `1.0.0.1-126.255.255.254`，第一段第一位二进制位以 0 开头，最后三段表示主机地址；
>
> B类地址 `128.1.0.1-191.255.255.254`，第一段前两位二进制位为 10 开头，最后两段表示主机地址；
>
> C类地址 `192.0.1.1-223.255.255.254`，第一段前三位二进制位为 110 开头，最后一段表示主机地址；
>
> D 类地址（群播地址） ,第一段前四位为 1110 开头。

IP 协议中的生存时间：

> 生存时间（TTL，time-to-live）是Internet协议（IP）包中的一个值，它告知路由器该包是否在网络中时间过长而应该被丢弃。

双绞线的双绞原因：

> 绞合可以减少对相邻导线的电磁干扰。

关于 `10BASE-T`：

> 10 代表数据传输率，BASE 基带传输，T 代表双绞线。F 为光纤

网络冲突：

> `IEEE802.3` 协议采用 `CSMA/CD` 协议，一定会发生冲突；
>
> `802.4` 和 `802.5` 则不会。

路由选择协议：

> `RIP` 协议：AS 内部的路由选择协议，采用距离向量算法，限制最大为 15 的跳度；
>
> `OSPF` 协议：AS 内部的路由选择协议，采用 Dijkstra 路径选择算法；
>
> `BGP` 协议：AS 之间的路由选择协议，同样使用距离向量算法，但是传输信息中包含了 `AS-PATH`，因此不会出现环路问题。

SOCKET 编程：

> 服务端代码：
>
> ```python
> from socket import *
>  
> HOST = 'localhost'
> PORT = 21567
> BUFFERSIZE = 1024
> ADDR = (HOST, PORT)
>  
> tcpServerSocket = socket(AF_INET, SOCK_STREAM)
> tcpServerSocket.bind(ADDR)  # 绑定地址（主机名，端口号）
> tcpServerSocket.listen(5)  # 开始监听TCP
>  
> while True:
>     print 'waiting for connection...'
>     # 被动接受TCP客户端的请求到来，阻塞式
>     tcpClientSocket, addr = tcpServerSocket.accept()
>     print 'connected from:' + str(addr)
>  
>     while True:
>         data = tcpClientSocket.recv(BUFFERSIZE)
>         if not data:
>             break
>         # 发送TCP数据
>         tcpClientSocket.send('%s' % data)
>         tcpClientSocket.close()
> tcpServerSocket.close()
> ```
>
> 客户端代码：
>
> ```python
> from socket import *
>  
> HOST = 'localhost'
> PORT = 21567
> BUFFERSIZE = 1024
> ADDR = (HOST, PORT)
>  
> tcpClientSocket = socket(AF_INET, SOCK_STREAM)
> tcpClientSocket.connect(ADDR)  # 连接到服务器
>  
> while True:
>     data = raw_input('>')
>     if not data:
>         break
>     tcpClientSocket.send(data)
>     data = tcpClientSocket.recv(BUFFERSIZE)
>     if not data:
>         break
>     print data
> tcpClientSocket.close()
> ```

码分多址通信（CDMA）：

> **码分多址**( Code Division Multiple Access，[CDMA](https://www.baidu.com/s?wd=CDMA\&tn=24004469\_oem_dg\&rsv_dl=gh_pl_sl_csd)）是通过编码区分不同用户信息，实现不同用户同频、同时传输的一种通信技术。
>
> [https://blog.csdn.net/huanhuan_Coder/article/details/83012467](https://blog.csdn.net/huanhuan_Coder/article/details/83012467)

虚电路：

> 虚电路表示这只是一条 **逻辑上的连接** ，分组都沿着这条逻辑连接按照存储转发方式传送，而 **并不是真正建立了一条物理连接** 。包括建立连接，传输数据，拆除连接三个阶段。建立连接之后就类似于专线，所以不存在路由选择

五层数据封装的名称：

> 1. 应用层，Message，报文；
> 2. 传输层，Segment，报文段；
> 3. 网络层，Datagram，数据报；
> 4. 链路层，Frame，帧；
> 5. 物理层，Bits，比特。

以太网帧长度的限制：

\>

> 在传统以太网中,有最小帧长度和最大帧长度的限制。
>
> 以太网的帧长度总是在一定范围内浮动，一般最大的帧长是 1518 字节，最小的帧长是 64 字节。在实际应用中，帧的大小是由设备的 MTU（最大传输单位）即设备每次能够传输的最大字节数自动来确定的。

网络协议的三要素：

> 语法 用来规定信息格式；数据及控制信息的格式、编码及信号电平等。
>
> 语义 用来说明通信双方应当怎么做；用于协调与差错处理的控制信息。
>
> 定时 （时序）定义了何时进行通信，先讲什么，后讲什么，讲话的速度等。比如是采用同步传输还是异步传输！

常见广域网：

> 几种常用的[广域网](https://baike.baidu.com/item/%E5%B9%BF%E5%9F%9F%E7%BD%91)：[公用电话交换网](https://baike.baidu.com/item/%E5%85%AC%E7%94%A8%E7%94%B5%E8%AF%9D%E4%BA%A4%E6%8D%A2%E7%BD%91)（PSTN）、分组交换网（X.25）、[数字数据网](https://baike.baidu.com/item/%E6%95%B0%E5%AD%97%E6%95%B0%E6%8D%AE%E7%BD%91)（DDN）、[帧中继](https://baike.baidu.com/item/%E5%B8%A7%E4%B8%AD%E7%BB%A7)（FR）、[交换式多兆位数据服务](https://baike.baidu.com/item/%E4%BA%A4%E6%8D%A2%E5%BC%8F%E5%A4%9A%E5%85%86%E4%BD%8D%E6%95%B0%E6%8D%AE%E6%9C%8D%E5%8A%A1)（SMDS）和[异步传输模式](https://baike.baidu.com/item/%E5%BC%82%E6%AD%A5%E4%BC%A0%E8%BE%93%E6%A8%A1%E5%BC%8F)（ATM）。

波特率：

> 波特率，可以通俗的理解为一个设备在一秒钟内发送（或接收）了多少码元的数据。

局域网广播地址：

> 主机号为全 1，表示广播地址

`TCP/UDP` 常见端口的服务：

> 见：[http://tool.oschina.net/commons?type=7](http://tool.oschina.net/commons?type=7) 与 [https://www.jianshu.com/p/048963e312bc](https://www.jianshu.com/p/048963e312bc)
>
> 常见数据库所在端口：

| mysql | sqlserver server | sqlserver monitor | oracle | postgre sql | oracle emctl | oracle xdb | oracle xdb ftp |
| ----- | ---------------- | ----------------- | ------ | ----------- | ------------ | ---------- | -------------- |
| 3306  | 1433             | 1434              | 1521   | 5432        | 1158         | 8080       | 2100           |
