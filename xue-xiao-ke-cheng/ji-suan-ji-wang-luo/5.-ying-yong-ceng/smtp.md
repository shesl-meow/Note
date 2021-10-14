# SMTP

> 学习地址：
>
> * [https://blog.csdn.net/kerry0071/article/details/28604267](https://blog.csdn.net/kerry0071/article/details/28604267)
> * [http://coolnull.com/3055.html](http://coolnull.com/3055.html)

## SMTP 协议

### 简介

SMTP 称为简单邮件传输协议（`Simple Mail Transfer Protocal`），目标是向用户提供高效、可靠的邮件传输。它的一个重要特点是它能够在传送中接力传送邮件，即邮件可以通过不同网络上的主机接力式传送。

通常它工作在两种情况下：

1. 邮件从客户机传输到服务器；
2. 从某一个服务器传输到另一个服务器。

SMTP 是一个请求/响应协议，它监听 25 号端口，用于接收用户的 Mail 请求，并与远端 Mail 服务器建立 SMTP 连接。

### 工作机制

发送 SMTP 在接收到用户的邮件请求后，判断此邮件是否为本地邮件，若是直接投送到用户的邮箱，否则向 DNS 查询远端邮件服务器的 MX 记录，并建立与远端接收 SMTP 之间的一个双向传送通道，此后 SMTP 命令由发送 SMTP 发出，由接收 SMTP 接收，而应答则反方向传送。一旦传送通道建立，SMTP 发送者发送 MAIL 命令指明邮件发送者。

如果 SMTP 接收者可以接收邮件则返回 OK 应答。SMTP 发送者再发出 RCPT 命令确认邮件是否接收到。如果 SMTP 接收者接收，则返回 OK 应答；如果不能接收到，则发出拒绝接收应答（但不中止整个邮件操作），双方将如此反复多次。当接收者收到全部邮件后会接收到特别的序列，入伏哦接收者成功处理了邮件，则返回 OK 应答。

### 连接和发送过程

1. 建立 `TCP` 连接。
2. 客户端发送 `HELO` 命令以标识发件人自己的身份。
3. 客户端发送 `MAIL` 命令，服务器端以 OK 作为响应，表示准备接收。
4. 客户端发送 `RCPT` 命令以标识该邮件的计划接收人，可以有多个 `RECPT` 行，服务器端则表示是否愿意为接收人接收邮件。
5. 客户端发送 `DATA` 命令，发送邮件，最后以只含有 `.` 的特殊行结尾。
6. 客户端发送 `QUIT` 命令，结束此次发送。

### Refrence

* STMP Command: [http://www.samlogic.net/articles/smtp-commands-reference.htm](http://www.samlogic.net/articles/smtp-commands-reference.htm)
* STMP Reply Code: [https://www.greenend.org.uk/rjk/tech/smtpreplies.html](https://www.greenend.org.uk/rjk/tech/smtpreplies.html)
