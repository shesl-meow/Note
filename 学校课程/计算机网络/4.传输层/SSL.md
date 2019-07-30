> 学习网址：
>
> - https://www.cnblogs.com/bhlsheji/p/4586597.html

# SSL

## 协议工作过程

### 分层结构

SSL 位于应用层和传输层之间，它能够为不论什么基于 TCP 等可靠连接的应用层协议提供安全性保证。SSL 协议本身分为两层：

- 上层为 SSL 握手协议 (SSL handshake protocol)、SSLpassword 变化协议 (SSL change cipher spec protocol) 和 SSL 警告协议 (SSL alert protocol)。

- 底层为 SSL 记录协议 (SSL record protocol)。

当中：

- `SSL 握手协议`：是 SSL 协议很重要的组成部分。用来协商通信过程中使用的加密套件(加密算法、密钥交换算法和 MAC 算法等)、在 server 和 client 之间安全地交换密钥、实现 server 和 client 的身份验证。

- `SSLpassword 变化协议`：client 和 server 端通过 password 变化协议通知对端。随后的报文都将使用新协商的加密套件和密钥进行保护和传输。

- `SSL 警告协议`：用来向通信对端报告告警信息，消息中包括告警的严重级别和描写叙述。
- `SSL 记录协议`：主要负责对上层的数据 (SSL 握手协议、SSLpassword 变化协议、SSL 警告协议和应用层协议报文) 进行分块、计算并加入 MAC 值、加密。并把处理后的记录块传输给对端。

### SSL 握手过程

SSL 通过握手过程在 client 和 server 之间协商会话參数，并建立会话。会话包括的主要參数有会话 ID、对方的证书、加密套件（密钥交换算法、数据加密算法和 MAC 算法等）以及主密钥（master secret）。通过 SSL 会话传输的数据，都将採用该会话的主密钥和加密套件进行加密、计算 MAC 等处理。

1. 仅验证 server 的 SSL 握手过程：
2. 