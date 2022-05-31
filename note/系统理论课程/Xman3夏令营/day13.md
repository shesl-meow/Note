# Web 安全

## Https下的Web同源安全问题研究

### XSS



### Cookie基础 &rarr; 同源策略

- Cookie SOP相比Web SOP：
  - 仅以domain/path作为同源限制
  - 不区分端口
  - 不区分HTTP/HTTPs

## CRLF注入

- `\r\n`分割

## Web Server的运行方式

### Apache

- 默认prefork mode
- 同一个连接用同一个进程处理
- mod_php

### Nginx

- event-driven
- 同一个连接请求用不同的线程处理
- php-fpm

## php disabled function绕过

- `/proc/self/mem` &rarr; 可以修改当前进程的内存
- 修改`got`
- 命令执行`！`

### 访问头

- X-Forwarded-For
  - 很多程序员用X-Forward-For来获取用户IP
  - 在HTTP请求头中可以伪造

### 响应头

- X-XSS-Protection
  - 一定程度上禁止反射性XSS攻击

