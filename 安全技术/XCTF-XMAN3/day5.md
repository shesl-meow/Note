# Web Day1

## 所需知识

1. HTTP抓包/修改：Http请求、响应流程

2. web前端：Cookie、缓存、跨域问题、编码（url编码、html实体编码、js编码）

3. web后端：php &rarr; 官方文档；Python &rarr; 廖雪峰Python教程

4. 数据库与服务器

5. 常见的web漏洞：XSS、SQL注入、CSRF、SSRF、命令执行、XXE、文件上传/包含/写入、反序列化、未授权访问、目录遍历、业务逻辑漏洞

6. 工具：Sqlmap、Burpsuit、Hackbar、Proxy SwitchyOme、Postman...


## Http请求

### Http请求响应

- 请求包格式 &rarr; 请求头格式：请求方法 + url/path + 协议版本

1. 1. GET请求 &rarr; 从指定的资源请求数据 &rarr; 可以被缓存，有长度限制
   2. POST请求 &rarr; 向指定的资源提交要被处理的数据 &rarr; 不会被缓存，没有长度限制
   3. 响应包 &rarr; 响应头：响应协议+状态码；响应主体：html代码

   - PHP后端获取请求头：`$_SERVER['HTPP_USER_AGENT']`

- 常见请求头说明：
  - Content-Length：请求长度，为了告诉服务器有多长（有时没有，使用一些分隔符指明长度）

## 题目类型

1. 入门题目

   - 查看源码（`view-source://www.baidu.com`）
   - 查看请求响应包（chrome开发者工具栏）
   - 文件泄露
     - 备份文件泄露：.index.php.swp、.index.php.swo、.index.php.bak、.index.php~
     - 源码压缩包：
     - git/svn泄露：利用工具GitHack、dvcs-ripper，可以获取网站源码
     - 其他文件泄露：.idea（使用intellij idea工程），.DS_Store（OS X下，可泄露文件），.pyc文件
   - JSfuck：利用js的弱类型特性，拼接字符串作为js代码运行 &rarr; 直接贴到chrome的开发者工具中即可运行
   - 请求修改、重放：请求头、请求包、Cookie

2. 常规题目

   - 一个存在漏洞的网站

   - SQL注入：拿到数据库中的flag
   - 命令执行、文件上传：拿到服务器上的flag
   - 拿到管理员的cookie &rarr; flag在cookie中（XSS）
   - XXE简介（https://thief.one/2017/06/20/1/，https://www.leavesongs.com/PENETRATION/slim3-xxe.html），xml外部实体注入 &rarr; SSRF
   - 其他一些漏洞利用（条件竞争、SSRF、XXE）

### XXE简介

​		