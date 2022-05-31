---
title: "NTP"
date: 2019-02-25T15:16:23+08:00
tags: [""]
categories: ["系统理论课程", "计算机网络"]
---

> 学习地址：
>
> - https://www.tecmint.com/synchronize-time-with-ntp-in-linux/


## Protocol

The **Network Time Protocol** (**NTP**) is a protocol used to synchronize computer system clock automatically over a networks. The machine can have the system clock use **Coordinated Universal Time** (**UTC**) rather than local time.

## `ntpdate`

The most common method to sync system time over a network in Linux desktops or servers is by executing the `ntpdate` command which can set your system time from an **NTP** time server. In this case, the **ntpd** daemon must be stopped on the machine where the `ntpdate` command is issued.



Installation:

```bash
$ apt-get install ntpdate
```

Example:

```bash
$ sudo ntpdate 1.ro.pool.ntp.org
```

In order to just query the server and not set the clock and use an unprivileged port to send the packets from, in order to bypass firewalls, issue `ntpdate` with the below flags:

```bash
$ sudo ntpdate -qu 1.ro.pool.ntp.org
```



Always try to query and sync the time with the closest **NTP** servers available for your zone. The list of the NTP server pools can be found at the following address: https://www.pool.ntp.org/en/



此后可以通过 `date` 指令查看系统时间。
