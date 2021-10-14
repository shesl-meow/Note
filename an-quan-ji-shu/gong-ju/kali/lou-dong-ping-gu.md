# 漏洞评估

## `Nessus`

使用 `Nessus` 这个工具，使用教程：[https://cloud.tencent.com/developer/article/1076409](https://cloud.tencent.com/developer/article/1076409)

### 发现本地漏洞

### 发现网络漏洞

1. 在 `Policies` → `Add` → `Web Application` 中选择 Web Application Tests 新建一个自己的 `Policies`。
2. 在 `My Scan` → `New Scan` 中通过之前定义的 `Policies` 定义一个新的 `Scan`
3. 在 `My Scan` 界面启动新的 `Scan` 

## OpenVAS

OpenVAS，即开放漏洞评估系统，是一个用于评估目标漏洞的杰出框架。它是 Nessus 项目的分支。不像 Nessus，OpenVAS提供了完全免费的版本。由于 OpenVAS 在Kali Linux中成为标准，我们将会以配置开始。
