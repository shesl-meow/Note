# Web服务器端安全

## 前置知识

### Http协议

- url说明
  - `协议 http` + `用户密码 user@pass` +`ip地址 127.0.0.1` + `端口port 8080` + `页面 index.php` + `参数 ?id=123` + `锚点 #123`
  - Http(s)协议：URL、HOST、User-Agent、Referer（代表跳转来源 &rarr; 可以用与做流量统计）、Cookie（反序列化）、X-Forwarded-For

## SQL注入

- 脚本语言无法理解SQL语句，两者对查询语句处理不一致，导致SQL注入，篡改了SQL语句原本逻辑
- SQL注入防御：
  - 字符串拼接形式：过滤单引号、双引号、反斜杠等关键词；转义。
  - 变量绑定，先给sql查询变量一个占位符，然后调用mysql的库进行预编译。

### Union注入

- 适用场景：有回显，可以看到某些字段的回显结果
- Union注入限制：很多攻击场景不是select注入，union语句被很多网页过滤

### 报错注入

- 常见报错注入函数：floor、extractvalue...

### Boolean盲注

- 在数据回显的不同，逐个爆破猜测。example，payload:

  ```mysql
  xx' and pass > '123'#
  ```

  sql查询语句如下：

  ```mysql
  select *from user where user = 'xx' and pass > '123'#
  ```

  - PS：mysql默认不区分大小写，可以先用binary函数处理

### Timing 盲注

- 页面不存在不同回显，但SQL语句被执行
- 逐个猜测 + 延时执行

### 文件读写

- 读取关键文件（mysql5.7之后引入了）

### 命令执行

### 宽字节注入

- 主要针对gbk

## WAF绕过

1. 双写关键字

   - WAF是用简单的非迭代的将select、or语句替换为空字符串

2. 编码绕过：ASCII、16进制、unicode编码、URL编码（开发程序员不知道url会自动解码一次，自己再写了url解码函数，我们可以将URL编码两次）

3. more trick：

   - 空格被限制：`select(username)from(admin)`， `select\**\username\**\from\**\admin`

   - 科学记数法绕过：`where username=1e1union select`

   - `>`, `=`, `<` 被限制：`where pass in (1,2)`

   - mysql对%00不会截断：se%00lect

   - PS：SQL测试语法：

     ```mysql
     select '1' > 'a'
     ```

     - 测试字符 `'1'` 与字符 `a` 的大小

## 命令执行漏洞

- 程序过滤不严谨，用户可以将代码注入并执行。高危函数：eval()、assert()
- 文件包含注入：

## 文件包含

- 在web开发中，为什么要使用本地文件包含？ &rarr; 提高代码重用性
- 如何获取临时文件名？利用：`phpinfo()`

### 本地文件包含 LFI

- 常见函数

  - include()、require() &rarr; require函数找不到文件就会引发一个错误。比如：

  ```php
  <?php include(_GET[...]); ?>
  ```

  - PS：`include once()` &rarr; 若文件中代码已经包含则不会再次被包含

- 使用 `filter` 的php协议读取敏感文件的base64代码：

```url
http://www.test.com/index.php?page=php://filter/convert.base64-encode/resource=../../../../ect/password
```

- 使用 `/proc/self/environ` 进行文件包含
  - 当向任意php文件post请求上传数据时，可以直接在phpinfo()页面找到临时文件的路径和名字

- 临时文件生存周期短，如何延长？
  - 通过分块传输编码，提前获知临时文件的名称
  - 通过增加临时文件名后的 数据长度来延长时间
  - 通过大量请求来延迟PHP脚本的执行速度
- 包含临时文件（条件竞争）

### 其他的文件包含

- 有限制的LFI
- 远程文件包含RFI：利用 `phar://` 和 `zip://` 伪协议可以解压缩包含一句木马

## 文件上传

- 最简单的文件上传代码：

  ```php
  if(is_uploaded_file($_['myfile']['tmp_name'])){
      $upload_file=$_FILES['myfile']['tmp_name'];
      $file_true_name=$_FILES['myfile']['name'];
      if(move_upload_file($upload_file, $file_true_name))
          echo $_FILES['myfile']['name']."上传成功";
      else echo "上传失败";
  }else echo "上传失败";
  ```

#### 防御文件上传

- 客户端的javaScript校验，通常校验扩展名 &rarr; 此时并没有发送数据包 &rarr; 抓包改包轻松爆破

- 检测MIME类型。

  - 客户端判断：`$_FILES['myfile']['type']=='image/jpeg'` &rarr; 类型也是根据文件名获取的
  - 服务端判断：

  ```php
  $finfo = finfo_open(FILEINFO_MINE);
  $mimetype = finfo_file($finfo, $file_true_name);
  ```

- 检查内容 &rarr; 黑名单（看上去很有效，但实际上只要是黑名单就可以被绕过） &rarr; 耗费资源

  ```php
  $content = file_get_contents($file_true_name);
  if(stripos($content, "<?php")){ die("php!!!"); }
  ```

- 隐藏文件 &rarr; 移到一个不为人知的路径 &rarr; 受到业务需求的限制，文件必须被访问到

  ```php
  $file_true_name=$secrect_path.$_FILES['myfile']['name'];
  if(move_uploaded_file($uploaded_file, $file_true_name)
     echo $_FILES['myfile']['name']."上传成功";
  else echo "上传失败";
  ```

- 随机文件名（局限性同上）：

  ```php
  $file_true_name=md5(rand(1,1000)).$_FILES['myfile']['name'];
  ```

- 检查文件扩展名

  - 最直接最有效的方法 &rarr; web服务器通过不同的问文件扩展名
  - 黑名单绕过
    - `php` &rarr;  `php3`、`php5`、`phtms`、 `pHp`...
    - `jsp` &rarr; `jspx`、 `jspf`
    - `asp` &rarr; `asa`、 `cer`、 `aspx`...
  - 白名单的绕过
    - 截断绕过：文件名 &rarr; `test.php(0x00).jpg`
    - 利用NTFS ADS特性、IIS5.x-6.x解析漏洞
    - Apache解析漏洞：Apache解析文件名是从右向左开始判断解析，如果后缀名为不可识别文件解析，就再往左判断。比如：`test.php.owf` 会被Apache解析为 `test.php`
    - Nginx解析漏洞：cgi.fix_pathinfo开启时（为1），当访问 `www.xx.com/phpinfo.jpg/q.php` 时，会将 `phpinfo.jpg` 当作php进行解析。

## 认证与授权

- Authentication & Authorization

### 认证

- 单因素认证与多因素认证
- 密码强度：OWASP推荐 &rarr; 6|8, 多种组合
- Session与Cookie

### Session Fixation攻击

### 单点登录SSO

- 简介： 三方参与 &rarr; 用户、浏览器、OpenID提供者
- 用户只需要登录一次、风险过于集中...

### 授权

- 用户只能访问有限的资源
- 越权 &rarr; 水平越权、垂直越权