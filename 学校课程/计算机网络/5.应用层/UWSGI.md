> 在搭建 NKCTF 网站的时候学习到的有关 UWSGI 的知识

## WSGI协议

几个概念：

- **WSGI**：Web Server Gateway Interface。`WSGI` 不是服务器，`python` 模块，框架，`API` 或者任何软件，只是一种规范，描述 `web server` 如何与 `web application` 通信的规范。
  1. `WSGI server` 负责从客户端接收请求，将 `request` 转发给 `application`，将 `application` 返回的 `response` 返回给客户端；
  2. `WSGI application` 接收由 `server` 转发的 `request`，处理请求，并将处理结果返回给 `server`。`application` 中可以包括多个栈式的中间件(`middlewares`)，这些中间件需要同时实现 server 与 application，因此可以在 WSGI 服务器与 WSGI 应用之间起调节作用：对服务器来说，中间件扮演应用程序，对应用程序来说，中间件扮演服务器。
- **uwsgi：**与 `WSGI` 一样是一种通信协议，是 `uWSGI` 服务器的独占协议，用于定义传输信息的类型，每一个 `uwsgi packet` 前 `4byte` 为传输信息类型的描述，与WSGI协议是两种东西，据说该协议是 `fcgi` 协议的10倍快。（**快速通用网关接口** &rarr; **Fast** **C**ommon **G**ateway **I**nterface／**FastCGI**）是一种让交互程序与Web服务器通信的协议）
- **uWSGI：**是一个 `web` 服务器，实现了 `WSGI `协议、`uwsgi` 协议、`http` 协议等。

## WSGI协议的实现

以 `Django` 为例，分析一下 `WSGI` 协议的具体实现过程：

### django WSGI application

`application` 的流程包括:

- 加载所有中间件，以及执行框架相关的操作，设置当前线程脚本前缀，发送请求开始信号；
- 处理请求，调用 `get_response()` 方法处理当前请求，该方法的的主要逻辑是通过 `urlconf` 找到对应的 `view` 和 `callback`，按顺序执行各种 `middleware` 和 `callback`。
- 调用由 `server` 传入的 `start_response()` 方法将响应 `header` 与 `status` 返回给 `server`。
- 返回响应正文

### django WSGI Server

通过 `python manage.py runserver` 运行 `django` 项目，在启动时都会调用下面的 `run` 方法，创建一个 `WSGIServer` 的实例，之后再调用其 `serve_forever()` 方法启动服务。

```python
def run(addr, port, wsgi_handler, ipv6=False, threading=False):
    server_address = (addr, port)
    if threading:
        httpd_cls = type(str('WSGIServer'), (socketserver.ThreadingMixIn, WSGIServer), {})
    else:
        httpd_cls = WSGIServer
    # 这里的wsgi_handler就是WSGIApplication
    httpd = httpd_cls(server_address, WSGIRequestHandler, ipv6=ipv6)
    if threading:
        httpd.daemon_threads = True
    httpd.set_app(wsgi_handler)
    httpd.serve_forever()
```



下面表示 `WSGI server` 服务器处理流程中关键的类和方法：

![Server](WSGI-Django_Server.png)
