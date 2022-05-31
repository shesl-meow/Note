> 学习网址：
> - https://www.djangoproject.com/start/
> - [Tutorial01](https://docs.djangoproject.com/en/2.1/intro/tutorial01/)

# Tutorial01

使用 Django，请配置 Python3.5 及以上环境，查看 Python 版本请使用以下命令：

```bash
$ python --version
```

本 tutorial 建立在已经安装 Django 环境的基础上，Django 是 Python 的一个模块，可以通过以下命令安装：

```bash
$ pip install django
```

可以通过以下命令检测 Django 是否已经安装：

```bash
$ python -m django --version
# 已经安装返回版本号，未安装返回 No module named django.
```

## Createing a project

第一次使用 Django，先进行初始化，使用 `cd` （change directory）命令到工作到目标文件夹，使用以下命令在当前文件夹下创建一个新的 Django 项目：

```bash
$ django-admin startproject mysite
```

*PostScript*: 项目的名称不应该与被 Python 或 Django 占用的关键词重合，比如：`django` 或 `test` 。

上述命令会自动生成以下文件，文件功能解释：

- `manage.py`：Django 提供的与项目进行交互的一个 Python 脚本文件，[详细信息](https://docs.djangoproject.com/en/2.1/ref/django-admin/)。
- `mysite/`：Python 项目的实际模块包，该文件夹的名字与项目名称相同。
- `mysite/__init__.py`：一个空文件。根据 Python 的标准规定，定义一个模块需要一个 `__init__.py` 文件，该空文件表示 `mysite` 是一个 Python 模块。
- `mysite/settings.py`：Django 项目配置文件。[详细信息](https://docs.djangoproject.com/en/2.1/topics/settings/)。

- `mysite/urls.py`：Django 项目的 URL 声明。[详细信息](https://docs.djangoproject.com/en/2.1/topics/http/urls/)。
- `mysite/wsgi.py`：兼容 wsgi 的 web 服务入口。[部署信息](https://docs.djangoproject.com/en/2.1/howto/deployment/wsgi/)。

## The development server

可以使用以下命令运行服务：

```bash
$ python manage.py runserver
```

默认运行端口是 8000，也可以指定端口运行服务：

```bash
$ python manage.py runserver 8000
```

完整的[参考信息](https://docs.djangoproject.com/en/2.1/ref/django-admin/#django-admin-runserver)。

## Creating the Polls app

app 与 project 的区别？

- app 是一个项目中具体完成某项功能的应用。一个项目由许多个 app 组成。

app 可以在任何位置，本 Tutorial 中，将其置于 `managy.py` 的同级目录下，输入以下命令：

```bash
$ python manage.py startapp polls
```

## Write your first view

将以下代码写入 `polls/views.py`：

```python
from django.http import HttpResponse


def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")
```

在 `polls` 文件夹内创建一个名为 `urls.py` 的文件，将以下代码写入 `polls/urls.py`：

```python
from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
]
```

下一步是在 `mysite/urls.py` 中导入我们刚才写的 `polls/urls.py`。先从 `django.urls` 库中导入 `include` 模块，并且加入 `path('polls/',include('polls.urls'))` 在 `urlpatterns` 中。`mysite/urls.py` 文件大致如下：

```python
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('polls/', include('polls.urls')),
    path('admin/', admin.site.urls),
]
```

输入配置服务器中的指令，并在浏览器中打开以下 url：`https://localhost:8000/polls/`。即可在浏览器中看到 `polls/views.py` 中响应的 http 请求。



*PostScript*：建议总是使用 **include** 来导入其他的 `urlpatterns`。

*PostScript*：关于 `path()` 函数的参数：

- `route`：一个包含 URL 模式字符串。Django 在收到一个请求后，会一个个遍历 URL patterns 中的字符串，找到符合的后进入该模式字符串指向的页面。
- `view`：route 参数中的模式字符串对应的 view 函数。
- 两个可选参数：`kwargs` 与 `name`。


