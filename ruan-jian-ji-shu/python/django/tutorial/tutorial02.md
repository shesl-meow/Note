# Tutorial02

## Database setup

打开 `mysite/settings.py`，这是一个 Python 的模块变量，表示着 Django 的设置。

Django 的数据库默认使用 SQLite，如果想使用其他 DBMS，需要更改 DATABASES 这个 Python 字典中，`'default'` 键值对应的字典，进行以下设置：

|  'default' 字典键 |                                                                                                'default' 字典可能值                                                                                                |
| :------------: | :-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
| **`'ENGINE'`** | `'django.db.backends.sqlite3'`, `'django.db.backends.postgresql'`,`'django.db.backends.mysql'`, `'django.db.backends.oracle'` , [etc](https://docs.djangoproject.com/en/2.1/ref/databases/#third-party-notes) |
|  **`'NAME'`**  |                                                                                           数据库的名称，如果使用 sqlite，则为文件的路径                                                                                          |
|    `'USER'`    |                                                                                           登录数据库的用户名，非 sqlite 数据库必须添加                                                                                          |
|  `'PASSWORD'`  |                                                                                        ##登录数据库用户名对应的密码，非 sqlite 数据库必须添加                                                                                       |
|    `'HOST'`    |                                                                                 连接数据库的主机名，sqlite 数据库不需声明，空字符串表示 `'localhost'`                                                                                 |

`mysite/settings.py` 中 `TIME_ZONE` 变量可以用于设置时区。

`mysite/settings.py` 中 `INSTALLED_APPS` 表示项目中所有应用的名字，默认情况下，包括了以下来自 Django 的 apps：

* [`django.contrib.admin`](https://docs.djangoproject.com/en/2.1/ref/contrib/admin/#module-django.contrib.admin) – The admin site. You’ll use it shortly.
* [`django.contrib.auth`](https://docs.djangoproject.com/en/2.1/topics/auth/#module-django.contrib.auth) – An authentication system.
* [`django.contrib.contenttypes`](https://docs.djangoproject.com/en/2.1/ref/contrib/contenttypes/#module-django.contrib.contenttypes) – A framework for content types.
* [`django.contrib.sessions`](https://docs.djangoproject.com/en/2.1/topics/http/sessions/#module-django.contrib.sessions) – A session framework.
* [`django.contrib.messages`](https://docs.djangoproject.com/en/2.1/ref/contrib/messages/#module-django.contrib.messages) – A messaging framework.
* [`django.contrib.staticfiles`](https://docs.djangoproject.com/en/2.1/ref/contrib/staticfiles/#module-django.contrib.staticfiles) – A framework for managing static files.

这里面的有些应用需要数据库中至少有一个表格，我们使用下面的命令创建他们：

```bash
$ python manage.py migrate
```

## Creating models

**Models**：模型，指明了数据库构造方式。一个模型对象对应一个表格，对象数据成员即为表格属性。

我们尝试在 polls 应用中新建两个名为 Question 和 Choice 的模型。在 `polls/models.py` 中使用两个 Python 的类表示，如下代码非常直白：

```python
from django.db import models

class Question(models.Model):
    question_text = models.CharField(max_length=200)
    pub_date = models.DateTimeField('date published')

class Choice(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    choice_text = models.CharField(max_length=200)
    votes = models.IntegerField(default=0)
```

## Activating models

通过 models ，可以直接在数据库中创建表格 或 操作数据库中的数据。但首先我们需要告诉 Django，该 polls 应用已经安装在了我们的项目中。

为了将我们的 apps 加入到我们的项目，我们需要更改 `mysites/settings.py` 中的 `INSTALLED_APPS` 设置。Polls 的配置文件在 `polls/apps.py` 文件的 `PollsConfig` 中，所以 `mysite/settings.py` 更改如下：

```python
INSTALLED_APPS = [
    'polls.apps.PollsConfig',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]
```

现在 Django 知道了需要添加 polls 这个应用，执行以下命令建立我们创建的 models 对应的数据库：

```bash
$ python manage.py makemigrations polls
```

因为在 Django 中写的应用有着很强的移植性，在一个项目中写的应用可以轻松移植到其他应用上，所以 Django 提供了以上的命令重新安装移植的命令 → 所以以上执行 makemigrations polls 命令就是把 polls 这个应用移植到本项目，并进行创建数据库。

Django 会将改变之后的内容存储在 `migration` 中，可以在 `polls/migrations/0001_initial.py` 这个文件中看到数据库的表格的创建方式。

以下一个命令执行 `polls/migrations/0001_initial.py` 的内容：（回显执行的 sql 命令）

```bash
$ python manage.py sqlmigrate polls 0001
```

如果你不进行以上的迁徙操作，可以通过以下的命令查看会出现的问题：

```bash
$ python manage.py check
```

**总结**：当你更改了 Django 项目的一个模型后，你需要通过以下的三步适配这些变化：

1. 创建一个模型 `models.py`
2. 执行命令 `python manage.py makemigrations`，在 `migrations/` 中生成数据库生成的中间 Python 脚本
3. 执行命令 `python manege.py migrate`，执行中间 Python 脚本，生成/修改数据库。

_PostScript_：你可以在下面这个网站查看完整的 [manage.py 使用说明](https://docs.djangoproject.com/en/2.1/ref/django-admin/)。

_PostScript_：可以在以下网站查看关于 Django 模型的使用，[中文使用说明](https://django-chinese-doc.readthedocs.io/zh_CN/latest/topics/db/models.html)，[官网使用说明](https://docs.djangoproject.com/en/1.11/topics/db/models/)。

## Playing with API

使用 Django 提供的以下命令，可以在该项目下进入 Python 的用户交互界面，可以用于测试刚才创建的 Question 和 Choice 模块：

```bash
$ python manage.py shell
```

以下命令，可以测试 Python 数据库提供的 API：

```python
>>> from polls.models import Choice, Question
# 从我们定义的应用 polls 的模块中导入 Choice 和 Question 对象

>>> Question.objects.all()
<QuerySet []>
# 这表示数据库中还没有 Question 这个对象

>>> from django.utils import timezone

>>> q = Question(question_text="What's new?", pub_date=timezone.now())
# 创建一个 Question 的对象 q, question_text 是 "What's new?"

>>> q.save()
# 将 q 这个 Question 对象存储进入数据库中

>>> Question.objects.all()
<QuerySet [<Question: Question object (1)>]>
# 我们新创建了一个 Question 对象
```

Django 提供的数据库查询操作 API [相关文档](https://docs.djangoproject.com/en/2.1/topics/db/queries/)。

## Introducing the Django Admin

### Creating an admin user

使用以下命令创建一个 admin 用户：

```bash
$ python manage.py createsuperuser
```

### Starting the development server

如同之前一样按照以下命令启动服务器：

```bash
$ python manage.py runserver
```

在浏览器中访问 URL：`localhost:8000/admin/`，输入在上一步中创建的用户名和密码，可以进入管理页面。

### Make the poll app modifiable in the admin

进入后发现页面中并没有显示我们创建的 Question 和 Choice 对象。

这时我们需要编辑 `polls/admin.py` 这个文件，输入以下代码：

```python
from django.contrib import admin

# Register your models here.
from .models import Question, Choice

admin.site.register(Question)
admin.site.register(Choice)
```

这时刷新浏览器，即可查看 `polls` 中的 Question 和 Choice 对象。
