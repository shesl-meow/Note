# Tutorial03

## Overview

Django 中定义了一个特殊的对象，称作 **view**，它抽象地对应着一个网页，Django 通过一个函数来抽象表示一个 view。同时 Django 提供了叫做 URLconfs 的东西，会将一个个 URL 模式字符串一一对应到每一个 view 中。

## Writing more view

我们可以在 `polls/views.py` 中加入以下代码：

```python
def detail(request, question_id):
    return HttpResponse("You're looking at question %s." % question_id)

def results(request, question_id):
    response = "You're looking at the results of question %s."
    return HttpResponse(response % question_id)

def vote(request, question_id):
    return HttpResponse("You're voting on question %s." % question_id)
```

然后将以下代码添加到 `polls/urls.py` 文件中：

```python
from django.urls import path

from . import views

urlpatterns = [
    # ex: /polls/
    path('', views.index, name='index'),
    # ex: /polls/5/
    path('<int:question_id>/', views.detail, name='detail'),
    # ex: /polls/5/results/
    path('<int:question_id>/results/', views.results, name='results'),
    # ex: /polls/5/vote/
    path('<int:question_id>/vote/', views.vote, name='vote'),
]
```

注意其中 `<int:question_id>` 这一部分：

* `<int:` 这一部分将 URL 中的请求部分转化成指定的类型，同时决定指向的模式字符串。
* `:question_id>` 这一部分给定匹配的模式字符串一个变量名。

_PostScript_：不建议愚蠢地将像 `.html` 一样的 URL cruft 添加到 path 中，比如：

```python
path('polls/latest.html', views.index)
```

## Write views that actually do something

每个 views 主要完成两件事情：返回包含所请求页面内容的 `HttpRsponse` 对象，或返回异常。

我们在 `polls/views.py` 中完成以下的事情（根据发布的日期显示系统中的最新的 5 个投票问题）：

```python
from django.http import HttpResponse
from .models import Question

def index(request):
    latest_question_list = Question.objects.order_by('-pub_date')[:5]
    output = ', '.join([q.question_text for q in latest_question_list])
    return HttpResponse(output)
```

这样的返回 Http 是硬核编码在 Python 代码中的，为了使前端代码与 Python 的后端代码分离，我们需要在应用中创建一个 `templates` 的子目录，进行渲染工作的 `DjangoTemplates` 会在每个 `INSTALLED_APPS` 中寻找一个 `templates` 的子目录。

所以我们创建目录以及文件 `polls/templates/polls/index.html`，并且写入以下内容：

```markup
{% if latest_question_list %}
    <ul>
    {% for question in latest_question_list %}
        <li><a href="/polls/{{ question.id }}/">{{ question.question_text }}</a></li>
    {% endfor %}
    </ul>
{% else %}
    <p>No polls are available.</p>
{% endif %}
```

将 `polls/views.py`，更改成以下内容：

```python
from django.http import HttpResponse
from django.template import loader

from .models import Question

def index(request):
    latest_question_list = Question.objects.order_by('-pub_date')[:5]
    template = loader.get_template('polls/index.html')
    context = {
        'latest_question_list': latest_question_list,
    }
    return HttpResponse(template.render(context, request))
```

主要到代码的最后一行：_加载模板，Python 渲染，返回 Http 响应_ → 是一个常用的功能，Django 将这三个功能集成到了一起形成了一个 shortcut，即可以用以下简化的代码表示：

```python
from django.shortcuts import render

from .models import Question

def index(request):
    latest_question_list = Question.objects.order_by('-pub_date')[:5]
    context = {'latest_question_list': latest_question_list}
    return render(request, 'polls/index.html', context)
```

## Raising a 404 error

Django 定义了一个返回 404 错误码的模块，通过以下方式导入：

```python
from django.http import Http404
```

在应用中，我们使用抛出异常的方式使用导入的 `Http404`，如下：

```python
raise Http404("This is a 404 error!")
```

一个实际的应用场景如下：

```python
from django.http import Http404
from django.shortcuts import render

from .models import Question
# ...
def detail(request, question_id):
    try:
        question = Question.objects.get(pk=question_id)
    except Question.DoesNotExist:
        raise Http404("Question does not exist")
    return render(request, 'polls/detail.html', {'question': question})
```

这段代码的意思是，从 `Question` 对应的所有对象中寻找一个 `pk=quesition_id` 的对象，如果不存在则抛出 `Http404` 的异常。

这个功能比较常用，因此 Django 提供了一个 shortcut：`get_object_or_404`。一个实例代码如下：

```python
from django.shortcuts import get_object_or_404, render

from .models import Question
# ...
def detail(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    return render(request, 'polls/detail.html', {'question': question})
```

还有一个类似的 shortcut 函数为：`get_list_or_404`

## Removing hardcodeed URLs in templates

在之前编写的 html 模板文件中，`href` 指向的 url 出现了直接拼接字符串的硬编码方式，我们可以使用以下的方式替换这种写法：

```markup
<li><a href="{% url 'polls' question.id %}">{{ question.question_text }}</a></li>
<!--
原来的写法：
<li><a href="/polls/{{ question.id }}/">{{ question.question_text }}</a></li>
--!>
```

这样做的好处是，将这个 `href` 与 `urlpatterns` 中对应的模式字符串连接起来，他们的任何改变会相互影响。

## Namespacing URL names

在实际的项目中可能存在许许多多的应用，那么使用上面的方法如何知道 URL 指向那个应用呢？

在应用的 `urls.py` 这个文件中，可以在 `urlpattern` 列表定义之前，加入：

```python
app_name = 'polls'
```

于是，可以对将应用模板改成如下形式：

```python
<li><a href="{% url 'polls:detail' question.id %}">{{ question.question_text }}</a></li>
<!--
原来的写法：
<li><a href="{% url 'detail' question.id %}">{{ question.question_text }}</a></li>
--!>
```
