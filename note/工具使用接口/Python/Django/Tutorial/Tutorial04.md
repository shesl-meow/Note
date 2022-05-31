---
title: "Tutorial04"
date: 2019-02-25T15:16:23+08:00
tags: [""]
categories: ["工具使用接口", "Python"]
---

> 参考资料：[Tutorial04](https://docs.djangoproject.com/en/2.1/intro/tutorial04/)


## Write a simple form

我们可以在之前编写的 html 文件的模板中加入 `<form>` 元素，以便我们后续的研究：

```html
<h1>{{ question.question_text }}</h1>

{% if error_message %}<p><strong>{{ error_message }}</strong></p>{% endif %}

<form action="{% url 'polls:vote' question.id %}" method="post">
{% csrf_token %}
{% for choice in question.choice_set.all %}
    <input type="radio" name="choice" id="choice{{ forloop.counter }}" value="{{ choice.id }}">
    <label for="choice{{ forloop.counter }}">{{ choice.choice_text }}</label><br>
{% endfor %}
<input type="submit" value="Vote">
</form>
```

以上的代码大致意思是在提交表单后，会连接到 `polls` 这个应用中，名为 `vote` 的 `urlpattern`，因此你需要在文件 `User/urls.py` 这个文件中为 `urlpattern` 添加以下代码：

```python
path('<int:question_id>/vote/', views.vote, name='vote'),
```

然后可以在 html 代码中注意到，在链接到 url 时，还传递了一个参数 `question.id`，这个参数会被 `urlpattern` 指向的函数作为传递参数，以下为 `vote` 函数实例：

```python
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse

from .models import Choice, Question
# ...
def vote(request, question_id):
    question = get_object_or_404(Question, pk=question_id)
    try:
        selected_choice = question.choice_set.get(pk=request.POST['choice'])
    except (KeyError, Choice.DoesNotExist):
        return render(request, 'polls/detail.html', {
            'question': question,
            'error_message': "You didn't select a choice.",
        })
    else:
        selected_choice.votes += 1
        selected_choice.save()
        # 每次处理 POST 数据时，都应当使用 HttpResponseRedirect 这个函数
        # 因为有时用户不停点击按键会发送多次请求
        return HttpResponseRedirect(reverse('polls:results', args=(question.id,)))
```



*PostScript*：这个代码其实是存在问题的，比如两个用户同时访问我们的页面，同时进行投票后我们的数据库中的 vote 只增加了一票，而实际上应该增加两票，这一点被称作 *竞争条件* (*race condition*)，[查看解决方法](https://docs.djangoproject.com/en/2.1/ref/models/expressions/#avoiding-race-conditions-using-f)。

## Use generic views: Less code is better

之前我们做的许多工作都在完成这样一件事情：通过用户访问的 URL 从数据库中提取数据，并且渲染相应的 html 模板。许多 WEB 系统中都会完成这一项功能，所以 Django 提供了一个 shortcut 来集成地完成这些功能，称作 *通用视图* (*generic views*)。

### Amend URLconf

首先，把 `polls/urls.py` 文件修改成如下形式：

```python
from django.urls import path

from . import views

app_name = 'polls'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('<int:pk>/', views.DetailView.as_view(), name='detail'),
    path('<int:pk>/results/', views.ResultsView.as_view(), name='results'),
    path('<int:question_id>/vote/', views.vote, name='vote'),
]
```

### Amend views

然后，把 `polls/views.py` 文件修改成如下形式：

```python
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views import generic

from .models import Choice, Question


class IndexView(generic.ListView):
    template_name = 'polls/index.html'
    context_object_name = 'latest_question_list'

    def get_queryset(self):
        """Return the last five published questions."""
        return Question.objects.order_by('-pub_date')[:5]


class DetailView(generic.DetailView):
    model = Question
    template_name = 'polls/detail.html'


class ResultsView(generic.DetailView):
    model = Question
    template_name = 'polls/results.html'


def vote(request, question_id):
    ... # same as above, no changes needed.
```

上面的更改简而言之是将函数式编程，重组成了面向对象式编程。注意到其中的对象派生自 `generic.ListView` 与 `generic.DetailView`，这两个系统对象分别抽象出 ”显示对象列表“ 和 ”显示特定类型对象的详细界面“。

默认情况下，`DetailView` 这个视图会使用 `<app_name>/<model_name>_detail.html` 这个前端模板。

同理 `ListView` 也会使用 `<app_name>/<model_name>_list.html` 这个模板。

完整的通用视图使用方法，可以查看[说明文档](https://docs.djangoproject.com/en/2.1/topics/class-based-views/)。


