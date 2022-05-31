---
title: "Tutorial05"
date: 2019-03-27T12:06:27+08:00
tags: [""]
categories: ["工具使用接口", "Python"]
---

> 参考资料：[Tutorial05](https://docs.djangoproject.com/en/2.1/intro/tutorial05/)


## Introducing automated testing

自动化测试：

- 测试可以节省你的时间
- 测试不仅仅可以发现问题，还能防止问题
- 测试使你的代码更受欢迎
- 测试有助于团队合作

## Writing our first test

### 1. identify a bug

onfirm the bug by using the [`shell`](https://docs.djangoproject.com/en/2.1/ref/django-admin/#django-admin-shell) to check the method on a question whose date lies in the future:

```bash
$ python manage.py shell
```

```python
>>> import datetime
>>> from django.utils import timezone
>>> from polls.models import Question
>>> # create a Question instance with pub_date 30 days in the future
>>> future_question = Question(pub_date=timezone.now() + datetime.timedelta(days=30))
>>> # was it published recently?
>>> future_question.was_published_recently()
True
```

### 2. create a test to expose the bug

通常，我们会把测试代码放在应用的`tests.py`文件中，测试系统将自动地从任何名字以test开头的文件中查找测试程序。每个app在创建的时候，都会自动创建一个`tests.py`文件，就像`views.py`等文件一样。

将下面的代码输入投票应用的`polls/tests.py`文件中：

```python
import datetime
from django.utils import timezone
from django.test import TestCase
from .models import Question

class QuestionMethodTests(TestCase):
    def test_was_published_recently_with_future_question(self):
        """
        在将来发布的问卷应该返回False
        """
        time = timezone.now() + datetime.timedelta(days=30)
        future_question = Question(pub_date=time)
        self.assertIs(future_question.was_published_recently(), False)
```

我们在这里创建了一个`django.test.TestCase`的子类，它具有一个方法，该方法创建一个`pub_date`在未来的Question实例。最后我们检查`was_published_recently()`的输出，它应该是 False。

### 3. Running tests

在终端中，运行下面的命令，

```bash
$ python manage.py test polls
```

你将看到结果如下：

```bash
Creating test database for alias 'default'...
F
======================================================================
FAIL: test_was_published_recently_with_future_question (polls.tests.QuestionMethodTests)
----------------------------------------------------------------------
Traceback (most recent call last):
File "/path/to/mysite/polls/tests.py", line 16, in test_was_published_recently_with_future_question
self.assertIs(future_question.was_published_recently(), False)
AssertionError: True is not False
----------------------------------------------------------------------
Ran 1 test in 0.001s
FAILED (failures=1)
Destroying test database for alias 'default'...
```

这其中都发生了些什么？：

- `python manage.py test polls` 命令会查找 `polls` 应用中所有的测试程序
- 发现一个 `django.test.TestCase` 的子类
- 为测试创建一个专用的数据库
- 查找名字以 `test` 开头的测试方法
- 在 `test_was_published_recently_with_future_question` 方法中，创建一个 Question 实例，该实例的 pub_data 字段的值是30天后的未来日期。
- 然后利用 `assertIs()` 方法，它发现 `was_published_recently()` 返回了True，而不是我们希望的 False。

最后，测试程序会通知我们哪个测试失败了，错误出现在哪一行。

整个测试用例基本上和 Python 内置的 `unittest` 非常相似，大家可以参考 Python 教程中测试相关的章节。

### 4. Fix the bug

修改源代码，具体如下：

```python
# polls/models.py

def was_published_recently(self):
    now = timezone.now()
    return now - datetime.timedelta(days=1) <= self.pub_date <= now
```

再次运行测试程序：

```bash
$ python manage.py test polls
```

```bash
Creating test database for alias 'default'...
.
----------------------------------------------------------------------
Ran 1 test in 0.001s
OK
Destroying test database for alias 'default'...
```

可以看到 bug 已经没有了。

### 5. More comprehensive tests

```python
def test_was_published_recently_with_old_question(self):
    """
    was_published_recently() returns False for questions whose pub_date
    is older than 1 day.
    """
    time = timezone.now() - datetime.timedelta(days=1, seconds=1)
    old_question = Question(pub_date=time)
    self.assertIs(old_question.was_published_recently(), False)

def test_was_published_recently_with_recent_question(self):
    """
    was_published_recently() returns True for questions whose pub_date
    is within the last day.
    """
    time = timezone.now() - datetime.timedelta(hours=23, minutes=59, seconds=59)
    recent_question = Question(pub_date=time)
    self.assertIs(recent_question.was_published_recently(), True)
```

## Test a view

### The Django test client

Django provides a test [`Client`](https://docs.djangoproject.com/en/2.1/topics/testing/tools/#django.test.Client) to simulate a user interacting with the code at the view level. We can use it in `tests.py` or even in the [`shell`](https://docs.djangoproject.com/en/2.1/ref/django-admin/#django-admin-shell).

We will start again with the [`shell`](https://docs.djangoproject.com/en/2.1/ref/django-admin/#django-admin-shell), where we need to do a couple of things that won’t be necessary in `tests.py`. The first is to set up the test environment in the [`shell`](https://docs.djangoproject.com/en/2.1/ref/django-admin/#django-admin-shell):

```bash
$ python manage.py shell
```

```python
>>> from django.test.utils import setup_test_environment
>>> setup_test_environment()
```

[`setup_test_environment()`](https://docs.djangoproject.com/en/2.1/topics/testing/advanced/#django.test.utils.setup_test_environment) installs a template renderer which will allow us to examine some additional attributes on responses such as `response.context` that otherwise wouldn’t be available. 

Next we need to import the test client class:

```python
>>> from django.test import Client
>>> # create an instance of the client for our use
>>> client = Client()
```

With that ready, we can ask the client to do some work for us:

```python
>>> # get a response from '/'
>>> response = client.get('/')
Not Found: /
>>> # we should expect a 404 from that address; if you instead see an
>>> # "Invalid HTTP_HOST header" error and a 400 response, you probably
>>> # omitted the setup_test_environment() call described earlier.
>>> response.status_code
404
>>> # on the other hand we should expect to find something at '/polls/'
>>> # we'll use 'reverse()' rather than a hardcoded URL
>>> from django.urls import reverse
>>> response = client.get(reverse('polls:index'))
>>> response.status_code
200
>>> response.content
b'\n    <ul>\n    \n        <li><a href="/polls/1/">What&#39;s up?</a></li>\n    \n    </ul>\n\n'
>>> response.context['latest_question_list']
<QuerySet [<Question: What's up?>]>
```

### Improving our view

```python
# polls/views.py
from django.utils import timezone

class IndexView(generic.ListView):
    template_name = 'polls/index.html'
    context_object_name = 'latest_question_list'

    def get_queryset(self):
        """
        Return the last five published questions (not including those set to be
        published in the future).
        """
        return Question.objects.filter(
            pub_date__lte=timezone.now()
        ).order_by('-pub_date')[:5]
```

### Test our new view

Add the following to `polls/tests.py`:

```python
from django.urls import reverse
```

and we’ll create a shortcut function to create questions as well as a new test class:

```python
def create_question(question_text, days):
    """
    Create a question with the given `question_text` and published the
    given number of `days` offset to now (negative for questions published
    in the past, positive for questions that have yet to be published).
    """
    time = timezone.now() + datetime.timedelta(days=days)
    return Question.objects.create(question_text=question_text, pub_date=time)


class QuestionIndexViewTests(TestCase):
    def test_no_questions(self):
        """
        If no questions exist, an appropriate message is displayed.
        """
        response = self.client.get(reverse('polls:index'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No polls are available.")
        self.assertQuerysetEqual(response.context['latest_question_list'], [])

    def test_past_question(self):
        """
        Questions with a pub_date in the past are displayed on the
        index page.
        """
        create_question(question_text="Past question.", days=-30)
        response = self.client.get(reverse('polls:index'))
        self.assertQuerysetEqual(
            response.context['latest_question_list'],
            ['<Question: Past question.>']
        )

    def test_future_question(self):
        """
        Questions with a pub_date in the future aren't displayed on
        the index page.
        """
        create_question(question_text="Future question.", days=30)
        response = self.client.get(reverse('polls:index'))
        self.assertContains(response, "No polls are available.")
        self.assertQuerysetEqual(response.context['latest_question_list'], [])

    def test_future_question_and_past_question(self):
        """
        Even if both past and future questions exist, only past questions
        are displayed.
        """
        create_question(question_text="Past question.", days=-30)
        create_question(question_text="Future question.", days=30)
        response = self.client.get(reverse('polls:index'))
        self.assertQuerysetEqual(
            response.context['latest_question_list'],
            ['<Question: Past question.>']
        )

    def test_two_past_questions(self):
        """
        The questions index page may display multiple questions.
        """
        create_question(question_text="Past question 1.", days=-30)
        create_question(question_text="Past question 2.", days=-5)
        response = self.client.get(reverse('polls:index'))
        self.assertQuerysetEqual(
            response.context['latest_question_list'],
            ['<Question: Past question 2.>', '<Question: Past question 1.>']
        )
```

### Testing the `DetailView`

```python
# polls/views.py
class DetailView(generic.DetailView):
    ...
    def get_queryset(self):
        """
        Excludes any questions that aren't published yet.
        """
        return Question.objects.filter(pub_date__lte=timezone.now())
```

And of course, we will add some tests, to check that a `Question` whose `pub_date` is in the past can be displayed, and that one with a `pub_date` in the future is not:

```python
# polls/tests.py
class QuestionDetailViewTests(TestCase):
    def test_future_question(self):
        """
        The detail view of a question with a pub_date in the future
        returns a 404 not found.
        """
        future_question = create_question(question_text='Future question.', days=5)
        url = reverse('polls:detail', args=(future_question.id,))
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

    def test_past_question(self):
        """
        The detail view of a question with a pub_date in the past
        displays the question's text.
        """
        past_question = create_question(question_text='Past Question.', days=-5)
        url = reverse('polls:detail', args=(past_question.id,))
        response = self.client.get(url)
        self.assertContains(response, past_question.question_text)
```


