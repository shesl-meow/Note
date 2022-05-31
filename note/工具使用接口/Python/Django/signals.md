---
title: "Django Signals"
date: 2019-03-27T12:06:27+08:00
tags: [""]
categories: ["工具使用接口", "Python"]
---


## Built-in Signals

Django provides a [set of built-in signals](https://docs.djangoproject.com/en/2.1/ref/signals/) that let user code get notified by Django itself of certain actions. These include some useful notifications:

- [`django.db.models.signals.pre_save`](https://docs.djangoproject.com/en/2.1/ref/signals/#django.db.models.signals.pre_save) & [`django.db.models.signals.post_save`](https://docs.djangoproject.com/en/2.1/ref/signals/#django.db.models.signals.post_save)

  Sent before or after a model’s [`save()`](https://docs.djangoproject.com/en/2.1/ref/models/instances/#django.db.models.Model.save) method is called.

- [`django.db.models.signals.pre_delete`](https://docs.djangoproject.com/en/2.1/ref/signals/#django.db.models.signals.pre_delete) & [`django.db.models.signals.post_delete`](https://docs.djangoproject.com/en/2.1/ref/signals/#django.db.models.signals.post_delete)

  Sent before or after a model’s [`delete()`](https://docs.djangoproject.com/en/2.1/ref/models/instances/#django.db.models.Model.delete) method or queryset’s [`delete()`](https://docs.djangoproject.com/en/2.1/ref/models/querysets/#django.db.models.query.QuerySet.delete) method is called.

- [`django.db.models.signals.m2m_changed`](https://docs.djangoproject.com/en/2.1/ref/signals/#django.db.models.signals.m2m_changed)

  Sent when a [`ManyToManyField`](https://docs.djangoproject.com/en/2.1/ref/models/fields/#django.db.models.ManyToManyField) on a model is changed.

- [`django.core.signals.request_started`](https://docs.djangoproject.com/en/2.1/ref/signals/#django.core.signals.request_started) & [`django.core.signals.request_finished`](https://docs.djangoproject.com/en/2.1/ref/signals/#django.core.signals.request_finished)

  Sent when Django starts or finishes an HTTP request.

See the [built-in signal documentation](https://docs.djangoproject.com/en/2.1/ref/signals/) for a complete list, and a complete explanation of each signal.

## Listen to Signals

To receive a signal, register a *receiver* function using the [`Signal.connect()`](https://docs.djangoproject.com/en/2.1/topics/signals/#django.dispatch.Signal.connect) method. The receiver function is called when the signal is sent:

```python
# 函数原型
Signal.connect(receiver, sender=None, weak=True, dispatch_uid=None)
"""
参数说明：
- receiver: 信号发生的回调函数
  See [Receiver functions](https://docs.djangoproject.com/en/2.1/topics/signals/#receiver-functions)

- sender: 指定一个信号的发生者
  See [Connecting to signals sent by specific senders](https://docs.djangoproject.com/en/2.1/topics/signals/#connecting-to-specific-signals)
  
- weak: 暂时没看懂，反正默认是 True 就对了

- dispatch_uid: 在可能发生重复信号的情况下设置接受器的唯一标识
"""
```

