# admin-site

> 官方文档：[https://docs.djangoproject.com/en/2.1/ref/contrib/admin/](https://docs.djangoproject.com/en/2.1/ref/contrib/admin/)

## Django admin site

### Overview

If you’re not using the default project template, here are the requirements:

1. Add `'django.contrib.admin'` and its dependencies -[`django.contrib.auth`](https://docs.djangoproject.com/en/2.1/topics/auth/#module-django.contrib.auth), [`django.contrib.contenttypes`](https://docs.djangoproject.com/en/2.1/ref/contrib/contenttypes/#module-django.contrib.contenttypes),[`django.contrib.messages`](https://docs.djangoproject.com/en/2.1/ref/contrib/messages/#module-django.contrib.messages), and [`django.contrib.sessions`](https://docs.djangoproject.com/en/2.1/topics/http/sessions/#module-django.contrib.sessions) - to your[`INSTALLED_APPS`](https://docs.djangoproject.com/en/2.1/ref/settings/#std:setting-INSTALLED_APPS) setting.
2. Configure a [`DjangoTemplates`](https://docs.djangoproject.com/en/2.1/topics/templates/#django.template.backends.django.DjangoTemplates) backend in your [`TEMPLATES`](https://docs.djangoproject.com/en/2.1/ref/settings/#std:setting-TEMPLATES) setting with`django.contrib.auth.context_processors.auth` and`django.contrib.messages.context_processors.messages` in the `'context_processors'` option of [`OPTIONS`](https://docs.djangoproject.com/en/2.1/ref/settings/#std:setting-TEMPLATES-OPTIONS).
3. If you’ve customized the [`MIDDLEWARE`](https://docs.djangoproject.com/en/2.1/ref/settings/#std:setting-MIDDLEWARE) setting,[`django.contrib.auth.middleware.AuthenticationMiddleware`](https://docs.djangoproject.com/en/2.1/ref/middleware/#django.contrib.auth.middleware.AuthenticationMiddleware)and [`django.contrib.messages.middleware.MessageMiddleware`](https://docs.djangoproject.com/en/2.1/ref/middleware/#django.contrib.messages.middleware.MessageMiddleware)must be included.
4. [Hook the admin’s URLs into your URLconf](https://docs.djangoproject.com/en/2.1/ref/contrib/admin/#hooking-adminsite-to-urlconf).

If you need to create a user to login with, use the [`createsuperuser`](https://docs.djangoproject.com/en/2.1/ref/django-admin/#django-admin-createsuperuser) command. By default, logging in to the admin requires that the user has the [`is_superuser`](https://docs.djangoproject.com/en/2.1/ref/contrib/auth/#django.contrib.auth.models.User.is_superuser) or [`is_staff`](https://docs.djangoproject.com/en/2.1/ref/contrib/auth/#django.contrib.auth.models.User.is_staff) attribute set to `True`.

所以，除超级用户外，设置一下属性即可允许一个普通用户登录 `admin` 后台管理界面：

```python
normal_user.is_staff = True
```

Finally, determine which of your application’s models should be editable in the admin interface. For each of those models, register them with the admin as described in [`ModelAdmin`](https://docs.djangoproject.com/en/2.1/ref/contrib/admin/#django.contrib.admin.ModelAdmin).（即需要通过 `ModelAdmin` 注册可以在 `admin-site` 中修改的表单）

Other topics：

* [Admin actions](https://docs.djangoproject.com/en/2.1/ref/contrib/admin/actions/)
* [The Django admin documentation generator](https://docs.djangoproject.com/en/2.1/ref/contrib/admin/admindocs/)
* [JavaScript customizations in the admin](https://docs.djangoproject.com/en/2.1/ref/contrib/admin/javascript/)

### `ModelAdmin`

#### Usage

The `ModelAdmin` class is the representation of a model in the admin interface. Usually, these are stored in a file named `admin.py` in your application. Let’s take a look at a very simple example of the `ModelAdmin`:

```python
from django.contrib import admin
from myproject.myapp.models import Author

class AuthorAdmin(admin.ModelAdmin):
    pass
admin.site.register(Author, AuthorAdmin)
```

当然你也可以不显示地声明一个 `ModelAdmin`，这时，Django 将会使用默认的借口做为函数的参数：

```python
from django.contrib import admin
from myproject.myapp.models import Author

admin.site.register(Author)
```

#### register decorator

There is also a decorator for registering your `ModelAdmin` classes:

```python
from django.contrib import admin
from .models import Author

@admin.register(Author)
class AuthorAdmin(admin.ModelAdmin):
    pass
```

It’s given one or more model classes to register with the `ModelAdmin`. If you’re using a custom [`AdminSite`](https://docs.djangoproject.com/en/2.1/ref/contrib/admin/#django.contrib.admin.AdminSite), pass it using the `site` keyword argument:

```python
from django.contrib import admin
from .models import Author, Editor, Reader
from myproject.admin_site import custom_admin_site

@admin.register(Author, Reader, Editor, site=custom_admin_site)
class PersonAdmin(admin.ModelAdmin):
    pass
```

#### Discovery of admin files

没看懂，算了。

#### `ModelAdmin` options

The `ModelAdmin` is very flexible. It has several options for dealing with customizing the interface. All options are defined on the `ModelAdmin` subclass:

1. `ModelAdmin.actions`：可以在 admin-site 页面的下拉列表中，定义自己的 `actions` 函数。详见：[AdminAction](https://docs.djangoproject.com/en/2.1/ref/contrib/admin/actions/)
2. `ModelAdmin.actions_on_top`、`ModelAdmin.actions_on_bottom`：控制下拉列表在 admin-site 页面中存在的位置。
3. `ModelAdmin.actions_selection_counter`：控制是否在动作下拉栏里面显示选择计数器。

（还有很多）

#### `ModelAdmin` methods

...

#### Adding custom validation to admin

### `InlineModelAdmin`

#### Usage

Important class:

* _class_ `InlineModelAdmin`
* _class_ `TabularInline`
* _class_ `StackedInline`

The admin interface has the ability to edit models on the same page as a parent model. These are called inlines.

Suppose you have these two models:

```python
from django.db import models

class Author(models.Model):
   name = models.CharField(max_length=100)

class Book(models.Model):
   author = models.ForeignKey(Author, on_delete=models.CASCADE)
   title = models.CharField(max_length=100)
```

You can edit the books authored by an author on the author page. You add inlines to a model by specifying them in a `ModelAdmin.inlines`:

```python
from django.contrib import admin

class BookInline(admin.TabularInline):
    model = Book

class AuthorAdmin(admin.ModelAdmin):
    inlines = [
        BookInline,
    ]
```

Django provides two subclasses of `InlineModelAdmin` and they are:

* [`TabularInline`](https://docs.djangoproject.com/en/2.1/ref/contrib/admin/#django.contrib.admin.TabularInline)
* [`StackedInline`](https://docs.djangoproject.com/en/2.1/ref/contrib/admin/#django.contrib.admin.StackedInline)

The difference between these two is merely the template used to render them.

#### `InlineModelAdmin` options

`InlineModelAdmin` shares many of the same features as `ModelAdmin`, and adds some of its own (the shared features are actually defined in the`BaseModelAdmin` superclass).
