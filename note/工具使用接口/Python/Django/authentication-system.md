---
title: "Authentication System"
date: 2019-02-25T15:16:23+08:00
tags: [""]
categories: ["工具使用接口", "Python"]
---

> 学习网址：
>
> - https://www.jianshu.com/p/17d4c2182ef7
> - http://www.liujiangblog.com/course/django/178
> - https://docs.djangoproject.com/en/1.11/topics/auth/
> - https://juejin.im/post/5987f51e51882549475a916d
>
> 官方的参考文档：https://docs.djangoproject.com/zh-hans/2.1/ref/contrib/auth/


## Using the Django authentication system

### User Object

User 是 Django 提供的一个对象，默认对象的主要属性是：`username`，`password`，`email`，`first_name`，`last_name`。参阅[完整的文档](https://www.rddoc.com/doc/Django/1.10.5/zh/ref/contrib/auth/#django.contrib.auth.models.User)：

- 关于 User 模块的操作（比如：使用 `create_user()` 函数创建对象）

  ```python
  from django.contrib.auth import get_user_model
  from django.contribute.auth.models import User
  # 导入 User 这个模块有以上两种方法
  
  User = get_user_model()
  # 该行获得 User 这个模块，与导入的 User 指向同一个模块
  
  Rookie_User = User.objects.create_user('Rookie', 'email@e.com', 'passwd')
  Rookie_User = User.objects.create(username="Rookie001")
  # 创建一个名为 ‘Rookie001’ 的 User 对象，返回该对象
  
  User.objects.get(username="Rookie001")
  # 查找一个满足特定条件的 User 类的对象
  
  Rookie_User.last_name = 'Smith' # 动态设置对象的其他成员
  
  user.save() # 将对象保存到数据库
  ```

- 创建超级用户：使用 `createsuperuser` 命令：

  ```bash
  $ python manage.py createsuperuser --username=john --email=email@e.com
  ```

- 更改密码：以下两种方法：

  ```bash
  $ python manage.py changepassword <username>
  ```

  ```python
  from django.contrib.auth.models import User
  Rookie_User = User.objects.get(username='john')
  Rookie_User.set_password('new_passwd')
  Rookie_User.save()
  ```

- 验证用户，`authenticate` 函数如果后端有效则返回 User 对象，若无效或引发 `PermissionDenies` 则返回 `None`，例如：

  ```python
  from django.contrib.auth import authenticate
  user = authenticate(username='john', password='secret')
  if user is not None:
      # A backend authenticated the credentials
  else:
      # No backend authenticated the credentials
  ```

### Permission and Authorization

默认情况下，使用 `python manage.py migrate` 命令时，Django 会给每个已经存在的 model 添加默认的权限。假设有个叫 foo 的应用中有个叫 bar 的模块，可以使用以下的命令查看权限：

```python
user.has_perm('foo.add_bar') # 查看用户 user 是否有添加 bar 这个模块对象的权限
user.has_perm('foo.change_bar') # 查看用户 user 是否有更改 bar 这个模块对象的权限
user.has_perm('foo.delete_bar') # 查看用户 user 是否有删除 bar 这个模块对象的权限
```

### Group Object

Django提供了一个 `django.contrib.auth.models.Group` 模型，该model可用于给用户分组，实现批量管理。用户和组属于多对多的关系。用法实例如下：

```python
from django.contrib.auth.models import Group

Rookie_Group = Group.objects.create(name="Rookie")
# 创建一个名为 ‘Rookie’ 的 Group 对象，返回该对象

Rookie_User.groups.add(Rookie_Group)
# 将 Rookie_User 这个用户加入 Rookie_Group 这个用户组

Rookie_Group.user_set.all() # 获取该用户组内的全部用户构成的一个列表
```

Group 模块中有成员：Permissions 模块的一个对象，用于管理用户的权限，其使用方法如下：

```python
group.permissions.set([permission_list]) # 用于设置用户组的权限
group.permissions.add(permission1, permission2, ...) # 给用户组添加权限
group.permissions.remove(permission1, permission2, ...) # 移除用户组中的某些权限
group.permissions.clear() # 清空该用户组的所有权限
```

`Permission` 也可以通过以下的方式进行自定义，下面给出一个用法实例：

```python
from myapp.models import BlogPost
from django.contrib.auth,models import Permission
from django.contrib.contenttypes.models import ContentType

content_type = ContentType.objects.get_for_models(BlogPost)
permisstion = Permission.objects.create(
    codename='can_publish',
    name='Can Publish Posts',
    content_type=content_type,
)
```

你可以通过 User 模型的 `user_permissions` 属性或者 Group 模型的 `permissions` 属性为用户添加该权限。

权限检查后，会被缓存在用户对象中，只有当对象再次被加载，权限才会更新。

## Authentication in Web requests

Django 在请求对象中使用 `sessions` 和中间关联请求进行用户登录认证。

每一次请求中都包含一个 `request.user` 属性，表示当前用户。如果该用户未登陆，该属性的值是一个 `AnonymousUser` 实例（匿名用户），如果已经登录，该属性就是一个User模型的实例。

可以使用 `is_authenticated` 进行判断，若是匿名用户，则返回 `False`。

### How to log a user in?

使用认证系统提供的 `login()` 方法登录用户。它接收一个 `HttpRequest` 参数和一个 `User` 对象参数。该方法会把用户的 ID 保存在 Django 的 session 中。下面是一个认证和登陆的例子：

```python
from django.contrib.auth import authenticate, login

def my_view(request):
    username = request.POST['username']
    password = request.POST['password']
    user = authenticate(username=username, password=password)
    if user is not None:
        login(request, user)
        # 跳转到成功页面
        ...
    else:
        # 返回一个非法登录的错误页面
        ...
```

### How to log a user out？

同样可以使用 Django 系统提供的函数：

```python
from django.contrib.auth import logout

def logout_view(request):
    logout(request)
    # 跳转到成功的页面
```

注意，被logout的用户如何没登录，不会抛出错误。 一旦logout，当前请求中的session数据都会被清空。

### Limiting access to logged-in users

主要是以下几种方法：

1. 原始方法，将用户重定向到登录页面：

   ```python
   from django.conf import settings
   from django.shortcuts import redirect
   
   def my_view(request):
   if not request.user.is_authenticated:
   	return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))
   # ...
   ```

2. 使用装饰器，被装饰的 views 只有用户登录后才可以访问。原型为：

   ```python
   login_required(redirect_field_name='next', login_url=None)[source]
   ```

   使用方法大致如下：

   ```python
   from django.contrib.auth.decorators import login_required
   
   @login_required
   def my_view(request):
       ...
   ```

   `login_required` 装饰器会判断当前用户是否已经登录：如果已经登录，执行正常的视图；如果没有登录，则会重定向到 `settings.LOGIN_URL` 指向的 `urlpatern`，并将当前访问的绝对路径作为 `url` 的 `next` 参数。

   如果你想使用自定义的参数，可以修改 `login_required()` 的 `redirect_field_name` 参数；如果你想修改重定向到的登录 URL，可以修改 `login_url` 参数。

3. 使用  `LoginRquired` Mixin。通过继承 `LoginRequiredMixin` 类的方式限制用户。在多重继承时，该类必须是继承关系最左边的父类。一个实例如下：

   ```python
   from django.contrib.auth.mixins import LoginRequiredMixin
   
   class MyView(LoginRequiredMixin, View):
       login_url = '/login/'
       redirect_field_name = 'redirect_to'
   ```

4. 进行测试，根据测试结果确定动作。比如根据邮箱地址判断用户权限：

   ```python
   from django.shortcuts import redirect
   
   def my_view(request):
       if not request.user.email.endswith('@example.com'):
           return redirect('/login/?next=%s' % request.path)
       # ...
   ```

5. 使用权限需求修饰器，Django 内置的装饰器 `permission_required` 会根据用户权限，决定视图的访问权限。权限的格式为：`<app label>.<permission codename>`，同 `login_required`，该装饰器还有一个可选的 `login_url` 参数，无权限用户会跳转到该 url。一个使用的例子如下：

   ```python
   from django.contrib.auth.decorators import permission_required
   
   @permission_required('polls.can_vote', login_url='/loginpage/')
   def my_view(request):
       ...
   ```

## Extending the existing `User` model

Django 用户认证系统提供的内置的 User 对象仅包含以下一些主要的属性：

- username, password, email, first_name, last_name

对于一些网站来说，用户可能还包含有昵称、头像、个性签名等等其它属性，因此仅仅使用 Django 内置的 User 模型是不够。好在 Django 用户系统遵循可拓展的设计原则，我们可以方便地拓展 User 模型。

我们可以通过以下两种方法扩展我们的 `User` 模型。

### use a OneToOneField

这适用于只希望存储与 `User` 相关联的用户模型，通常命名为`Profile`，`models` 定义如下：

```python
from django.contrib.auth.models import User

class Employee(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    department = models.CharField(max_length=100)
```

可以通过以下的方式获取相关的信息：

```python
>>> u = User.objects.get(username="a_username")
>>> a_department= u.employee.department
```

为了在 Admin 的界面管理我们的模型，需要在 `admin.py` 文件中添加以下模板：

```python
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User

from my_user_profile_app.models import Employee

# 为 Employee 定义一个内联的管理员描述
# Employee 和 User 表就会看起来像一张表一样
class EmployeeInline(admin.StackedInline):
    model = Employee
    can_delete = False
    verbose_name_plural = 'employee'

class UserAdmin(BaseUserAdmin):
    inlines = (EmployeeInline,)

admin.site.unregister(User)
admin.site.register(User, UserAdmin)
```

为了将我们定义的新 `User` 提交到 Django，令其可以识别，需要在 `settings` 中添加以下代码：

```python
AUTH_USER_MODEL = 'myapp.MyUser'
```

并且将 `User` 所在的应用添加到 `INSTALLED_APPS` 中。

### Using a custom user model

Django 强烈推荐我们使用 `AbstractUser` 来派生我们自己定义的 User 对象。事实上，系统定义的 `User` 对象实际上也是继承自 `AbstracUser` 的抽象基类，仅仅是继承，没有做任何拓展，源码如下：

```python
from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    """
    Users within the Django authentication system are represented by this
    model.

    Username, password and email are required. Other fields are optional.
    """
    class Meta(AbstractUser.Meta):
        swappable = 'AUTH_USER_MODEL'
```

所以，如果我们通过继承 `AbstractUser`，将获得 `User` 的全部特性，而且还可以根据自己的需求进行拓展。

*PostScript*：不要忘记像前一种方法一样在 `setting.py` 中添加 `AUTH_USER_MODEL` 与 `INSTALLED_APPS` 设置。



一个实例如下：

1. 在 `users/models.py` 中写下如下代码：

   ```python
   from django.db import models
   from django.contrib.auth.models import AbstractUser
   
   class User(AbstractUser):
   	nickname = models.CharField(max_length=50, blank=True)
   
       class Meta(AbstractUser.Meta):
           pass
   ```

2. 在 `settings.py` 中添加以下代码：

   ```python
   AUTH_USER_MODEL = 'users.User'
   
   LANGUAGE_CODE = 'zh-hans'
   TIME_ZONE = 'Asia/Shanghai'
   ```

3. 运行以下的两行代码：

   ```bash
   $ python manage.py makemigrations
   
   $ python manage.py migrate
   ```


