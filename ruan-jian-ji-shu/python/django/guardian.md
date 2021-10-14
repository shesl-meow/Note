# guardian

> 项目地址：[https://github.com/django-guardian/django-guardian](https://github.com/django-guardian/django-guardian)
>
> 官方文档：[https://django-guardian.readthedocs.io/en/stable/](https://django-guardian.readthedocs.io/en/stable/)
>
> 中文介绍：[https://www.jianshu.com/p/404fd39d5efc](https://www.jianshu.com/p/404fd39d5efc)

## django-guardian

`django-guardian` 是一个对象权限的框架。

对象权限是一种**对象颗粒度上的权限机制**，它允许**为每个具体对象授权**。

`Django` 其实包含了 object permission 的框架，但没有具体实现，object permission 的实现需要借助第三方 app[ django-guardian](https://link.jianshu.com/?t=https%3A%2F%2Fgithub.com%2Flukaszb%2Fdjango-guardian)**，**我们在开发中用调用 `django guradian` 封装好的方法即可。

### Tutorial

1.  安装：

    ```bash
    $ pip install django-guardian
    ```
2.  配置：

    在 `INSTALLED_APPS` 中添加一个该模块：

    ```python
    INSTALLED_APPS = (
        ...
        'guardian',
    )
    ```

    在 `settings.py` 中新添加一个数据 `AUTENTICATION_BACKENDS`：

    ```python
    AUTHENTICATION_BACKENDS = (
        'django.contrib.auth.backends.ModelBackend', # default
        'guardian.backends.ObjectPermissionBackend',
    )
    ```

    然后生成 `guardian` 的数据表：

    ```bash
    $ python manage.py migrate
    ```
3.  给对象赋权：

    ```python
    >>> from django.contrib.auth.models import User, Group
    >>> jack = User.objects.create_user('jack', 'jack@example.com', 'topsecretagentjack')
    >>> admins = Group.objects.create(name='admins')
    >>> jack.has_perm('change_group', admins)
    False
    >>>
    >>> # 关键
    >>> from guardian.models import UserObjectPermission 
    >>> UserObjectPermission.objects.assign_perm('change_group', jack, obj=admins)
    <UserObjectPermission: admins | jack | change_group>
    >>>
    >>>
    >>> jack.has_perm('change_group', admins)
    True
    ```
4.  `admin-site` 界面中：

    ```python
    from django.contrib import admin
    from myapp.models import Author
    from guardian.admin import GuardedModelAdmin

    # Old way:
    #class AuthorAdmin(admin.ModelAdmin):
    #    pass

    # With object permissions support
    class AuthorAdmin(GuardedModelAdmin):
        pass

    admin.site.register(Author, AuthorAdmin)
    ```
