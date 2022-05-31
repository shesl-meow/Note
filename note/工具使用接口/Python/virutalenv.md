---
title: "`pipenv` & `virtualenv`"
date: 2019-03-01T12:25:20+08:00
tags: [""]
categories: ["工具使用接口", "Python"]
---

> 学习地址：https://docs.python-guide.org/dev/virtualenvs/


Make sure you have got `python` and `pip` install:

```bash
$ python --version

$ pip --version
```

## `pipenv`

1. Install `pipenv`:

   ```bash
   $ pip install --user pipenv
   ```

2. Install packages for your project:

   ```bash
   $ cd myproject
   
   $ pipenv install requests
   ```

3. Using installed packages:

   For script file as below (`main.py`):

   ```python
   import requests
   
   response = requests.get('https://httpbin.org/ip')
   
   print('Your IP is {0}'.format(response.json()['origin']))
   ```

   Then you can run this script using `pipenv run`:

   ```bash
   $ pipenv run python main.py
   ```

   It’s also possible to spawn a new shell that ensures all commands have access to your installed packages with 

   ```bash
   $ pipenv shell
   ```

## `virtualenv`

1. Install virutalenv via `pip`:

   ```bash
   $ pip install virtualenv
   ...
   
   $ virtualenv --version
   # Test your installation
   ```

2. `virtualenv venv` will create a folder in the current directory which will contain the Python executable files, and a copy of the `pip` library which you can use to install other packages:

   ```bash
   $ virtualenv <venv>
   # omitting the name will place the files in the current directory instead.
   ```

   You can also chose your own python interpreter:

   ```bash
   $ virtualenv -p /usr/bin/python2.7 <venv>
   ```

3. To begin using the virtual environment, it needs to be activated:

   ```bash
   $ source venv/bin/activate
   ```

4. If you are done working in the virtual environment for the moment, you can deactivate it:

   ```bash
   $ deactivate
   ```

## `virtualenvwrapper`

1. To install (make sure **virtualenv** is already installed):

   ```bash
   $ pip install virtualenvwrapper
   
   $ export WORKON_HOME=~/.python_envs
   
   $ source /usr/local/bin/virtualenvwrapper.sh
   ```

2. Create a virtual environment:

   ```bash
   $ workon <my_project>
   ```

3. Alternatively, you can make a project, which creates the virtual environment, and also a project directory inside `$WORKON_HOME`, which is `cd`-ed into when you `workon myproject`:

   ```bash
   $ mkproject <my_project>
   ```

4. Deactivating is still the same:

   ```bash
   $ deactivate
   ```

5. To delete the enviroment:

   ```bash
   $ rmvirtualenv <venv>
   ```

6. Other useful commands

   - `lsvirtualenv`: List all of the environments.
   - `cdvirtualenv`: Navigate into the directory of the currently activated virtual environment, so you can browse its `site-packages`, for example.
   - `cdsitepackages`: Like the above, but directly into `site-packages` directory.
   - `lssitepackages`: Shows contents of `site-packages` directory.
