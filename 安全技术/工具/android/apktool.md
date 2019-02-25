> 学习途径：
>
> - 官网教程：https://ibotpeaches.github.io/Apktool/

# `apktool`

## Basic

First lets take a lesson into apk files. Apks are nothing more than a zip file containing resources and assembled java code. If you were to simply unzip an apk like so, you would be left with files such as `classes.dex` and `resources.arsc`.

```bash
$ unzip testapp.apk -d unzip-folder
...

$ cd unzip-folder

$ ls
AndroidManifest.xml  META-INF  classes.dex  res  resources.arsc
```

Obviously, editing or viewing a compiled file is next to impossible. That is where Apktool comes into play:

```bash
$ apktool d testapp.apk
I: Using Apktool 2.3.4 on testapp.apk
...
```

## Decoding

The decode option on Apktool can be invoked either from `d` or `decode` like shown below.

```bash
$ apktool d foo.jar
# decodes foo.jar to foo.jar.out folder

$ apktool decode foo.jar
# decodes foo.jar to foo.jar.out folder

$ apktool d bar.apk
# decodes bar.apk to bar folder

$ apktool decode bar.apk
# decodes bar.apk to bar folder

$ apktool d bar.apk -o baz
# decodes bar.apk to baz folder
```

## Building

The build option can be invoked either from `b` or `build` like shown below

```bash
$ apktool b foo.jar.out
# builds foo.jar.out folder into foo.jar.out/dist/foo.jar file

$ apktool build foo.jar.out
# builds foo.jar.out folder into foo.jar.out/dist/foo.jar file

$ apktool b bar
# builds bar folder into bar/dist/bar.apk file

$ apktool b .
# builds current directory into ./dist

$ apktool b bar -o new_bar.apk
# builds bar folder into new_bar.apk

$ apktool b bar.apk
# WRONG: brut.androlib.AndrolibException: brut.directory.PathNotExist: apktool.yml
# Must use folder, not apk/jar file
```

## Frameworks

Frameworks can be installed either from `if` or `install-framework`, in addition two parameters

- `-p, --frame-path <dir>` - Store framework files into `<dir>`
- `-t, --tag <tag>` - Tag frameworks using `<tag>`

- `-t, --tag <tag>` - Tag frameworks using `<tag>`

Allow for a finer control over how the files are named and how they are stored.

```bash
$ apktool if framework-res.apk
I: Framework installed to: 1.apk 
# pkgId of framework-res.apk determines number (which is 0x01)

$ apktool if com.htc.resources.apk
I: Framework installed to: 2.apk 
# pkgId of com.htc.resources is 0x02

$ apktool if com.htc.resources.apk -t htc
I: Framework installed to: 2-htc.apk 
# pkgId-tag.apk

$ apktool if framework-res.apk -p foo/bar
I: Framework installed to: foo/bar/1.apk

$ apktool if framework-res.apk -t baz -p foo/bar
I: Framework installed to: foo/bar/1-baz.ap
```