# exe0 

## 概述

首先我们看看 lab1 与 lab2 的代码有什么不同：

1. 在 ucore_os_lab 这个项目中添加不同的 repo，用以回滚到最原始的版本：

   ```bash
   $ git remote -v
   origin	https://github.com/chyyuu/ucore_os_lab.git (fetch)
   origin	https://github.com/chyyuu/ucore_os_lab.git (push)
   
   $ git remote add upstream https://github.com/chyyuu/ucore_os_lab
   
   $ git remote -v
   origin	https://github.com/chyyuu/ucore_os_lab.git (fetch)
   origin	https://github.com/chyyuu/ucore_os_lab.git (push)
   upstream	https://github.com/chyyuu/ucore_os_lab (fetch)
   upstream	https://github.com/chyyuu/ucore_os_lab (push)
   ```

2. 拉取主仓中最新的代码，并且切换到远程的 master 分支：

   ```bash
   $ git pull upstream master
   From https://github.com/chyyuu/ucore_os_lab
    * branch            master     -> FETCH_HEAD
    * [new branch]      master     -> upstream/master
   Already up to date.
   
   $ git checkout upstream/master
   ```

3. 然后我们使用 `diff` 命令查看 lab1 与 lab2 的代码差异：

   ```bash
   $ diff -rq labcodes/lab1 labcodes/lab2
   ...
   ```

   这个命令有大量的回显，所以这两个子文件夹是不一样的。

## 解决方案

我需要满足这样一些条件的解决方案：

1. 显然我们并不想手动进行更改；
2. 我们并不想使用图形化工具；
3. 我们也并不想，逐个找我们更改了哪些文件，然后通过某种方式 “一键更改”，这种解决方案虽然比第一种简单一些，听起来仍然很愚蠢。

我们首先明白我们要做的是一件什么样的事情，我画了一个流程图：

```
                     +-------------+ 
        +------------| lab1:legacy |
        |            +------|------+
        |                   |
        |                   |                                           
 change1: fileA, fileB      |                                           
        |                   |                                           
        |            change2: fileC, fileD                              
        |                   |                                           
        |                   |                                           
        |                   |                                           
        v                   v                                           
  +-----------+       +-----------+                                     
  | lab2:HEAD |       | lab1:HEAD |                                     
  +-----|-----+       +-----|-----+                                     
        |                   |                                           
        |       merge       |                                           
        |<------------------+                                           
        |                                                               
        |                                                               
 change3: fileA, fileB, fileC, fileD                                    
        |                                                               
        v                                                               
 +-------------+                                                        
 | lab2:target |                                                        
 +-------------+                                                        
```

简单的说，我们要做的事情是通过 change1 与 change2 得到 change3。

如果这是分支开发，那事情就会很简单，直接使用 `git merge` 或者 `git stash push/apply` 即可。但是我们工作在两个不同的文件夹下，我们有以下的思路：

1. 通过 `git diff` 命令，将 chang2 导出；
2. 通过 sed 命令，将 lab1 替换为 lab2 导入到文件中；
3. 通过 `git apply` 命令将补丁文件 `apply` 到 `lab2:HEAD` 上。

## 实现

我们首先找到本仓库引入原始 `labcodes` 的 commit：`ed036f7b95e0a968ea2e14537b7eecfc20291ce7`：

1. 导出 change2：

   ```bash
   $ git diff ed036f7b95e0a968ea2e14537b7eecfc20291ce7 HEAD labcodes/lab1/ | sed 's/lab1/lab2/g' > lab2/exe0.patch
   ```

2. 进行 merge：

   ```bash
   $ git apply lab2/exe0.patch
   ```