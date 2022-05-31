---
title: "vimtutor"
date: 2022-05-31T12:50:56+08:00
tags: [""]
categories: ["工具使用接口", "Linux-Command"]
---

> 学习地址：`vimtutor`
>
> `vimtutor` 是一个由 `vim` 官方提供的教程，在 `bash` 界面直接运行 `vimtutor` 即可查看。


## Lesson 1

1. 移动光标：

   ```
            ^
            k
      < h       l >
            j
            v
   ```

   *HINT*：

   1. h 的键位于左边，每次按下就会向左移动。
   2. l 的键位于右边，每次按下就会向右移动。
   3. j 键看起来很象一支尖端方向朝下的箭头。

2. `vim` 的退出：
   1. 输入 `:q!<Enter>` 会退出编辑器并且丢弃进入编辑器之后的所有改动。
   2. 按下 `:wq<Enter>`保存并退出 `vim`

3. 删除光标所在位置的字符：可以按下 `x` 键来删除光标所在位置的字符。

4. 插入文本：可以按下 `i` 键来插入字符。

5. 添加文本：可以按下 `A` 键来添加文本（光标会定位到行末）

## Lesson 2

1. 删除类命令：

   1. 删除单词：按下 `dw` 可以从光标处删除到一个单词的末尾
   2. 删除到行末：输入 `d$` 从当前光标删除到行末。

2. **命令和对象**：许多改变文本的命令都由一个操作符和一个动作构成。

   比如：

   - 以上的删除操作符 `d` 的命令格式如下：`d motion`。

   其中：

   - `d` ：删除操作符。
   - `motion`：删除符的操作对象

   `motion` 的简短动作列表：

   - `w` - 从当前光标当前位置直到下一个单词起始处，不包括它的第一个字符。
   - `e` - 从当前光标当前位置直到单词末尾，包括最后一个字符。（与 `w` 区别为不会删除空格）
   - `$` - 从当前光标当前位置直到当前行末。

3. 使用计数指定动作：在动作前输入数字 `n`，会使该动作重复 `n` 次。

   示例：

   - 输入 `2w` 使光标向前移动两个单词。
   - 输入 `3e` 使光标向前移动到第三个单词的末尾。
   - 输入 `0` 使得光标移动到行首。

4. 使用操作符时，在对象前输入数字 `n` 可以重复 `n` 次。

   格式：`operator [number] motion`

   比如：`d2w` 可以删除光标所在位置的下两个单词删除。

5. 删除整行：连续输入两次 d ，即 `dd` 可以删除光标所在位置的整行。

6. 撤销类命令：
   1. 撤销最后执行的命令：输入 `u` 来撤销最后执行的命令。
   2. 撤销对整行的修改：输入 `U` 来撤销对整行的修改。
   3. 重做撤销的命令： `CTRL+R`

## Lesson 3

1. Put command: Type  `p`  to put previously deleted text after the cursor. 
2. Replace command: Type  `rx`  to replace the character at the cursor with  x.

3. The change operator: To change until the end of a word, type  `ce`.

   This operator format: `c [motion] number `, where the motions are the  same.

## Lesson 4

1. Cursor location and file status:

   1. Type `CTRL-G` to show your location in the file and the file status.

      *NOTICE*: You may see the cursor position in the lower right corner of the screen. This happens when the 'ruler' option is set (see  :help 'ruler'  )

   2. Type  `G`  to move to a bottom of the file.

   3. Type  `gg`  to move you to the start of the file.

   4. Type the number of a line, and then `G`. This will goto a specific line.

2. The search command: 

   1. Type  `/`  followed by a phrase to search for the phrase.
   2. To search for a phrase in the backward direction, use  `?`  instead of  `/` .
   3. To search for the same phrase again, simply type  `n`.
   4. findTo search for the same phrase in the opposite direction, type  `N`.
   5. To go back to where you came from press  `CTRL-O`, `CTRL-I` goes forward.

3. Matching parentheses search: Type `%` to find a matching `)`, `]`, or `}`.

4. The substitute command:
   1. Type `:s/old/new` to substitute 'new' for the first 'old' in a line
   2. Type `:s/old/new/g` to substitute new for all 'old's on a line type
   3. Type `:#,#s/old/new/g` where `#,#` are the line numbers of the range of lines where the substitution is to be done.
   4. Type `:%s/old/new/g` to change every occurrence in the whole file.
   5. Type `:%s/old/new/gc` to find every occurrence in the whole file, with a prompt whether to substitute or not.

## Lesson 5

1. Execute an external command: Type `:!` followed by an external command to execute that command.

   - *NOTICE*: All `:` commands must be finished by hitting `<ENTER>`.

2. More on writing files: To save the changes made to the text, type `:w FILENAME` .

3. Selecting text to write: To save part of the file, type `v` motion `:w FILENAME`

4. Retrieving and merging files: To insert the contents of a file, type `:r FILENAME`

   - *PostScript*: You can also read the output of an external command. 

     For example, `:r !ls`  reads the output of the ls command and puts it below the cursor.

## Lesson 6

1. The open command: 
   1. Type `o` to open a line below the cursor and place you in Insert mode.
   2. To open up a line ABOVE the cursor, simply type a capital  `O`

2. The append command: Type `a` to insert text AFTER the cursor.
   - *NOTICE*: `a`, `i` and `A` all go to the same Insert mode, the only difference is where the characters are inserted.

3. Another way to replace: Type a capital `R` to replace more than one character.

4. Copy and paste text:
   1. Use `y` operator to copy text.
   2. Use `p` operator to paste it.
   3. *PS*: Move the cursor to the end of next line `j$`

5. Set option: Set an option so a search or substitute ignores case

   1. set the `ic` (ignore case) option by entering: `:set ic`

   2. set the 'hlsearch' (highlight search) and 'incsearch' (show partial matches) options: `:set hls is`

   3. to disable ignoring case by enter: `:set noic`
   4. to remove the highlighting of matches enter: `:nohlsearch`
   5.  If you want to ignore case for just one search command, use `\c` in the phrase:  `/ignore\c  <ENTER>`

## Lesson 7

1. Getting help: type one of these three command:

   - press the `<HELP>` key (if you have one)
   - press the `<F1>` key (if you have one)
   - type   `:help <ENTER>`

    You can find help on just about any subject, by giving an argument to the `:help command`

   - `:help w`
   - `:help c_CTRL-D`
   - `:help insert-index`
   - `:help user-manual`

2. Create a startup script: editing the following file in Unix `:e ~/.vimrc`

   - for more information, type `:help vimrc-intro`

3. Completion: command line completion with `CTRL-D` and `<TAB>`

   - *NOTICE*: make sure vim is not in compatible mode: `:set nocp`


