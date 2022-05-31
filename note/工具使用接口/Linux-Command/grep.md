---
title: "grep"
date: 2019-02-25T15:16:23+08:00
tags: [""]
categories: ["工具使用接口", "Linux-Command"]
---




## Example

> https://stackoverflow.com/questions/16956810/how-do-i-find-all-files-containing-specific-text-on-linux

Find all files containing specific text:

```bash
$ grep -rnw '/path/to/somewhere/' -e 'pattern'
```

- `-r` or `-R` is recursive,
- `-n` is line number, and
- `-w` stands for match the whole word.
- `-l` (lower-case L) can be added to just give the file name of matching files.

Along with these, `--exclude`, `--include`, `--exclude-dir` flags could be used for efficient searching:

- This will only search through those files which have .c or .h extensions:

  ```bash
  $ grep --include=\*.{c,h} -rnw '/path/to/somewhere/' -e "pattern"
  ```

- This will exclude searching all the files ending with .o extension:

  ```bash
  $ grep --exclude=*.o -rnw '/path/to/somewhere/' -e "pattern"
  ```

- For directories it's possible to exclude a particular directory(ies) through `--exclude-dir` parameter. For example, this will exclude the dirs dir1/, dir2/ and all of them matching *.dst/:

  ```bash
  $ grep --exclude-dir={dir1,dir2,*.dst} -rnw '/path/to/somewhere/' -e "pattern"
  ```


