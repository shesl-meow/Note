---
title: "Awk"
date: 2019-02-25T15:16:23+08:00
tags: [""]
categories: ["工具使用接口", "Linux-Command"]
---


## Brief Introduction

> 学习网址：https://www.tecmint.com/use-linux-awk-command-to-filter-text-string-in-files/

The general syntax of `awk` is:

```bash
$ awk 'script' filename
# 'script' format => '/pattern/ action'
```

Where `'script'` is a set of commands that are understood by `awk` and execute on file, filename.

It works by reading a given line in the file, makes a copy of the line and then executes the script on the line. This is repeated on all the lines in the file.

The `'script'` is in the form `'/pattern/ action'` where **pattern** is a regular expression and the **action** is what awk will do when it finds the given pattern in a line.

## The GNU Awk User's Guide

> 学习网址：https://www.gnu.org/software/gawk/manual/gawk.html#Getting-Started

`awk` is an *interpreted* language which means awk utility reads your program and then processes your data according to the instructions in your program. `awk` programs are *data driven* while most other languages are *procedural*.

When you run `awk`, you specify an `awk` *program* that tells `awk` what to do. The program consists of a series of *rules*. Each rule specifies one pattern to search for and one action to perform upon finding the pattern.

An `awk` program looks like this:

```awk
pattern {action}
pattern {action}
```

## 1. Run `awk` programs

If the program is short, it is easiest to include it in the command that runs `awk`:

```bash
$ awk 'program' input-file1 input-file2
```

otehrwise:

```bash
$ awk -f program-file input-file1 input-file2
```

### 1.1 Running

Running without input files

```bash
$ awk 'program'
```

`awk` applies the program to the *standard input*, which usually means whatever you type on the keyboard. This continues until you indicate end-of-file by typing `Ctrl-d`. (On non-POSIX operating systems, the end-of-file character may be different.)



Executable `awk` program

```awk
#!/bin/awk -f

BEGIN {print "Don't Panic!"}
```

### 1.2 Example programs

This is a typical task that `awk` programs do.

```bash
$ ls -l | awk '$6 == "Nov"{ sum += $5 }
>	END {print sum}'
```

1. The `awk` utility reads the input files one line at a time. For each line, `awk` tries the patterns of each rule. If several patterns match, then several actions execute in the order in which they appear in the `awk` program. If no patterns match, then no actions run.

2. This command prints the total number of bytes in all the files in the current directory that were last modified in November (of any year). 

3. When `awk` statements within one rule are short, you might want to put more than one of them on a line. This is accomplished by separating the statements with a semicolon (‘;’). This also applies to the rules themselves. Thus, the program shown at the start of this section could also be written this way:

   ```bash
   $ ls -l | awk '$6 == "Nov"{ sum += $5 }; END {print sum}'
   ```



Print every line that has at least one field: 

```bash
$ awk 'NF>0' data
```

1. default action is `{print $0}`
2. `NF` stand for the fields amout in one line



Count line in a file:

```bash
$ awk 'END {print NR}' data
```

## 2. Running awk and gawk

## 3. Regex Expression

## 4. Reading Input Files

The input is read in units called *records*, and is processed by the rules of your program one record at a time. By default, each record is one line. Each record is automatically split into chunks called *fields*. This makes it more convenient for programs to work on the parts of a record.

### Record Split

Record splitting with standard `awk`.

Records are separated by a character called the *record separator*. By default, the record separator is the newline character. This is why records are, by default, single lines. To use a different character for the record separator, simply assign that character to the predefined variable `RS`. For example:

```bash
$ awk 'BEGIN {RS='u'}; {print $0}' data
```

Another way to change to record separator is on the command line, using the variable-assignment feature:

```bash
$ awk '{print $0}' RS="u" data
```


