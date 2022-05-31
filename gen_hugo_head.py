import re
import os
import sys
import datetime

name_2_date_index = {}

def gen_name_2_date():
    output = open("name_2_date", "w")
    curr_path = os.path.abspath("./")
    for dirpath, dnames, fnames in os.walk(curr_path):
        for fname in fnames:
            filename = dirpath + "/" + fname
            filedate = os.popen(f"git log --follow --format=%ad --date iso-strict \"{filename}\" | tail -1").read().strip()
            index = "/".join(filename.split('/')[-2:])
            output.write(f"{index}\n{filedate}\n")
    output.close()


def load_name_2_date():
    global name_2_date_index
    input = open("name_2_date", "r")
    name = None
    for line in input:
        if not name:
            name = line.strip().split("/")
            if len(name) != 2:
                name = None
            continue
        if not name[1] in name_2_date_index:
            name_2_date_index[name[1]] = []
        name_2_date_index[name[1]].append([name[0], line.strip()])
        name = None
    input.close()


def parse_file(filename):
    global name_2_date_index
    if filename.endswith("_index.md") or filename.endswith("README.md"):
        print(f"skip file: {filename}") 
        return
    filename = os.path.abspath(filename)
    rf = open(filename, "r")
    input = rf.read()
    rf.close()
    if input.startswith("---"):
        print(f"skip file: {filename}")
        return

    print(f"start parse: {filename}")
    filepath = filename.split("/")
    title = filepath[-1]
    body = input
    tags = []
    filedate = datetime.datetime.now().astimezone().replace(microsecond=0).isoformat()

    z = re.match(r"((.|\n)*\n)?# (.*)\n((.|\n)*)", input)
    if z is not None:
        title = z[3]
        body = (z[1] or "") + z[4]
        tags = filepath[(filepath.index('content') + 2):-1] if ('content' in filepath) else filepath[:-1]
        tags.append(title)

    if filepath[-1] in name_2_date_index:
        lst = name_2_date_index[filepath[-1]]
        filedate = lst[0][1]
        for item in lst:
            if item[0] == filepath[-2]:
                filedate = item[1]
                break
    
    output = f"""\
---
title: "{title}"
date: {filedate}
tags: ["{'", "'.join(tags)}"]
categories: ["{'", "'.join(tags[:-1])}"]
---

{body}
"""
    wf = open(filename, "w")
    wf.write(output)
    wf.close()
    print(f"parsed file: {filename}")


def iterate_parse_file(dirpath):
    for dirpath, dnames, fnames in os.walk(dirpath):
        for fname in fnames:
            if fname.endswith(".md"):
                filename = dirpath + "/" + fname
                parse_file(filename)


if __name__ == "__main__":
    load_name_2_date()
    iterate_parse_file(sys.argv[1])
