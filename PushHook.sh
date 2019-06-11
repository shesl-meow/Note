#!/bin/sh

# TODO: change directory to the shell script dir
cd `cd $(dirname "$0"); pwd -P;`
# TODO: reset all change back
git checkout HEAD .
# TODO: pull the newest version.
git pull

chmod +x *.sh
./GnrSummary.sh
./CheckReadme.sh .
./EscapeCurlyBraces.sh .

# TODO: This file occur a crash that i can't fix
rm ./安全技术/理论/XMAN3夏令营/day8.md
rm ./学校课程/信息安全数学基础/HOMEWORK/4.1.md

gitbook install
gitbook build
