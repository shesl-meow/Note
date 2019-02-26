#!/bin/sh

# TODO: change directory to the shell script dir
cd `$(dirname "$0")`
# TODO: reset all change back
git checkout HEAD .
# TODO: pull the newest version.
git pull

chmod +x $SELFPATH/*.sh
./CheckReadme.sh .
./EscapeCurlyBraces.sh .

gitbook install
gitbook build
