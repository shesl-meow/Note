#!/bin/sh

chmod +x *.sh

# TODO: reset all change back
git checkout HEAD .

# TODO: pull the newest version.
git pull

./CheckReadme.sh .
./EscapeCurlyBraces.sh .

gitbook build
