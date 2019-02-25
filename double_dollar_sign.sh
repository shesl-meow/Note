#!/bin/bash

if [ $# -lt 1 ]; then
	echo "Please specify the filename and targetname."
	echo "Or specify the foldername"
	exit 1
fi

# replace all `$balabala$` to `$$balabala$$`
if [ -d "$1" ]; then
	find $1 -type f -name "*.md" | while read f; do
		echo "Replace on file $f";
		sed "s/\([^\$]\|^\)\\\$\([^\$]\+\)\\\$\([^\$]\|$\)/\1\$\$\2\$\$\3/g" "$f" > tmp
		mv tmp "$f"
	done
elif [ -f "$1" ]; then
	sed "s/\([^\$]\|^\)\\\$\([^\$]\+\)\\\$\([^\$]\|$\)/\1\$\$\2\$\$\3/g" "$1" > tmp
	if [ $# -eq 1 ]; then
		mv tmp "$1"
	else
		mv tmp "$2"
	fi
else
	echo "Parameter $1 is illegal."
	exit 2
fi
