#!/bin/bash

gnr_summary () {
	# Parameter:
	#	p1: indicate title level.(eg: `\t\t*`)
	#	p2: indicate folder/file name.
	name=`basename $2`
	if [ -f $2 ]; then
		name="${name%.*}"
		echo -e "$1 [${name}]($2)" >> SUMMARY.md
	elif [ -d $2 ]; then
		echo "Find in directory: $2"
		echo -e "$1 [${name}]($2/README.md)" >> SUMMARY.md
		# Ignore all foldername begin with `.` or folder-self.
		# And query all files end with `.md` except `README.md`
		find $2 -maxdepth 1 -type d -not -name ".*" \
			-and -type d -not -name "`basename $2`" \
		 	-or -type f -name "*.md" \
		 	-and -type f -not -name "*README.md" \
		 	| xargs -n1 basename | sort -n | while read recur;
		do
			gnr_summary "\t$1" $2/$recur;
		done
	else
		echo "Illegal Parameter."
		exit 1
	fi
}

rm SUMMARY.md && touch SUMMARY.md
find . -maxdepth 1 -type d -not -name "." \
	-and -not -name ".git" \
	-and -not -name "node_modules" \
	-and -not -name "_book" | sort -n | while read recur;
do
	gnr_summary "*" $recur;
done
