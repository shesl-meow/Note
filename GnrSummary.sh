#!/bin/bash

gnr_summary () {
	# Parameter:
	#	p1: indicate title level.(eg: `\t\t*`)
	#	p2: indicate folder/file name.
	name=`basename $2`
	if [ -f $2 ]; then
		name="${name%.*}"
		echo -e "$1 [${name}]($2)\n" >> SUMMARY.md
	elif [ -d $2 ]; then
		echo "Find in directory: $2"
		echo -e "$1 [${name}]($2/README.md)\n" >> SUMMARY.md
		# Ignore all foldername begin with `.` or folder-self.
		# And query all files end with `.md` except `README.md`
		find $2 -maxdepth 1 -type d -not -name ".*" -and -type d -not -name "`basename $2`" \
		 	-or -type f -name "*.md" -and -type f -not -name "*README.md" | sort -n | while read recur;
		do
			gnr_summary "\t$1" $recur;
		done
	else
		echo "Illegal Parameter."
		exit 1
	fi
}

echo "" > SUMMARY.md
find . -maxdepth 1 -type d -not -name ".*" \
 	-or -type f -name "*.md" | sort -n | while read recur;
do
	gnr_summary "*" $recur;
done
