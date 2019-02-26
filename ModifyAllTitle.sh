#!/bin/bash

# increase or decrease all title of a markdown file.

if [ $# -le 1 ]; then
	echo "Insufficient parameter amount. Please specify two."
	echo "	Par1: increase[i] or decrease[d] the title size."
	echo "	Par2: markdown filename or foldername"
	exit 1;
fi

execute () {
	if [[ "$1" = "i" ]]; then
		sed "s/^\([#]\+ \)/#\1/g" $2 > tmp && mv tmp $2
		echo "FILE[$2] => Increase all header by one."
	elif [[ "$1" = "d" ]]; then
		sed "s/^#\([#]\+ \)/\1/g" $2 > tmp && mv tmp $2
		echo "FILE[$2] => Decrease all header by one except the max-one(#)."
	else
		echo "Illegal parameter 1."
		exit 2;
	fi
}

if [ -d $2 ]; then
	find $2 -type f -name "*.md" | while read f; do
		execute $1 $f
	done
elif [ -f $2 ]; then
	execute $1 $2
else
	"Illegal parameter 2."
	exit 2;
fi
