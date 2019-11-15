#!/bin/bash

if [ $# -le 1 ]; then
	echo "Please specify the filename or foldername."
	exit 1
fi

case "$OSTYPE" in
	darwin*) SED="gsed" ;;
	*) SED="sed" ;;
esac

delete_all_url () {
	echo "delete all in file: $1"
	$SED 's/\[\([^]]*\)\]([^)]*)/\1/g' "$1" > tmp
	mv tmp "$1"
}

if [ -f $1 ]; then
	delete_all_url $1
elif [ -d $1 ]; then
	find $1 -name "*.md" | while read f;
	do
		delete_all_url "$f"
	done
fi
