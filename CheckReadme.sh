#!/bin/bash

if [[ $1 = "--help" ]] || [[ $1 = "-h" ]]; then
	echo -e "This is a bash script check if 'README.md' file exist.\n" \
		"Any subfolder of provided folder require a 'README.md' file\n"
	echo -e "Parameter:\n" \
		"  p1: folder name."
	exit 0
fi

check_readme () {
	# Parameter
	# 	p1: folder name.
	find $1 -type d -not -path "*/.git*" \
		-and -not -path "*/_book*" \
		-and -not -path "*/node_modules*" | while read f;
	do
		if [[ ! -e "$f/README.md" ]]; then
			echo "Folder[$f] doesn't have README.md file. Create it."
			echo "# `basename $f`" > "$f/README.md"
		fi
	done
}

if [[ -d $1 ]]; then
	check_readme $1
else
	echo "Illegal parameter."
	exit 1
fi
