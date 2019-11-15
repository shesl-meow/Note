#!/bin/bash

if [[ $1 = '--help' ]] || [[ $1 = '-h' ]]; then
	echo -e "This is a bash script used to escape\n  double curly braces for gitbook using:\n" \
		"  - Example1: '{{' ==> '{% raw %}{{{% endraw %}'\n" \
		"  - Example2: '{%' ==> '{% raw %}{%{% endraw %}'\n"
	echo -e "Parameter:\n" \
		"  p1: filename or foldername.\n"
	exit 0
fi

case "$OSTYPE" in
	darwin*) SED="gsed" ;;
	*) SED="sed" ;;
esac

escape_file () {
	# Parameter:
	#	p1: the escape target filename
	$SED 's/{{/__AA__/g; s/}}/__BB__/g; s/{%/__AX__/g; s/%}/__BX__/g' $1 > tmp;
	$SED 's/__AA__/{% raw %}{{{% endraw %}/g; s/__BB__/{% raw %}}}{% endraw %}/g;
		s/__AX__/{% raw %}{%{% endraw %}/g; s/__BX__/{% raw %}%}{% endraw %}/g' tmp > $1
	rm tmp;
	echo "Escape all pattern on file[$1]"
}

if [ -f $1 ]; then
	escape_file $1;
elif [ -d $1 ]; then
	find "$1" -type f -not -name "*EscapeCurlyBraces.sh" \
		-and -not -path "*/.git*" \
		-and -not -path "*/node_modules*" \
		-and -not -path "*/_book*" | while read f;
	do
		escape_file $f;
	done
else
	echo "Illegal parameter"
	exit 1
fi
