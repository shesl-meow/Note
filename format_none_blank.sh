#!/bin/bash

if [ $# -lt 2 ]; then
	echo "Please specify the filename and targetname."
	exit 1
fi

# Format: There should be blank between 
#		`none-ascii char` vs `ascii char`

# None blank on both side.
sed "s/\([^\x00-\x7F]\)\([\x21-\x7F]\|[\x21-\x7F][\x00-\x7F]*[\x21-\x7F]\)\([^\x00-\x7F]\)/\1 \2 \3/g" $1 > $2
# None blank on left side.
sed "s/\([^\x00-\x7F]\)\([\x21-\x7F]\|[\x21-\x7F][\x00-\x7F]*[\x21-\x7F]\)\($\| \)/\1 \2\3/g" $2 > tmp
mv tmp $2
# None blank on right side
sed "s/\( \|^\)\([\x21-\x7F]\|[\x21-\x7F][\x00-\x7F]*[\x21-\x7F]\)\([^\x00-\x7F]\)/\1\2 \3/g" $2 > tmp
mv tmp $2