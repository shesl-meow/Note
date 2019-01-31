#!/bin/bash

# split header a file into
# 	multiple files with its header as filename

if [ $# -lt 1 ]; then
	echo "Please specify filename."
	echo "	parameter1: filename."
	exit 1
elif [ ! -f $1 ]; then
	echo "The parameter1 is not a file."
	exit 1
fi

dn=`dirname $1`
bn=`basename $1`
fn=${bn%.*}
en=${bn##*.}

if [[ ! $en = "md" ]]; then
	echo "dirname: $dn; filename: $fn; extension-name: $en;"
	echo ""
	echo "please specify a file with .md subffix."
	exit 1
fi

python_code="
with open('$1', 'r') as f: raw=f.readlines()
f=open('$dn/$fn/README.md', 'w')
print('defaut filename README.md')
fnum=0
for l in raw:
	if l.startswith('# '):
		f.close()
		fnum += 1
		fname=l[2:].strip().replace(' ', '') + '.md'
		if not fname.startswith('1'):
			fname=str(fnum) + '.' + fname
		f=open('$dn/$fn/' + fname, 'w')
		print('Wirte into ' + f.name)
	f.write(l)
f.close()
"

if [ -d $dn/$fn ]; then
	echo "directory $dn/$fn already exisit, delete it first."
	rm -rf $dn/$fn
fi
mkdir $dn/$fn

if command -v python >/dev/null 2>&1; then
	python -c "$python_code"
elif command -v python3 >/dev/null 2>&1; then
	python3 -c "$python_code"
elif command -v python2 >/dev/null 2>&1; then
	python2 -c "python_code"
else
	echo "Python utity is required for this script."
	exit 2
fi
