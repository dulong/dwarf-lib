#!/bin/bash

find /root/download/linux-3.3.7/ /usr/local/bin /bin /usr/bin | while read a; do
	echo "parsing "$a
	java -Xmx1024m -jar peter-dwarf.jar $a $1
	r=$?
	if [[ $r -gt 0 && $r -lt 100 ]]; then
		echo "peter-dwarf failed on "$a" ,return value="$r;
		exit;
	fi
done

