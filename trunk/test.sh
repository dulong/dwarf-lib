#!/bin/bash

find /usr/local/bin /bin /usr/bin | while read a; do
	echo "parsing "$a
	java -Xmx1024m -jar peter-dwarf.jar $a
	r=$?
	if [[ $r > 0 && $r < 100 ]]; then
		echo "peter-dwarf failed on "$a" ,return value="$r;
		exit;
	fi
done

