#!/bin/bash

find /usr/local/bin | while read a; do
	java -Xmx1024m -jar peter-dwarf.jar $a
done
