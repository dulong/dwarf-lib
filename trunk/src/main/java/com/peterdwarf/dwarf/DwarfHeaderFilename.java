package com.peterdwarf.dwarf;

import java.io.File;

public class DwarfHeaderFilename implements Comparable<DwarfHeaderFilename> {
	public int entryNo;
	public File file;
	public long dir;
	public long time;
	public long len;

	@Override
	public int compareTo(DwarfHeaderFilename o) {
		return file.getName().compareToIgnoreCase(o.file.getName());
	}
}
