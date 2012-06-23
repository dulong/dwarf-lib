package com.peterdwarf.dwarf;

import java.util.Vector;

public class CompileUnit {
	public int offset;
	public int length;
	public int version;
	public int abbrev_offset;
	public int addr_size;
	public Vector<DebugInfoEntry> debugInfoEntry = new Vector<DebugInfoEntry>();
}
