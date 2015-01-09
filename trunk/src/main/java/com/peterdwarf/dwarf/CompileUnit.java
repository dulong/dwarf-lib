package com.peterdwarf.dwarf;

import java.util.Vector;

public class CompileUnit implements Comparable<CompileUnit> {
	public int offset;
	public int length;
	public int version;
	public int abbrev_offset;
	public int addr_size;
	public Vector<DebugInfoEntry> debugInfoEntry = new Vector<DebugInfoEntry>();

	public String DW_AT_producer;
	public int DW_AT_language;
	public String DW_AT_name;
	public String DW_AT_comp_dir;
	public long DW_AT_low_pc;
	public long DW_AT_high_pc;
	public String DW_AT_stmt_list;

	public String toString() {
		String str = "";
		str += "  Compilation Unit @ offset 0x" + Integer.toHexString(offset) + ":\n";
		str += "  	   Length:        0x" + Integer.toHexString(length) + " (32-bit)" + "\n";
		str += "  	   Version:       " + version + "\n";
		str += "  	   Abbrev Offset: " + abbrev_offset + "\n";
		str += "  	   Pointer Size:  " + addr_size + "\n";
		str += "  	   Low pc:  " + DW_AT_low_pc + "\n";
		str += "  	   High pc:  " + DW_AT_high_pc + "\n";
		return str;
	}

	@Override
	public int compareTo(CompileUnit a) {
		return DW_AT_name.compareTo(a.DW_AT_name);
	}
}
