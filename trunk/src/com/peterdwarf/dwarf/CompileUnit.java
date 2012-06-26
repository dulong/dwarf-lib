package com.peterdwarf.dwarf;

import java.util.Vector;

public class CompileUnit {
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
}
