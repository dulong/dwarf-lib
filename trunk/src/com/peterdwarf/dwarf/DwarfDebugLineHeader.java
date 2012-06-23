package com.peterdwarf.dwarf;

import java.util.Vector;

public class DwarfDebugLineHeader {
	public long total_length;
	public int version;
	public long prologue_length;
	public int minimum_instruction_length;
	public int max_ops_per_insn;
	public boolean default_is_stmt;
	public byte line_base;
	public int line_range;
	public int opcode_base;
	public final byte[] standard_opcode_lengths = new byte[12];
	public Vector<String> dirnames = new Vector<String>();
	public Vector<DwarfHeaderFilename> filenames = new Vector<DwarfHeaderFilename>();
	public Vector<DwarfLine> lines = new Vector<DwarfLine>();

}
