package com.peterdwarf.dwarf;

import java.util.Vector;

public class DwarfHeader {
	public long total_length;
	public int version;
	public long header_length;
	public int minimum_instruction_length;
	public boolean default_is_stmt;
	public byte line_base;
	public int line_range;
	public int opcode_base;
	public final byte[] standard_opcode_lengths = new byte[12];
	public Vector<String> dirnames = new Vector<String>();
	public Vector<DwarfHeader_filename> filenames = new Vector<DwarfHeader_filename>();
	public Vector<DwarfLine> lines = new Vector<DwarfLine>();
}
