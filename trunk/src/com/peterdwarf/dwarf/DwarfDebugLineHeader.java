package com.peterdwarf.dwarf;

import java.util.Vector;

public class DwarfDebugLineHeader {
	public long offset;
	public long total_length;
	public int version;
	public long prologue_length;
	public int minimum_instruction_length;
	public int max_ops_per_insn;
	public boolean default_is_stmt;
	public byte line_base;
	public int line_range;
	public int opcode_base;
	public final byte[] standard_opcode_lengths = new byte[8+1];
	public Vector<String> dirnames = new Vector<String>();
	public Vector<DwarfHeaderFilename> filenames = new Vector<DwarfHeaderFilename>();
	public Vector<DwarfLine> lines = new Vector<DwarfLine>();

	public String toString() {
		System.out.printf("Offset:                      0x%x\n", offset);
		System.out.printf("Length:                      %d\n", total_length);
		System.out.printf("DWARF Version:               %d\n", version);
		System.out.printf("Prologue Length:             %d\n", prologue_length);
		System.out.printf("Minimum Instruction Length:  %d\n", minimum_instruction_length);
		System.out.printf("Initial value of 'is_stmt':  %d\n", default_is_stmt ? 1 : 0);
		System.out.printf("Line Base:                   %d\n", line_base);
		System.out.printf("Line Range:                  %d\n", line_range);
		System.out.printf("Opcode Base:                 %d\n", opcode_base);
		return "";
	}

}
