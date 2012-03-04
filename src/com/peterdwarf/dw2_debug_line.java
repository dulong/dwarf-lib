package com.peterdwarf;

import java.nio.ByteBuffer;

public class dw2_debug_line {
	long total_length;
	int version;
	long header_length;
	int minimum_instruction_length;
	boolean default_is_stmt;
	byte line_base;
	int line_range;
	int opcode_base;
	final byte[] standard_opcode_lengths = new byte[9];

	public void parseHeader(ByteBuffer b) {
		total_length = (long) b.getInt() & 0xFFFFFFFFL;
		version = b.getShort() & 0xFFFF;
		header_length = (long) b.getInt() & 0xFFFFFFFFL;
		minimum_instruction_length = b.get() & 0xFF;
		default_is_stmt = b.get() != 0;
		line_base = b.get();
		line_range = b.get() & 0xFF;
		opcode_base = b.get() & 0xFF;
		b.get(standard_opcode_lengths);
	}

	public String toString() {
		java.lang.StringBuffer str = new java.lang.StringBuffer(super.toString());
		str.append(" [ total_length: ").append(total_length);
		str.append("; version: ").append(version);
		str.append("; prologue_length: ").append(header_length);
		str.append("; minimum_instruction_length: ").append(minimum_instruction_length);
		str.append("; default_is_stmt: ").append(default_is_stmt);
		str.append("; line_base: ").append(line_base);
		str.append("; line_range: ").append(line_range);
		str.append("; opcode_base: ").append(opcode_base);
		str.append("; standard_opcode_lengths: { ");
		str.append(standard_opcode_lengths[0]).append(", ");
		str.append(standard_opcode_lengths[1]).append(", ");
		str.append(standard_opcode_lengths[2]).append(", ");
		str.append(standard_opcode_lengths[3]).append(", ");
		str.append(standard_opcode_lengths[4]).append(", ");
		str.append(standard_opcode_lengths[5]).append(", ");
		str.append(standard_opcode_lengths[6]).append(", ");
		str.append(standard_opcode_lengths[7]).append(", ");
		str.append(standard_opcode_lengths[8]).append(" } ]");
		return str.toString();
	}
}