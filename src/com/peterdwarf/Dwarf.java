package com.peterdwarf;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.util.LinkedList;

import com.peterdwarf.elf.SectionFinder;

public class Dwarf {
	public MappedByteBuffer byteBuffer;
	public long total_length;
	public int version;
	public long header_length;
	public int minimum_instruction_length;
	public boolean default_is_stmt;
	public byte line_base;
	public int line_range;
	public int opcode_base;
	public final byte[] standard_opcode_lengths = new byte[12];

	public boolean init(File file, String sectionName) {
		try {
			byteBuffer = SectionFinder.findSection(file, sectionName);
			System.out.println(byteBuffer.position() + ",," + byteBuffer.limit());
			parseHeader(byteBuffer);
			printHeader();

			System.out.println("-----------------");

			parseHeader(byteBuffer);
			printHeader();
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	public void parseHeader(ByteBuffer b) {
		final int begin = b.position();

		total_length = (long) b.getInt() & 0xFFFFFFFFL;
		version = b.getShort() & 0xFFFF;
		header_length = (long) b.getInt() & 0xFFFFFFFFL;
		minimum_instruction_length = b.get() & 0xFF;
		default_is_stmt = b.get() != 0;
		line_base = b.get();
		line_range = b.get() & 0xFF;
		opcode_base = b.get() & 0xFF;
		b.get(standard_opcode_lengths);

		final int end = (int) (begin + total_length + 4);
		final int prologue_end = (int) (begin + header_length + 9);

		DwarfLib.printMappedByteBuffer(b);

		// Skip the directories; they end with a single null byte.
		String s;
		while ((s = DwarfLib.getString(b)).length() > 0) {
			System.out.println("Directory: " + s);
		}

		// Read the file names.
		LinkedList<String> fnames = new LinkedList<String>();
		while (b.hasRemaining() && b.position() < prologue_end) {
			String fname = DwarfLib.getString(b);
			System.out.println("File name: " + fname);

			fnames.add(fname);

			long u1 = DwarfLib.getUleb128(b);
			long u2 = DwarfLib.getUleb128(b);
			long u3 = DwarfLib.getUleb128(b);
			System.out.println("   dir: " + new Long(u1) + ", time: " + new Long(u2) + ", len: " + new Long(u3));
		}
		b.position(end);
	}

	public void printHeader() {
		System.out.println("total_length: " + total_length);
		System.out.println("version: " + version);
		System.out.println("prologue_length: " + header_length);
		System.out.println("minimum_instruction_length: " + minimum_instruction_length);
		System.out.println("default_is_stmt: " + default_is_stmt);
		System.out.println("line_base: " + line_base);
		System.out.println("line_range: " + line_range);
		System.out.println("opcode_base: " + opcode_base);
		System.out.print("standard_opcode_lengths: { ");
		System.out.print(standard_opcode_lengths[0]);
		System.out.print(standard_opcode_lengths[1]);
		System.out.print(standard_opcode_lengths[2]);
		System.out.print(standard_opcode_lengths[3]);
		System.out.print(standard_opcode_lengths[4]);
		System.out.print(standard_opcode_lengths[5]);
		System.out.print(standard_opcode_lengths[6]);
		System.out.print(standard_opcode_lengths[7]);
		System.out.print(standard_opcode_lengths[8]);
		System.out.print(standard_opcode_lengths[9]);
		System.out.print(standard_opcode_lengths[10]);
		System.out.print(standard_opcode_lengths[11]);
		System.out.println(" }");
	}
}
