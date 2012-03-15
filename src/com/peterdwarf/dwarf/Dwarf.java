package com.peterdwarf.dwarf;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.util.LinkedList;
import java.util.Vector;

import com.peterdwarf.elf.SectionFinder;

public class Dwarf {
	public MappedByteBuffer byteBuffer;
	public Vector<DwarfHeader> headers = new Vector<DwarfHeader>();

	public boolean init(File file, String sectionName) {
		try {
			byteBuffer = SectionFinder.findSection(file, sectionName);
			while (((ByteBuffer) byteBuffer).hasRemaining()) {
				parseHeader(byteBuffer);
			}
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	public void parseHeader(ByteBuffer b) {
		final int begin = b.position();

		DwarfHeader header = new DwarfHeader();
		header.total_length = (long) b.getInt() & 0xFFFFFFFFL;
		header.version = b.getShort() & 0xFFFF;
		header.header_length = (long) b.getInt() & 0xFFFFFFFFL;
		header.minimum_instruction_length = b.get() & 0xFF;
		header.default_is_stmt = b.get() != 0;
		header.line_base = b.get();
		header.line_range = b.get() & 0xFF;
		header.opcode_base = b.get() & 0xFF;
		b.get(header.standard_opcode_lengths);

		final int end = (int) (begin + header.total_length + 4);
		final int prologue_end = (int) (begin + header.header_length + 9);

		// Skip the directories; they end with a single null byte.
		String s;
		while ((s = DwarfLib.getString(b)).length() > 0) {
			header.dirnames.add(s);
		}

		// Read the file names.
		LinkedList<String> fnames = new LinkedList<String>();
		while (b.hasRemaining() && b.position() < prologue_end) {
			DwarfHeader_filename f = new DwarfHeader_filename();
			String fname = DwarfLib.getString(b);

			fnames.add(fname);

			long u1 = DwarfLib.getUleb128(b);
			long u2 = DwarfLib.getUleb128(b);
			long u3 = DwarfLib.getUleb128(b);

			f.dir = u1;
			f.time = u2;
			f.len = u3;
			header.filenames.add(f);

		}
		System.out.println("--" + b.position());

		b.get();

		long address = 0;
		long file_num = 1;
		int line_num = 1;
		long column_num = 0;
		boolean is_stmt = header.default_is_stmt;
		boolean basic_block = false;
		boolean end_sequence = false;

		while (b.hasRemaining()) {
			int opcode = b.get() & 0xff;

			if (opcode == 0) {
				long size = DwarfLib.getUleb128(b);
				int code = b.get();
				if (code == 1) {
					System.out.println("Extended opcode:" + code + " End of sequence");
					break;
				} else if (code == 2) {
					address = b.getInt();
					System.out.println("Extended opcode:" + code + "\t,address=" + Long.toHexString(address));
				} else if (code == 4) {
					int discriminator = b.get();
					System.out.println("Extended opcode:" + code + ",\tset discriminator=" + discriminator);
				} else {
					System.out.println("error, wrong size in address,\topcode=" + opcode + ", code=" + code);
					// System.exit(1);
				}
			} else if (opcode > header.opcode_base) {
				opcode -= header.opcode_base;
				int advance_address = ((opcode / header.line_range) * header.minimum_instruction_length);
				address += advance_address;
				int advance_line = ((opcode % header.line_range) + header.line_base);
				line_num += advance_line;
				System.out.println("Special  opcode:" + opcode + ",\tadvance address by " + advance_address + " to " + Long.toHexString(address) + ", line by " + advance_line
						+ " to " + line_num);
			} else {
				if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_copy) {
					is_stmt = false;
					continue;
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_advance_pc) {
					long advance_address = DwarfLib.getUleb128(b);
					address += header.minimum_instruction_length * advance_address;
					System.out.println("advance pc, address=" + Long.toHexString(address));
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_advance_line) {
					long advance_line = DwarfLib.getUleb128(b);
					line_num += advance_line;
					System.out.println("advence line, line=" + line_num);
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_set_file) {
					long fileno = DwarfLib.getUleb128(b);
					file_num = fileno;
					System.out.println("set file, file=" + line_num);
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_set_column) {
					long colno = DwarfLib.getUleb128(b);
					column_num = colno;
					System.out.println("set column, column=" + column_num);
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_negate_stmt) {
					is_stmt = !is_stmt;
					System.out.println("!stmt, stmt=" + is_stmt);
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_set_basic_block) {
					basic_block = true;
					System.out.println("set basic_block, basic_block=" + basic_block);
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_fixed_advance_pc) {
					int advance_address = b.getInt();
					address += advance_address;
					System.out.println("fixed advance pc, address=" + Long.toHexString(address));
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_const_add_pc) {
					int advance_address = (header.minimum_instruction_length * ((255 - header.opcode_base) / header.line_range));
					address += advance_address;
					System.out.println("add pc, address=" + Long.toHexString(address));
				} else {
					System.out.println("error, what? opcode=" + opcode);
				}
			}
		}
		DwarfLib.printMappedByteBuffer(b);
		b.position(end);
		System.out.println("++" + b.position());

		headers.add(header);
	}
}
