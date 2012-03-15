package com.peterdwarf.dwarf;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.util.LinkedList;
import java.util.Vector;

import com.peterdwarf.Global;
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

		DwarfHeader dwarfHeader = new DwarfHeader();
		dwarfHeader.total_length = (long) b.getInt() & 0xFFFFFFFFL;
		dwarfHeader.version = b.getShort() & 0xFFFF;
		dwarfHeader.header_length = (long) b.getInt() & 0xFFFFFFFFL;
		dwarfHeader.minimum_instruction_length = b.get() & 0xFF;
		dwarfHeader.default_is_stmt = b.get() != 0;
		dwarfHeader.line_base = b.get();
		dwarfHeader.line_range = b.get() & 0xFF;
		dwarfHeader.opcode_base = b.get() & 0xFF;
		b.get(dwarfHeader.standard_opcode_lengths);

		final int end = (int) (begin + dwarfHeader.total_length + 4);
		final int prologue_end = (int) (begin + dwarfHeader.header_length + 9);

		// Skip the directories; they end with a single null byte.
		String s;
		while ((s = DwarfLib.getString(b)).length() > 0) {
			dwarfHeader.dirnames.add(s);
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
			dwarfHeader.filenames.add(f);
		}
		if (Global.debug) {
			System.out.println("--" + b.position());
		}

		b.get();

		long address = 0;
		long file_num = 1;
		int line_num = 1;
		long column_num = 0;
		boolean is_stmt = dwarfHeader.default_is_stmt;
		boolean basic_block = false;
		boolean end_sequence = false;

		while (b.hasRemaining()) {
			int opcode = b.get() & 0xff;

			if (opcode == 0) {
				long size = DwarfLib.getUleb128(b);
				int code = b.get();
				if (code == 1) {
					if (Global.debug) {
						System.out.println("Extended opcode:" + code + " End of sequence");
					}
					break;
				} else if (code == 2) {
					address = b.getInt();
					if (Global.debug) {
						System.out.println("Extended opcode:" + code + "\t,address=" + Long.toHexString(address));
					}
				} else if (code == 4) {
					int discriminator = b.get();
					if (Global.debug) {
						System.out.println("Extended opcode:" + code + ",\tset discriminator=" + discriminator);
					}
				} else {
					if (Global.debug) {
						System.out.println("error, wrong size in address,\topcode=" + opcode + ", code=" + code);
					}
					// System.exit(1);
				}
			} else if (opcode > dwarfHeader.opcode_base) {
				opcode -= dwarfHeader.opcode_base;
				int advance_address = ((opcode / dwarfHeader.line_range) * dwarfHeader.minimum_instruction_length);
				address += advance_address;
				int advance_line = ((opcode % dwarfHeader.line_range) + dwarfHeader.line_base);
				line_num += advance_line;
				if (Global.debug) {
					System.out.println("Special  opcode:" + opcode + ",\tadvance address by " + advance_address + " to " + Long.toHexString(address) + ", line by " + advance_line
							+ " to " + line_num);
				}
			} else {
				if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_copy) {
					is_stmt = false;
					continue;
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_advance_pc) {
					long advance_address = DwarfLib.getUleb128(b);
					address += dwarfHeader.minimum_instruction_length * advance_address;
					if (Global.debug) {
						System.out.println("advance pc, address=" + Long.toHexString(address));
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_advance_line) {
					long advance_line = DwarfLib.getUleb128(b);
					line_num += advance_line;
					if (Global.debug) {
						System.out.println("advence line, line=" + line_num);
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_set_file) {
					long fileno = DwarfLib.getUleb128(b);
					file_num = fileno;
					if (Global.debug) {
						System.out.println("set file, file=" + line_num);
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_set_column) {
					long colno = DwarfLib.getUleb128(b);
					column_num = colno;
					if (Global.debug) {
						System.out.println("set column, column=" + column_num);
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_negate_stmt) {
					is_stmt = !is_stmt;
					if (Global.debug) {
						System.out.println("!stmt, stmt=" + is_stmt);
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_set_basic_block) {
					basic_block = true;
					if (Global.debug) {
						System.out.println("set basic_block, basic_block=" + basic_block);
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_fixed_advance_pc) {
					int advance_address = b.getInt();
					address += advance_address;
					if (Global.debug) {
						System.out.println("fixed advance pc, address=" + Long.toHexString(address));
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_const_add_pc) {
					int advance_address = (dwarfHeader.minimum_instruction_length * ((255 - dwarfHeader.opcode_base) / dwarfHeader.line_range));
					address += advance_address;
					if (Global.debug) {
						System.out.println("add pc, address=" + Long.toHexString(address));
					}
				} else {
					if (Global.debug) {
						System.out.println("error, what? opcode=" + opcode);
					}
				}
			}
			DwarfLine dwarfLine = new DwarfLine();
			dwarfLine.address = address;
			dwarfLine.file_num = file_num;
			dwarfLine.line_num = line_num;
			dwarfLine.column_num = column_num;
			dwarfLine.is_stmt = is_stmt;
			dwarfLine.basic_block = basic_block;
			dwarfHeader.lines.add(dwarfLine);
		}
		b.position(end);

		headers.add(dwarfHeader);
	}
}
