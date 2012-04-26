package com.peterdwarf.dwarf;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.util.Vector;

import com.peterdwarf.Global;
import com.peterdwarf.elf.SectionFinder;

public class Dwarf {
	public MappedByteBuffer byteBuffer;
	public MappedByteBuffer debug_abbrevBuffer;
	public MappedByteBuffer debug_str;
	public Vector<DwarfHeader> headers = new Vector<DwarfHeader>();
	public Vector<CompileUnit> compileUnits = new Vector<CompileUnit>();
	private File file;

	public File getFile() {
		return file;
	}

	public boolean init(File file) {
		this.file = file;
		headers.clear();
		compileUnits.clear();

		try {
			debug_str = SectionFinder.findSection(file, ".debug_str");
			System.out.println(".debug_str:");
			DwarfLib.printMappedByteBuffer(debug_str);
			System.out.println();

			debug_abbrevBuffer = SectionFinder.findSection(file, ".debug_abbrev");
			System.out.println(".debug_abbrev:");
			DwarfLib.printMappedByteBuffer(debug_abbrevBuffer);
			System.out.println();

			byteBuffer = SectionFinder.findSection(file, ".debug_info");
			System.out.println(".debug_info:");
			DwarfLib.printMappedByteBuffer(byteBuffer);
			parseDebugInfo(byteBuffer);

			byteBuffer = SectionFinder.findSection(file, ".debug_line");
			while (((ByteBuffer) byteBuffer).hasRemaining()) {
				parseHeader(byteBuffer);
			}
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	public void parseDebugInfo(ByteBuffer b) {
		int baseOffset = 0;
		int fuck;
		while (b.hasRemaining()) {
			CompileUnit cu = new CompileUnit();
			fuck = b.position();
			cu.length = b.getInt();
			cu.version = b.getShort();
			cu.abbrev_offset = b.getInt();
			cu.addr_size = b.get();
			compileUnits.add(cu);

			debug_abbrevBuffer.position(cu.abbrev_offset);
			byte byte1 = debug_abbrevBuffer.get();
			byte byte2 = debug_abbrevBuffer.get();
			byte byte3 = debug_abbrevBuffer.get();
			//			debug_abbrevBuffer.position(cu.abbrev_offset + 3);
			System.out.println("baseOffset=" + baseOffset);
			while (b.position() < cu.length + baseOffset) {
				Tag tag = new Tag();
				//				System.out.println("PPPPPP = " + Integer.toHexString(b.position()));

				System.out.println("<" + Integer.toHexString(b.position()) + "> " + Definition.getTagName(byte2) + " = " + byte1 + ",," + byte2 + ",," + byte3);
				int abbrevNo = b.get();
				tag.abbrevNo = abbrevNo;
				System.out.println("abbrevNo=" + abbrevNo + ", offset=" + debug_abbrevBuffer.position());
				while (true) {
					int atTag = debug_abbrevBuffer.get();
					int atValue = debug_abbrevBuffer.get();
					tag.atTag = atTag;
					tag.atValue = atValue;

					if (atTag != 0) {
						System.out.printf("<%x>\tAT: %5x %-20s %5d %10s", b.position(), atTag, Definition.getATname(atTag), atValue, Definition.getFormName(atValue));
					}
					if (atTag == 0) {
						if (debug_abbrevBuffer.hasRemaining()) {
							byte1 = debug_abbrevBuffer.get();
						}
						if (debug_abbrevBuffer.hasRemaining()) {
							byte2 = debug_abbrevBuffer.get();
						}
						if (debug_abbrevBuffer.hasRemaining()) {
							byte3 = debug_abbrevBuffer.get();
						}
						//System.out.println(Integer.toHexString(b.position()) + "-" + baseOffset + "=" + (b.position() - baseOffset));
						break;
					} else if (atValue == Definition.DW_FORM_string) {
						//						long stringOffset = DwarfLib.getUleb128(b);
						//						String s = DwarfLib.getString(debug_str, (int) stringOffset);
						//						System.out.print("\t" + stringOffset + "=" + s);
						//						int stringOffset = b.getInt();
						byte temp;
						System.out.print("\t");
						while ((temp = b.get()) != 0) {
							System.out.print((char) temp);
						}
						//						System.out.print(Integer.toHexString(stringOffset));
					} else if (atValue == Definition.DW_FORM_addr) {
						if (cu.addr_size == 4) {
							int address = b.getInt();
							System.out.print("\t0x" + Integer.toHexString(address));
						} else {
							System.out.println("not support address size");
							System.exit(1);
						}
					} else if (atValue == Definition.DW_FORM_strp) {
						int stringOffset = b.getInt();
						String s = DwarfLib.getString(debug_str, stringOffset);
						System.out.print("\t(offset : 0x" + Integer.toHexString(stringOffset) + ") " + s);
					} else if (atValue == Definition.DW_FORM_data1) {
						byte data = b.get();
						System.out.print("\t0x" + Integer.toHexString(data));
					} else if (atValue == Definition.DW_FORM_data2) {
						short data = b.getShort();
						System.out.print("\t0x" + Integer.toHexString(data));
					} else if (atValue == Definition.DW_FORM_data4) {
						int data = b.getInt();
						System.out.print("\t0x" + Integer.toHexString(data));
					} else if (atValue == Definition.DW_FORM_data8) {
						long data = b.getLong();
						System.out.print("\t0x" + Long.toHexString(data));
					} else if (atValue == Definition.DW_FORM_ref1) {
						byte data = b.get();
						System.out.print("\t0x" + Integer.toHexString(data));
					} else if (atValue == Definition.DW_FORM_ref2) {
						short data = b.getShort();
						System.out.print("\t0x" + Integer.toHexString(data));
					} else if (atValue == Definition.DW_FORM_ref4) {
						int data = b.getInt();
						int orip = b.position();
						System.out.println("\tf=" + fuck + "," + cu.abbrev_offset);
						b.position(fuck + data);
						System.out.print("\tdata=" + Integer.toHexString(data) + "\t0x" + Integer.toHexString(b.get()));
						b.position(orip);
					} else if (atValue == Definition.DW_FORM_ref8) {
						long data = b.getLong();
						System.out.print("\t0x" + Long.toHexString(data));
					} else if (atValue == Definition.DW_FORM_block) {
						long size = DwarfLib.getUleb128(b);
						System.out.print("\t" + size + " : ");
						for (int z = 0; z < size; z++) {
							System.out.print(Integer.toHexString(b.get()) + " ");
						}
						System.out.println();
					} else if (atValue == Definition.DW_FORM_block1) {
						int size = b.get();
						System.out.print("\t" + size + " : ");
						for (int z = 0; z < size; z++) {
							System.out.print(Integer.toHexString(b.get()) + " ");
						}
						System.out.print(Integer.toHexString(b.get()) + " ");

					} else if (atValue == Definition.DW_FORM_block2) {
						short size = b.getShort();
						System.out.print("\t" + size + " : ");
						for (int z = 0; z < size; z++) {
							System.out.print(Integer.toHexString(b.get()) + " ");
						}
						System.out.println();
					} else if (atValue == Definition.DW_FORM_block4) {
						int size = b.getInt();
					} else if (atValue == Definition.DW_FORM_ref_udata) {
						long data = DwarfLib.getUleb128(b);
					} else if (atValue == Definition.DW_FORM_flag) {
						byte flag = b.get();
						System.out.print("\t0x" + Integer.toHexString(flag));
					} else {
						System.out.println("unsupport DW_FORM_? = " + atValue);
						System.exit(1);
					}

					System.out.println();

					//					System.out.println("                  -----------" + Integer.toHexString(b.position()));
				}
				//				System.out.println("                  >>>>>>>>>>>" + Integer.toHexString(b.position()));
			}
			b.get();
			System.out.println();
			System.out.println("======================================" + b.position());
			System.out.println();
			baseOffset += b.position();
			System.out.println("end");
		}
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
		while (b.hasRemaining() && b.position() < prologue_end) {
			DwarfHeader_filename f = new DwarfHeader_filename();
			String fname = DwarfLib.getString(b);
			long u1 = DwarfLib.getUleb128(b);
			long u2 = DwarfLib.getUleb128(b);
			long u3 = DwarfLib.getUleb128(b);
			f.filename = fname;
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
