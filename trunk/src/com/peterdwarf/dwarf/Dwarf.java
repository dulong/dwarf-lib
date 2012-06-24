package com.peterdwarf.dwarf;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.Vector;

import com.peterdwarf.Global;
import com.peterdwarf.elf.Elf32_Ehdr;
import com.peterdwarf.elf.Elf32_Shdr;
import com.peterdwarf.elf.Elf32_Sym;
import com.peterdwarf.elf.Elf_Common;
import com.peterdwarf.elf.SectionFinder;

public class Dwarf {
	public ByteBuffer byteBuffer;
	public ByteBuffer debug_abbrevBuffer;
	public ByteBuffer debug_str;
	public ByteBuffer symtab_str;
	public ByteBuffer strtab_str;
	public Vector<DwarfDebugLineHeader> headers = new Vector<DwarfDebugLineHeader>();
	public Vector<CompileUnit> compileUnits = new Vector<CompileUnit>();
	public Vector<Elf32_Sym> symbols = new Vector<Elf32_Sym>();
	private LinkedHashMap<Integer, LinkedHashMap<Integer, Abbrev>> abbrevList;
	public static File file;
	public static Elf32_Ehdr ehdr = new Elf32_Ehdr();

	public boolean init(File file) {
		Dwarf.file = file;

		try {
			ehdr.read(new RandomAccessFile(file, "r"));
		} catch (Exception e1) {
			e1.printStackTrace();
			System.exit(1);
		}

		compileUnits.clear();

		try {
			debug_str = SectionFinder.findSectionByte(file, ".debug_str");
			if (debug_str == null) {
				return false;
			}
			// System.out.println(".debug_str:");
			// DwarfLib.printMappedByteBuffer(debug_str);
			// System.out.println();

			strtab_str = SectionFinder.findSectionByte(file, ".strtab");
			// allStrings =
			// Charset.forName("ASCII").decode(strtab_str).toString().split("\0");

			symtab_str = SectionFinder.findSectionByte(file, ".symtab");
			// System.out.println(".symtab:");
			symbols = parseSymtab(symtab_str);
			// System.out.printf("Num:\t%-8s\t%-8s\t%-8s\t%-8s\t%-8s\t%-8s\t%-8s\n",
			// "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name");
			// int x = 0;
			// for (Elf32_Sym symbol : symbols) {
			// System.out.printf("%d:\t%08x\t%8d\t%s\t%s\t%s\t\t%s\t", x,
			// symbol.st_value, symbol.st_size,
			// Elf_Common.getSTTypeName(Elf_Common.ELF32_ST_TYPE(symbol.st_info)),
			// Elf_Common.getSTBindName(Elf_Common.ELF32_ST_BIND(symbol.st_info)),
			// Elf_Common.get_symbol_visibility(Elf_Common.ELF_ST_VISIBILITY(symbol.st_other)),
			// Elf_Common.get_symbol_index_type((byte) symbol.st_shndx));
			// System.out.printf("%s", DwarfLib.getString(strtab_str,
			// symbol.st_name));
			// System.out.println();
			// x++;
			// }
			// System.out.println();

			debug_abbrevBuffer = SectionFinder.findSectionByte(file, ".debug_abbrev");
			// System.out.println(".debug_abbrev:");
			abbrevList = parseDebugAbbrev(debug_abbrevBuffer);
			if (Global.debug) {
				for (Integer abbrevOffset : abbrevList.keySet()) {
					System.out.println("Abbrev offset=" + abbrevOffset);
					LinkedHashMap<Integer, Abbrev> abbrevHashtable = abbrevList.get(abbrevOffset);
					for (Integer abbrevNo : abbrevHashtable.keySet()) {
						Abbrev abbrev = abbrevHashtable.get(abbrevNo);
						System.out.printf("%d\t%s\t%s\n", abbrev.number, Definition.getTagName(abbrev.tag), abbrev.has_children ? "has children" : "no children");

						for (AbbrevEntry entry : abbrev.entries) {
							System.out.printf("\t%x\t%x\t%s\t%s\n", entry.at, entry.form, Definition.getATName(entry.at), Definition.getFormName(entry.form));
						}
					}
				}
			}
			if (Global.debug) {
				System.out.println();
			}

			byteBuffer = SectionFinder.findSectionByte(file, ".debug_info");
			Elf32_Shdr debugInfoSection = null;
			for (Elf32_Shdr s : SectionFinder.getAllSection(file)) {
				if (s.section_name.equals(".debug_info")) {
					debugInfoSection = s;
					break;
				}
			}
			if (debugInfoSection != null) {
				parseDebugInfo(debugInfoSection, byteBuffer);
			}

			byteBuffer = SectionFinder.findSectionByte(file, ".debug_line");
			while (((ByteBuffer) byteBuffer).hasRemaining()) {
				parseHeader(byteBuffer);
			}
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	public static Vector<Elf32_Sym> parseSymtab(ByteBuffer symtab) {
		Vector<Elf32_Sym> symbols = new Vector<Elf32_Sym>();
		while (symtab.remaining() >= 16) {
			Elf32_Sym symbol = new Elf32_Sym();
			symbol.st_name = symtab.getInt();
			symbol.st_value = symtab.getInt();
			symbol.st_size = symtab.getInt();
			symbol.st_info = symtab.get();
			symbol.st_other = symtab.get();
			symbol.st_shndx = symtab.getShort();
			symbols.add(symbol);
		}
		return symbols;
	}

	public LinkedHashMap<Integer, LinkedHashMap<Integer, Abbrev>> parseDebugAbbrev(ByteBuffer debug_abbrev_bytes) {
		LinkedHashMap<Integer, LinkedHashMap<Integer, Abbrev>> vector = new LinkedHashMap<Integer, LinkedHashMap<Integer, Abbrev>>();
		LinkedHashMap<Integer, Abbrev> abbrevList = new LinkedHashMap<Integer, Abbrev>();

		int acumalateOffset = debug_abbrev_bytes.position();
		while (debug_abbrev_bytes.hasRemaining()) {
			Abbrev abbrev = new Abbrev();
			int number = (int) DwarfLib.getUleb128(debug_abbrev_bytes);
			if (number == 0) {
				vector.put(acumalateOffset, abbrevList);
				abbrevList = new LinkedHashMap<Integer, Abbrev>();
				acumalateOffset = debug_abbrev_bytes.position();
				continue;
			}
			int tag = (int) DwarfLib.getUleb128(debug_abbrev_bytes);
			int has_children = debug_abbrev_bytes.get();
			abbrev.number = number;
			abbrev.tag = tag;
			if (has_children == Definition.DW_CHILDREN_yes) {
				abbrev.has_children = true;
			}

			abbrev.entries.clear();

			while (true) {
				AbbrevEntry abbrevEntry = new AbbrevEntry();
				//				tag = debug_abbrev_bytes.get();
				tag = (int) DwarfLib.getUleb128(debug_abbrev_bytes);
				int form = (int) DwarfLib.getUleb128(debug_abbrev_bytes);
				//				int form = debug_abbrev_bytes.get();
				if (tag == 0 && form == 0) {
					break;
				}
				abbrevEntry.at = tag;
				abbrevEntry.form = form;
				abbrev.entries.add(abbrevEntry);
			}
			abbrevList.put(number, abbrev);
		}
		return vector;
	}

	public void parseDebugInfo(Elf32_Shdr debugInfoSection, ByteBuffer debugInfoBytes) {
		if (abbrevList == null) {
			throw new IllegalArgumentException("abbrevList is null, please call parseDebugAbbrev() first");
		}
		calculationRelocation(debugInfoSection, debugInfoBytes);

		int start = 0;
		int initial_length_size = 0;
		while (debugInfoBytes.remaining() > 11) {
			CompileUnit cu = new CompileUnit();
			cu.offset = debugInfoBytes.position();
			cu.length = debugInfoBytes.getInt();
			cu.version = debugInfoBytes.getShort();
			cu.abbrev_offset = debugInfoBytes.getInt();
			cu.addr_size = debugInfoBytes.get();
			compileUnits.add(cu);

			System.out.println("l=" + cu.length);
			System.out.println("o=" + cu.abbrev_offset);

			if (cu.length == 0xffffffff) {
				cu.length = (int) debugInfoBytes.getLong();
				initial_length_size = 12;
			} else {
				initial_length_size = 4;
			}

			while (debugInfoBytes.position() < cu.offset + cu.length) {
				DebugInfoEntry debugInfoEntry = new DebugInfoEntry();
				debugInfoEntry.position = debugInfoBytes.position();
				debugInfoEntry.abbrevNo = (int) DwarfLib.getUleb128(debugInfoBytes);

				Abbrev abbrev = abbrevList.get(cu.abbrev_offset).get(debugInfoEntry.abbrevNo);
				if (abbrev == null) {
					continue;
				}
				debugInfoEntry.name = Definition.getTagName(abbrev.tag);
				cu.debugInfoEntry.add(debugInfoEntry);

				if (Global.debug) {
					System.out.println(Integer.toHexString(debugInfoEntry.position) + " > " + debugInfoEntry.name);
				}
				for (AbbrevEntry entry : abbrev.entries) {
					DebugInfoAbbrevEntry debugInfoAbbrevEntry = new DebugInfoAbbrevEntry();
					debugInfoEntry.debugInfoAbbrevEntry.add(debugInfoAbbrevEntry);

					debugInfoAbbrevEntry.name = Definition.getATName(entry.at);
					debugInfoAbbrevEntry.form = entry.form;
					debugInfoAbbrevEntry.position = debugInfoBytes.position();
					if (Global.debug) {
						System.out.print("\t" + Integer.toHexString(debugInfoAbbrevEntry.position) + " > " + debugInfoAbbrevEntry.name);
					}

					if (entry.form == Definition.DW_FORM_string) {
						byte temp;
						String value = "";
						while ((temp = debugInfoBytes.get()) != 0) {
							value += ((char) temp);
						}
						if (Global.debug) {
							System.out.print("\t:\t" + value);
						}
						debugInfoAbbrevEntry.value = value;
					} else if (entry.form == Definition.DW_FORM_addr) {
						if (cu.addr_size == 4) {
							int address = debugInfoBytes.getInt();
							debugInfoAbbrevEntry.value = address;
						} else {
							debugInfoAbbrevEntry.value = null;
							System.err.println("debugInfoAbbrevEntry.value = null");
							// System.exit(-1);
						}
					} else if (entry.form == Definition.DW_FORM_strp) {
						int stringOffset = debugInfoBytes.getInt();
						String s = DwarfLib.getString(debug_str, stringOffset);
						if (Global.debug) {
							System.out.printf("\t(indirect string, offset: %x):\t%s", stringOffset, s);
						}
						debugInfoAbbrevEntry.value = s;
					} else if (entry.form == Definition.DW_FORM_data1) {
						int data = debugInfoBytes.get() & 0xff;
						debugInfoAbbrevEntry.value = data;
						if (Global.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_data2) {
						short data = debugInfoBytes.getShort();
						debugInfoAbbrevEntry.value = Integer.toHexString(data);
						if (Global.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_data4) {
						int data = debugInfoBytes.getInt();
						debugInfoAbbrevEntry.value = Integer.toHexString(data);
						if (Global.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_data8) {
						long data = debugInfoBytes.getLong();
						debugInfoAbbrevEntry.value = Long.toHexString(data);
						if (Global.debug) {
							System.out.print("\t:\t" + data + cu.offset);
						}
					} else if (entry.form == Definition.DW_FORM_ref1) {
						byte data = debugInfoBytes.get();
						debugInfoAbbrevEntry.value = Integer.toHexString(data);
						if (Global.debug) {
							System.out.print("\t:\t" + data + cu.offset);
						}
					} else if (entry.form == Definition.DW_FORM_ref2) {
						short data = debugInfoBytes.getShort();
						debugInfoAbbrevEntry.value = Integer.toHexString(data);
						if (Global.debug) {
							System.out.print("\t:\t" + data + cu.offset);
						}
					} else if (entry.form == Definition.DW_FORM_ref4) {
						int data = debugInfoBytes.getInt();
						debugInfoAbbrevEntry.value = Integer.toHexString(data);
						if (Global.debug) {
							System.out.printf("\t:\t%x %x", data, data + cu.offset);
						}
					} else if (entry.form == Definition.DW_FORM_ref8) {
						long data = debugInfoBytes.getLong();
						debugInfoAbbrevEntry.value = Long.toHexString(data);
						if (Global.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_block) {
						long size = DwarfLib.getUleb128(debugInfoBytes);
						byte bytes[] = new byte[(int) size];
						if (Global.debug) {
							System.out.print("\t:\t");
						}
						for (int z = 0; z < size; z++) {
							bytes[z] = (byte) (debugInfoBytes.get() & 0xff);
							if (Global.debug) {
								System.out.printf("%x\t", bytes[z]);
							}
						}
						debugInfoAbbrevEntry.value = bytes;
					} else if (entry.form == Definition.DW_FORM_block1) {
						int size = debugInfoBytes.get();
						byte bytes[] = new byte[(int) size];
						if (Global.debug) {
							System.out.print("\t:\t");
						}
						for (int z = 0; z < size; z++) {
							bytes[z] = (byte) (debugInfoBytes.get() & 0xff);
							if (Global.debug) {
								System.out.printf("%x\t", bytes[z]);
							}
						}
						debugInfoAbbrevEntry.value = bytes;
					} else if (entry.form == Definition.DW_FORM_block2) {
						short size = debugInfoBytes.getShort();
						byte bytes[] = new byte[(int) size];
						if (Global.debug) {
							System.out.print("\t:\t");
						}
						for (int z = 0; z < size; z++) {
							bytes[z] = (byte) (debugInfoBytes.get() & 0xff);
							if (Global.debug) {
								System.out.printf("%x\t", bytes[z]);
							}
						}
						debugInfoAbbrevEntry.value = bytes;
					} else if (entry.form == Definition.DW_FORM_block4) {
						int size = debugInfoBytes.getInt();
						byte bytes[] = new byte[(int) size];
						if (Global.debug) {
							System.out.print("\t:\t");
						}
						for (int z = 0; z < size; z++) {
							bytes[z] = (byte) (debugInfoBytes.get() & 0xff);
							if (Global.debug) {
								System.out.printf("%x\t", bytes[z]);
							}
						}
						debugInfoAbbrevEntry.value = bytes;
					} else if (entry.form == Definition.DW_FORM_ref_udata) {
						long data = DwarfLib.getUleb128(debugInfoBytes);
						debugInfoAbbrevEntry.value = data;
						if (Global.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_flag) {
						byte flag = debugInfoBytes.get();
						debugInfoAbbrevEntry.value = flag;
						if (Global.debug) {
							System.out.print("\t:\t" + flag);
						}
					} else if (entry.form == Definition.DW_FORM_sec_offset) {
						int value = debugInfoBytes.getInt();
						debugInfoAbbrevEntry.value = value;
						if (Global.debug) {
							System.out.print("\t:\t" + value);
						}
					} else if (entry.form == Definition.DW_FORM_flag_present) {
						//						byte value = debugInfoBytes.get();
						debugInfoAbbrevEntry.value = 1;
						if (Global.debug) {
							System.out.print("\t:\t1");
						}
					} else if (entry.form == Definition.DW_FORM_exprloc) {
						long size = DwarfLib.getUleb128(debugInfoBytes);
						byte bytes[] = new byte[(int) size];
						if (Global.debug) {
							System.out.print("\t:\t");
						}
						for (int z = 0; z < size; z++) {
							bytes[z] = (byte) (debugInfoBytes.get() & 0xff);
							if (Global.debug) {
								System.out.print(bytes[z] + "\t");
							}
						}
					} else {
						System.out.println("unsupport DW_FORM_? = 0x" + Integer.toHexString(entry.form));
					}

					if (Global.debug) {
						System.out.println();
					}
				}

			}

			start += cu.length + initial_length_size;
			debugInfoBytes.position(start);
			//			debugInfoBytes.get();
		}

	}

	private void calculationRelocation(Elf32_Shdr debugInfoSection, ByteBuffer debugInfoBytes) {
		if (ehdr.e_type != Elf_Common.ET_REL) {
			return;
		}

		Elf32_Shdr debugInfoRelSection = null;
		for (Elf32_Shdr s : SectionFinder.getAllRelocationSection(file)) {
			if (s.sh_info == debugInfoSection.number) {
				debugInfoRelSection = s;
				break;
			}
		}
		if (debugInfoRelSection != null) {
			System.out.println("debugInfoRelSection");
			try {
				// MappedByteBuffer byteBuffer =
				// SectionFinder.findSectionByte(Dwarf.file,
				// debugInfoRelSection.section_name);
				ByteBuffer byteBuffer = SectionFinder.findSectionByte(Dwarf.file, ".rel.debug_info");
				int size = Integer.MAX_VALUE;
				if (debugInfoRelSection.sh_type == Elf_Common.SHT_RELA) {
					size = 12;
				} else if (debugInfoRelSection.sh_type == Elf_Common.SHT_REL) {
					size = 8;
				}
				while (byteBuffer.remaining() >= size) {
					int offset = byteBuffer.getInt();
					int info = byteBuffer.getInt();
					int addend = 0;
					if (debugInfoRelSection.sh_type == Elf_Common.SHT_RELA) {
						addend = byteBuffer.getInt();
					}
					int relocationType = Elf_Common.ELF32_R_TYPE(info);
					// System.out.printf("%x\t", offset);
					// System.out.printf("%x\t", info);
					// if (debugInfoRelSection.sh_type == Elf_Common.SHT_RELA) {
					// System.out.printf("%x\t", addend);
					// }
					// System.out.printf("%s\t",
					// Elf_Common.getRelocationTypeName(relocationType));
					// System.out.printf("%d\t", Elf_Common.ELF32_R_SYM(info));
					// System.out.printf("%08x\t",
					// symbols.get(Elf_Common.ELF32_R_SYM(info)).st_value);

					// relocation
					int temp = debugInfoBytes.position();

					if (debugInfoBytes.remaining() >= 4) {
						debugInfoBytes.position(offset);
						if (offset < 140) {
							System.out.println(Integer.toHexString(offset) + "==" + symbols.get(Elf_Common.ELF32_R_SYM(info)).st_value + addend);
						}
						debugInfoBytes.putInt(symbols.get(Elf_Common.ELF32_R_SYM(info)).st_value + addend);
						debugInfoBytes.position(temp);
					}

					// System.out.printf("%s\t", DwarfLib.getString(strtab_str,
					// symbols.get(Elf_Common.ELF32_R_SYM(info)).st_name));
					// System.out.printf("\n");
				}

			} catch (Exception e) {
				e.printStackTrace();
				System.exit(-1);
			}
		}
	}

	public void parseHeader(ByteBuffer debugLineBytes) {
		final int begin = debugLineBytes.position();

		DwarfDebugLineHeader dwarfDebugLineHeader = new DwarfDebugLineHeader();
		dwarfDebugLineHeader.total_length = (long) debugLineBytes.getInt() & 0xFFFFFFFFL;
		dwarfDebugLineHeader.version = debugLineBytes.getShort() & 0xFFFF;
		dwarfDebugLineHeader.prologue_length = (long) debugLineBytes.getInt() & 0xFFFFFFFFL;
		dwarfDebugLineHeader.minimum_instruction_length = debugLineBytes.get() & 0xFF;

		final int end = (int) (begin + dwarfDebugLineHeader.total_length + 4);
		final int prologue_end = (int) (begin + dwarfDebugLineHeader.prologue_length + 9);

		if (dwarfDebugLineHeader.version >= 4) {
			dwarfDebugLineHeader.max_ops_per_insn = debugLineBytes.get();
			if (dwarfDebugLineHeader.max_ops_per_insn == 0) {
				System.out.println("Invalid maximum operations per insn.");
				System.exit(-1);
			}
		} else {
			dwarfDebugLineHeader.max_ops_per_insn = 1;
		}

		dwarfDebugLineHeader.default_is_stmt = debugLineBytes.get() != 0;
		dwarfDebugLineHeader.line_base = debugLineBytes.get();
		dwarfDebugLineHeader.line_range = debugLineBytes.get() & 0xFF;
		dwarfDebugLineHeader.opcode_base = debugLineBytes.get() & 0xFF;
		debugLineBytes.get(dwarfDebugLineHeader.standard_opcode_lengths);

		// Skip the directories; they end with a single null byte.
		String s;
		dwarfDebugLineHeader.dirnames.add(".");
		while ((s = DwarfLib.getString(debugLineBytes)).length() > 0) {
			dwarfDebugLineHeader.dirnames.add(s);
		}

		// Read the file names.
		int entryNo = 1;
		while (debugLineBytes.hasRemaining() && debugLineBytes.position() < prologue_end) {
			DwarfHeaderFilename f = new DwarfHeaderFilename();
			String fname = DwarfLib.getString(debugLineBytes);
			long u1 = DwarfLib.getUleb128(debugLineBytes);
			long u2 = DwarfLib.getUleb128(debugLineBytes);
			long u3 = DwarfLib.getUleb128(debugLineBytes);
			f.entryNo = entryNo;
			if (new File(dwarfDebugLineHeader.dirnames.get((int) u1)).isAbsolute()) {
				f.file = new File(dwarfDebugLineHeader.dirnames.get((int) u1) + File.separator + fname);
			} else {
				f.file = new File(file.getParent() + File.separator + dwarfDebugLineHeader.dirnames.get((int) u1) + File.separator + fname);
			}
			f.dir = u1;
			f.time = u2;
			f.len = u3;
			entryNo++;
			dwarfDebugLineHeader.filenames.add(f);
		}
		if (Global.debug) {
			System.out.println("--" + debugLineBytes.position());
		}

		debugLineBytes.get();

		long address = 0;
		long file_num = 1;
		int line_num = 1;
		long column_num = 0;
		boolean is_stmt = dwarfDebugLineHeader.default_is_stmt;
		boolean basic_block = false;
		int op_index = 0;
		boolean end_sequence = false;
		int last_file_entry = 0;

		while (debugLineBytes.hasRemaining() && debugLineBytes.position() < end) {
			int opcode = debugLineBytes.get() & 0xff;

			if (opcode > dwarfDebugLineHeader.opcode_base) {
				opcode -= dwarfDebugLineHeader.opcode_base;
				int advance_address = ((opcode / dwarfDebugLineHeader.line_range) * dwarfDebugLineHeader.minimum_instruction_length);
				address += advance_address;
				int advance_line = ((opcode % dwarfDebugLineHeader.line_range) + dwarfDebugLineHeader.line_base);
				line_num += advance_line;
				if (Global.debug) {
					System.out.println("Special opcode:" + opcode + ",\tadvance address by " + advance_address + " to " + Long.toHexString(address) + ", line by " + advance_line
							+ " to " + line_num);
				}
			} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_extended_op) {
				long size = DwarfLib.getUleb128(debugLineBytes);
				if (size == 0) {
					System.out.println("Error: DW_LNS_extended_op size=0");
					return;
				}
				int code = debugLineBytes.get();
				if (code == Dwarf_line_number_x_ops.DW_LNE_end_sequence) {
					if (Global.debug) {
						System.out.println("Extended opcode:" + code + " End of sequence");
					}
					address = 0;
					op_index = 0;
					file_num = 1;
					line_num = 1;
					column_num = 0;
					is_stmt = dwarfDebugLineHeader.default_is_stmt;
					basic_block = false;
					end_sequence = false;
					last_file_entry = 0;
				} else if (code == Dwarf_line_number_x_ops.DW_LNE_set_address) {
					address = debugLineBytes.getInt();
					op_index = 0;
					if (Global.debug) {
						System.out.println("Extended opcode:" + code + ": set Address to 0x" + Long.toHexString(address));
					}
				} else if (code == Dwarf_line_number_x_ops.DW_LNE_define_file) {
					int dir_index = 0;

					++last_file_entry;
				} else if (code == Dwarf_line_number_x_ops.DW_LNE_set_discriminator) {
					int discriminator = debugLineBytes.get();
					if (Global.debug) {
						System.out.println("Extended opcode:" + code + ",\tset discriminator=" + discriminator);
					}
				} else {
					if (Global.debug) {
						System.out.println("error, wrong size in address,\topcode=" + opcode + ", code=" + code);
					}
					// System.exit(1);
				}
				for (int x = 0; x < size; x++) {
					// debugLineBytes.get();
				}
			} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_copy) {
				if (Global.debug) {
					System.out.println("Copy");
				}
				is_stmt = false;
				continue;
			} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_advance_pc) {
				long advance_address = DwarfLib.getUleb128(debugLineBytes);
				address += dwarfDebugLineHeader.minimum_instruction_length * advance_address;
				if (Global.debug) {
					System.out.println("advance pc, address=" + Long.toHexString(address));
				}
			} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_advance_line) {
				long advance_line = DwarfLib.getSLEB128(debugLineBytes);
				if (Global.debug) {
					System.out.println("Advance Line by " + advance_line + " to " + (line_num + advance_line));
				}
				line_num += advance_line;
			} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_set_file) {
				long fileno = DwarfLib.getUleb128(debugLineBytes);
				file_num = fileno;
				if (Global.debug) {
					System.out.println("set file, file=" + line_num);
				}
			} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_set_column) {
				long colno = DwarfLib.getUleb128(debugLineBytes);
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
				int advance_address = debugLineBytes.getInt();
				address += advance_address;
				if (Global.debug) {
					System.out.println("fixed advance pc, address=" + Long.toHexString(address));
				}
			} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_const_add_pc) {
				int advance_address = (dwarfDebugLineHeader.minimum_instruction_length * ((255 - dwarfDebugLineHeader.opcode_base) / dwarfDebugLineHeader.line_range));
				address += advance_address;
				if (Global.debug) {
					System.out.println("Advance PC by constant " + advance_address + " to 0x" + Long.toHexString(address));
				}
			} else {
				if (Global.debug) {
					System.out.println("error, what? opcode=" + opcode);
				}
			}

			DwarfLine dwarfLine = new DwarfLine();
			dwarfLine.address = address;
			dwarfLine.file_num = file_num - 1;
			dwarfLine.line_num = line_num;
			dwarfLine.column_num = column_num;
			dwarfLine.is_stmt = is_stmt;
			dwarfLine.basic_block = basic_block;
			dwarfDebugLineHeader.lines.add(dwarfLine);
		}
		debugLineBytes.position(end);

		headers.add(dwarfDebugLineHeader);
	}

}
