package com.peterdwarf.dwarf;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Stack;
import java.util.Vector;

import com.peterdwarf.DwarfGlobal;
import com.peterdwarf.elf.Elf32_Ehdr;
import com.peterdwarf.elf.Elf32_Shdr;
import com.peterdwarf.elf.Elf32_Sym;
import com.peterdwarf.elf.Elf_Common;
import com.peterdwarf.elf.SectionFinder;
import com.peterswing.CommonLib;

public class Dwarf {
	public ByteBuffer byteBuffer;
	public ByteBuffer debug_abbrevBuffer;
	public ByteBuffer debug_bytes;
	public ByteBuffer symtab_bytes;
	private ByteBuffer strtab_bytes;
	public ByteBuffer debug_loc;
	public Vector<DwarfDebugLineHeader> headers = new Vector<DwarfDebugLineHeader>();
	public Vector<CompileUnit> compileUnits = new Vector<CompileUnit>();
	public Vector<Elf32_Sym> symbols = new Vector<Elf32_Sym>();
	public LinkedHashMap<Integer, LinkedHashMap<Integer, Abbrev>> abbrevList;
	public File file;
	public String realFilename;
	public Elf32_Ehdr ehdr = new Elf32_Ehdr();
	public boolean isLoading;
	public String loadingMessage;
	public Vector<Elf32_Shdr> sections = new Vector<Elf32_Shdr>();

	//	List<Integer> addSubNode = Arrays.asList(Definition.DW_TAG_union_type, Definition.DW_TAG_array_type, Definition.DW_TAG_structure_type, Definition.DW_TAG_subprogram,
	//			Definition.DW_TAG_lexical_block);
	//	List<Integer> returnSubNode = Arrays.asList(Definition.DW_TAG_member, Definition.DW_TAG_subrange_type, Definition.DW_TAG_unspecified_parameters, Definition.DW_TAG_variable,
	//			Definition.DW_TAG_formal_parameter);

	public int initElf(File file, String realFilename, long memoryOffset) {
		this.file = file;
		this.realFilename = realFilename;

		isLoading = true;
		if (!file.isFile()) {
			System.err.println(file.getAbsolutePath() + " is not a file!!!");
			return 100;
		}

		if (!isELF(file)) {
			return 101;
		}

		try {
			sections = SectionFinder.getAllSections(file);
		} catch (IOException e2) {
			return 23;
		}

		// read program header
		try {
			ehdr.read(new RandomAccessFile(file, "r"));
		} catch (Exception e1) {
			e1.printStackTrace();
			return 1;
		}
		// end read program header

		compileUnits.clear();

		try {
			debug_loc = SectionFinder.findSectionByte(ehdr, file, ".debug_loc");
			

			System.exit(-1);

			debug_bytes = SectionFinder.findSectionByte(ehdr, file, ".debug_str");
			if (debug_bytes == null) {
				System.err.println("missing section .debug_str");
				return 24;
			}
			strtab_bytes = SectionFinder.findSectionByte(ehdr, file, ".strtab");
			symtab_bytes = SectionFinder.findSectionByte(ehdr, file, ".symtab");
			symbols = parseSymtab(symtab_bytes, strtab_bytes);
			debug_abbrevBuffer = SectionFinder.findSectionByte(ehdr, file, ".debug_abbrev");
			abbrevList = parseDebugAbbrev(debug_abbrevBuffer);
			if (DwarfGlobal.debug) {
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
			if (DwarfGlobal.debug) {
				System.out.println();
			}

			byteBuffer = SectionFinder.findSectionByte(ehdr, file, ".debug_info");
			Elf32_Shdr debugInfoSection = null;
			for (Elf32_Shdr s : sections) {
				if (s.section_name.equals(".debug_info")) {
					debugInfoSection = s;
					break;
				}
			}
			if (debugInfoSection != null) {
				int r = parseDebugInfo(debugInfoSection, byteBuffer);
				if (r > 0) {
					return r;
				}
			}

			Elf32_Shdr shdr = SectionFinder.getSectionHeader(ehdr, file, ".debug_line");
			byteBuffer = SectionFinder.findSectionByte(ehdr, file, shdr.section_name);
			calculationRelocation(shdr, byteBuffer, ".rel.debug_line");
			int x = 0;
			while (((ByteBuffer) byteBuffer).hasRemaining() && x < compileUnits.size()) {
				int r = parseHeader(byteBuffer, compileUnits.get(x), memoryOffset);
				x++;
				if (r > 0) {
					return r;
				}
			}
		} catch (OutOfMemoryError e) {
			e.printStackTrace();
			loadingMessage = file.getAbsolutePath() + " : out of memory error";
			return 19;
		} catch (IOException e) {
			e.printStackTrace();
			loadingMessage = file.getAbsolutePath() + " : IO exception";
			return 2;
		}
		isLoading = false;
		return 0;
	}

	public boolean isELF(File file) {
		InputStream is;
		try {
			is = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return false;
		}
		try {
			is.skip(1);
			if (is.read() != 0x45 || is.read() != 0x4c || is.read() != 0x46) {
				return false;
			}
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		} finally {
			try {
				is.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return true;
	}

	private static Vector<Elf32_Sym> parseSymtab(ByteBuffer symtab, ByteBuffer strtab) {
		Vector<Elf32_Sym> symbols = new Vector<Elf32_Sym>();
		while (symtab.remaining() >= 16) {
			Elf32_Sym symbol = new Elf32_Sym();
			symbol.st_name = symtab.getInt();
			symbol.st_value = symtab.getInt();
			symbol.st_size = symtab.getInt();
			symbol.st_info = symtab.get();
			symbol.st_other = symtab.get();
			symbol.st_shndx = symtab.getShort();
			symbol.name = DwarfLib.getString(strtab, symbol.st_name);
			symbols.add(symbol);
		}
		return symbols;
	}

	private LinkedHashMap<Integer, LinkedHashMap<Integer, Abbrev>> parseDebugAbbrev(ByteBuffer debug_abbrev_bytes) {
		LinkedHashMap<Integer, LinkedHashMap<Integer, Abbrev>> vector = new LinkedHashMap<Integer, LinkedHashMap<Integer, Abbrev>>();
		LinkedHashMap<Integer, Abbrev> abbrevList = new LinkedHashMap<Integer, Abbrev>();

		int acumalateOffset = debug_abbrev_bytes.position();
		while (debug_abbrev_bytes.hasRemaining()) {
			Abbrev abbrev = new Abbrev();
			int number = (int) DwarfLib.getULEB128(debug_abbrev_bytes);
			if (number == 0) {
				vector.put(acumalateOffset, abbrevList);
				abbrevList = new LinkedHashMap<Integer, Abbrev>();
				acumalateOffset = debug_abbrev_bytes.position();
				continue;
			}
			int tag = (int) DwarfLib.getULEB128(debug_abbrev_bytes);
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
				tag = (int) DwarfLib.getULEB128(debug_abbrev_bytes);
				int form = (int) DwarfLib.getULEB128(debug_abbrev_bytes);
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

	private int parseDebugInfo(Elf32_Shdr debugInfoSection, ByteBuffer debugInfoBytes) throws OutOfMemoryError {
		if (abbrevList == null) {
			throw new IllegalArgumentException("abbrevList is null, please call parseDebugAbbrev() first");
		}
		int r = calculationRelocation(debugInfoSection, debugInfoBytes, ".rel.debug_info");
		if (r > 0) {
			return r;
		}
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

			if (cu.length == 0xffffffff) {
				cu.length = (int) debugInfoBytes.getLong();
				initial_length_size = 12;
			} else {
				initial_length_size = 4;
			}
			if (DwarfGlobal.debug) {
				System.out.println(Integer.toHexString(debugInfoBytes.position()) + " " + cu);
			}

			//			DebugInfoEntry currentDebugInfoEntry = null;
			Stack<Vector<DebugInfoEntry>> originalDebugInfoEntry = new Stack<Vector<DebugInfoEntry>>();
			Vector<DebugInfoEntry> currentDebugInfoEntry = cu.debugInfoEntries;
			Stack<Long> siblingValue = new Stack<Long>();

			while (debugInfoBytes.position() <= cu.offset + cu.length + 1) {
				loadingMessage = "parsing .debug_info " + debugInfoBytes.position() + " bytes";
				DebugInfoEntry debugInfoEntry = new DebugInfoEntry();

				debugInfoEntry.position = debugInfoBytes.position();

				if (siblingValue.size() > 0 && debugInfoEntry.position == siblingValue.peek()) {
					currentDebugInfoEntry = originalDebugInfoEntry.pop();
					siblingValue.pop();
				}

				debugInfoEntry.abbrevNo = (int) DwarfLib.getULEB128(debugInfoBytes);
				Abbrev abbrev = abbrevList.get(cu.abbrev_offset).get(debugInfoEntry.abbrevNo);
				if (abbrev == null) {
					continue;
				}
				debugInfoEntry.name = Definition.getTagName(abbrev.tag);

				if (DwarfGlobal.debug) {
					System.out.println(Integer.toHexString(debugInfoEntry.position) + " > " + debugInfoEntry.name);
					System.out.flush();
				}
				for (AbbrevEntry entry : abbrev.entries) {
					loadingMessage = "parsing .debug_info " + debugInfoBytes.position() + " bytes";

					DebugInfoAbbrevEntry debugInfoAbbrevEntry = new DebugInfoAbbrevEntry();
					debugInfoAbbrevEntry.name = Definition.getATName(entry.at);
					debugInfoEntry.debugInfoAbbrevEntries.put(debugInfoAbbrevEntry.name, debugInfoAbbrevEntry);
					debugInfoAbbrevEntry.form = entry.form;
					debugInfoAbbrevEntry.position = debugInfoBytes.position();
					if (DwarfGlobal.debug) {
						System.out.print("\t" + Integer.toHexString(debugInfoAbbrevEntry.position) + " > " + entry.form + " = " + debugInfoAbbrevEntry.name);
					}

					if (entry.form == Definition.DW_FORM_string) {
						byte temp;
						String value = "";
						while ((temp = debugInfoBytes.get()) != 0) {
							value += ((char) temp);
						}
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + value);
						}
						debugInfoAbbrevEntry.value = value;
					} else if (entry.form == Definition.DW_FORM_addr) {
						if (cu.addr_size == 4) {
							long address = debugInfoBytes.getInt();
							debugInfoAbbrevEntry.value = address;
						} else {
							debugInfoAbbrevEntry.value = null;
							System.err.println("debugInfoAbbrevEntry.value = null");
						}
					} else if (entry.form == Definition.DW_FORM_strp) {
						int stringOffset = debugInfoBytes.getInt();
						String s = DwarfLib.getString(debug_bytes, stringOffset);
						if (DwarfGlobal.debug) {
							System.out.printf("\t(indirect string, offset: %x):\t%s", stringOffset, s);
						}
						debugInfoAbbrevEntry.value = s;
					} else if (entry.form == Definition.DW_FORM_data1) {
						int data = debugInfoBytes.get() & 0xff;
						debugInfoAbbrevEntry.value = data;
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_data2) {
						short data = debugInfoBytes.getShort();
						debugInfoAbbrevEntry.value = Integer.toHexString(data);
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_data4) {
						int data = debugInfoBytes.getInt();
						debugInfoAbbrevEntry.value = Integer.toHexString(data);
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_data8) {
						long data = debugInfoBytes.getLong();
						debugInfoAbbrevEntry.value = Long.toHexString(data);
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data + cu.offset);
						}
					} else if (entry.form == Definition.DW_FORM_ref1) {
						byte data = debugInfoBytes.get();
						debugInfoAbbrevEntry.value = Integer.toHexString(data + cu.offset);
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data + cu.offset);
						}
					} else if (entry.form == Definition.DW_FORM_ref2) {
						short data = debugInfoBytes.getShort();
						debugInfoAbbrevEntry.value = Integer.toHexString(data + cu.offset);
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data + cu.offset);
						}
					} else if (entry.form == Definition.DW_FORM_ref4) {
						int data = debugInfoBytes.getInt();
						debugInfoAbbrevEntry.value = Integer.toHexString(data + cu.offset);
						if (DwarfGlobal.debug) {
							System.out.printf("\t:\t%x %x", data, data + cu.offset);
						}
					} else if (entry.form == Definition.DW_FORM_ref8) {
						long data = debugInfoBytes.getLong();
						debugInfoAbbrevEntry.value = Long.toHexString(data + cu.offset);
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_block) {
						long size = DwarfLib.getULEB128(debugInfoBytes);
						byte bytes[] = new byte[(int) size];
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t");
						}
						for (int z = 0; z < size; z++) {
							bytes[z] = (byte) (debugInfoBytes.get() & 0xff);
							if (DwarfGlobal.debug) {
								System.out.printf("%x\t", bytes[z]);
							}
						}
						debugInfoAbbrevEntry.value = bytes;
					} else if (entry.form == Definition.DW_FORM_block1) {
						int size = debugInfoBytes.get() & 0xff;
						byte bytes[] = new byte[(int) size];
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t");
						}
						for (int z = 0; z < size; z++) {
							bytes[z] = (byte) (debugInfoBytes.get() & 0xff);
							if (DwarfGlobal.debug) {
								System.out.printf("%x\t", bytes[z]);
							}
						}
						debugInfoAbbrevEntry.value = bytes;
					} else if (entry.form == Definition.DW_FORM_block2) {
						short size = debugInfoBytes.getShort();
						byte bytes[] = new byte[(int) size];
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t");
						}
						for (int z = 0; z < size; z++) {
							bytes[z] = (byte) (debugInfoBytes.get() & 0xff);
							if (DwarfGlobal.debug) {
								System.out.printf("%x\t", bytes[z]);
							}
						}
						debugInfoAbbrevEntry.value = bytes;
					} else if (entry.form == Definition.DW_FORM_block4) {
						int size = debugInfoBytes.getInt();
						byte bytes[] = new byte[(int) size];
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t");
						}
						for (int z = 0; z < size; z++) {
							bytes[z] = (byte) (debugInfoBytes.get() & 0xff);
							if (DwarfGlobal.debug) {
								System.out.printf("%x\t", bytes[z]);
							}
						}
						debugInfoAbbrevEntry.value = bytes;
					} else if (entry.form == Definition.DW_FORM_ref_udata) {
						long data = DwarfLib.getULEB128(debugInfoBytes);
						debugInfoAbbrevEntry.value = data;
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_flag) {
						byte flag = debugInfoBytes.get();
						debugInfoAbbrevEntry.value = flag;
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + flag);
						}
					} else if (entry.form == Definition.DW_FORM_sec_offset) {
						int value = debugInfoBytes.getInt();
						debugInfoAbbrevEntry.value = value;
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + value);
						}
					} else if (entry.form == Definition.DW_FORM_flag_present) {
						//						byte value = debugInfoBytes.get();
						debugInfoAbbrevEntry.value = 1;
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t1");
						}
					} else if (entry.form == Definition.DW_FORM_exprloc) {
						long size = DwarfLib.getULEB128(debugInfoBytes);
						byte bytes[] = new byte[(int) size];
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t");
						}
						debugInfoAbbrevEntry.value = "";
						for (int z = 0; z < size; z++) {
							bytes[z] = (byte) (debugInfoBytes.get() & 0xff);
							debugInfoAbbrevEntry.value += (bytes[z] & 0xFF) + ", ";
							if (DwarfGlobal.debug) {
								System.out.print(bytes[z] + "\t");
							}
						}
					} else if (entry.form == Definition.DW_FORM_sdata) {
						long data = DwarfLib.getSLEB128(debugInfoBytes);
						debugInfoAbbrevEntry.value = data;
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_udata) {
						long data = DwarfLib.getULEB128(debugInfoBytes);
						debugInfoAbbrevEntry.value = data;
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data);
						}
					} else {
						System.out.println(" unsupport DW_FORM_? = 0x" + Integer.toHexString(entry.form));
						return 3;
					}

					if (debugInfoEntry.name.equals("DW_TAG_compile_unit")) {
						if (debugInfoAbbrevEntry.name.equals("DW_AT_producer")) {
							cu.DW_AT_producer = String.valueOf(debugInfoAbbrevEntry.value);
						} else if (debugInfoAbbrevEntry.name.equals("DW_AT_language")) {
							cu.DW_AT_language = (int) Long.parseLong(debugInfoAbbrevEntry.value.toString(), 16);
						} else if (debugInfoAbbrevEntry.name.equals("DW_AT_name")) {
							cu.DW_AT_name = String.valueOf(debugInfoAbbrevEntry.value);
						} else if (debugInfoAbbrevEntry.name.equals("DW_AT_comp_dir")) {
							cu.DW_AT_comp_dir = String.valueOf(debugInfoAbbrevEntry.value);
						} else if (debugInfoAbbrevEntry.name.equals("DW_AT_low_pc")) {
							cu.DW_AT_low_pc = Long.parseLong(debugInfoAbbrevEntry.value.toString(), 10);
						} else if (debugInfoAbbrevEntry.name.equals("DW_AT_high_pc")) {
							cu.DW_AT_high_pc = Long.parseLong(debugInfoAbbrevEntry.value.toString(), 16);
						} else if (debugInfoAbbrevEntry.name.equals("DW_AT_stmt_list")) {
							cu.DW_AT_stmt_list = String.valueOf(debugInfoAbbrevEntry.value);
						}
					}

					if (DwarfGlobal.debug) {
						System.out.println();
					}
				}
				currentDebugInfoEntry.add(debugInfoEntry);
				DebugInfoAbbrevEntry debugInfoAbbrevEntry = debugInfoEntry.debugInfoAbbrevEntries.get("DW_AT_sibling");
				//				if (abbrevList.get(cu.abbrev_offset).get(debugInfoEntry.abbrevNo).has_children) {
				//					originalDebugInfoEntry.push(currentDebugInfoEntry);
				//					currentDebugInfoEntry = debugInfoEntry.debugInfoEntries;
				//				}
				if (debugInfoAbbrevEntry != null) {
					originalDebugInfoEntry.push(currentDebugInfoEntry);
					currentDebugInfoEntry = debugInfoEntry.debugInfoEntries;
					siblingValue.push(CommonLib.convertFilesize("0x" + debugInfoAbbrevEntry.value));
				}
			}

			start += cu.length + initial_length_size;
			debugInfoBytes.position(start);
		}
		return 0;
	}

	private int calculationRelocation(Elf32_Shdr debugInfoSection, ByteBuffer debugInfoBytes, String relocationInfoSectionName) {
		int originalPosition = debugInfoBytes.position();
		if (ehdr.e_type != Elf_Common.ET_REL) {
			return 0;
		}

		Elf32_Shdr debugInfoRelSection = null;
		for (Elf32_Shdr s : SectionFinder.getAllRelocationSection(file)) {
			if (s.sh_info == debugInfoSection.number) {
				debugInfoRelSection = s;
				break;
			}
		}
		if (debugInfoRelSection != null) {
			try {
				ByteBuffer byteBuffer = SectionFinder.findSectionByte(ehdr, file, relocationInfoSectionName);
				int size = Integer.MAX_VALUE;
				if (debugInfoRelSection.sh_type == Elf_Common.SHT_RELA) {
					size = 12;
				} else if (debugInfoRelSection.sh_type == Elf_Common.SHT_REL) {
					size = 8;
				}
				boolean is_rela;
				if (debugInfoRelSection.sh_type == Elf_Common.SHT_RELA) {
					is_rela = true;
				}
				if (ehdr.e_machine == Definition.EM_SH) {
					is_rela = false;
				}
				while (byteBuffer.remaining() >= size) {
					int offset = byteBuffer.getInt();
					int info = byteBuffer.getInt();

					int addend = 0;

					int relocationType = Elf_Common.ELF32_R_TYPE(info);

					debugInfoBytes.position(offset);
					if (debugInfoRelSection.sh_type != Elf_Common.SHT_RELA || (ehdr.e_machine == Definition.EM_XTENSA && relocationType == 1)
							|| ((ehdr.e_machine == Definition.EM_PJ || ehdr.e_machine == Definition.EM_PJ_OLD) && relocationType == 1)
							|| ((ehdr.e_machine == Definition.EM_D30V || ehdr.e_machine == Definition.EM_CYGNUS_D30V) && relocationType == 12)) {
						addend = debugInfoBytes.getInt();
					}
					if (DwarfGlobal.debug) {
						System.out.printf("%x\t", offset);
						System.out.printf("%x\t", info);
						if (debugInfoRelSection.sh_type == Elf_Common.SHT_RELA) {
							System.out.printf("%x\t", addend);
						}
						System.out.printf("%s\t", Elf_Common.getRelocationTypeName(relocationType));
						System.out.printf("%d\t", Elf_Common.ELF32_R_SYM(info));
						System.out.printf("%08x\t", symbols.get(Elf_Common.ELF32_R_SYM(info)).st_value);
					}

					// relocation
					int temp = debugInfoBytes.position();

					if (debugInfoBytes.remaining() >= 4) {
						debugInfoBytes.position(offset);
						int value = symbols.get(Elf_Common.ELF32_R_SYM(info)).st_value + addend;
						debugInfoBytes.putInt(value);
						debugInfoBytes.position(temp);
						if (DwarfGlobal.debug) {
							System.out.print(",replace offset " + offset + " to " + value + ", addend=" + Integer.toHexString(addend) + ", ");
						}
					}

					if (DwarfGlobal.debug) {
						//System.out.printf("%s\t", DwarfLib.getString(strtab_str, symbols.get(Elf_Common.ELF32_R_SYM(info)).st_name));
						//System.out.printf("\n");
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
				debugInfoBytes.position(originalPosition);
				return 1;
			}
		}
		debugInfoBytes.position(originalPosition);
		return 0;
	}

	private int parseHeader(ByteBuffer debugLineBytes, CompileUnit compileUnit, long memoryOffset) {
		try {
			final int begin = debugLineBytes.position();

			DwarfDebugLineHeader dwarfDebugLineHeader = new DwarfDebugLineHeader();
			dwarfDebugLineHeader.offset = debugLineBytes.position();
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
					return 5;
				}
			} else {
				dwarfDebugLineHeader.max_ops_per_insn = 1;
			}

			dwarfDebugLineHeader.default_is_stmt = debugLineBytes.get() != 0;
			dwarfDebugLineHeader.line_base = debugLineBytes.get();
			dwarfDebugLineHeader.line_range = debugLineBytes.get() & 0xFF;
			dwarfDebugLineHeader.opcode_base = debugLineBytes.get() & 0xFF;
			dwarfDebugLineHeader.standard_opcode_lengths = new byte[dwarfDebugLineHeader.opcode_base - 1];
			debugLineBytes.get(dwarfDebugLineHeader.standard_opcode_lengths);

			// Skip the directories; they end with a single null byte.
			String s;
			while ((s = DwarfLib.getString(debugLineBytes)).length() > 0) {
				dwarfDebugLineHeader.dirnames.add(s);
			}

			if (DwarfGlobal.debug) {
				System.out.println(dwarfDebugLineHeader);
				for (String dir : dwarfDebugLineHeader.dirnames) {
					System.out.println(dir);
				}
			}

			// Read the file names.
			int entryNo = 1;
			while (debugLineBytes.hasRemaining() && debugLineBytes.position() < prologue_end) {
				loadingMessage = "parsing .debug_line " + debugLineBytes.position() + " bytes";
				DwarfHeaderFilename f = new DwarfHeaderFilename();
				String fname = DwarfLib.getString(debugLineBytes);
				long u1 = DwarfLib.getULEB128(debugLineBytes);
				long u2 = DwarfLib.getULEB128(debugLineBytes);
				long u3 = DwarfLib.getULEB128(debugLineBytes);
				f.entryNo = entryNo;

				try {
					if (u1 == 0) {
						f.file = new File(compileUnit.DW_AT_comp_dir + File.separator + fname);
					} else if (new File(dwarfDebugLineHeader.dirnames.get((int) u1 - 1)).isAbsolute()) {
						f.file = new File(dwarfDebugLineHeader.dirnames.get((int) u1 - 1) + File.separator + fname);
					} else {
						f.file = new File(compileUnit.DW_AT_comp_dir + File.separator + dwarfDebugLineHeader.dirnames.get((int) u1 - 1) + File.separator + fname);
					}
					if (DwarfGlobal.debug && !f.file.exists()) {
						System.err.println(f.file.getAbsolutePath() + " is not exist");
					}
				} catch (Exception ex) {
					ex.printStackTrace();
					System.out.println(u1);
				}
				f.dir = u1;
				f.time = u2;
				f.len = u3;
				entryNo++;
				dwarfDebugLineHeader.filenames.add(f);

				if (DwarfGlobal.debug) {
					System.out.println(f.dir + "\t" + f.time + "\t" + f.len + "\t" + f.file);
				}
			}
			if (DwarfGlobal.debug) {
				System.out.println("--" + debugLineBytes.position());
			}

			debugLineBytes.get();

			BigInteger address = BigInteger.ZERO;
			long file_num = 0;
			int line_num = 1;
			long column_num = 0;
			boolean is_stmt = dwarfDebugLineHeader.default_is_stmt;
			boolean basic_block = false;
			int op_index = 0;
			boolean end_sequence = false;
			int last_file_entry = 0;

			while (debugLineBytes.hasRemaining() && debugLineBytes.position() < end) {
				if (DwarfGlobal.debug) {
					System.out.print("> 0x" + Integer.toHexString(debugLineBytes.position() - 0xf0) + " ");
				}
				int opcode = debugLineBytes.get() & 0xff;
				if (opcode >= dwarfDebugLineHeader.opcode_base) {
					opcode -= dwarfDebugLineHeader.opcode_base;
					int advance_address = ((opcode / dwarfDebugLineHeader.line_range) * dwarfDebugLineHeader.minimum_instruction_length);
					address = address.add(BigInteger.valueOf(advance_address));
					int advance_line = ((opcode % dwarfDebugLineHeader.line_range) + dwarfDebugLineHeader.line_base);
					line_num += advance_line;
					if (DwarfGlobal.debug) {
						System.out.println("Special opcode:" + opcode + ",\tadvance address by " + advance_address + " to 0x" + address.toString(16) + ", line by " + advance_line
								+ " to " + line_num);
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_extended_op) {
					long size = DwarfLib.getULEB128(debugLineBytes);
					if (size == 0) {
						System.out.println("Error: DW_LNS_extended_op size=0");
						return 11;
					}
					int code = debugLineBytes.get();
					if (code == Dwarf_line_number_x_ops.DW_LNE_end_sequence) {
						if (DwarfGlobal.debug) {
							System.out.println("Extended opcode:" + code + " End of sequence");
						}
						address = BigInteger.ZERO;
						op_index = 0;
						file_num = 1;
						line_num = 1;
						column_num = 0;
						is_stmt = dwarfDebugLineHeader.default_is_stmt;
						basic_block = false;
						end_sequence = false;
						last_file_entry = 0;
						continue;
					} else if (code == Dwarf_line_number_x_ops.DW_LNE_set_address) {
						address = BigInteger.valueOf(debugLineBytes.getInt());
						op_index = 0;
						if (DwarfGlobal.debug) {
							System.out.println("Extended opcode:" + code + ": set Address to 0x" + address.toString(16));
						}
						//					continue;
					} else if (code == Dwarf_line_number_x_ops.DW_LNE_define_file) {
						int dir_index = 0;

						++last_file_entry;
					} else if (code == Dwarf_line_number_x_ops.DW_LNE_set_discriminator) {
						int discriminator = debugLineBytes.get();
						if (DwarfGlobal.debug) {
							System.out.println("Extended opcode:" + code + ",\tset discriminator=" + discriminator);
						}
						continue;
					} else {
						if (DwarfGlobal.debug) {
							System.out.println("error, wrong size in address,\topcode=" + opcode + ", code=" + code);
						}
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_copy) {
					if (DwarfGlobal.debug) {
						System.out.println("Copy");
					}
					is_stmt = false;
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_advance_pc) {
					long adjust;
					if (dwarfDebugLineHeader.max_ops_per_insn == 1) {
						long advance_address = DwarfLib.getULEB128(debugLineBytes);
						adjust = dwarfDebugLineHeader.minimum_instruction_length * advance_address;
						address = address.add(BigInteger.valueOf(adjust));
					} else {
						adjust = DwarfLib.getULEB128(debugLineBytes);
						address = BigInteger.valueOf(((op_index + adjust) / dwarfDebugLineHeader.max_ops_per_insn) * dwarfDebugLineHeader.minimum_instruction_length);
						op_index = (int) ((op_index + adjust) % dwarfDebugLineHeader.max_ops_per_insn);
					}
					if (DwarfGlobal.debug) {
						System.out.println("advance pc by " + adjust + ", address=" + address.toString(16));
					}

					continue;
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_advance_line) {
					long advance_line = DwarfLib.getSLEB128(debugLineBytes);
					if (DwarfGlobal.debug) {
						System.out.println("Advance Line by " + advance_line + " to " + (line_num + advance_line));
					}
					line_num += advance_line;
					continue;
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_set_file) {
					long fileno = DwarfLib.getULEB128(debugLineBytes);
					file_num = fileno - 1;
					if (DwarfGlobal.debug) {
						System.out.println("set file, file=" + file_num);
					}
					continue;
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_set_column) {
					long colno = DwarfLib.getULEB128(debugLineBytes);
					column_num = colno;
					if (DwarfGlobal.debug) {
						System.out.println("set column, column=" + column_num);
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_negate_stmt) {
					is_stmt = !is_stmt;
					if (DwarfGlobal.debug) {
						System.out.println("!stmt, stmt=" + is_stmt);
					}
					continue;
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_set_basic_block) {
					basic_block = true;
					if (DwarfGlobal.debug) {
						System.out.println("set basic_block, basic_block=" + basic_block);
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_fixed_advance_pc) {
					int advance_address = debugLineBytes.getInt();
					address = address.add(BigInteger.valueOf(advance_address));
					op_index = 0;
					if (DwarfGlobal.debug) {
						System.out.println("fixed advance pc, address=" + address.toString(16));
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_const_add_pc) {
					long advance_address;

					if (dwarfDebugLineHeader.max_ops_per_insn == 1) {
						advance_address = (dwarfDebugLineHeader.minimum_instruction_length * ((255 - dwarfDebugLineHeader.opcode_base) / dwarfDebugLineHeader.line_range));
						address = address.add(BigInteger.valueOf(advance_address));
					} else {
						long adjust = ((255 - dwarfDebugLineHeader.opcode_base) / dwarfDebugLineHeader.line_range);
						advance_address = dwarfDebugLineHeader.minimum_instruction_length * ((op_index + adjust) / dwarfDebugLineHeader.max_ops_per_insn);
						address = address.add(BigInteger.valueOf(advance_address));
						op_index = (int) ((op_index + adjust) % dwarfDebugLineHeader.max_ops_per_insn);
					}

					if (DwarfGlobal.debug) {
						System.out.println("Advance PC by constant " + advance_address + " to 0x" + address.toString(16));
					}

					continue;
				} else {
					if (DwarfGlobal.debug) {
						System.out.println("error, what? opcode=" + opcode);
					}
					return 14;
				}

				DwarfLine dwarfLine = new DwarfLine();
				dwarfLine.address = address.add(BigInteger.valueOf(memoryOffset));
				dwarfLine.file_num = file_num;
				dwarfLine.line_num = line_num;
				dwarfLine.column_num = column_num;
				dwarfLine.is_stmt = is_stmt;
				dwarfLine.basic_block = basic_block;
				dwarfDebugLineHeader.lines.add(dwarfLine);
			}
			Collections.sort(dwarfDebugLineHeader.lines);
			debugLineBytes.position(end);

			headers.add(dwarfDebugLineHeader);
			return 0;
		} catch (Exception ex) {
			return 18;
		}
	}

	@Override
	public String toString() {
		if (realFilename != null) {
			return realFilename;
		} else if (file != null) {
			return file.getName();
		}
		return super.toString();
	}

	//	int hashCode = -99999;
	//	Hashtable<Long, CompileUnit> ht;

	public CompileUnit getCompileUnit(long address) {
		//		if (hashCode != compileUnits.hashCode()) {
		//			ht = new Hashtable<Long, CompileUnit>();
		//			hashCode = compileUnits.hashCode();
		//		}
		//		if (ht.containsKey(address)) {
		//			return ht.get(address);
		//		}
		for (CompileUnit cu : compileUnits) {
			if (address >= cu.DW_AT_high_pc && address <= (cu.DW_AT_high_pc + cu.DW_AT_low_pc - 1)) {
				//				ht.put(address, cu);
				return cu;
			}
		}
		return null;
	}

	public Vector<DebugInfoEntry> getSubProgram(long address) {
		for (CompileUnit compileUnit : compileUnits) {
			if (compileUnit.DW_AT_low_pc == address) {
				return compileUnit.debugInfoEntries;
			}
		}
		return null;
	}

}
