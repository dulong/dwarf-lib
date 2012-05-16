package com.peterdwarf.elf;

import java.io.IOException;
import java.io.RandomAccessFile;

import com.peterdwarf.dwarf.DwarfLib;

public class Elf32_Shdr {
	public static int SHT_NULL = 0; /* Section header table entry unused */
	public static int SHT_PROGBITS = 1; /* Program specific (private) data */
	public static int SHT_SYMTAB = 2; /* Link editing symbol table */
	public static int SHT_STRTAB = 3; /* A string table */
	public static int SHT_RELA = 4; /* Relocation entries with addends */
	public static int SHT_HASH = 5; /* A symbol hash table */
	public static int SHT_DYNAMIC = 6; /* Information for dynamic linking */
	public static int SHT_NOTE = 7; /* Information that marks file */
	public static int SHT_NOBITS = 8; /* Section occupies no space in file */
	public static int SHT_REL = 9; /* Relocation entries, no addends */
	public static int SHT_SHLIB = 10; /* Reserved, unspecified semantics */
	public static int SHT_DYNSYM = 11; /* Dynamic linking symbol table */

	public int number;
	public long sh_name;
	public String section_name;
	public int sh_type;
	public int sh_flags;
	public long sh_addr;
	public long sh_offset;
	public long sh_size;
	public int sh_link;
	public int sh_info;
	public int sh_addralign;
	public long sh_entsize;

	public Elf32_Shdr() {
	}

	public static int sizeof() {
		return 40;
	}

	public void read(int number, RandomAccessFile f) throws IOException {
		this.number = number;
		sh_name = DwarfLib.readUWord(f);
		sh_type = DwarfLib.readWord(f);
		sh_flags = DwarfLib.readWord(f);
		sh_addr = DwarfLib.readUWord(f);
		sh_offset = DwarfLib.readUWord(f);
		sh_size = DwarfLib.readUWord(f);
		sh_link = DwarfLib.readWord(f);
		sh_info = DwarfLib.readWord(f);
		sh_addralign = DwarfLib.readWord(f);
		sh_entsize = DwarfLib.readWord(f);
	}

	public String toString() {
		// StringBuffer str = new StringBuffer(super.toString());
		StringBuffer str = new StringBuffer();
		str.append("[ number: ").append(number);
		str.append("; sh_name: ").append(sh_name);
		str.append("; section_name: ").append(section_name);
		str.append("; sh_type: ").append(sh_type);
		str.append("; sh_flags: 0x").append(Long.toHexString(sh_flags));
		str.append("; sh_addr: 0x").append(Long.toHexString(sh_addr));
		str.append("; sh_offset: ").append(sh_offset);
		str.append("; sh_size: ").append(sh_size);
		str.append("; sh_link: ").append(sh_link);
		str.append("; sh_info: ").append(sh_info);
		str.append("; sh_addralgin: ").append(sh_addralign);
		str.append("; sh_entsize: ").append(sh_entsize);
		str.append(" ]");
		return str.toString();
	}
}
