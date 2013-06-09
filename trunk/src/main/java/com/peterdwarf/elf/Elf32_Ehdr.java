package com.peterdwarf.elf;

import java.io.IOException;
import java.io.RandomAccessFile;

import com.peterdwarf.dwarf.DwarfLib;

public class Elf32_Ehdr {
	public static final int EI_NIDENT = 16;

	public final byte[] e_ident = new byte[EI_NIDENT];/* Magic number and other info. */
	public int e_type; /* Object file type. */
	public int e_machine; /* Architecture type. */
	public int e_version; /* Object file version. */
	public long e_entry; /* Entry point virtual address. */
	public long e_phoff; /* Program header table file offset. */
	public long e_shoff; /* Section header table file offset. */
	public int e_flags; /* Processor-specific flags. */
	public int e_ehsize; /* ELF header size in bytes. */
	public int e_phentsize; /* Program header table entry size. */
	public int e_phentnum; /* Program header table entry count. */
	public int e_shentsize; /* Section header table entry size. */
	public int e_shnum; /* Section header table entry count. */
	public int e_shstrndx; /* Section header string table index. */

	public Elf32_Ehdr() {
	}

	public void read(RandomAccessFile f) throws IOException {
		f.readFully(e_ident);
		e_type = DwarfLib.readUHalf(f);
		e_machine = DwarfLib.readUHalf(f);
		e_version = DwarfLib.readWord(f);
		e_entry = DwarfLib.readUWord(f);
		e_phoff = DwarfLib.readUWord(f);
		e_shoff = DwarfLib.readUWord(f);
		e_flags = DwarfLib.readWord(f);
		e_ehsize = DwarfLib.readUHalf(f);
		e_phentsize = DwarfLib.readUHalf(f);
		e_phentnum = DwarfLib.readUHalf(f);
		e_shentsize = DwarfLib.readUHalf(f);
		e_shnum = DwarfLib.readUHalf(f);
		e_shstrndx = DwarfLib.readUHalf(f);
	}

	public String toString() {
		java.lang.StringBuffer str = new java.lang.StringBuffer(super.toString());
		str.append(" [ e_ident: ");
		for (int i = 0; i < EI_NIDENT; i++) {
			if (e_ident[i] < 0x10 && e_ident[i] >= 0)
				str.append('0');
			str.append(Integer.toHexString(e_ident[i] & 0xFF));
		}
		str.append("; e_type: ").append(e_type & 0xFFFF);
		str.append("; e_machine: ").append(e_machine & 0xFFFF);
		str.append("; e_version: ").append(e_version & 0xFFFF);
		str.append("; e_entry: 0x").append(Long.toHexString(e_entry));
		str.append("; e_phoff: ").append((long) e_phoff & 0xFFFFFFFFL);
		str.append("; e_shoff: ").append((long) e_shoff & 0xFFFFFFFFL);
		str.append("; e_flags: 0x").append(Integer.toHexString(e_flags));
		str.append("; e_ehsize: ").append(e_ehsize & 0xFFFF);
		str.append("; e_phentsize: ").append(e_phentsize & 0xFFFF);
		str.append("; e_phentnum: ").append(e_phentnum & 0xFFFF);
		str.append("; e_shentsize: ").append(e_shentsize & 0xFFFF);
		str.append("; e_shnum: ").append(e_shnum & 0xFFFF);
		str.append("; e_shstrndx: ").append(e_shstrndx & 0xFFFF);
		str.append(" ]");
		return str.toString();
	}
}
