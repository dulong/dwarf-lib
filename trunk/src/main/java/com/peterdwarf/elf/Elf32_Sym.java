package com.peterdwarf.elf;

public class Elf32_Sym implements Comparable {
	public int st_name;
	public int st_value;
	public int st_size;
	public byte st_info;
	public byte st_other;
	public short st_shndx;
	public String name;

	@Override
	public int compareTo(Object o) {
		return name.compareToIgnoreCase(((Elf32_Sym) o).name);
	}

	public String toString() {
		return name;
	}
}
