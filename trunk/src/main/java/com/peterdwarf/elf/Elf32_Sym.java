package com.peterdwarf.elf;

public class Elf32_Sym implements Comparable<Elf32_Sym> {
	public int st_name;
	public int st_value;
	public int st_size;
	public byte st_info;
	public byte st_other;
	public short st_shndx;
	public String name;

	@Override
	public int compareTo(Elf32_Sym o) {
		System.out.println("hey");
		if (st_value == o.st_value) {
			return 0;
		} else {
			return name.compareToIgnoreCase(o.name);
		}
	}

	public String toString() {
		return name;
	}
}
