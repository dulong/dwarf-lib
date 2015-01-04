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
		if (st_value == o.st_value) {
			return 0;
		} else if (name != null && o.name != null) {
			return name.compareToIgnoreCase(o.name);
		} else {
			return 0;
		}
	}

	public boolean checkWithinRange(long address) {
		if (address >= st_value && address <= st_value + st_size) {
			return true;
		} else {
			return false;
		}
	}

	public String toString() {
		return name;
	}
}
