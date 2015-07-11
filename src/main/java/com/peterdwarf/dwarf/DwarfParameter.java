package com.peterdwarf.dwarf;

public class DwarfParameter {
	public String name;
	public String registerName;
	public String type;
	public int size;
	public long offset;

	public DwarfParameter(String name, String registerName, String type, int size, long offset) {
		super();
		this.name = name;
		this.registerName = registerName;
		this.type = type;
		this.size = size;
		this.offset = offset;
	}

	public String toString() {
		return "name= " + name + ", registerName=" + registerName + ", type=" + type + ", size=" + size + ", offset=" + offset;
	}

}
