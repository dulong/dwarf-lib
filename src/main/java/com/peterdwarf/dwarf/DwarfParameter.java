package com.peterdwarf.dwarf;

public class DwarfParameter {
	public String name;
	public String registerName;
	public int offset;

	public DwarfParameter(String name, String registerName, int offset) {
		super();
		this.name = name;
		this.registerName = registerName;
		this.offset = offset;
	}

}
