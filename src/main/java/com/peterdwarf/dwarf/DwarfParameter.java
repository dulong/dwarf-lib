package com.peterdwarf.dwarf;

public class DwarfParameter {
	public String name;
	public String registerName;
	public String type;
	public long offset;

	public DwarfParameter(String name, String registerName, String type, long offset) {
		super();
		this.name = name;
		this.registerName = registerName;
		this.type = type;
		this.offset = offset;
	}

}
