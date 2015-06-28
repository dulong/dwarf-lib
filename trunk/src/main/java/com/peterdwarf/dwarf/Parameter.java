package com.peterdwarf.dwarf;

public class Parameter {
	public String name;
	public String registerName;
	public int offset;

	public Parameter(String name, String registerName, int offset) {
		super();
		this.name = name;
		this.registerName = registerName;
		this.offset = offset;
	}

}
