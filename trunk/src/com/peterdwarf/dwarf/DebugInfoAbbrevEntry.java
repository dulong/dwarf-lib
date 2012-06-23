package com.peterdwarf.dwarf;

public class DebugInfoAbbrevEntry {
	public String name;
	public int form;
	public Object value;
	public int position;

	public String toString() {
		return "position=" + Integer.toHexString(position) + ", name=" + name + ", form=" + form + ", value=" + value;
	}
}
