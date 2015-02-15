package com.peterdwarf.dwarf;

public class DebugInfoAbbrevEntry {
	public String name;
	public int form;
	public Object value;
	public int position;

	public String toString() {
		return "0x" + Integer.toHexString(position) + ", " + name + ", form=" + form + ", value=" + value;
	}
}
