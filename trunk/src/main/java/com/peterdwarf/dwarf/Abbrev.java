package com.peterdwarf.dwarf;

import java.util.Vector;

public class Abbrev {
	public int number;
	public int tag;
	public boolean has_children;
	public Vector<AbbrevEntry> entries = new Vector<AbbrevEntry>();

	public String toString() {
		return number + ": " + Definition.getTagName(tag) + ", " + (has_children ? "has children" : "no children");
	}
}
