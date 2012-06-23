package com.peterdwarf.dwarf;

import java.util.Vector;

public class Abbrev {
	int number;
	int tag;
	boolean has_children;
	Vector<AbbrevEntry> entries = new Vector<AbbrevEntry>();
}
