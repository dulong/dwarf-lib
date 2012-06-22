package com.peterdwarf.dwarf;

import java.util.Vector;

public class Abbrev {
	/**
	 * @uml.property  name="number"
	 */
	int number;
	/**
	 * @uml.property  name="tag"
	 */
	int tag;
	/**
	 * @uml.property  name="has_children"
	 */
	boolean has_children;
	/**
	 * @uml.property  name="entries"
	 * @uml.associationEnd  multiplicity="(0 -1)" elementType="com.peterdwarf.dwarf.AbbrevEntry"
	 */
	Vector<AbbrevEntry> entries = new Vector<AbbrevEntry>();
}
