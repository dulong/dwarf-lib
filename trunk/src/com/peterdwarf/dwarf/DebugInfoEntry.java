package com.peterdwarf.dwarf;

import java.util.Vector;

public class DebugInfoEntry {
	/**
	 * @uml.property  name="position"
	 */
	public int position;
	/**
	 * @uml.property  name="abbrevNo"
	 */
	public int abbrevNo;

	/**
	 * @uml.property  name="debugInfoAbbrevEntry"
	 * @uml.associationEnd  multiplicity="(0 -1)" elementType="com.peterdwarf.dwarf.DebugInfoAbbrevEntry"
	 */
	public Vector<DebugInfoAbbrevEntry> debugInfoAbbrevEntry = new Vector<DebugInfoAbbrevEntry>();
	/**
	 * @uml.property  name="name"
	 */
	public String name;
}
