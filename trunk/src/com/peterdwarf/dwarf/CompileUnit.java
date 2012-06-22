package com.peterdwarf.dwarf;

import java.util.Vector;

public class CompileUnit {
	/**
	 * @uml.property  name="offset"
	 */
	public int offset;
	/**
	 * @uml.property  name="length"
	 */
	public int length;
	/**
	 * @uml.property  name="version"
	 */
	public int version;
	/**
	 * @uml.property  name="abbrev_offset"
	 */
	public int abbrev_offset;
	/**
	 * @uml.property  name="addr_size"
	 */
	public int addr_size;

	/**
	 * @uml.property  name="debugInfoEntry"
	 * @uml.associationEnd  multiplicity="(0 -1)" elementType="com.peterdwarf.dwarf.DebugInfoEntry"
	 */
	public Vector<DebugInfoEntry> debugInfoEntry = new Vector<DebugInfoEntry>();
}
