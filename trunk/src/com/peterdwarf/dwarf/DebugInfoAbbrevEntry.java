package com.peterdwarf.dwarf;

public class DebugInfoAbbrevEntry {
	/**
	 * @uml.property  name="name"
	 */
	public String name;
	/**
	 * @uml.property  name="form"
	 */
	public int form;
	/**
	 * @uml.property  name="value"
	 */
	public Object value;
	/**
	 * @uml.property  name="position"
	 */
	public int position;

	public String toString() {
		return "position=" + Integer.toHexString(position) + ", name=" + name + ", form=" + form + ", value=" + value;
	}
}
