package com.peterdwarf.dwarf;

import java.util.Vector;

public class DebugInfoEntry {
	public int position;
	public int abbrevNo;

	public Vector<DebugInfoAbbrevEntry> debugInfoAbbrevEntries = new Vector<DebugInfoAbbrevEntry>();
	public String name;

	public Vector<DebugInfoEntry> debugInfoEntries = new Vector<DebugInfoEntry>();

	public String toString() {
		return "0x" + Integer.toHexString(position) + ", " + name + ", abbrevNo=" + abbrevNo;
	}
}
