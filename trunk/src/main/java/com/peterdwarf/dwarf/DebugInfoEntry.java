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

	public Object getValueByTagName(String tagName) {
		if (debugInfoAbbrevEntries == null) {
			return null;
		}
		for (DebugInfoAbbrevEntry debugInfoAbbrevEntry : debugInfoAbbrevEntries) {
			if (debugInfoAbbrevEntry.name.equals(tagName)) {
				return debugInfoAbbrevEntry.value;
			}
		}
		return null;
	}
}
