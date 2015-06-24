package com.peterdwarf.dwarf;

import java.util.Hashtable;
import java.util.Vector;

public class DebugInfoEntry {
	public int position;
	public int abbrevNo;

	public Hashtable<String, DebugInfoAbbrevEntry> debugInfoAbbrevEntries = new Hashtable<String, DebugInfoAbbrevEntry>();
	public String name;

	public Vector<DebugInfoEntry> debugInfoEntries = new Vector<DebugInfoEntry>();

	public String toString() {
		return "0x" + Integer.toHexString(position) + ", " + name + ", abbrevNo=" + abbrevNo;
	}

	public Vector<DebugInfoEntry> getDebugInfoEntryByName(String name) {
		if (debugInfoEntries == null) {
			return null;
		}
		Vector<DebugInfoEntry> r = new Vector<DebugInfoEntry>();
		for (DebugInfoEntry debugInfoEntry : debugInfoEntries) {
			if (debugInfoEntry.name.equals(name)) {
				r.add(debugInfoEntry);
			}
		}
		return r;
	}

}
