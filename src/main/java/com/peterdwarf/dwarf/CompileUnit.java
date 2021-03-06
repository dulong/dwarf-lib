package com.peterdwarf.dwarf;

import java.util.Vector;

public class CompileUnit implements Comparable<CompileUnit> {
	public int offset;
	public int length;
	public int version;
	public int abbrev_offset;
	public int addr_size;
	public Vector<DebugInfoEntry> debugInfoEntries = new Vector<DebugInfoEntry>();

	public String DW_AT_producer;
	public int DW_AT_language;
	public String DW_AT_name;
	public String DW_AT_comp_dir;
	public long DW_AT_low_pc;
	public long DW_AT_high_pc;
	public String DW_AT_stmt_list;
	public DwarfDebugLineHeader dwarfDebugLineHeader;

	public String toString() {
		String str = "";
		str += "  Compilation Unit @ offset 0x" + Integer.toHexString(offset) + ":\n";
		str += "  	   Name:  " + DW_AT_name + "\n";
		str += "  	   Length:        0x" + Integer.toHexString(length) + " (32-bit)" + "\n";
		str += "  	   Version:       " + version + "\n";
		str += "  	   Abbrev Offset: " + abbrev_offset + "\n";
		str += "  	   Pointer Size:  " + addr_size + "\n";
		str += "  	   Low pc:  " + DW_AT_low_pc + "\n";
		str += "  	   High pc:  " + DW_AT_high_pc + "\n";
		return str;
	}

	@Override
	public int compareTo(CompileUnit a) {
		return DW_AT_name.compareTo(a.DW_AT_name);
	}

	public DebugInfoEntry getDebugInfoEntryByPosition(int position) {
		for (DebugInfoEntry d : debugInfoEntries) {
			DebugInfoEntry t = getDebugInfoEntryByPosition(d, position);
			if (t != null) {
				return t;
			}
		}
		return null;
	}

	public DebugInfoEntry getDebugInfoEntryByPosition(DebugInfoEntry debugInfoEntry, int position) {
		if (debugInfoEntry.position == position) {
			return debugInfoEntry;
		}
		for (DebugInfoEntry dd : debugInfoEntry.debugInfoEntries) {
			DebugInfoEntry t = getDebugInfoEntryByPosition(dd, position);
			if (t != null) {
				return t;
			}
		}
		return null;
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

	public Vector<DebugInfoEntry> getSubDebugInfoEntryByName(String name) {
		for (DebugInfoEntry debugInfoEntry : debugInfoEntries) {
			//debugInfoEntry.debugInfoAbbrevEntries.get(name);
			if (debugInfoEntry.getDebugInfoEntryByName(name) != null) {
				return debugInfoEntry.getDebugInfoEntryByName(name);
			}
		}
		return null;
	}
}
