package com.peterdwarf.dwarf;

import com.peterswing.CommonLib;

public class DebugInfoAbbrevEntry {
	public String name;
	public int form;
	public Object value;
	public int position;

	public String toString() {
		if (name.equals("DW_AT_low_pc") || name.equals("DW_AT_high_pc")) {
			if (value instanceof String) {
				return "0x" + Integer.toHexString(position) + ", " + name + ", form=" + form + ", value=0x" + CommonLib.string2long("0x" + value);
			} else {
				return "0x" + Integer.toHexString(position) + ", " + name + ", form=" + form + ", value=0x" + Long.toHexString((Long) value);
			}
		} else {
			return "0x" + Integer.toHexString(position) + ", " + name + ", form=" + form + ", value=" + value;
		}
	}
}
