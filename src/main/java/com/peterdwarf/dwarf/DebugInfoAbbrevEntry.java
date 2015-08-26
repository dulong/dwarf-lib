package com.peterdwarf.dwarf;

import com.peterswing.CommonLib;

public class DebugInfoAbbrevEntry {
	public String name;
	public int form;
	public String formStr;
	public Object value;
	public int position;

	public String toString() {
		if (name.equals("DW_AT_low_pc") || name.equals("DW_AT_high_pc")) {
			if (value instanceof String) {
				return "0x" + Integer.toHexString(position) + ", " + name + ", form=" + form + " (" + formStr + "), value=0x" + CommonLib.string2long("0x" + value);
			} else {
				return "0x" + Integer.toHexString(position) + ", " + name + ", form=" + form + " (" + formStr + "), value=0x" + Long.toHexString((Long) value);
			}
		} else {
			if (form == Definition.DW_FORM_block1) {
				String str = "";
				for (byte b : (byte[]) value) {
					str += Integer.toHexString(b);
					str += " ";
				}
				return "0x" + Integer.toHexString(position) + ", " + name + ", form=" + form + " (" + formStr + "), value=" + str;
			} else {
				return "0x" + Integer.toHexString(position) + ", " + name + ", form=" + form + " (" + formStr + "), value=" + value;
			}
		}
	}
}
