package com.peterdwarf.dwarf;

import java.math.BigInteger;

public class DwarfLine implements Comparable {
	public BigInteger address;
	public long file_num;
	public int line_num;
	public long column_num;
	public boolean is_stmt;
	public boolean basic_block;

	@Override
	public int compareTo(Object o) {
		DwarfLine o2 = (DwarfLine) o;
		if (file_num != o2.file_num) {
			return (int) (file_num - o2.file_num);
		} else {
			return line_num - o2.line_num;
		}
	}
}
