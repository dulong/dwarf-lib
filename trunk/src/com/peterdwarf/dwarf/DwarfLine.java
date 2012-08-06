package com.peterdwarf.dwarf;

import java.math.BigInteger;

public class DwarfLine {
	public BigInteger address;
	public long file_num;
	public int line_num;
	public long column_num;
	public boolean is_stmt;
	public boolean basic_block;
}
