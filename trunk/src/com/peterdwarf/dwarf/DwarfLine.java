package com.peterdwarf.dwarf;


public class DwarfLine {
	/**
	 * @uml.property  name="address"
	 */
	public long address;
	/**
	 * @uml.property  name="file_num"
	 */
	public long file_num;
	/**
	 * @uml.property  name="line_num"
	 */
	public int line_num;
	/**
	 * @uml.property  name="column_num"
	 */
	public long column_num;
	/**
	 * @uml.property  name="is_stmt"
	 */
	public boolean is_stmt;
	/**
	 * @uml.property  name="basic_block"
	 */
	public boolean basic_block;
}
