package com.peterdwarf.dwarf;

import java.util.Vector;

public class DwarfDebugLineHeader {
	/**
	 * @uml.property  name="total_length"
	 */
	public long total_length;
	/**
	 * @uml.property  name="version"
	 */
	public int version;
	/**
	 * @uml.property  name="prologue_length"
	 */
	public long prologue_length;
	/**
	 * @uml.property  name="minimum_instruction_length"
	 */
	public int minimum_instruction_length;
	/**
	 * @uml.property  name="max_ops_per_insn"
	 */
	public int max_ops_per_insn;
	/**
	 * @uml.property  name="default_is_stmt"
	 */
	public boolean default_is_stmt;
	/**
	 * @uml.property  name="line_base"
	 */
	public byte line_base;
	/**
	 * @uml.property  name="line_range"
	 */
	public int line_range;
	/**
	 * @uml.property  name="opcode_base"
	 */
	public int opcode_base;
	/**
	 * @uml.property  name="standard_opcode_lengths" multiplicity="(0 -1)" dimension="1"
	 */
	public final byte[] standard_opcode_lengths = new byte[12];
	/**
	 * @uml.property  name="dirnames"
	 * @uml.associationEnd  multiplicity="(0 -1)" elementType="java.lang.String"
	 */
	public Vector<String> dirnames = new Vector<String>();
	/**
	 * @uml.property  name="filenames"
	 * @uml.associationEnd  multiplicity="(0 -1)" elementType="com.peterdwarf.dwarf.DwarfHeaderFilename"
	 */
	public Vector<DwarfHeaderFilename> filenames = new Vector<DwarfHeaderFilename>();
	/**
	 * @uml.property  name="lines"
	 * @uml.associationEnd  multiplicity="(0 -1)" elementType="com.peterdwarf.dwarf.DwarfLine"
	 */
	public Vector<DwarfLine> lines = new Vector<DwarfLine>();

}
