package com.peterdwarf.dwarf;

import java.util.Hashtable;

public class FrameChunk {
	//String chunk_start;
	public int ncols;
	/* DW_CFA_{undefined,same_value,offset,register,unreferenced}  */
	public long col_type[];
	public long col_offset[];
	public String augmentation = "";
	public int code_factor;
	public int data_factor;
	public long pc_begin;
	public long pc_range;
	public int cfa_reg;
	public long cfa_offset;
	public long ra;
	public int fde_encoding;
	public char cfa_exp;
	public int ptr_size;
	public char segment_size;
	public FrameChunk next;

	public Hashtable<String, Object[]> fieDetails = new Hashtable<String, Object[]>();
}
