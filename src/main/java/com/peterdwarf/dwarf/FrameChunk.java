package com.peterdwarf.dwarf;

public class FrameChunk {
	String chunk_start;
	int ncols;
	/* DW_CFA_{undefined,same_value,offset,register,unreferenced}  */
	int col_type;
	int col_offset;
	String augmentation;
	int code_factor;
	int data_factor;
	long pc_begin;
	long pc_range;
	int cfa_reg;
	long cfa_offset;
	long ra;
	char fde_encoding;
	char cfa_exp;
	int ptr_size;
	char segment_size;
}
