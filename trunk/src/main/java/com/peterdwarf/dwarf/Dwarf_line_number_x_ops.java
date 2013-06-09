package com.peterdwarf.dwarf;

public class Dwarf_line_number_x_ops {
	public static int DW_LNE_end_sequence = 1;
	public static int DW_LNE_set_address = 2;
	public static int DW_LNE_define_file = 3;
	public static int DW_LNE_set_discriminator = 4;
	/* HP extensions.  */
	public static int DW_LNE_HP_negate_is_UV_update = 0x11;
	public static int DW_LNE_HP_push_context = 0x12;
	public static int DW_LNE_HP_pop_context = 0x13;
	public static int DW_LNE_HP_set_file_line_column = 0x14;
	public static int DW_LNE_HP_set_routine_name = 0x15;
	public static int DW_LNE_HP_set_sequence = 0x16;
	public static int DW_LNE_HP_negate_post_semantics = 0x17;
	public static int DW_LNE_HP_negate_function_exit = 0x18;
	public static int DW_LNE_HP_negate_front_end_logical = 0x19;
	public static int DW_LNE_HP_define_proc = 0x20;
	public static int DW_LNE_HP_source_file_correlation = 0x80;

	public static int DW_LNE_lo_user = 0x80;
	public static int DW_LNE_hi_user = 0xff;

}
