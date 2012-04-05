package com.peterdwarf.dwarf;

public class CompileUnit {
	public int length;
	public int version;
	public int abbrev_offset;
	public int addr_size;

	public static final int DW_TAG_array_type = 0x01;
	public static final int DW_TAG_class_type = 0x02;
	public static final int DW_TAG_entry_point = 0x03;
	public static final int DW_TAG_enumeration_type = 0x04;
	public static final int DW_TAG_formal_parameter = 0x05;
	public static final int DW_TAG_imported_declaration = 0x08;
	public static final int DW_TAG_label = 0x0a;
	public static final int DW_TAG_lexical_block = 0x0b;
	public static final int DW_TAG_member = 0x0d;
	public static final int DW_TAG_pointer_type = 0x0f;
	public static final int DW_TAG_reference_type = 0x10;
	public static final int DW_TAG_compile_unit = 0x11;
	public static final int DW_TAG_string_type = 0x12;
	public static final int DW_TAG_structure_type = 0x13;
	public static final int DW_TAG_subroutine_type = 0x15;
	public static final int DW_TAG_typedef = 0x16;
	public static final int DW_TAG_union_type = 0x17;
	public static final int DW_TAG_unspecified_parameters = 0x18;
	public static final int DW_TAG_variant = 0x19;
	public static final int DW_TAG_common_block = 0x1a;
	public static final int DW_TAG_common_inclusion = 0x1b;
	public static final int DW_TAG_inheritance = 0x1c;
	public static final int DW_TAG_inlined_subroutine = 0x1d;
	public static final int DW_TAG_module = 0x1e;
	public static final int DW_TAG_ptr_to_member_type = 0x1f;
	public static final int DW_TAG_set_type = 0x20;
	public static final int DW_TAG_subrange_type = 0x21;
	public static final int DW_TAG_with_stmt = 0x22;
	public static final int DW_TAG_access_declaration = 0x23;
	public static final int DW_TAG_base_type = 0x24;
	public static final int DW_TAG_catch_block = 0x25;
	public static final int DW_TAG_const_type = 0x26;
	public static final int DW_TAG_constant = 0x27;
	public static final int DW_TAG_enumerator = 0x28;
	public static final int DW_TAG_file_type = 0x29;
	public static final int DW_TAG_friend = 0x2a;
	public static final int DW_TAG_namelist = 0x2b;
	/*
	 * Early releases of this header had the following misspelled with a
	 * trailing 's'
	 */
	public static final int DW_TAG_namelist_item = 0x2c; /* DWARF3/2 spelling */
	public static final int DW_TAG_namelist_items = 0x2c; /* SGI misspelling/typo */
	public static final int DW_TAG_packed_type = 0x2d;
	public static final int DW_TAG_subprogram = 0x2e;
	/*
	 * The DWARF2 document had two spellings of the following two TAGs, DWARF3
	 * specifies the longer spelling.
	 */
	public static final int DW_TAG_template_type_parameter = 0x2f; /* DWARF3/2 spelling */
	public static final int DW_TAG_template_type_param = 0x2f; /* DWARF2 spelling */
	public static final int DW_TAG_template_value_parameter = 0x30; /* DWARF3/2 spelling */
	public static final int DW_TAG_template_value_param = 0x30; /* DWARF2 spelling */
	public static final int DW_TAG_thrown_type = 0x31;
	public static final int DW_TAG_try_block = 0x32;
	public static final int DW_TAG_variant_part = 0x33;
	public static final int DW_TAG_variable = 0x34;
	public static final int DW_TAG_volatile_type = 0x35;
	public static final int DW_TAG_dwarf_procedure = 0x36; /* DWARF3 */
	public static final int DW_TAG_restrict_type = 0x37; /* DWARF3 */
	public static final int DW_TAG_interface_type = 0x38; /* DWARF3 */
	public static final int DW_TAG_namespace = 0x39; /* DWARF3 */
	public static final int DW_TAG_imported_module = 0x3a; /* DWARF3 */
	public static final int DW_TAG_unspecified_type = 0x3b; /* DWARF3 */
	public static final int DW_TAG_partial_unit = 0x3c; /* DWARF3 */
	public static final int DW_TAG_imported_unit = 0x3d; /* DWARF3 */
	/* Do not use DW_TAG_mutable_type */
	public static final int DW_TAG_mutable_type = 0x3e; /* Withdrawn from DWARF3 by DWARF3f. */
	public static final int DW_TAG_condition = 0x3f; /* DWARF3f */
	public static final int DW_TAG_shared_type = 0x40; /* DWARF3f */
	public static final int DW_TAG_type_unit = 0x41; /* DWARF4 */
	public static final int DW_TAG_rvalue_reference_type = 0x42; /* DWARF4 */
	public static final int DW_TAG_template_alias = 0x43; /* DWARF4 */
	public static final int DW_TAG_lo_user = 0x4080;

	public static final int DW_TAG_MIPS_loop = 0x4081;

	/* HP extensions: ftp://ftp.hp.com/pub/lang/tools/WDB/wdb-4.0.tar.gz */
	public static final int DW_TAG_HP_array_descriptor = 0x4090; /* HP */

	/* GNU extensions. The first 3 missing the GNU_. */
	public static final int DW_TAG_format_label = 0x4101; /* GNU. Fortran. */
	public static final int DW_TAG_function_template = 0x4102; /* GNU. For C++ */
	public static final int DW_TAG_class_template = 0x4103; /* GNU. For C++ */
	public static final int DW_TAG_GNU_BINCL = 0x4104; /* GNU */
	public static final int DW_TAG_GNU_EINCL = 0x4105; /* GNU */

	/* GNU extension. http://gcc.gnu.org/wiki/TemplateParmsDwarf */
	public static final int DW_TAG_GNU_template_template_parameter = 0x4106; /* GNU */
	public static final int DW_TAG_GNU_template_template_param = 0x4106; /* GNU */
	public static final int DW_TAG_GNU_template_parameter_pack = 0x4107; /* GNU */
	public static final int DW_TAG_GNU_formal_parameter_pack = 0x4108; /* GNU */

	public static final int DW_TAG_GNU_call_site = 0x4109; /* GNU */
	public static final int DW_TAG_GNU_call_site_parameter = 0x410a; /* GNU */

	public static String getTagName(int x) {
		switch (x) {
		case DW_TAG_array_type:
			return "DW_TAG_array_type";
		case DW_TAG_class_type:
			return "DW_TAG_class_type";
		case DW_TAG_entry_point:
			return "DW_TAG_entry_point";
		case DW_TAG_enumeration_type:
			return "DW_TAG_enumeration_type";
		case DW_TAG_formal_parameter:
			return "DW_TAG_formal_parameter";
		case DW_TAG_imported_declaration:
			return "DW_TAG_imported_declaration";
		case DW_TAG_label:
			return "DW_TAG_label";
		case DW_TAG_lexical_block:
			return "DW_TAG_lexical_block";
		case DW_TAG_member:
			return "DW_TAG_member";
		case DW_TAG_pointer_type:
			return "DW_TAG_pointer_type";
		case DW_TAG_reference_type:
			return "DW_TAG_reference_type";
		case DW_TAG_compile_unit:
			return "DW_TAG_compile_unit";
		case DW_TAG_string_type:
			return "DW_TAG_string_type";
		case DW_TAG_structure_type:
			return "DW_TAG_structure_type";
		case DW_TAG_subroutine_type:
			return "DW_TAG_subroutine_type";
		case DW_TAG_typedef:
			return "DW_TAG_typedef";
		case DW_TAG_union_type:
			return "DW_TAG_union_type";
		case DW_TAG_unspecified_parameters:
			return "DW_TAG_unspecified_parameters";
		case DW_TAG_variant:
			return "DW_TAG_variant";
		case DW_TAG_common_block:
			return "DW_TAG_common_block";
		case DW_TAG_common_inclusion:
			return "DW_TAG_common_inclusion";
		case DW_TAG_inheritance:
			return "DW_TAG_inheritance";
		case DW_TAG_inlined_subroutine:
			return "DW_TAG_inlined_subroutine";
		case DW_TAG_module:
			return "DW_TAG_module";
		case DW_TAG_ptr_to_member_type:
			return "DW_TAG_ptr_to_member_type";
		case DW_TAG_set_type:
			return "DW_TAG_set_type";
		case DW_TAG_subrange_type:
			return "DW_TAG_subrange_type";
		case DW_TAG_with_stmt:
			return "DW_TAG_with_stmt";
		case DW_TAG_access_declaration:
			return "DW_TAG_access_declaration";
		case DW_TAG_base_type:
			return "DW_TAG_base_type";
		case DW_TAG_catch_block:
			return "DW_TAG_catch_block";
		case DW_TAG_const_type:
			return "DW_TAG_const_type";
		case DW_TAG_constant:
			return "DW_TAG_constant";
		case DW_TAG_enumerator:
			return "DW_TAG_enumerator";
		case DW_TAG_file_type:
			return "DW_TAG_file_type";
		case DW_TAG_friend:
			return "DW_TAG_friend";
		case DW_TAG_namelist:
			return "DW_TAG_namelist";
		case DW_TAG_namelist_item:
			return "DW_TAG_namelist_item";
		case DW_TAG_packed_type:
			return "DW_TAG_packed_type";
		case DW_TAG_subprogram:
			return "DW_TAG_subprogram";
		case DW_TAG_template_type_parameter:
			return "DW_TAG_template_type_parameter";
		case DW_TAG_template_value_parameter:
			return "DW_TAG_template_value_parameter";
		case DW_TAG_thrown_type:
			return "DW_TAG_thrown_type";
		case DW_TAG_try_block:
			return "DW_TAG_try_block";
		case DW_TAG_variant_part:
			return "DW_TAG_variant_part";
		case DW_TAG_variable:
			return "DW_TAG_variable";
		case DW_TAG_volatile_type:
			return "DW_TAG_volatile_type";
		case DW_TAG_dwarf_procedure:
			return "DW_TAG_dwarf_procedure";
		case DW_TAG_restrict_type:
			return "DW_TAG_restrict_type";
		case DW_TAG_interface_type:
			return "DW_TAG_interface_type";
		case DW_TAG_namespace:
			return "DW_TAG_namespace";
		case DW_TAG_imported_module:
			return "DW_TAG_imported_module";
		case DW_TAG_unspecified_type:
			return "DW_TAG_unspecified_type";
		case DW_TAG_partial_unit:
			return "DW_TAG_partial_unit";
		case DW_TAG_imported_unit:
			return "DW_TAG_imported_unit";

		case DW_TAG_mutable_type:
			return "DW_TAG_mutable_type";
		case DW_TAG_condition:
			return "DW_TAG_condition";
		case DW_TAG_shared_type:
			return "DW_TAG_shared_type";
		case DW_TAG_type_unit:
			return "DW_TAG_type_unit";
		case DW_TAG_rvalue_reference_type:
			return "DW_TAG_rvalue_reference_type";
		case DW_TAG_template_alias:
			return "DW_TAG_template_alias";
		case DW_TAG_lo_user:
			return "DW_TAG_lo_user";
		case DW_TAG_MIPS_loop:
			return "DW_TAG_MIPS_loop";
		case DW_TAG_HP_array_descriptor:
			return "DW_TAG_HP_array_descriptor";
		case DW_TAG_format_label:
			return "DW_TAG_format_label";
		case DW_TAG_function_template:
			return "DW_TAG_function_template";
		case DW_TAG_class_template:
			return "DW_TAG_class_template";
		case DW_TAG_GNU_BINCL:
			return "DW_TAG_GNU_BINCL";
		case DW_TAG_GNU_EINCL:
			return "DW_TAG_GNU_EINCL";
		case DW_TAG_GNU_template_template_parameter:
			return "DW_TAG_GNU_template_template_parameter";
		case DW_TAG_GNU_template_parameter_pack:
			return "DW_TAG_GNU_template_parameter_pack";
		case DW_TAG_GNU_formal_parameter_pack:
			return "DW_TAG_GNU_formal_parameter_pack";
		case DW_TAG_GNU_call_site:
			return "DW_TAG_GNU_call_site";
		case DW_TAG_GNU_call_site_parameter:
			return "DW_TAG_GNU_call_site_parameter";
		default:
			return null;
		}
	}

	/////////////////////////////////////////////////////////////////////////////
	public static final int DW_AT_sibling = 0x0001;
	public static final int DW_AT_location = 0x0002;
	public static final int DW_AT_name = 0x0003;
	public static final int DW_AT_ordering = 0x0009;
	public static final int DW_AT_subscr_data = 0x000a;
	public static final int DW_AT_byte_size = 0x000b;
	public static final int DW_AT_bit_offset = 0x000c;
	public static final int DW_AT_bit_size = 0x000d;
	public static final int DW_AT_element_list = 0x000f;
	public static final int DW_AT_stmt_list = 0x0010;
	public static final int DW_AT_low_pc = 0x0011;
	public static final int DW_AT_high_pc = 0x0012;
	public static final int DW_AT_language = 0x0013;
	public static final int DW_AT_member = 0x0014;
	public static final int DW_AT_discr = 0x0015;
	public static final int DW_AT_discr_value = 0x0016;
	public static final int DW_AT_visibility = 0x0017;
	public static final int DW_AT_import = 0x0018;
	public static final int DW_AT_string_length = 0x0019;
	public static final int DW_AT_common_reference = 0x001a;
	public static final int DW_AT_comp_dir = 0x001b;
	public static final int DW_AT_const_value = 0x001c;
	public static final int DW_AT_containing_type = 0x001d;
	public static final int DW_AT_default_value = 0x001e;
	public static final int DW_AT_inline = 0x0020;
	public static final int DW_AT_is_optional = 0x0021;
	public static final int DW_AT_lower_bound = 0x0022;
	public static final int DW_AT_producer = 0x0025;
	public static final int DW_AT_prototyped = 0x0027;
	public static final int DW_AT_return_addr = 0x002a;
	public static final int DW_AT_start_scope = 0x002c;
	public static final int DW_AT_bit_stride = 0x002e;
	public static final int DW_AT_upper_bound = 0x002f;
	public static final int DW_AT_abstract_origin = 0x0031;
	public static final int DW_AT_accessibility = 0x0032;
	public static final int DW_AT_address_class = 0x0033;
	public static final int DW_AT_artificial = 0x0034;
	public static final int DW_AT_base_types = 0x0035;
	public static final int DW_AT_calling_convention = 0x0036;
	public static final int DW_AT_count = 0x0037;
	public static final int DW_AT_data_member_location = 0x0038;
	public static final int DW_AT_decl_column = 0x0039;
	public static final int DW_AT_decl_file = 0x003a;
	public static final int DW_AT_decl_line = 0x003b;
	public static final int DW_AT_declaration = 0x003c;
	public static final int DW_AT_discr_list = 0x003d;
	public static final int DW_AT_encoding = 0x003e;
	public static final int DW_AT_external = 0x003f;
	public static final int DW_AT_frame_base = 0x0040;
	public static final int DW_AT_friend = 0x0041;
	public static final int DW_AT_identifier_case = 0x0042;
	public static final int DW_AT_macro_info = 0x0043;
	public static final int DW_AT_namelist_item = 0x0044;
	public static final int DW_AT_priority = 0x0045;
	public static final int DW_AT_segment = 0x0046;
	public static final int DW_AT_specification = 0x0047;
	public static final int DW_AT_static_link = 0x0048;
	public static final int DW_AT_type = 0x0049;
	public static final int DW_AT_use_location = 0x004a;
	public static final int DW_AT_variable_parameter = 0x004b;
	public static final int DW_AT_virtuality = 0x004c;
	public static final int DW_AT_vtable_elem_location = 0x004d;
	public static final int DW_AT_allocated = 0x004e;
	public static final int DW_AT_associated = 0x004f;
	public static final int DW_AT_data_location = 0x0050;
	public static final int DW_AT_byte_stride = 0x0051;
	public static final int DW_AT_entry_pc = 0x0052;
	public static final int DW_AT_use_UTF8 = 0x0053;
	public static final int DW_AT_extension = 0x0054;
	public static final int DW_AT_ranges = 0x0055;
	public static final int DW_AT_trampoline = 0x0056;
	public static final int DW_AT_call_column = 0x0057;
	public static final int DW_AT_call_file = 0x0058;
	public static final int DW_AT_call_line = 0x0059;
	public static final int DW_AT_description = 0x005a;
	public static final int DW_AT_binary_scale = 0x005b;
	public static final int DW_AT_decimal_scale = 0x005c;
	public static final int DW_AT_small = 0x005d;
	public static final int DW_AT_decimal_sign = 0x005e;
	public static final int DW_AT_digit_count = 0x005f;
	public static final int DW_AT_picture_string = 0x0060;
	public static final int DW_AT_mutable = 0x0061;
	public static final int DW_AT_threads_scaled = 0x0062;
	public static final int DW_AT_explicit = 0x0063;
	public static final int DW_AT_object_pointer = 0x0064;
	public static final int DW_AT_endianity = 0x0065;
	public static final int DW_AT_elemental = 0x0066;
	public static final int DW_AT_pure = 0x0067;
	public static final int DW_AT_recursive = 0x0068;
	public static final int DW_AT_signature = 0x0069;
	public static final int DW_AT_main_subprogram = 0x006a;
	public static final int DW_AT_data_bit_offset = 0x006b;
	public static final int DW_AT_const_expr = 0x006c;
	public static final int DW_AT_enum_class = 0x006d;
	public static final int DW_AT_linkage_name = 0x006e;
	public static final int DW_AT_HP_block_index = 0x2000;
	public static final int DW_AT_MIPS_fde = 0x2001;
	public static final int DW_AT_CPQ_semantic_events = 0x2002;
	public static final int DW_AT_MIPS_tail_loop_begin = 0x2003;
	public static final int DW_AT_CPQ_split_lifetimes_rtn = 0x2004;
	public static final int DW_AT_MIPS_loop_unroll_factor = 0x2005;
	public static final int DW_AT_MIPS_software_pipeline_depth = 0x2006;
	public static final int DW_AT_MIPS_linkage_name = 0x2007;
	public static final int DW_AT_MIPS_stride = 0x2008;
	public static final int DW_AT_MIPS_abstract_name = 0x2009;
	public static final int DW_AT_MIPS_clone_origin = 0x200a;
	public static final int DW_AT_MIPS_has_inlines = 0x200b;
	public static final int DW_AT_MIPS_stride_byte = 0x200c;
	public static final int DW_AT_MIPS_stride_elem = 0x200d;
	public static final int DW_AT_MIPS_ptr_dopetype = 0x200e;
	public static final int DW_AT_MIPS_allocatable_dopetype = 0x200f;
	public static final int DW_AT_MIPS_assumed_shape_dopetype = 0x2010;
	public static final int DW_AT_HP_proc_per_section = 0x2011;
	public static final int DW_AT_HP_raw_data_ptr = 0x2012;
	public static final int DW_AT_HP_pass_by_reference = 0x2013;
	public static final int DW_AT_HP_opt_level = 0x2014;
	public static final int DW_AT_HP_prof_version_id = 0x2015;
	public static final int DW_AT_HP_opt_flags = 0x2016;
	public static final int DW_AT_HP_cold_region_low_pc = 0x2017;
	public static final int DW_AT_HP_cold_region_high_pc = 0x2018;
	public static final int DW_AT_HP_all_variables_modifiable = 0x2019;
	public static final int DW_AT_HP_linkage_name = 0x201a;
	public static final int DW_AT_HP_prof_flags = 0x201b;
	public static final int DW_AT_INTEL_other_endian = 0x2026;
	public static final int DW_AT_sf_names = 0x2101;
	public static final int DW_AT_src_info = 0x2102;
	public static final int DW_AT_mac_info = 0x2103;
	public static final int DW_AT_src_coords = 0x2104;
	public static final int DW_AT_body_begin = 0x2105;
	public static final int DW_AT_body_end = 0x2106;
	public static final int DW_AT_GNU_vector = 0x2107;
	public static final int DW_AT_GNU_guarded_by = 0x2108;
	public static final int DW_AT_GNU_pt_guarded_by = 0x2109;
	public static final int DW_AT_GNU_guarded = 0x210a;
	public static final int DW_AT_GNU_pt_guarded = 0x210b;
	public static final int DW_AT_GNU_locks_excluded = 0x210c;
	public static final int DW_AT_GNU_exclusive_locks_required = 0x210d;
	public static final int DW_AT_GNU_shared_locks_required = 0x210e;
	public static final int DW_AT_GNU_odr_signature = 0x210f;
	public static final int DW_AT_GNU_template_name = 0x2110;
	public static final int DW_AT_GNU_call_site_value = 0x2111;
	public static final int DW_AT_GNU_call_site_data_value = 0x2112;
	public static final int DW_AT_GNU_call_site_target = 0x2113;
	public static final int DW_AT_GNU_call_site_target_clobbered = 0x2114;
	public static final int DW_AT_GNU_tail_call = 0x2115;
	public static final int DW_AT_GNU_all_tail_call_sites = 0x2116;
	public static final int DW_AT_GNU_all_call_sites = 0x2117;
	public static final int DW_AT_GNU_all_source_call_sites = 0x2118;
	public static final int DW_AT_SUN_template = 0x2201;
	public static final int DW_AT_SUN_alignment = 0x2202;
	public static final int DW_AT_SUN_vtable = 0x2203;
	public static final int DW_AT_SUN_count_guarantee = 0x2204;
	public static final int DW_AT_SUN_command_line = 0x2205;
	public static final int DW_AT_SUN_vbase = 0x2206;
	public static final int DW_AT_SUN_compile_options = 0x2207;
	public static final int DW_AT_SUN_language = 0x2208;
	public static final int DW_AT_SUN_browser_file = 0x2209;
	public static final int DW_AT_SUN_vtable_abi = 0x2210;
	public static final int DW_AT_SUN_func_offsets = 0x2211;
	public static final int DW_AT_SUN_cf_kind = 0x2212;
	public static final int DW_AT_SUN_vtable_index = 0x2213;
	public static final int DW_AT_SUN_omp_tpriv_addr = 0x2214;
	public static final int DW_AT_SUN_omp_child_func = 0x2215;
	public static final int DW_AT_SUN_func_offset = 0x2216;
	public static final int DW_AT_SUN_memop_type_ref = 0x2217;
	public static final int DW_AT_SUN_profile_id = 0x2218;
	public static final int DW_AT_SUN_memop_signature = 0x2219;
	public static final int DW_AT_SUN_obj_dir = 0x2220;
	public static final int DW_AT_SUN_obj_file = 0x2221;
	public static final int DW_AT_SUN_original_name = 0x2222;
	public static final int DW_AT_SUN_hwcprof_signature = 0x2223;
	public static final int DW_AT_SUN_amd64_parmdump = 0x2224;
	public static final int DW_AT_SUN_part_link_name = 0x2225;
	public static final int DW_AT_SUN_link_name = 0x2226;
	public static final int DW_AT_SUN_pass_with_const = 0x2227;
	public static final int DW_AT_SUN_return_with_const = 0x2228;
	public static final int DW_AT_SUN_import_by_name = 0x2229;
	public static final int DW_AT_SUN_f90_pointer = 0x222a;
	public static final int DW_AT_SUN_pass_by_ref = 0x222b;
	public static final int DW_AT_SUN_f90_allocatable = 0x222c;
	public static final int DW_AT_SUN_f90_assumed_shape_array = 0x222d;
	public static final int DW_AT_SUN_c_vla = 0x222e;
	public static final int DW_AT_SUN_return_value_ptr = 0x2230;
	public static final int DW_AT_SUN_dtor_start = 0x2231;
	public static final int DW_AT_SUN_dtor_length = 0x2232;
	public static final int DW_AT_SUN_dtor_state_initial = 0x2233;
	public static final int DW_AT_SUN_dtor_state_final = 0x2234;
	public static final int DW_AT_SUN_dtor_state_deltas = 0x2235;
	public static final int DW_AT_SUN_import_by_lname = 0x2236;
	public static final int DW_AT_SUN_f90_use_only = 0x2237;
	public static final int DW_AT_SUN_namelist_spec = 0x2238;
	public static final int DW_AT_SUN_is_omp_child_func = 0x2239;
	public static final int DW_AT_SUN_fortran_main_alias = 0x223a;
	public static final int DW_AT_SUN_fortran_based = 0x223b;
	public static final int DW_AT_ALTIUM_loclist = 0x2300;
	public static final int DW_AT_use_GNAT_descriptive_type = 0x2301;
	public static final int DW_AT_GNAT_descriptive_type = 0x2302;
	public static final int DW_AT_upc_threads_scaled = 0x3210;
	public static final int DW_AT_PGI_lbase = 0x3a00;
	public static final int DW_AT_PGI_soffset = 0x3a01;
	public static final int DW_AT_PGI_lstride = 0x3a02;
	public static final int DW_AT_APPLE_optimized = 0x3fe1;
	public static final int DW_AT_APPLE_flags = 0x3fe2;
	public static final int DW_AT_APPLE_isa = 0x3fe3;
	public static final int DW_AT_APPLE_block = 0x3fe4;
	public static final int DW_AT_APPLE_major_runtime_vers = 0x3fe5;
	public static final int DW_AT_APPLE_runtime_class = 0x3fe6;
	public static final int DW_AT_APPLE_omit_frame_ptr = 0x3fe7;
	public static final int DW_AT_hi_user = 0x3fff;

	public static final int DW_FORM_addr = 0x0001;
	public static final int DW_FORM_block2 = 0x0003;
	public static final int DW_FORM_block4 = 0x0004;
	public static final int DW_FORM_data2 = 0x0005;
	public static final int DW_FORM_data4 = 0x0006;
	public static final int DW_FORM_data8 = 0x0007;
	public static final int DW_FORM_string = 0x0008;
	public static final int DW_FORM_block = 0x0009;
	public static final int DW_FORM_block1 = 0x000a;
	public static final int DW_FORM_data1 = 0x000b;
	public static final int DW_FORM_flag = 0x000c;
	public static final int DW_FORM_sdata = 0x000d;
	public static final int DW_FORM_strp = 0x000e;
	public static final int DW_FORM_udata = 0x000f;
	public static final int DW_FORM_ref_addr = 0x0010;
	public static final int DW_FORM_ref1 = 0x0011;
	public static final int DW_FORM_ref2 = 0x0012;
	public static final int DW_FORM_ref4 = 0x0013;
	public static final int DW_FORM_ref8 = 0x0014;
	public static final int DW_FORM_ref_udata = 0x0015;
	public static final int DW_FORM_indirect = 0x0016;
	public static final int DW_FORM_sec_offset = 0x0017;
	public static final int DW_FORM_exprloc = 0x0018;
	public static final int DW_FORM_flag_present = 0x0019;
	public static final int DW_FORM_ref_sig8 = 0x0020;

	public static String getFormName(int x) {
		switch (x) {
		case DW_FORM_addr:
			return "DW_FORM_addr";
		case DW_FORM_block2:
			return "DW_FORM_block2";
		case DW_FORM_block4:
			return "DW_FORM_block4";
		case DW_FORM_data2:
			return "DW_FORM_data2";
		case DW_FORM_data4:
			return "DW_FORM_data4";
		case DW_FORM_data8:
			return "DW_FORM_data8";
		case DW_FORM_string:
			return "DW_FORM_string";
		case DW_FORM_block:
			return "DW_FORM_block";
		case DW_FORM_block1:
			return "DW_FORM_block1";
		case DW_FORM_data1:
			return "DW_FORM_data1";
		case DW_FORM_flag:
			return "DW_FORM_flag";
		case DW_FORM_sdata:
			return "DW_FORM_sdata";
		case DW_FORM_strp:
			return "DW_FORM_strp";
		case DW_FORM_udata:
			return "DW_FORM_udata";
		case DW_FORM_ref_addr:
			return "DW_FORM_ref_addr";
		case DW_FORM_ref1:
			return "DW_FORM_ref1";
		case DW_FORM_ref2:
			return "DW_FORM_ref2";
		case DW_FORM_ref4:
			return "DW_FORM_ref4";
		case DW_FORM_ref8:
			return "DW_FORM_ref8";
		case DW_FORM_ref_udata:
			return "DW_FORM_ref_udata";
		case DW_FORM_indirect:
			return "DW_FORM_indirect";
		case DW_FORM_sec_offset:
			return "DW_FORM_sec_offset";
		case DW_FORM_exprloc:
			return "DW_FORM_exprloc";
		case DW_FORM_flag_present:
			return "DW_FORM_flag_present";
		case DW_FORM_ref_sig8:
			return "DW_FORM_ref_sig8";
		default:
			return null;
		}
	}

	public static String getATname(int x) {
		switch (x) {
		case DW_AT_sibling:
			return "DW_AT_sibling";
		case DW_AT_location:
			return "DW_AT_location";
		case DW_AT_name:
			return "DW_AT_name";
		case DW_AT_ordering:
			return "DW_AT_ordering";
		case DW_AT_subscr_data:
			return "DW_AT_subscr_data";
		case DW_AT_byte_size:
			return "DW_AT_byte_size";
		case DW_AT_bit_offset:
			return "DW_AT_bit_offset";
		case DW_AT_bit_size:
			return "DW_AT_bit_size";
		case DW_AT_element_list:
			return "DW_AT_element_list";
		case DW_AT_stmt_list:
			return "DW_AT_stmt_list";
		case DW_AT_low_pc:
			return "DW_AT_low_pc";
		case DW_AT_high_pc:
			return "DW_AT_high_pc";
		case DW_AT_language:
			return "DW_AT_language";
		case DW_AT_member:
			return "DW_AT_member";
		case DW_AT_discr:
			return "DW_AT_discr";
		case DW_AT_discr_value:
			return "DW_AT_discr_value";
		case DW_AT_visibility:
			return "DW_AT_visibility";
		case DW_AT_import:
			return "DW_AT_import";
		case DW_AT_string_length:
			return "DW_AT_string_length";
		case DW_AT_common_reference:
			return "DW_AT_common_reference";
		case DW_AT_comp_dir:
			return "DW_AT_comp_dir";
		case DW_AT_const_value:
			return "DW_AT_const_value";
		case DW_AT_containing_type:
			return "DW_AT_containing_type";
		case DW_AT_default_value:
			return "DW_AT_default_value";
		case DW_AT_inline:
			return "DW_AT_inline";
		case DW_AT_is_optional:
			return "DW_AT_is_optional";
		case DW_AT_lower_bound:
			return "DW_AT_lower_bound";
		case DW_AT_producer:
			return "DW_AT_producer";
		case DW_AT_prototyped:
			return "DW_AT_prototyped";
		case DW_AT_return_addr:
			return "DW_AT_return_addr";
		case DW_AT_start_scope:
			return "DW_AT_start_scope";
		case DW_AT_bit_stride:
			return "DW_AT_bit_stride";
		case DW_AT_upper_bound:
			return "DW_AT_upper_bound";
		case DW_AT_abstract_origin:
			return "DW_AT_abstract_origin";
		case DW_AT_accessibility:
			return "DW_AT_accessibility";
		case DW_AT_address_class:
			return "DW_AT_address_class";
		case DW_AT_artificial:
			return "DW_AT_artificial";
		case DW_AT_base_types:
			return "DW_AT_base_types";
		case DW_AT_calling_convention:
			return "DW_AT_calling_convention";
		case DW_AT_count:
			return "DW_AT_count";
		case DW_AT_data_member_location:
			return "DW_AT_data_member_location";
		case DW_AT_decl_column:
			return "DW_AT_decl_column";
		case DW_AT_decl_file:
			return "DW_AT_decl_file";
		case DW_AT_decl_line:
			return "DW_AT_decl_line";
		case DW_AT_declaration:
			return "DW_AT_declaration";
		case DW_AT_discr_list:
			return "DW_AT_discr_list";
		case DW_AT_encoding:
			return "DW_AT_encoding";
		case DW_AT_external:
			return "DW_AT_external";
		case DW_AT_frame_base:
			return "DW_AT_frame_base";
		case DW_AT_friend:
			return "DW_AT_friend";
		case DW_AT_identifier_case:
			return "DW_AT_identifier_case";
		case DW_AT_macro_info:
			return "DW_AT_macro_info";
		case DW_AT_namelist_item:
			return "DW_AT_namelist_item";
		case DW_AT_priority:
			return "DW_AT_priority";
		case DW_AT_segment:
			return "DW_AT_segment";
		case DW_AT_specification:
			return "DW_AT_specification";
		case DW_AT_static_link:
			return "DW_AT_static_link";
		case DW_AT_type:
			return "DW_AT_type";
		case DW_AT_use_location:
			return "DW_AT_use_location";
		case DW_AT_variable_parameter:
			return "DW_AT_variable_parameter";
		case DW_AT_virtuality:
			return "DW_AT_virtuality";
		case DW_AT_vtable_elem_location:
			return "DW_AT_vtable_elem_location";
		case DW_AT_allocated:
			return "DW_AT_allocated";
		case DW_AT_associated:
			return "DW_AT_associated";
		case DW_AT_data_location:
			return "DW_AT_data_location";
		case DW_AT_byte_stride:
			return "DW_AT_byte_stride";
		case DW_AT_entry_pc:
			return "DW_AT_entry_pc";
		case DW_AT_use_UTF8:
			return "DW_AT_use_UTF8";
		case DW_AT_extension:
			return "DW_AT_extension";
		case DW_AT_ranges:
			return "DW_AT_ranges";
		case DW_AT_trampoline:
			return "DW_AT_trampoline";
		case DW_AT_call_column:
			return "DW_AT_call_column";
		case DW_AT_call_file:
			return "DW_AT_call_file";
		case DW_AT_call_line:
			return "DW_AT_call_line";
		case DW_AT_description:
			return "DW_AT_description";
		case DW_AT_binary_scale:
			return "DW_AT_binary_scale";
		case DW_AT_decimal_scale:
			return "DW_AT_decimal_scale";
		case DW_AT_small:
			return "DW_AT_small";
		case DW_AT_decimal_sign:
			return "DW_AT_decimal_sign";
		case DW_AT_digit_count:
			return "DW_AT_digit_count";
		case DW_AT_picture_string:
			return "DW_AT_picture_string";
		case DW_AT_mutable:
			return "DW_AT_mutable";
		case DW_AT_threads_scaled:
			return "DW_AT_threads_scaled";
		case DW_AT_explicit:
			return "DW_AT_explicit";
		case DW_AT_object_pointer:
			return "DW_AT_object_pointer";
		case DW_AT_endianity:
			return "DW_AT_endianity";
		case DW_AT_elemental:
			return "DW_AT_elemental";
		case DW_AT_pure:
			return "DW_AT_pure";
		case DW_AT_recursive:
			return "DW_AT_recursive";
		case DW_AT_signature:
			return "DW_AT_signature";
		case DW_AT_main_subprogram:
			return "DW_AT_main_subprogram";
		case DW_AT_data_bit_offset:
			return "DW_AT_data_bit_offset";
		case DW_AT_const_expr:
			return "DW_AT_const_expr";
		case DW_AT_enum_class:
			return "DW_AT_enum_class";
		case DW_AT_linkage_name:
			return "DW_AT_linkage_name";
		case DW_AT_HP_block_index:
			return "DW_AT_HP_block_index";
		case DW_AT_MIPS_fde:
			return "DW_AT_MIPS_fde";
		case DW_AT_CPQ_semantic_events:
			return "DW_AT_CPQ_semantic_events";
		case DW_AT_MIPS_tail_loop_begin:
			return "DW_AT_MIPS_tail_loop_begin";
		case DW_AT_CPQ_split_lifetimes_rtn:
			return "DW_AT_CPQ_split_lifetimes_rtn";
		case DW_AT_MIPS_loop_unroll_factor:
			return "DW_AT_MIPS_loop_unroll_factor";
		case DW_AT_MIPS_software_pipeline_depth:
			return "DW_AT_MIPS_software_pipeline_depth";
		case DW_AT_MIPS_linkage_name:
			return "DW_AT_MIPS_linkage_name";
		case DW_AT_MIPS_stride:
			return "DW_AT_MIPS_stride";
		case DW_AT_MIPS_abstract_name:
			return "DW_AT_MIPS_abstract_name";
		case DW_AT_MIPS_clone_origin:
			return "DW_AT_MIPS_clone_origin";
		case DW_AT_MIPS_has_inlines:
			return "DW_AT_MIPS_has_inlines";
		case DW_AT_MIPS_stride_byte:
			return "DW_AT_MIPS_stride_byte";
		case DW_AT_MIPS_stride_elem:
			return "DW_AT_MIPS_stride_elem";
		case DW_AT_MIPS_ptr_dopetype:
			return "DW_AT_MIPS_ptr_dopetype";
		case DW_AT_MIPS_allocatable_dopetype:
			return "DW_AT_MIPS_allocatable_dopetype";
		case DW_AT_MIPS_assumed_shape_dopetype:
			return "DW_AT_MIPS_assumed_shape_dopetype";
		case DW_AT_HP_proc_per_section:
			return "DW_AT_HP_proc_per_section";
		case DW_AT_HP_raw_data_ptr:
			return "DW_AT_HP_raw_data_ptr";
		case DW_AT_HP_pass_by_reference:
			return "DW_AT_HP_pass_by_reference";
		case DW_AT_HP_opt_level:
			return "DW_AT_HP_opt_level";
		case DW_AT_HP_prof_version_id:
			return "DW_AT_HP_prof_version_id";
		case DW_AT_HP_opt_flags:
			return "DW_AT_HP_opt_flags";
		case DW_AT_HP_cold_region_low_pc:
			return "DW_AT_HP_cold_region_low_pc";
		case DW_AT_HP_cold_region_high_pc:
			return "DW_AT_HP_cold_region_high_pc";
		case DW_AT_HP_all_variables_modifiable:
			return "DW_AT_HP_all_variables_modifiable";
		case DW_AT_HP_linkage_name:
			return "DW_AT_HP_linkage_name";
		case DW_AT_HP_prof_flags:
			return "DW_AT_HP_prof_flags";
		case DW_AT_INTEL_other_endian:
			return "DW_AT_INTEL_other_endian";
		case DW_AT_sf_names:
			return "DW_AT_sf_names";
		case DW_AT_src_info:
			return "DW_AT_src_info";
		case DW_AT_mac_info:
			return "DW_AT_mac_info";
		case DW_AT_src_coords:
			return "DW_AT_src_coords";
		case DW_AT_body_begin:
			return "DW_AT_body_begin";
		case DW_AT_body_end:
			return "DW_AT_body_end";
		case DW_AT_GNU_vector:
			return "DW_AT_GNU_vector";
		case DW_AT_GNU_guarded_by:
			return "DW_AT_GNU_guarded_by";
		case DW_AT_GNU_pt_guarded_by:
			return "DW_AT_GNU_pt_guarded_by";
		case DW_AT_GNU_guarded:
			return "DW_AT_GNU_guarded";
		case DW_AT_GNU_pt_guarded:
			return "DW_AT_GNU_pt_guarded";
		case DW_AT_GNU_locks_excluded:
			return "DW_AT_GNU_locks_excluded";
		case DW_AT_GNU_exclusive_locks_required:
			return "DW_AT_GNU_exclusive_locks_required";
		case DW_AT_GNU_shared_locks_required:
			return "DW_AT_GNU_shared_locks_required";
		case DW_AT_GNU_odr_signature:
			return "DW_AT_GNU_odr_signature";
		case DW_AT_GNU_template_name:
			return "DW_AT_GNU_template_name";
		case DW_AT_GNU_call_site_value:
			return "DW_AT_GNU_call_site_value";
		case DW_AT_GNU_call_site_data_value:
			return "DW_AT_GNU_call_site_data_value";
		case DW_AT_GNU_call_site_target:
			return "DW_AT_GNU_call_site_target";
		case DW_AT_GNU_call_site_target_clobbered:
			return "DW_AT_GNU_call_site_target_clobbered";
		case DW_AT_GNU_tail_call:
			return "DW_AT_GNU_tail_call";
		case DW_AT_GNU_all_tail_call_sites:
			return "DW_AT_GNU_all_tail_call_sites";
		case DW_AT_GNU_all_call_sites:
			return "DW_AT_GNU_all_call_sites";
		case DW_AT_GNU_all_source_call_sites:
			return "DW_AT_GNU_all_source_call_sites";
		case DW_AT_SUN_template:
			return "DW_AT_SUN_template";
		case DW_AT_SUN_alignment:
			return "DW_AT_SUN_alignment";
		case DW_AT_SUN_vtable:
			return "DW_AT_SUN_vtable";
		case DW_AT_SUN_count_guarantee:
			return "DW_AT_SUN_count_guarantee";
		case DW_AT_SUN_command_line:
			return "DW_AT_SUN_command_line";
		case DW_AT_SUN_vbase:
			return "DW_AT_SUN_vbase";
		case DW_AT_SUN_compile_options:
			return "DW_AT_SUN_compile_options";
		case DW_AT_SUN_language:
			return "DW_AT_SUN_language";
		case DW_AT_SUN_browser_file:
			return "DW_AT_SUN_browser_file";
		case DW_AT_SUN_vtable_abi:
			return "DW_AT_SUN_vtable_abi";
		case DW_AT_SUN_func_offsets:
			return "DW_AT_SUN_func_offsets";
		case DW_AT_SUN_cf_kind:
			return "DW_AT_SUN_cf_kind";
		case DW_AT_SUN_vtable_index:
			return "DW_AT_SUN_vtable_index";
		case DW_AT_SUN_omp_tpriv_addr:
			return "DW_AT_SUN_omp_tpriv_addr";
		case DW_AT_SUN_omp_child_func:
			return "DW_AT_SUN_omp_child_func";
		case DW_AT_SUN_func_offset:
			return "DW_AT_SUN_func_offset";
		case DW_AT_SUN_memop_type_ref:
			return "DW_AT_SUN_memop_type_ref";
		case DW_AT_SUN_profile_id:
			return "DW_AT_SUN_profile_id";
		case DW_AT_SUN_memop_signature:
			return "DW_AT_SUN_memop_signature";
		case DW_AT_SUN_obj_dir:
			return "DW_AT_SUN_obj_dir";
		case DW_AT_SUN_obj_file:
			return "DW_AT_SUN_obj_file";
		case DW_AT_SUN_original_name:
			return "DW_AT_SUN_original_name";
		case DW_AT_SUN_hwcprof_signature:
			return "DW_AT_SUN_hwcprof_signature";
		case DW_AT_SUN_amd64_parmdump:
			return "DW_AT_SUN_amd64_parmdump";
		case DW_AT_SUN_part_link_name:
			return "DW_AT_SUN_part_link_name";
		case DW_AT_SUN_link_name:
			return "DW_AT_SUN_link_name";
		case DW_AT_SUN_pass_with_const:
			return "DW_AT_SUN_pass_with_const";
		case DW_AT_SUN_return_with_const:
			return "DW_AT_SUN_return_with_const";
		case DW_AT_SUN_import_by_name:
			return "DW_AT_SUN_import_by_name";
		case DW_AT_SUN_f90_pointer:
			return "DW_AT_SUN_f90_pointer";
		case DW_AT_SUN_pass_by_ref:
			return "DW_AT_SUN_pass_by_ref";
		case DW_AT_SUN_f90_allocatable:
			return "DW_AT_SUN_f90_allocatable";
		case DW_AT_SUN_f90_assumed_shape_array:
			return "DW_AT_SUN_f90_assumed_shape_array";
		case DW_AT_SUN_c_vla:
			return "DW_AT_SUN_c_vla";
		case DW_AT_SUN_return_value_ptr:
			return "DW_AT_SUN_return_value_ptr";
		case DW_AT_SUN_dtor_start:
			return "DW_AT_SUN_dtor_start";
		case DW_AT_SUN_dtor_length:
			return "DW_AT_SUN_dtor_length";
		case DW_AT_SUN_dtor_state_initial:
			return "DW_AT_SUN_dtor_state_initial";
		case DW_AT_SUN_dtor_state_final:
			return "DW_AT_SUN_dtor_state_final";
		case DW_AT_SUN_dtor_state_deltas:
			return "DW_AT_SUN_dtor_state_deltas";
		case DW_AT_SUN_import_by_lname:
			return "DW_AT_SUN_import_by_lname";
		case DW_AT_SUN_f90_use_only:
			return "DW_AT_SUN_f90_use_only";
		case DW_AT_SUN_namelist_spec:
			return "DW_AT_SUN_namelist_spec";
		case DW_AT_SUN_is_omp_child_func:
			return "DW_AT_SUN_is_omp_child_func";
		case DW_AT_SUN_fortran_main_alias:
			return "DW_AT_SUN_fortran_main_alias";
		case DW_AT_SUN_fortran_based:
			return "DW_AT_SUN_fortran_based";
		case DW_AT_ALTIUM_loclist:
			return "DW_AT_ALTIUM_loclist";
		case DW_AT_use_GNAT_descriptive_type:
			return "DW_AT_use_GNAT_descriptive_type";
		case DW_AT_GNAT_descriptive_type:
			return "DW_AT_GNAT_descriptive_type";
		case DW_AT_upc_threads_scaled:
			return "DW_AT_upc_threads_scaled";
		case DW_AT_PGI_lbase:
			return "DW_AT_PGI_lbase";
		case DW_AT_PGI_soffset:
			return "DW_AT_PGI_soffset";
		case DW_AT_PGI_lstride:
			return "DW_AT_PGI_lstride";
		case DW_AT_APPLE_optimized:
			return "DW_AT_APPLE_optimized";
		case DW_AT_APPLE_flags:
			return "DW_AT_APPLE_flags";
		case DW_AT_APPLE_isa:
			return "DW_AT_APPLE_isa";
		case DW_AT_APPLE_block:
			return "DW_AT_APPLE_block";
		case DW_AT_APPLE_major_runtime_vers:
			return "DW_AT_APPLE_major_runtime_vers";
		case DW_AT_APPLE_runtime_class:
			return "DW_AT_APPLE_runtime_class";
		case DW_AT_APPLE_omit_frame_ptr:
			return "DW_AT_APPLE_omit_frame_ptr";
		case DW_AT_hi_user:
			return "DW_AT_hi_user";
		default:
			return null;
		}
	}
}
