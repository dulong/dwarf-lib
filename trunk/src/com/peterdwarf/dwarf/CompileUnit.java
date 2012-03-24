package com.peterdwarf.dwarf;

public class CompileUnit {
	public int length;
	public int version;
	public int abbrev_offset;
	public int addr_size;
	

#define DW_TAG_array_type               0x01
#define DW_TAG_class_type               0x02
#define DW_TAG_entry_point              0x03
#define DW_TAG_enumeration_type         0x04
#define DW_TAG_formal_parameter         0x05
#define DW_TAG_imported_declaration     0x08
#define DW_TAG_label                    0x0a
#define DW_TAG_lexical_block            0x0b
#define DW_TAG_member                   0x0d
#define DW_TAG_pointer_type             0x0f
#define DW_TAG_reference_type           0x10
#define DW_TAG_compile_unit             0x11
#define DW_TAG_string_type              0x12
#define DW_TAG_structure_type           0x13
#define DW_TAG_subroutine_type          0x15
#define DW_TAG_typedef                  0x16
#define DW_TAG_union_type               0x17
#define DW_TAG_unspecified_parameters   0x18
#define DW_TAG_variant                  0x19
#define DW_TAG_common_block             0x1a
#define DW_TAG_common_inclusion         0x1b
#define DW_TAG_inheritance              0x1c
#define DW_TAG_inlined_subroutine       0x1d
#define DW_TAG_module                   0x1e
#define DW_TAG_ptr_to_member_type       0x1f
#define DW_TAG_set_type                 0x20
#define DW_TAG_subrange_type            0x21
#define DW_TAG_with_stmt                0x22
#define DW_TAG_access_declaration       0x23
#define DW_TAG_base_type                0x24
#define DW_TAG_catch_block              0x25
#define DW_TAG_const_type               0x26
#define DW_TAG_constant                 0x27
#define DW_TAG_enumerator               0x28
#define DW_TAG_file_type                0x29
#define DW_TAG_friend                   0x2a
#define DW_TAG_namelist                 0x2b
        /*  Early releases of this header had the following
            misspelled with a trailing 's' */
#define DW_TAG_namelist_item            0x2c /* DWARF3/2 spelling */
#define DW_TAG_namelist_items           0x2c /* SGI misspelling/typo */
#define DW_TAG_packed_type              0x2d
#define DW_TAG_subprogram               0x2e
        /*  The DWARF2 document had two spellings of the following
            two TAGs, DWARF3 specifies the longer spelling. */
#define DW_TAG_template_type_parameter  0x2f /* DWARF3/2 spelling*/
#define DW_TAG_template_type_param      0x2f /* DWARF2   spelling*/
#define DW_TAG_template_value_parameter 0x30 /* DWARF3/2 spelling*/
#define DW_TAG_template_value_param     0x30 /* DWARF2   spelling*/
#define DW_TAG_thrown_type              0x31
#define DW_TAG_try_block                0x32
#define DW_TAG_variant_part             0x33
#define DW_TAG_variable                 0x34
#define DW_TAG_volatile_type            0x35
#define DW_TAG_dwarf_procedure          0x36  /* DWARF3 */
#define DW_TAG_restrict_type            0x37  /* DWARF3 */
#define DW_TAG_interface_type           0x38  /* DWARF3 */
#define DW_TAG_namespace                0x39  /* DWARF3 */
#define DW_TAG_imported_module          0x3a  /* DWARF3 */
#define DW_TAG_unspecified_type         0x3b  /* DWARF3 */
#define DW_TAG_partial_unit             0x3c  /* DWARF3 */
#define DW_TAG_imported_unit            0x3d  /* DWARF3 */
        /*  Do not use DW_TAG_mutable_type */
#define DW_TAG_mutable_type 0x3e /* Withdrawn from DWARF3 by DWARF3f. */
#define DW_TAG_condition                0x3f  /* DWARF3f */
#define DW_TAG_shared_type              0x40  /* DWARF3f */
#define DW_TAG_type_unit                0x41  /* DWARF4 */
#define DW_TAG_rvalue_reference_type    0x42  /* DWARF4 */
#define DW_TAG_template_alias           0x43  /* DWARF4 */
#define DW_TAG_lo_user                  0x4080

#define DW_TAG_MIPS_loop                0x4081

/* HP extensions: ftp://ftp.hp.com/pub/lang/tools/WDB/wdb-4.0.tar.gz  */
#define DW_TAG_HP_array_descriptor      0x4090 /* HP */

/* GNU extensions.  The first 3 missing the GNU_. */
#define DW_TAG_format_label             0x4101 /* GNU. Fortran. */
#define DW_TAG_function_template        0x4102 /* GNU. For C++ */
#define DW_TAG_class_template           0x4103 /* GNU. For C++ */
#define DW_TAG_GNU_BINCL                0x4104 /* GNU */
#define DW_TAG_GNU_EINCL                0x4105 /* GNU */

/* GNU extension. http://gcc.gnu.org/wiki/TemplateParmsDwarf */
#define DW_TAG_GNU_template_template_parameter  0x4106 /* GNU */
#define DW_TAG_GNU_template_template_param      0x4106 /* GNU */
#define DW_TAG_GNU_template_parameter_pack      0x4107 /* GNU */
#define DW_TAG_GNU_formal_parameter_pack        0x4108 /* GNU */

#define DW_TAG_GNU_call_site                    0x4109 /* GNU */
#define DW_TAG_GNU_call_site_parameter          0x410a /* GNU */
}
