package com.peterdwarf.elf;

public class Elf_Common {
	public static int R_386_NONE = 0; /* No reloc */
	public static int R_386_32 = 1; /* Direct 32 bit  */
	public static int R_386_PC32 = 2; /* PC relative 32 bit */
	public static int R_386_GOT32 = 3; /* 32 bit GOT entry */
	public static int R_386_PLT32 = 4; /* 32 bit PLT address */
	public static int R_386_COPY = 5; /* Copy symbol at runtime */
	public static int R_386_GLOB_DAT = 6; /* Create GOT entry */
	public static int R_386_JUMP_SLOT = 7; /* Create PLT entry */
	public static int R_386_RELATIVE = 8; /* Adjust by program base */
	public static int R_386_GOTOFF = 9; /* 32 bit offset to GOT */
	public static int R_386_GOTPC = 10; /* 32 bit PC relative offset to GOT */
	public static int R_386_32PLT = 11; /* Used by Sun */
	public static int FIRST_INVALID_RELOC = 12;
	public static int LAST_INVALID_RELOC = 13;
	public static int R_386_TLS_TPOFF = 14;
	public static int R_386_TLS_IE = 15;
	public static int R_386_TLS_GOTIE = 16;
	public static int R_386_TLS_LE = 17;
	public static int R_386_TLS_GD = 18;
	public static int R_386_TLS_LDM = 19;
	public static int R_386_16 = 20;
	public static int R_386_PC16 = 21;
	public static int R_386_8 = 22;
	public static int R_386_PC8 = 23;
	public static int R_386_TLS_GD_32 = 24;
	public static int R_386_TLS_GD_PUSH = 25;
	public static int R_386_TLS_GD_CALL = 26;
	public static int R_386_TLS_GD_POP = 27;
	public static int R_386_TLS_LDM_32 = 28;
	public static int R_386_TLS_LDM_PUSH = 29;
	public static int R_386_TLS_LDM_CALL = 30;
	public static int R_386_TLS_LDM_POP = 31;
	public static int R_386_TLS_LDO_32 = 32;
	public static int R_386_TLS_IE_32 = 33;
	public static int R_386_TLS_LE_32 = 34;
	public static int R_386_TLS_DTPMOD32 = 35;
	public static int R_386_TLS_DTPOFF32 = 36;
	public static int R_386_TLS_TPOFF32 = 37;
	/* 38 */
	public static int R_386_TLS_GOTDESC = 39;
	public static int R_386_TLS_DESC_CALL = 40;
	public static int R_386_TLS_DESC = 41;
	public static int R_386_IRELATIVE = 42; /* Adjust indirectly by program base */

	/* Used by Intel.  */
	public static int R_386_USED_BY_INTEL_200 = 200;
	public static int R_386_GNU_VTINHERIT = 250;
	public static int R_386_GNU_VTENTRY = 251;

	public static String getRelocationTypeName(int relocationType) {
		if (relocationType == R_386_NONE) {
			return "R_386_NONE";
		} else if (relocationType == R_386_32) {
			return "R_386_32";
		} else if (relocationType == R_386_PC32) {
			return "R_386_PC32";
		} else if (relocationType == R_386_GOT32) {
			return "R_386_GOT32";
		} else if (relocationType == R_386_PLT32) {
			return "R_386_PLT32";
		} else if (relocationType == R_386_COPY) {
			return "R_386_COPY";
		} else if (relocationType == R_386_GLOB_DAT) {
			return "R_386_GLOB_DAT";
		} else if (relocationType == R_386_JUMP_SLOT) {
			return "R_386_JUMP_SLOT";
		} else if (relocationType == R_386_RELATIVE) {
			return "R_386_RELATIVE";
		} else if (relocationType == R_386_GOTOFF) {
			return "R_386_GOTOFF";
		} else if (relocationType == R_386_GOTPC) {
			return "R_386_GOTPC";
		} else if (relocationType == R_386_32PLT) {
			return "R_386_32PLT";
		} else if (relocationType == FIRST_INVALID_RELOC) {
			return "FIRST_INVALID_RELOC";
		} else if (relocationType == LAST_INVALID_RELOC) {
			return "LAST_INVALID_RELOC";
		} else if (relocationType == R_386_TLS_TPOFF) {
			return "R_386_TLS_TPOFF";
		} else if (relocationType == R_386_TLS_IE) {
			return "R_386_TLS_IE";
		} else if (relocationType == R_386_TLS_GOTIE) {
			return "R_386_TLS_GOTIE";
		} else if (relocationType == R_386_TLS_LE) {
			return "R_386_TLS_LE";
		} else if (relocationType == R_386_TLS_GD) {
			return "R_386_TLS_GD";
		} else if (relocationType == R_386_TLS_LDM) {
			return "R_386_TLS_LDM";
		} else if (relocationType == R_386_16) {
			return "R_386_16";
		} else if (relocationType == R_386_PC16) {
			return "R_386_PC16";
		} else if (relocationType == R_386_8) {
			return "R_386_8";
		} else if (relocationType == R_386_PC8) {
			return "R_386_PC8";
		} else if (relocationType == R_386_TLS_GD_32) {
			return "R_386_TLS_GD_32";
		} else if (relocationType == R_386_TLS_GD_PUSH) {
			return "R_386_TLS_GD_PUSH";
		} else if (relocationType == R_386_TLS_GD_CALL) {
			return "R_386_TLS_GD_CALL";
		} else if (relocationType == R_386_TLS_GD_POP) {
			return "R_386_TLS_GD_POP";
		} else if (relocationType == R_386_TLS_LDM_32) {
			return "R_386_TLS_LDM_32";
		} else if (relocationType == R_386_TLS_LDM_PUSH) {
			return "R_386_TLS_LDM_PUSH";
		} else if (relocationType == R_386_TLS_LDM_CALL) {
			return "R_386_TLS_LDM_CALL";
		} else if (relocationType == R_386_TLS_LDM_POP) {
			return "R_386_TLS_LDM_POP";
		} else if (relocationType == R_386_TLS_LDO_32) {
			return "R_386_TLS_LDO_32";
		} else if (relocationType == R_386_TLS_IE_32) {
			return "R_386_TLS_IE_32";
		} else if (relocationType == R_386_TLS_LE_32) {
			return "R_386_TLS_LE_32";
		} else if (relocationType == R_386_TLS_DTPMOD32) {
			return "R_386_TLS_DTPMOD32";
		} else if (relocationType == R_386_TLS_DTPOFF32) {
			return "R_386_TLS_DTPOFF32";
		} else if (relocationType == R_386_TLS_TPOFF32) {
			return "R_386_TLS_TPOFF32";
		} else if (relocationType == R_386_TLS_GOTDESC) {
			return "R_386_TLS_GOTDESC";
		} else if (relocationType == R_386_TLS_DESC_CALL) {
			return "R_386_TLS_DESC_CALL";
		} else if (relocationType == R_386_TLS_DESC) {
			return "R_386_TLS_DESC";
		} else if (relocationType == R_386_IRELATIVE) {
			return "R_386_IRELATIVE";
		} else if (relocationType == R_386_USED_BY_INTEL_200) {
			return "R_386_USED_BY_INTEL_200";
		} else if (relocationType == R_386_GNU_VTINHERIT) {
			return "R_386_GNU_VTINHERIT";
		} else if (relocationType == R_386_GNU_VTENTRY) {
			return "R_386_GNU_VTENTRY";
		} else {
			return null;
		}
	}

	public static int ELF32_R_SYM(int i) {
		return i >> 8;
	}

	public static int ELF32_R_TYPE(int i) {
		return i & 0xff;
	}

	public static int ELF32_R_INFO(int s, int t) {
		return (s << 8) + (t & 0xff);
	}

	public static int SHT_NULL = 0; /* Section header table entry unused */
	public static int SHT_PROGBITS = 1; /* Program specific (private) data */
	public static int SHT_SYMTAB = 2; /* Link editing symbol table */
	public static int SHT_STRTAB = 3; /* A string table */
	public static int SHT_RELA = 4; /* Relocation entries with addends */
	public static int SHT_HASH = 5; /* A symbol hash table */
	public static int SHT_DYNAMIC = 6; /* Information for dynamic linking */
	public static int SHT_NOTE = 7; /* Information that marks file */
	public static int SHT_NOBITS = 8; /* Section occupies no space in file */
	public static int SHT_REL = 9; /* Relocation entries, no addends */
	public static int SHT_SHLIB = 10; /* Reserved, unspecified semantics */
	public static int SHT_DYNSYM = 11; /* Dynamic linking symbol table */

}
