package com.peterdwarf.elf;

public class Elf_Common {
	public static int ET_REL = 1;

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

	public static int STT_NOTYPE = 0;
	public static int STT_OBJECT = 1;
	public static int STT_FUNC = 2;
	public static int STT_SECTION = 3;
	public static int STT_FILE = 4;
	public static int STT_LOPROC = 13;
	public static int STT_HIPROC = 15;

	public static String getSTTypeName(int x) {
		if (x == STT_NOTYPE) {
			return "STT_NOTYPE";
		} else if (x == STT_OBJECT) {
			return "STT_OBJECT";
		} else if (x == STT_FUNC) {
			return "STT_FUNC";
		} else if (x == STT_SECTION) {
			return "STT_SECTION";
		} else if (x == STT_FILE) {
			return "STT_FILE";
		} else if (x == STT_LOPROC) {
			return "STT_LOPROC";
		} else if (x == STT_HIPROC) {
			return "STT_HIPROC";
		} else {
			return null;
		}
	}

	public static int STB_LOCAL = 0;
	public static int STB_GLOBAL = 1;
	public static int STB_WEAK = 2;
	public static int STB_LOPROC = 13;
	public static int STB_HIPROC = 15;

	public static String getSTBindName(int x) {
		if (x == STB_LOCAL) {
			return "STB_LOCAL";
		} else if (x == STB_GLOBAL) {
			return "STB_GLOBAL";
		} else if (x == STB_WEAK) {
			return "STB_WEAK";
		} else if (x == STB_LOPROC) {
			return "STB_LOPROC";
		} else if (x == STB_HIPROC) {
			return "STB_HIPROC";
		} else {
			return null;
		}
	}

	public static int ELF32_ST_BIND(int i) {
		return ((i) >> 4);
	}

	public static int ELF32_ST_TYPE(int i) {
		return ((i) & 0xf);
	}

	public static int ELF32_ST_INFO(int b, int t) {
		return (((b) << 4) + ((t) & 0xf));
	}

	public static int ELF_ST_VISIBILITY(int i) {
		return i & 0x3;
	}

	public static final int SHN_UNDEF = 0;
	public static final int SHN_LORESERVE = 0xff00;
	public static final int SHN_LOPROC = 0xff00;
	public static final int SHN_HIPROC = 0xff1f;
	public static final int SHN_ABS = 0xff0f1;
	public static final int SHN_COMMON = 0xfff2;
	public static final int SHN_HIRESERVE = 0xffff;

	public static String get_symbol_index_type(byte type) {
		switch (type) {
		case SHN_UNDEF:
			return "UND";
		case (byte) SHN_ABS:
			return "ABS";
		case (byte) SHN_COMMON:
			return "COM";
		default:
			return String.valueOf(type);
		}
	}

	public static final int STV_DEFAULT = 0; /* Visibility is specified by binding type */
	public static final int STV_INTERNAL = 1; /* OS specific version of STV_HIDDEN */
	public static final int STV_HIDDEN = 2; /* Can only be seen inside currect component */
	public static final int STV_PROTECTED = 3; /* Treat as STB_LOCAL inside current component */

	public static String get_symbol_visibility(int visibility) {
		switch (visibility) {
		case STV_DEFAULT:
			return "DEFAULT";
		case STV_INTERNAL:
			return "INTERNAL";
		case STV_HIDDEN:
			return "HIDDEN";
		case STV_PROTECTED:
			return "PROTECTED";
		default:
			return null;
		}
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
