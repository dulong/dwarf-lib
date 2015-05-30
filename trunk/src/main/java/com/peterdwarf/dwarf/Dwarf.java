package com.peterdwarf.dwarf;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Stack;
import java.util.Vector;

import org.apache.commons.codec.binary.Hex;

import com.peterdwarf.DwarfGlobal;
import com.peterdwarf.elf.Elf32_Ehdr;
import com.peterdwarf.elf.Elf32_Shdr;
import com.peterdwarf.elf.Elf32_Sym;
import com.peterdwarf.elf.Elf_Common;
import com.peterdwarf.elf.SectionFinder;
import com.peterswing.CommonLib;

public class Dwarf {
	public ByteBuffer byteBuffer;
	public ByteBuffer debug_abbrevBuffer;
	public ByteBuffer debug_bytes;
	public ByteBuffer symtab_bytes;
	private ByteBuffer strtab_bytes;
	public ByteBuffer debug_loc;
	public ByteBuffer eh_frame_bytes;

	public Vector<CompileUnit> compileUnits = new Vector<CompileUnit>();
	public Vector<Elf32_Sym> symbols = new Vector<Elf32_Sym>();
	public Vector<DebugLocEntry> debugLocEntries = new Vector<DebugLocEntry>();
	public LinkedHashMap<Integer, LinkedHashMap<Integer, Abbrev>> abbrevList;
	public File file;
	public String realFilename;
	public Elf32_Ehdr ehdr = new Elf32_Ehdr();
	public boolean isLoading;
	public String loadingMessage;
	public Vector<Elf32_Shdr> sections = new Vector<Elf32_Shdr>();
	public int addressSize;
	public int offset_size;
	public Vector<FrameChunk> ehFrames = new Vector<FrameChunk>();

	public int initElf(File file, String realFilename, long memoryOffset) {
		this.file = file;
		this.realFilename = realFilename;

		isLoading = true;
		if (!file.isFile()) {
			System.err.println(file.getAbsolutePath() + " is not a file!!!");
			return 100;
		}

		if (!isELF(file)) {
			return 101;
		}

		try {
			sections = SectionFinder.getAllSections(file);
			if (SectionFinder.getElf32_Ehdr(file).is32Bits()) {
				addressSize = 4;
				offset_size = 4;
			} else if (SectionFinder.getElf32_Ehdr(file).is64Bits()) {
				addressSize = 8;
				offset_size = 8;
			} else {
				System.err.println("Invalid address size");
				System.exit(12);
			}
		} catch (IOException e2) {
			return 23;
		}

		// read program header
		try {
			ehdr.read(new RandomAccessFile(file, "r"));
		} catch (Exception e1) {
			e1.printStackTrace();
			return 1;
		}
		// end read program header

		compileUnits.clear();

		try {
			debug_loc = SectionFinder.findSectionByte(ehdr, file, ".debug_loc");
			while (debug_loc != null && debug_loc.hasRemaining()) {
				int start = debug_loc.getInt();
				int end = debug_loc.getInt();
				if (start == 0 && end == 0) {
					continue;
				}
				int blockSize = debug_loc.getShort();
				if (blockSize < 0) {
					break;
				}
				byte[] block = new byte[blockSize];
				debug_loc.get(block);

				if (DwarfGlobal.debug) {
					System.out.println("---------------------------");
					System.out.println(Integer.toHexString(start) + "," + Integer.toHexString(end) + "," + blockSize + "," + Hex.encodeHexString(block) + " , "
							+ Definition.getOPName(0xff & block[0]));
				}

				DebugLocEntry debugLocEntry = new DebugLocEntry();
				debugLocEntry.start = start;
				debugLocEntry.end = debugLocEntry.end;
				debugLocEntry.blockSize = blockSize;
				debugLocEntry.blocks = block;
				debugLocEntry.name = Definition.getOPName(0xff & block[0]);

				int offset = 0;
				int loc_len = debugLocEntry.blockSize;
				while (offset < loc_len) {
					debugLocEntry.op_count = 0;
					while (offset < loc_len) {
						long operand1 = 0;
						long operand2 = 0;
						int atom = 0;

						debugLocEntry.op_count++;
						atom = debugLocEntry.blocks[offset] & 0xff;
						offset++;
						if (DwarfGlobal.debug) {
							System.out.println(Definition.getOPName(atom));
						}
						switch (atom) {
						case Definition.DW_OP_reg0:
						case Definition.DW_OP_reg1:
						case Definition.DW_OP_reg2:
						case Definition.DW_OP_reg3:
						case Definition.DW_OP_reg4:
						case Definition.DW_OP_reg5:
						case Definition.DW_OP_reg6:
						case Definition.DW_OP_reg7:
						case Definition.DW_OP_reg8:
						case Definition.DW_OP_reg9:
						case Definition.DW_OP_reg10:
						case Definition.DW_OP_reg11:
						case Definition.DW_OP_reg12:
						case Definition.DW_OP_reg13:
						case Definition.DW_OP_reg14:
						case Definition.DW_OP_reg15:
						case Definition.DW_OP_reg16:
						case Definition.DW_OP_reg17:
						case Definition.DW_OP_reg18:
						case Definition.DW_OP_reg19:
						case Definition.DW_OP_reg20:
						case Definition.DW_OP_reg21:
						case Definition.DW_OP_reg22:
						case Definition.DW_OP_reg23:
						case Definition.DW_OP_reg24:
						case Definition.DW_OP_reg25:
						case Definition.DW_OP_reg26:
						case Definition.DW_OP_reg27:
						case Definition.DW_OP_reg28:
						case Definition.DW_OP_reg29:
						case Definition.DW_OP_reg30:
						case Definition.DW_OP_reg31:
							break;

						case Definition.DW_OP_regx:
							operand1 = DwarfLib.getULEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							//							operand1 = _dwarf_decode_u_leb128(loc_ptr, &leb128_length);
							//							loc_ptr = loc_ptr + leb128_length;
							offset = offset + DwarfLib.getULEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							break;

						case Definition.DW_OP_lit0:
						case Definition.DW_OP_lit1:
						case Definition.DW_OP_lit2:
						case Definition.DW_OP_lit3:
						case Definition.DW_OP_lit4:
						case Definition.DW_OP_lit5:
						case Definition.DW_OP_lit6:
						case Definition.DW_OP_lit7:
						case Definition.DW_OP_lit8:
						case Definition.DW_OP_lit9:
						case Definition.DW_OP_lit10:
						case Definition.DW_OP_lit11:
						case Definition.DW_OP_lit12:
						case Definition.DW_OP_lit13:
						case Definition.DW_OP_lit14:
						case Definition.DW_OP_lit15:
						case Definition.DW_OP_lit16:
						case Definition.DW_OP_lit17:
						case Definition.DW_OP_lit18:
						case Definition.DW_OP_lit19:
						case Definition.DW_OP_lit20:
						case Definition.DW_OP_lit21:
						case Definition.DW_OP_lit22:
						case Definition.DW_OP_lit23:
						case Definition.DW_OP_lit24:
						case Definition.DW_OP_lit25:
						case Definition.DW_OP_lit26:
						case Definition.DW_OP_lit27:
						case Definition.DW_OP_lit28:
						case Definition.DW_OP_lit29:
						case Definition.DW_OP_lit30:
						case Definition.DW_OP_lit31:
							operand1 = atom - Definition.DW_OP_lit0;
							break;

						case Definition.DW_OP_addr:
							//READ_UNALIGNED(dbg, operand1, Dwarf_Unsigned, loc_ptr, addressSize);
							if (addressSize == 4) {
								operand1 = CommonLib.getInt(debugLocEntry.blocks, offset);
							} else {
								operand1 = CommonLib.getLong(CommonLib.byteArrayToIntArray(debugLocEntry.blocks), offset);
							}
							//							loc_ptr += addressSize;
							offset += addressSize;
							break;

						case Definition.DW_OP_const1u:
							operand1 = 0xff & debugLocEntry.blocks[offset];
							offset = offset + 1;
							break;

						case Definition.DW_OP_const1s:
							operand1 = debugLocEntry.blocks[offset];
							//SIGN_EXTEND(operand1, 1);
							offset = offset + 1;
							break;

						case Definition.DW_OP_const2u:
							//							READ_UNALIGNED(dbg, operand1, Dwarf_Unsigned, loc_ptr, 2);
							operand1 = CommonLib.getShort(CommonLib.byteArrayToIntArray(debugLocEntry.blocks), offset);
							//							loc_ptr = loc_ptr + 2;
							offset = offset + 2;
							break;

						case Definition.DW_OP_const2s:
							//							READ_UNALIGNED(dbg, operand1, Dwarf_Unsigned, loc_ptr, 2);
							operand1 = CommonLib.getShort(CommonLib.byteArrayToIntArray(debugLocEntry.blocks), offset);
							//SIGN_EXTEND(operand1, 2);
							//loc_ptr = loc_ptr + 2;
							offset = offset + 2;
							break;

						case Definition.DW_OP_const4u:
							//READ_UNALIGNED(dbg, operand1, Dwarf_Unsigned, loc_ptr, 4);
							operand1 = CommonLib.getInt(debugLocEntry.blocks, offset);
							//loc_ptr = loc_ptr + 4;
							offset = offset + 4;
							break;

						case Definition.DW_OP_const4s:
							//READ_UNALIGNED(dbg, operand1, Dwarf_Unsigned, loc_ptr, 4);
							operand1 = CommonLib.getInt(debugLocEntry.blocks, offset);
							//SIGN_EXTEND(operand1, 4);
							//loc_ptr = loc_ptr + 4;
							offset = offset + 4;
							break;

						case Definition.DW_OP_const8u:
							//READ_UNALIGNED(dbg, operand1, Dwarf_Unsigned, loc_ptr, 8);
							operand1 = CommonLib.getLong(CommonLib.byteArrayToIntArray(debugLocEntry.blocks), offset);
							//loc_ptr = loc_ptr + 8;
							offset = offset + 8;
							break;

						case Definition.DW_OP_const8s:
							//READ_UNALIGNED(dbg, operand1, Dwarf_Unsigned, loc_ptr, 8);
							operand1 = CommonLib.getLong(CommonLib.byteArrayToIntArray(debugLocEntry.blocks), offset);
							//loc_ptr = loc_ptr + 8;
							offset = offset + 8;
							break;

						case Definition.DW_OP_constu:
							//operand1 = _dwarf_decode_u_leb128(loc_ptr, &leb128_length);
							operand1 = DwarfLib.getULEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							offset = offset + DwarfLib.getULEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							break;

						case Definition.DW_OP_consts:
							//operand1 = _dwarf_decode_s_leb128(loc_ptr, &leb128_length);
							operand1 = DwarfLib.getSLEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							offset = offset + DwarfLib.getSLEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							break;

						case Definition.DW_OP_fbreg:
							//operand1 = _dwarf_decode_s_leb128(loc_ptr, &leb128_length);
							operand1 = DwarfLib.getSLEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							offset = offset + DwarfLib.getSLEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							break;
						case Definition.DW_OP_breg0:
						case Definition.DW_OP_breg1:
						case Definition.DW_OP_breg2:
						case Definition.DW_OP_breg3:
						case Definition.DW_OP_breg4:
						case Definition.DW_OP_breg5:
						case Definition.DW_OP_breg6:
						case Definition.DW_OP_breg7:
						case Definition.DW_OP_breg8:
						case Definition.DW_OP_breg9:
						case Definition.DW_OP_breg10:
						case Definition.DW_OP_breg11:
						case Definition.DW_OP_breg12:
						case Definition.DW_OP_breg13:
						case Definition.DW_OP_breg14:
						case Definition.DW_OP_breg15:
						case Definition.DW_OP_breg16:
						case Definition.DW_OP_breg17:
						case Definition.DW_OP_breg18:
						case Definition.DW_OP_breg19:
						case Definition.DW_OP_breg20:
						case Definition.DW_OP_breg21:
						case Definition.DW_OP_breg22:
						case Definition.DW_OP_breg23:
						case Definition.DW_OP_breg24:
						case Definition.DW_OP_breg25:
						case Definition.DW_OP_breg26:
						case Definition.DW_OP_breg27:
						case Definition.DW_OP_breg28:
						case Definition.DW_OP_breg29:
						case Definition.DW_OP_breg30:
						case Definition.DW_OP_breg31:
							//operand1 = _dwarf_decode_s_leb128(loc_ptr, &leb128_length);
							operand1 = DwarfLib.getSLEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							offset = offset + DwarfLib.getSLEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							break;

						case Definition.DW_OP_bregx:
							/* uleb reg num followed by sleb offset */
							//operand1 = _dwarf_decode_u_leb128(loc_ptr, &leb128_length);
							operand1 = DwarfLib.getULEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							offset = offset + DwarfLib.getULEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));

							//operand2 = _dwarf_decode_s_leb128(loc_ptr, &leb128_length);
							operand2 = DwarfLib.getSLEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							offset = offset + DwarfLib.getSLEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							break;

						case Definition.DW_OP_dup:
						case Definition.DW_OP_drop:
							break;

						case Definition.DW_OP_pick:
							//operand1 = *(Dwarf_Small *) loc_ptr;
							operand1 = debugLocEntry.blocks[offset];
							//loc_ptr = loc_ptr + 1;
							offset = offset + 1;
							break;

						case Definition.DW_OP_over:
						case Definition.DW_OP_swap:
						case Definition.DW_OP_rot:
						case Definition.DW_OP_deref:
							break;

						case Definition.DW_OP_deref_size:
							//operand1 = *(Dwarf_Small *) loc_ptr;
							operand1 = debugLocEntry.blocks[offset];
							//loc_ptr = loc_ptr + 1;
							offset = offset + 1;
							break;

						case Definition.DW_OP_xderef:
							break;

						case Definition.DW_OP_xderef_size:
							//operand1 = *(Dwarf_Small *) loc_ptr;
							operand1 = debugLocEntry.blocks[offset];
							//loc_ptr = loc_ptr + 1;
							offset = offset + 1;
							break;

						case Definition.DW_OP_abs:
						case Definition.DW_OP_and:
						case Definition.DW_OP_div:
						case Definition.DW_OP_minus:
						case Definition.DW_OP_mod:
						case Definition.DW_OP_mul:
						case Definition.DW_OP_neg:
						case Definition.DW_OP_not:
						case Definition.DW_OP_or:
						case Definition.DW_OP_plus:
							break;

						case Definition.DW_OP_plus_uconst:
							//operand1 = _dwarf_decode_u_leb128(loc_ptr, &leb128_length);
							operand1 = DwarfLib.getULEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							offset = offset + DwarfLib.getULEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							break;

						case Definition.DW_OP_shl:
						case Definition.DW_OP_shr:
						case Definition.DW_OP_shra:
						case Definition.DW_OP_xor:
							break;

						case Definition.DW_OP_le:
						case Definition.DW_OP_ge:
						case Definition.DW_OP_eq:
						case Definition.DW_OP_lt:
						case Definition.DW_OP_gt:
						case Definition.DW_OP_ne:
							break;

						case Definition.DW_OP_skip:
						case Definition.DW_OP_bra:
							//READ_UNALIGNED(dbg, operand1, Dwarf_Unsigned, loc_ptr, 2);
							operand1 = CommonLib.getShort(CommonLib.byteArrayToIntArray(debugLocEntry.blocks), offset);
							//loc_ptr = loc_ptr + 2;
							offset = offset + 2;
							break;

						case Definition.DW_OP_piece:
							//operand1 = _dwarf_decode_u_leb128(loc_ptr, &leb128_length);
							operand1 = DwarfLib.getULEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							offset = offset + DwarfLib.getULEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							break;

						case Definition.DW_OP_nop:
							break;
						case Definition.DW_OP_push_object_address: /* DWARF3 */
							break;
						case Definition.DW_OP_call2: /* DWARF3 */
							//READ_UNALIGNED(dbg, operand1, Dwarf_Unsigned, loc_ptr, 2);
							operand1 = CommonLib.getShort(CommonLib.byteArrayToIntArray(debugLocEntry.blocks), offset);
							//loc_ptr = loc_ptr + 2;
							offset = offset + 2;
							break;

						case Definition.DW_OP_call4: /* DWARF3 */
							//READ_UNALIGNED(dbg, operand1, Dwarf_Unsigned, loc_ptr, 4);
							operand1 = CommonLib.getInt(debugLocEntry.blocks, offset);
							//loc_ptr = loc_ptr + 4;
							offset = offset + 4;
							break;
						case Definition.DW_OP_call_ref: /* DWARF3 */
							//READ_UNALIGNED(dbg, operand1, Dwarf_Unsigned, loc_ptr, offset_size);
							if (offset_size == 4) {
								operand1 = CommonLib.getInt(debugLocEntry.blocks, offset);
							} else if (offset_size == 8) {
								operand1 = CommonLib.getLong(CommonLib.byteArrayToIntArray(debugLocEntry.blocks), offset);
							}
							//loc_ptr = loc_ptr + offset_size;
							offset = offset + offset_size;
							break;

						case Definition.DW_OP_form_tls_address: /* DWARF3f */
							break;
						case Definition.DW_OP_call_frame_cfa: /* DWARF3f */
							break;
						case Definition.DW_OP_bit_piece: /* DWARF3f */
							/* uleb size in bits followed by uleb offset in bits */
							//operand1 = _dwarf_decode_u_leb128(loc_ptr, &leb128_length);
							operand1 = DwarfLib.getULEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							offset = offset + DwarfLib.getULEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));

							//operand2 = _dwarf_decode_u_leb128(loc_ptr, &leb128_length);
							operand2 = DwarfLib.getULEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							offset = offset + DwarfLib.getULEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							break;

						/*  The operator means: push the currently computed
						 (by the operations encountered so far in this
						 expression) onto the expression stack as the offset
						 in thread-local-storage of the variable. */
						case Definition.DW_OP_GNU_push_tls_address: /* 0xe0  */
							/* Believed to have no operands. */
							/* Unimplemented in gdb 7.5.1 ? */
							break;
						case Definition.DW_OP_GNU_deref_type: /* 0xf6 */
							/* die offset (uleb128). */
							//operand1 = _dwarf_decode_u_leb128(loc_ptr, &leb128_length);
							operand1 = DwarfLib.getULEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							offset = offset + DwarfLib.getULEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							break;

						case Definition.DW_OP_implicit_value: /* DWARF4 0xa0 */
							/*  uleb length of value bytes followed by that
							 number of bytes of the value. */
							//operand1 = _dwarf_decode_u_leb128(loc_ptr, &leb128_length);
							operand1 = DwarfLib.getULEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							offset = offset + DwarfLib.getULEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));

							/*  Second operand is block of 'operand1' bytes of stuff. */
							/*  This using the second operand as a pointer
							 is quite ugly. */
							/*  This gets an ugly compiler warning. Sorry. */
							//operand2 = (Dwarf_Unsigned) loc_ptr;
							operand2 = CommonLib.getLong(CommonLib.byteArrayToIntArray(debugLocEntry.blocks), offset);
							offset = (int) (offset + operand1);
							//loc_ptr = loc_ptr + operand1;
							break;
						case Definition.DW_OP_stack_value: /* DWARF4 */
							break;
						case Definition.DW_OP_GNU_uninit: /* 0xf0 */
							/* Unimplemented in gdb 7.5.1  */
							/*  Carolyn Tice: Follws a DW_OP_reg or DW_OP_regx
							 and marks the reg as being uninitialized. */
							break;
						case Definition.DW_OP_GNU_encoded_addr: { /*  0xf1 */
							/*  Richard Henderson: The operand is an absolute
							 address.  The first byte of the value
							 is an encoding length: 0 2 4 or 8.  If zero
							 it means the following is address-size.
							 The address then follows immediately for
							 that number of bytes. */
							int length = 0;
							//int reares = read_encoded_addr(loc_ptr, dbg, &operand1, &length, error);
							int reares;
							switch (addressSize) {
							case 1:
								operand1 = debugLocEntry.blocks[offset];
								offset += length;
								break;

							case 2:
								//								READ_UNALIGNED(dbg, operand, Dwarf_Unsigned, loc_ptr, 2);
								//								*val_out = operand;
								//								len += 2;
								operand1 = CommonLib.getShort(CommonLib.byteArrayToIntArray(debugLocEntry.blocks), offset);
								offset = offset + 2;
								break;
							case 4:
								//READ_UNALIGNED(dbg, operand, Dwarf_Unsigned, loc_ptr, 4);
								//*val_out = operand;
								//len += 4;
								operand1 = CommonLib.getInt(debugLocEntry.blocks, offset);
								offset = offset + 4;
								break;
							case 8:
								//READ_UNALIGNED(dbg, operand, Dwarf_Unsigned, loc_ptr, 8);
								//*val_out = operand;
								//len += 8;
								operand1 = CommonLib.getLong(CommonLib.byteArrayToIntArray(debugLocEntry.blocks), offset);
								offset = offset + 8;
								break;
							default:
								/* We do not know how much to read. */
								//_dwarf_error(dbg, error, DW_DLE_GNU_OPCODE_ERROR);
								return Definition.DW_DLV_ERROR;
							}
							;

							//							if (reares != Definition.DW_DLV_OK) {
							//								/*  Oops. The caller will notice and
							//								 will issue DW_DLV_ERROR. */
							//								return Definition.DW_DLV_OK;
							//							}
							//							loc_ptr += length;
							//							offset += length;
						}
							break;
						case Definition.DW_OP_implicit_pointer: /* DWARF5 */
						case Definition.DW_OP_GNU_implicit_pointer: { /* 0xf2 */
							/*  Jakub Jelinek: The value is an optimized-out
							 pointer value. Represented as
							 an offset_size DIE offset
							 (a simple unsigned integer) in DWARF3,4
							 followed by a signed leb128 offset.
							 For DWARF2, it is actually pointer size
							 (address size).
							 http://www.dwarfstd.org/ShowIssue.php?issue=100831.1 */
							//Dwarf_Small iplen = offset_size;
							//if (version_stamp == CURRENT_VERSION_STAMP /* 2 */) {
							//	iplen = addressSize;
							//}
							//READ_UNALIGNED(dbg, operand1, Dwarf_Unsigned, loc_ptr, iplen);
							//loc_ptr = loc_ptr + iplen;

							if (addressSize == 4) {
								operand1 = CommonLib.getInt(debugLocEntry.blocks, offset);
								offset = offset + 4;
							} else if (addressSize == 8) {
								operand1 = CommonLib.getInt(debugLocEntry.blocks, offset);
								offset = offset + 8;
							}

							//offset = offset + iplen;

							//operand2 = _dwarf_decode_s_leb128(loc_ptr, &leb128_length);
							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;

							operand2 = DwarfLib.getSLEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							offset = offset + DwarfLib.getSLEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
						}

							break;
						case Definition.DW_OP_GNU_entry_value: /* 0xf3 */
							/*  Jakub Jelinek: A register reused really soon,
							 but the value is unchanged.  So to represent
							 that value we have a uleb128 size followed
							 by a DWARF expression block that size.
							 http://www.dwarfstd.org/ShowIssue.php?issue=100909.1 */

							/*  uleb length of value bytes followed by that
							 number of bytes of the value. */
							//operand1 = _dwarf_decode_u_leb128(loc_ptr, &leb128_length);
							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							operand2 = DwarfLib.getULEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							offset = offset + DwarfLib.getULEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));

							/*  Second operand is block of 'operand1' bytes of stuff. */
							/*  This using the second operand as a pointer
							 is quite ugly. */
							/*  This gets an ugly compiler warning. Sorry. */
							//operand2 = (Dwarf_Unsigned) loc_ptr;

							int size = debugLocEntry.blocks.length - offset;
							if (size == 2) {
								operand2 = CommonLib.getShort(CommonLib.byteArrayToIntArray(debugLocEntry.blocks), offset);
							} else if (size == 4) {
								operand2 = CommonLib.getInt(CommonLib.byteArrayToIntArray(debugLocEntry.blocks), offset);
							} else {
								operand2 = CommonLib.getLong(CommonLib.byteArrayToIntArray(debugLocEntry.blocks), offset);
							}
							offset = offset + 8;

							//offset = offset + operand1;
							//loc_ptr = loc_ptr + operand1;
							break;
						case Definition.DW_OP_GNU_const_type: /* 0xf4 */
						{
							int blocklen = 0;
							/* die offset as uleb. */
							//operand1 = _dwarf_decode_u_leb128(loc_ptr, &leb128_length);
							operand1 = DwarfLib.getULEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));

							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							offset = offset + DwarfLib.getULEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));

							/*  Next byte is size of data block.
							 We pass the length and block via a a pointer
							 to the length byte. */
							//operand2 = (Dwarf_Unsigned) loc_ptr;
							operand2 = CommonLib.getLong(CommonLib.byteArrayToIntArray(debugLocEntry.blocks), offset);

							//blocklen = *(Dwarf_Small *) loc_ptr;
							blocklen = debugLocEntry.blocks[offset];

							//loc_ptr = loc_ptr + 1;
							offset = offset + 1;
							/* Following that is data block of bytes. */
							offset = offset + blocklen;
							//loc_ptr = loc_ptr + blocklen;
						}
							break;
						case Definition.DW_OP_GNU_regval_type: /* 0xf5 */
							/* reg num uleb*/
							//operand1 = _dwarf_decode_u_leb128(loc_ptr, &leb128_length);
							operand1 = DwarfLib.getULEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));

							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							/* cu die off uleb*/
							//operand2 = _dwarf_decode_u_leb128(loc_ptr, &leb128_length);
							operand1 = DwarfLib.getULEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;

							offset = offset + DwarfLib.getULEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));

							break;
						case Definition.DW_OP_GNU_convert: /* 0xf7 */
						case Definition.DW_OP_GNU_reinterpret: /* 0xf9 */
							/* die offset  or zero */
							//operand1 = _dwarf_decode_u_leb128(loc_ptr, &leb128_length);
							operand1 = DwarfLib.getULEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));

							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							offset = offset + DwarfLib.getULEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							break;
						case Definition.DW_OP_GNU_parameter_ref: /* 0xfa */
							/* 4 byte unsigned int */
							//READ_UNALIGNED(dbg, operand1, Dwarf_Unsigned, loc_ptr, 4);
							operand1 = CommonLib.getInt(debugLocEntry.blocks, offset);
							//loc_ptr = loc_ptr + 4;
							offset = offset + 4;
							break;
						case Definition.DW_OP_addrx: /* DWARF5 */
						case Definition.DW_OP_GNU_addr_index: /* 0xfb DebugFission */
							/*  Index into .debug_addr. The value in .debug_addr
							 is an address. */
							//operand1 = _dwarf_decode_u_leb128(loc_ptr, &leb128_length);
							operand1 = DwarfLib.getULEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));

							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							offset = offset + DwarfLib.getULEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							break;
						case Definition.DW_OP_constx: /* DWARF5 */
						case Definition.DW_OP_GNU_const_index: /* 0xfc DebugFission */
							/*  Index into .debug_addr. The value in .debug_addr
							 is a constant that fits in an address. */
							//operand1 = _dwarf_decode_u_leb128(loc_ptr, &leb128_length);
							operand1 = DwarfLib.getULEB128(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							//loc_ptr = loc_ptr + leb128_length;
							//offset = offset + leb128_length;
							offset = offset + DwarfLib.getULEB128Count(ByteBuffer.wrap(Arrays.copyOfRange(debugLocEntry.blocks, offset, debugLocEntry.blocks.length)));
							break;
						default:
							/*  Some memory does leak here.  */
							//_dwarf_error(dbg, error, DW_DLE_LOC_EXPR_BAD);
							System.err.println("DW_DLE_LOC_EXPR_BAD");
							return Definition.DW_DLV_ERROR;
						}
					}
				}
				debugLocEntries.add(debugLocEntry);
			}

			debug_bytes = SectionFinder.findSectionByte(ehdr, file, ".debug_str");
			if (debug_bytes == null) {
				System.err.println("missing section .debug_str");
				return 24;
			}
			strtab_bytes = SectionFinder.findSectionByte(ehdr, file, ".strtab");
			symtab_bytes = SectionFinder.findSectionByte(ehdr, file, ".symtab");
			symbols = parseSymtab(symtab_bytes, strtab_bytes);
			debug_abbrevBuffer = SectionFinder.findSectionByte(ehdr, file, ".debug_abbrev");
			abbrevList = parseDebugAbbrev(debug_abbrevBuffer);
			if (DwarfGlobal.debug) {
				for (Integer abbrevOffset : abbrevList.keySet()) {
					System.out.println("Abbrev offset=" + abbrevOffset);
					LinkedHashMap<Integer, Abbrev> abbrevHashtable = abbrevList.get(abbrevOffset);
					for (Integer abbrevNo : abbrevHashtable.keySet()) {
						Abbrev abbrev = abbrevHashtable.get(abbrevNo);

						System.out.printf("%d\t%s\t%s\n", abbrev.number, Definition.getTagName(abbrev.tag), abbrev.has_children ? "has children" : "no children");

						for (AbbrevEntry entry : abbrev.entries) {
							System.out.printf("\t%x\t%x\t%s\t%s\n", entry.at, entry.form, Definition.getATName(entry.at), Definition.getFormName(entry.form));
						}
					}
				}
			}
			if (DwarfGlobal.debug) {
				System.out.println();
			}

			byteBuffer = SectionFinder.findSectionByte(ehdr, file, ".debug_info");
			Elf32_Shdr debugInfoSection = null;
			for (Elf32_Shdr s : sections) {
				if (s.section_name.equals(".debug_info")) {
					debugInfoSection = s;
					break;
				}
			}
			if (debugInfoSection != null) {
				int r = parseDebugInfo(debugInfoSection, byteBuffer);
				if (r > 0) {
					return r;
				}
			}

			Elf32_Shdr shdr = SectionFinder.getSectionHeader(ehdr, file, ".debug_line");
			byteBuffer = SectionFinder.findSectionByte(ehdr, file, shdr.section_name);
			calculationRelocation(shdr, byteBuffer, ".rel.debug_line");
			int x = 0;
			while (((ByteBuffer) byteBuffer).hasRemaining() && x < compileUnits.size()) {
				int r = parseHeader(byteBuffer, compileUnits.get(x), memoryOffset);
				x++;
				if (r > 0) {
					return r;
				}
			}

			Elf32_Shdr ehFrameSection = SectionFinder.getSection(file, ".eh_frame");
			eh_frame_bytes = SectionFinder.findSectionByte(ehdr, file, ".eh_frame");
			System.out.println("eh_frame_bytes=" + eh_frame_bytes.limit());
			System.out.println(ehFrameSection.sh_size);

			long start = 0;
			long end = ehFrameSection.sh_size;
			int initial_length_size;
			int max_regs = 0;
			String bad_reg = "bad register: ";
			while (start < end && eh_frame_bytes.position() < eh_frame_bytes.capacity()) {
				int saved_start = eh_frame_bytes.position();
				long length = eh_frame_bytes.getInt() & 0xffffffffL;
				if (length == 0xffffffff) {
					length = CommonLib.get64BitsInt(eh_frame_bytes).longValue();
					offset_size = 8;
					initial_length_size = 12;
				} else {
					offset_size = 4;
					initial_length_size = 4;
				}

				long block_end = saved_start + length + initial_length_size;

				int cieID = (int) (eh_frame_bytes.getInt() & 0xffffffffL);

				int eh_addr_size = 4;

				FrameChunk fc;
				FrameChunk remembered_state = null;

				if (cieID == 0) {
					// read CIE
					fc = new FrameChunk();
					int version = eh_frame_bytes.get();
					System.out.println("version=" + version);

					int temp;
					do {
						temp = eh_frame_bytes.get();
						fc.augmentation += (char) temp;
					} while (temp != 0);
					System.out.println("augmentation=" + fc.augmentation);

					if (fc.augmentation.equals("eh")) {
						start += eh_addr_size;
					}

					if (version >= 4) {
						System.out.println("not support version>=4");
						System.exit(-2);
					} else {
						fc.ptr_size = eh_addr_size;
						fc.segment_size = 0;
					}

					fc.code_factor = (int) DwarfLib.getULEB128(eh_frame_bytes);
					System.out.println("codeAlignmentFactor=" + fc.code_factor);

					fc.data_factor = (int) DwarfLib.getSLEB128(eh_frame_bytes);
					System.out.println("dataAlignmentFactor=" + fc.data_factor);

					if (version == 1) {
						fc.ra = eh_frame_bytes.get();
					} else {
						fc.ra = DwarfLib.getULEB128(eh_frame_bytes);
					}

					int augmentationDataLength = 0;
					byte augmentationData[] = null;
					if (fc.augmentation.charAt(0) == 'z') {
						augmentationDataLength = (int) DwarfLib.getULEB128(eh_frame_bytes);
						augmentationData = new byte[augmentationDataLength];

						for (int z = 0; z < augmentationDataLength; z++) {
							augmentationData[z] = eh_frame_bytes.get();
						}
					}

					if (augmentationDataLength > 0) {
						byte q[] = augmentationData;
						int qPointer = 0;

						/* PR 17531: file: 015adfaa.  */
						//						if (qend < q) {
						//							warn(_("Negative augmentation data length: 0x%lx"), augmentationDataLength);
						//							augmentation_data_len = 0;
						//						}

						for (int tempX = 0; tempX < augmentationDataLength; tempX++) {
							char p = (char) fc.augmentation.charAt(tempX + 1);
							if (p == 'L') {
								qPointer++;
							} else if (p == 'P') {
								qPointer += 1 + size_of_encoded_value(q[qPointer], eh_addr_size);
							} else if (p == 'R') {
								fc.fde_encoding = q[qPointer++];
							} else if (p == 'S') {
							} else {
								break;
							}
						}
					}

					ehFrames.add(fc);
					// read CIE end

					int mreg = max_regs > 0 ? max_regs - 1 : 0;
					if (mreg < fc.ra) {
						mreg = (int) fc.ra;
					}

					frame_need_space(fc, mreg);
				} else {
					// start FDE
					System.out.println("FDE");
					fc = new FrameChunk();
					ehFrames.add(fc);

					FrameChunk cie = ehFrames.get(0);
					fc.ncols = cie.ncols;
					fc.col_type = new long[fc.ncols];
					fc.col_offset = new long[fc.ncols];
					fc.augmentation = cie.augmentation;
					fc.ptr_size = cie.ptr_size;
					eh_addr_size = cie.ptr_size;
					fc.segment_size = cie.segment_size;
					fc.code_factor = cie.code_factor;
					fc.data_factor = cie.data_factor;
					fc.cfa_reg = cie.cfa_reg;
					fc.cfa_offset = cie.cfa_offset;
					fc.ra = cie.ra;
					if (frame_need_space(fc, max_regs > 0 ? max_regs - 1 : 0) < 0) {
						System.err.println("Invalid max register\n");
						System.exit(111);
					}
					fc.fde_encoding = cie.fde_encoding;

					int encoded_ptr_size = 0;
					if (fc.fde_encoding > 0) {
						encoded_ptr_size = size_of_encoded_value(fc.fde_encoding, eh_addr_size);
					}

					fc.pc_begin = get_encoded_value(eh_frame_bytes, fc.fde_encoding, ehFrameSection, eh_addr_size);

					fc.pc_range = byte_get(eh_frame_bytes, encoded_ptr_size);

					int augmentationDataLength = 0;
					byte augmentationData[] = null;
					if (fc.augmentation.charAt(0) == 'z') {
						augmentationDataLength = (int) DwarfLib.getULEB128(eh_frame_bytes);
						augmentationData = new byte[augmentationDataLength];

						int oldPosition = eh_frame_bytes.position();
						for (int z = 0; z < augmentationDataLength; z++) {
							augmentationData[z] = eh_frame_bytes.get();
						}
						eh_frame_bytes.position(oldPosition);
					}

					System.out.printf("%x..%x\n", fc.pc_begin, fc.pc_begin + fc.pc_range);
					fc.pc_begin_real = fc.pc_begin;
					fc.pc_range_real = fc.pc_range;
					// FDE end
				}
				FrameChunk cie = ehFrames.get(0);

				String reg_prefix = "";
				int index = 0;

				while (eh_frame_bytes.position() < block_end) {
					int op = eh_frame_bytes.get();
					byte opa = (byte) (op & 0x3fL);
					long ofs;

					if ((op & 0xc0L) > 0) {
						op &= 0xc0;
					}

					switch (op) {
					case Definition.DW_CFA_advance_loc:
						System.out.printf("  DW_CFA_advance_loc: %d to %x\n", opa * fc.code_factor, fc.pc_begin + opa * fc.code_factor);
						fc.fieDetails.put((index++) + ": DW_CFA_advance_loc", new Object[] { opa * fc.code_factor, fc.pc_begin + opa * fc.code_factor });
						fc.pc_begin += opa * fc.code_factor;
						break;
					case Definition.DW_CFA_offset:
						long roffs = DwarfLib.getULEB128(eh_frame_bytes);
						if (opa >= fc.ncols) {
							reg_prefix = bad_reg;
						}
						if (reg_prefix != null) {
							System.out.printf("  DW_CFA_offset: r(%d) %s%s at cfa %d\n", opa, reg_prefix, Definition.dwarf_regnames_i386[opa], roffs * fc.data_factor);
							fc.fieDetails.put((index++) + ": DW_CFA_offset", new Object[] { "r" + opa, reg_prefix, Definition.dwarf_regnames_i386[opa], roffs * fc.data_factor });
						}
						if (reg_prefix == null) {
							fc.col_type[opa] = Definition.DW_CFA_offset;
							fc.col_offset[opa] = roffs * fc.data_factor;
						}
						break;
					case Definition.DW_CFA_restore:
						if (opa >= cie.ncols || opa >= fc.ncols) {
							reg_prefix = bad_reg;
						}
						System.out.printf("  DW_CFA_restore: %s%s\n", reg_prefix, Definition.dwarf_regnames_i386[opa]);
						fc.fieDetails.put((index++) + ": DW_CFA_restore", new Object[] { reg_prefix, Definition.dwarf_regnames_i386[opa] });
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							fc.col_type[opa] = cie.col_type[opa];
							fc.col_offset[opa] = cie.col_offset[opa];
							if (fc.col_type[opa] == Definition.DW_CFA_unreferenced) {
								fc.col_type[opa] = Definition.DW_CFA_undefined;
							}
						}
						break;
					case Definition.DW_CFA_set_loc:
						long vma = get_encoded_value(eh_frame_bytes, fc.fde_encoding, ehFrameSection, (int) block_end);
						System.out.printf("  DW_CFA_set_loc: %x\n", vma);
						fc.fieDetails.put((index++) + ": DW_CFA_set_loc", new Object[] { reg_prefix, Definition.dwarf_regnames_i386[opa] });
						fc.pc_begin = vma;
						break;
					case Definition.DW_CFA_advance_loc1:
						//SAFE_BYTE_GET_AND_INC(ofs, start, 1, end);
						ofs = byte_get(eh_frame_bytes, 1);
						System.out.printf("  DW_CFA_advance_loc1: %d to %x\n", ofs * fc.code_factor, fc.pc_begin + ofs * fc.code_factor);
						fc.fieDetails.put((index++) + ": DW_CFA_set_loc", new Object[] { ofs * fc.code_factor, fc.pc_begin + ofs * fc.code_factor });
						fc.pc_begin += ofs * fc.code_factor;
						break;
					case Definition.DW_CFA_advance_loc2:
						//SAFE_BYTE_GET_AND_INC(ofs, start, 2, block_end);
						ofs = byte_get(eh_frame_bytes, 2);
						System.out.printf("  DW_CFA_advance_loc2: %d to %x\n", ofs * fc.code_factor, fc.pc_begin + ofs * fc.code_factor);
						fc.fieDetails.put((index++) + ": DW_CFA_advance_loc2", new Object[] { ofs * fc.code_factor, fc.pc_begin + ofs * fc.code_factor });
						fc.pc_begin += ofs * fc.code_factor;
						break;
					case Definition.DW_CFA_advance_loc4:
						//SAFE_BYTE_GET_AND_INC(ofs, start, 4, block_end);
						ofs = byte_get(eh_frame_bytes, 4);
						System.out.printf("  DW_CFA_advance_loc4: %d to %x\n", ofs * fc.code_factor, fc.pc_begin + ofs * fc.code_factor);
						fc.fieDetails.put((index++) + ": DW_CFA_advance_loc4", new Object[] { ofs * fc.code_factor, fc.pc_begin + ofs * fc.code_factor });
						fc.pc_begin += ofs * fc.code_factor;
						break;
					case Definition.DW_CFA_offset_extended:
						long reg = DwarfLib.getULEB128(eh_frame_bytes);
						roffs = DwarfLib.getULEB128(eh_frame_bytes);

						if (reg >= fc.ncols) {
							reg_prefix = bad_reg;
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							System.out.printf("  DW_CFA_offset_extended: %s%s at cfa%+ld\n", reg_prefix, Definition.dwarf_regnames_i386[(int) reg], roffs * fc.data_factor);
							fc.fieDetails.put((index++) + ": DW_CFA_offset_extended",
									new Object[] { reg_prefix, Definition.dwarf_regnames_i386[(int) reg], roffs * fc.data_factor });
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							fc.col_type[(int) reg] = Definition.DW_CFA_offset;
							fc.col_offset[(int) reg] = roffs * fc.data_factor;
						}
						break;
					case Definition.DW_CFA_val_offset:
						reg = DwarfLib.getULEB128(eh_frame_bytes);
						roffs = DwarfLib.getULEB128(eh_frame_bytes);

						if (reg >= fc.ncols) {
							reg_prefix = bad_reg;
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							System.out.printf("  DW_CFA_val_offset: %s%s at cfa%+ld\n", reg_prefix, Definition.dwarf_regnames_i386[(int) reg], roffs * fc.data_factor);
							fc.fieDetails.put((index++) + ": DW_CFA_val_offset", new Object[] { reg_prefix, Definition.dwarf_regnames_i386[(int) reg], roffs * fc.data_factor });
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							fc.col_type[(int) reg] = Definition.DW_CFA_val_offset;
							fc.col_offset[(int) reg] = roffs * fc.data_factor;
						}
						break;
					case Definition.DW_CFA_restore_extended:
						reg = DwarfLib.getULEB128(eh_frame_bytes);
						if (reg >= cie.ncols || reg >= fc.ncols) {
							reg_prefix = bad_reg;
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							System.out.printf("  DW_CFA_restore_extended: %s%s\n", reg_prefix, Definition.dwarf_regnames_i386[(int) reg]);
							fc.fieDetails.put((index++) + ": DW_CFA_restore_extended", new Object[] { reg_prefix, Definition.dwarf_regnames_i386[(int) reg] });
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							fc.col_type[(int) reg] = cie.col_type[(int) reg];
							fc.col_offset[(int) reg] = cie.col_offset[(int) reg];
						}
						break;
					case Definition.DW_CFA_undefined:
						reg = DwarfLib.getULEB128(eh_frame_bytes);
						if (reg >= fc.ncols) {
							reg_prefix = bad_reg;
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							System.out.printf("  DW_CFA_undefined: %s%s\n", reg_prefix, Definition.dwarf_regnames_i386[(int) reg]);
							fc.fieDetails.put((index++) + ": DW_CFA_undefined", new Object[] { reg_prefix, Definition.dwarf_regnames_i386[(int) reg] });
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							fc.col_type[(int) reg] = Definition.DW_CFA_undefined;
							fc.col_offset[(int) reg] = 0;
						}
						break;
					case Definition.DW_CFA_same_value:
						reg = DwarfLib.getULEB128(eh_frame_bytes);
						if (reg >= fc.ncols) {
							reg_prefix = bad_reg;
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							System.out.printf("  DW_CFA_same_value: %s%s\n", reg_prefix, Definition.dwarf_regnames_i386[(int) reg]);
							fc.fieDetails.put((index++) + ": DW_CFA_same_value", new Object[] { reg_prefix, Definition.dwarf_regnames_i386[(int) reg] });
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							fc.col_type[(int) reg] = Definition.DW_CFA_same_value;
							fc.col_offset[(int) reg] = 0;
						}
						break;
					case Definition.DW_CFA_register:
						reg = DwarfLib.getULEB128(eh_frame_bytes);
						roffs = DwarfLib.getULEB128(eh_frame_bytes);
						if (reg >= fc.ncols) {
							reg_prefix = bad_reg;
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							System.out.printf("  DW_CFA_register: %s%s in ", reg_prefix, Definition.dwarf_regnames_i386[(int) reg]);
							fc.fieDetails.put((index++) + ": DW_CFA_register", new Object[] { reg_prefix, Definition.dwarf_regnames_i386[(int) reg] });
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							fc.col_type[(int) reg] = Definition.DW_CFA_register;
							fc.col_offset[(int) reg] = roffs;
						}
						break;
					case Definition.DW_CFA_remember_state:
						System.out.printf("  DW_CFA_remember_state\n");
						fc.fieDetails.put((index++) + ": DW_CFA_remember_state", new Object[] {});
						FrameChunk rs = new FrameChunk();
						rs.cfa_offset = fc.cfa_offset;
						rs.cfa_reg = fc.cfa_reg;
						rs.ra = fc.ra;
						rs.cfa_exp = fc.cfa_exp;
						rs.ncols = fc.ncols;
						rs.col_type = fc.col_type;
						rs.col_offset = fc.col_offset;
						rs.next = remembered_state;
						remembered_state = rs;
						break;
					case Definition.DW_CFA_restore_state:
						System.out.printf("  DW_CFA_restore_state\n");
						fc.fieDetails.put((index++) + ": DW_CFA_restore_state", new Object[] {});
						rs = remembered_state;
						if (rs != null) {
							remembered_state = rs.next;
							fc.cfa_offset = rs.cfa_offset;
							fc.cfa_reg = rs.cfa_reg;
							fc.ra = rs.ra;
							fc.cfa_exp = rs.cfa_exp;
							if (frame_need_space(fc, rs.ncols - 1) < 0) {
								System.out.printf("Invalid column number in saved frame state\n");
								fc.ncols = 0;
								break;
							}
							fc.col_type = rs.col_type;
							fc.col_offset = rs.col_offset;
						} else {
							System.out.printf("Mismatched DW_CFA_restore_state\n");
						}
						break;
					case Definition.DW_CFA_def_cfa:
						long cfa_reg = DwarfLib.getULEB128(eh_frame_bytes);
						long cfa_offset = DwarfLib.getULEB128(eh_frame_bytes);
						long cfa_exp = 0;
						System.out.println("  DW_CFA_def_cfa: r" + cfa_reg + " " + Definition.dwarf_regnames_i386[(int) cfa_reg] + " ofs " + cfa_offset);
						fc.fieDetails.put((index++) + ": DW_CFA_def_cfa", new Object[] { Definition.dwarf_regnames_i386[(int) cfa_reg] + " ofs " + cfa_offset });
						break;
					case Definition.DW_CFA_def_cfa_register:
						fc.cfa_reg = (int) DwarfLib.getULEB128(eh_frame_bytes);
						fc.cfa_exp = 0;
						System.out.printf("  DW_CFA_def_cfa_register: %s\n", Definition.dwarf_regnames_i386[fc.cfa_reg]);
						fc.fieDetails.put((index++) + ": DW_CFA_def_cfa_register", new Object[] { Definition.dwarf_regnames_i386[fc.cfa_reg] });
						break;
					case Definition.DW_CFA_def_cfa_offset:
						fc.cfa_offset = DwarfLib.getULEB128(eh_frame_bytes);
						System.out.printf("  DW_CFA_def_cfa_offset: %d\n", fc.cfa_offset);
						fc.fieDetails.put((index++) + ": DW_CFA_def_cfa_offset", new Object[] { fc.cfa_offset });
						break;
					case Definition.DW_CFA_nop:
						System.out.println("  DW_CFA_nop");
						fc.fieDetails.put((index++) + ": DW_CFA_nop", new Object[] {});
						break;
					case Definition.DW_CFA_def_cfa_expression:
						long ul = DwarfLib.getULEB128(eh_frame_bytes);

						if (start >= block_end || start + ul > block_end || start + ul < start) {
							System.out.printf("  DW_CFA_def_cfa_expression: <corrupt len %lu>\n", ul);
							break;
						}

						System.out.printf("  DW_CFA_def_cfa_expression (");
						decode_location_expression(eh_frame_bytes, eh_addr_size, 0, -1, ul, 0, ehFrameSection);
						System.out.printf(")\n");
						fc.fieDetails.put((index++) + ": DW_CFA_def_cfa_expression", new Object[] {});

						fc.cfa_exp = 1;
						start += ul;
						break;

					case Definition.DW_CFA_expression:
						reg = DwarfLib.getULEB128(eh_frame_bytes);
						ul = DwarfLib.getULEB128(eh_frame_bytes);

						if (reg >= fc.ncols) {
							reg_prefix = bad_reg;
						}
						/* PR 17512: file: 069-133014-0.006.  */
						/* PR 17512: file: 98c02eb4.  */
						long tmp = start + ul;
						if (start >= block_end || tmp > block_end || tmp < start) {
							System.out.printf("  DW_CFA_expression: <corrupt len %lu>\n", ul);
							fc.fieDetails.put((index++) + ": DW_CFA_expression", new Object[] { ul });
							break;
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							System.out.printf("  DW_CFA_expression: %s%s (", reg_prefix, Definition.dwarf_regnames_i386[(int) reg]);
							decode_location_expression(eh_frame_bytes, eh_addr_size, 0, -1, ul, 0, ehFrameSection);
							System.out.printf(")\n");
							fc.fieDetails.put((index++) + ": DW_CFA_expression", new Object[] {});
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							fc.col_type[(int) reg] = Definition.DW_CFA_expression;
						}
						start = tmp;
						break;
					case Definition.DW_CFA_val_expression:
						reg = DwarfLib.getULEB128(eh_frame_bytes);
						ul = DwarfLib.getULEB128(eh_frame_bytes);
						if (reg >= fc.ncols) {
							reg_prefix = bad_reg;
						}
						tmp = start + ul;
						if (start >= block_end || tmp > block_end || tmp < start) {
							System.out.printf("  DW_CFA_val_expression: <corrupt len %lu>\n", ul);
							fc.fieDetails.put((index++) + ": DW_CFA_val_expression", new Object[] { ul });
							break;
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							System.out.printf("  DW_CFA_val_expression: %s%s (", reg_prefix, Definition.dwarf_regnames_i386[(int) reg]);
							decode_location_expression(eh_frame_bytes, eh_addr_size, 0, -1, ul, 0, ehFrameSection);
							System.out.printf(")\n");
							fc.fieDetails.put((index++) + ": DW_CFA_val_expression", new Object[] {});
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							fc.col_type[(int) reg] = Definition.DW_CFA_val_expression;
						}
						start = tmp;
						break;
					case Definition.DW_CFA_offset_extended_sf:
						reg = DwarfLib.getULEB128(eh_frame_bytes);
						long l = DwarfLib.getSLEB128(eh_frame_bytes);

						if (frame_need_space(fc, (int) reg) < 0) {
							reg_prefix = bad_reg;
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							System.out.printf("  DW_CFA_offset_extended_sf: %s%s at cfa%+ld\n", reg_prefix, Definition.dwarf_regnames_i386[(int) reg], (long) (l * fc.data_factor));
							fc.fieDetails.put((index++) + ": DW_CFA_offset_extended_sf", new Object[] { reg_prefix, Definition.dwarf_regnames_i386[(int) reg],
									(long) (l * fc.data_factor) });
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							fc.col_type[(int) reg] = Definition.DW_CFA_offset;
							fc.col_offset[(int) reg] = l * fc.data_factor;
						}
						break;
					case Definition.DW_CFA_val_offset_sf:
						reg = DwarfLib.getULEB128(eh_frame_bytes);
						l = DwarfLib.getSLEB128(eh_frame_bytes);

						if (frame_need_space(fc, (int) reg) < 0) {
							reg_prefix = bad_reg;
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							System.out.printf("  DW_CFA_val_offset_sf: %s%s at cfa%+ld\n", reg_prefix, Definition.dwarf_regnames_i386[(int) reg], (long) (l * fc.data_factor));
							fc.fieDetails.put((index++) + ": DW_CFA_val_offset_sf", new Object[] { reg_prefix, Definition.dwarf_regnames_i386[(int) reg],
									(long) (l * fc.data_factor) });
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							fc.col_type[(int) reg] = Definition.DW_CFA_val_offset;
							fc.col_offset[(int) reg] = l * fc.data_factor;
						}
						break;
					case Definition.DW_CFA_def_cfa_sf:
						fc.cfa_reg = (int) DwarfLib.getULEB128(eh_frame_bytes);
						fc.cfa_offset = DwarfLib.getSLEB128(eh_frame_bytes);

						fc.cfa_offset = fc.cfa_offset * fc.data_factor;
						fc.cfa_exp = 0;

						System.out.printf("  DW_CFA_def_cfa_sf: %s ofs %d\n", Definition.dwarf_regnames_i386[fc.cfa_reg], (int) fc.cfa_offset);
						fc.fieDetails.put((index++) + ": DW_CFA_def_cfa_sf", new Object[] { Definition.dwarf_regnames_i386[fc.cfa_reg], (int) fc.cfa_offset });
						break;
					case Definition.DW_CFA_def_cfa_offset_sf:
						fc.cfa_offset = DwarfLib.getSLEB128(eh_frame_bytes);
						fc.cfa_offset *= fc.data_factor;

						System.out.printf("  DW_CFA_def_cfa_offset_sf: %d\n", (int) fc.cfa_offset);
						fc.fieDetails.put((index++) + ": DW_CFA_def_cfa_offset_sf", new Object[] { fc.cfa_offset });
						break;
					case Definition.DW_CFA_MIPS_advance_loc8:
						ofs = byte_get(eh_frame_bytes, 8);

						System.out.printf("  DW_CFA_MIPS_advance_loc8: %ld to %x\n", ofs * fc.code_factor, fc.pc_begin + ofs * fc.code_factor);
						fc.fieDetails.put((index++) + ": DW_CFA_MIPS_advance_loc8", new Object[] { ofs * fc.code_factor, fc.pc_begin + ofs * fc.code_factor });
						fc.pc_begin += ofs * fc.code_factor;
						break;
					case Definition.DW_CFA_GNU_window_save:
						System.out.printf("  DW_CFA_GNU_window_save\n");
						break;

					case Definition.DW_CFA_GNU_args_size:
						ul = DwarfLib.getULEB128(eh_frame_bytes);

						System.out.printf("  DW_CFA_GNU_args_size: %ld\n", ul);
						fc.fieDetails.put((index++) + ": DW_CFA_GNU_args_size", new Object[] { ul });
						break;
					case Definition.DW_CFA_GNU_negative_offset_extended:
						reg = DwarfLib.getULEB128(eh_frame_bytes);
						l = -DwarfLib.getULEB128(eh_frame_bytes);

						if (frame_need_space(fc, (int) reg) < 0) {
							reg_prefix = bad_reg;
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							System.out.printf("  DW_CFA_GNU_negative_offset_extended: %s%s at cfa%+ld\n", reg_prefix, Definition.dwarf_regnames_i386[(int) reg],
									(long) (l * fc.data_factor));
							fc.fieDetails.put((index++) + ": DW_CFA_GNU_negative_offset_extended", new Object[] { reg_prefix, Definition.dwarf_regnames_i386[(int) reg],
									(long) (l * fc.data_factor) });
						}
						if (reg_prefix.length() == 0 || reg_prefix.charAt(0) == '\0') {
							fc.col_type[(int) reg] = Definition.DW_CFA_offset;
							fc.col_offset[(int) reg] = l * fc.data_factor;
						}
						break;
					default:
						System.out.println("dwarf has something not supported yet");
						System.exit(1);
					}
				}
			}
		} catch (OutOfMemoryError e) {
			e.printStackTrace();
			loadingMessage = file.getAbsolutePath() + " : out of memory error";
			return 19;
		} catch (IOException e) {
			e.printStackTrace();
			loadingMessage = file.getAbsolutePath() + " : IO exception";
			return 2;
		}
		isLoading = false;
		return 0;
	}

	private void decode_location_expression(ByteBuffer eh_frame_bytes2, int eh_addr_size, int i, int j, long ul, int k, Elf32_Shdr ehFrameSection) {
		System.out.println("not support decode_location_expression");
		System.exit(400);
	}

	private int frame_need_space(FrameChunk fc, int reg) {
		int prev = fc.ncols;

		if (reg < fc.ncols)
			return 0;

		if (reg > Definition.dwarf_regnames_x86_64.length) {
			return -1;
		}

		fc.ncols = reg + 1;
		/* PR 17512: file: 10450-2643-0.004.
		 If reg == -1 then this can happen...  */
		if (fc.ncols == 0) {
			return -1;
		}

		/* PR 17512: file: 2844a11d.  */
		if (fc.ncols > 1024) {
			System.out.println("Unfeasibly large register number: " + reg);
			fc.ncols = 0;
			/* FIXME: 1024 is an arbitrary limit.  Increase it if
			 we ever encounter a valid binary that exceeds it.  */
			return -1;
		}

		fc.col_type = new long[fc.ncols];
		fc.col_offset = new long[fc.ncols];
		/* PR 17512: file:002-10025-0.005.  */

		while (prev < fc.ncols) {
			fc.col_type[prev] = Definition.DW_CFA_unreferenced;
			fc.col_offset[prev] = 0;
			//System.out.println("\t\t" + fc.col_type[prev] + ", " + fc.col_offset[prev]);
			prev++;
		}

		return 1;
	}

	public static int size_of_encoded_value(int encoding, int eh_addr_size) {
		switch (encoding & 0x7) {
		default: /* ??? */
		case 0:
			return eh_addr_size;
		case 2:
			return 2;
		case 3:
			return 4;
		case 4:
			return 8;
		}
	}

	public static long get_encoded_value(ByteBuffer byteBuffer, int encoding, Elf32_Shdr section, int eh_addr_size) {
		int size = size_of_encoded_value(encoding, eh_addr_size);
		long val;

		if (byteBuffer.position() + size >= byteBuffer.capacity()) {
			System.out.println("Encoded value extends past end of section");
			//*pdata = end;
			//return 0;
			System.exit(112);
		}

		/* PR 17512: file: 002-829853-0.004.  */
		if (size > 8) {
			System.out.println("Encoded size of " + size + " is too large to read");
			//*pdata = end;
			//return 0;
			System.exit(112);
		}

		/* PR 17512: file: 1085-5603-0.004.  */
		if (size == 0) {
			System.out.println("Encoded size of 0 is too small to read");
			//*pdata = end;
			//return 0;
			System.exit(113);
		}

		int oldPosition = byteBuffer.position();
		if ((encoding & Definition.DW_EH_PE_signed) > 0) {
			val = byte_get_signed(byteBuffer, size);
		} else {
			//val = byte_get(byteBuffer, size);
			val = byte_get(byteBuffer, size);
		}

		byteBuffer.position(oldPosition);

		if ((encoding & 0x70) == Definition.DW_EH_PE_pcrel) {
			val += section.sh_addr + byteBuffer.position();
			val &= 0xffffffffL;
		}

		byteBuffer.position(oldPosition + size);

		return val;
	}

	public static long byte_get(ByteBuffer byteBuffer, int size) {
		//		System.out.println(byteBuffer.get());
		//		System.out.println(byteBuffer.get());
		//		System.out.println(byteBuffer.get());
		//		System.out.println(byteBuffer.get());
		long x = 0;
		if (size == 1) {
			x = byteBuffer.get();
			x &= 0xffL;
		} else if (size == 2) {
			x = byteBuffer.getShort();
			x &= 0xffffL;
		} else if (size == 4) {
			x = byteBuffer.getInt();
			x &= 0xffffffffL;
		} else if (size == 8) {
			x = byteBuffer.getLong();
			x &= 0xffffffffffffffffL;
		} else {
			System.out.println("byte_get_signed, wrong size = " + size);
			System.exit(115);
		}
		return x;
	}

	public static long byte_get_signed(ByteBuffer byteBuffer, int size) {
		long x = byte_get(byteBuffer, size);

		switch (size) {
		case 1:
			x = (x ^ 0x80) - 0x80;
			x &= 0xffL;
			break;
		case 2:
			x = (x ^ 0x8000) - 0x8000;
			x &= 0xffffL;
			break;
		case 4:
			x = (x ^ 0x80000000) - 0x80000000;
			x &= 0xffffffffL;
			break;
		case 8:
			x = (x ^ 0x8000000000000000L) - 0x8000000000000000L;
			x &= 0xffffffffffffffffL;
			break;
		default:
			System.out.println("byte_get_signed not support size=" + size);
			System.exit(40);
		}
		return x;
	}

	public boolean isELF(File file) {
		InputStream is;
		try {
			is = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return false;
		}
		try {
			is.skip(1);
			if (is.read() != 0x45 || is.read() != 0x4c || is.read() != 0x46) {
				return false;
			}
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		} finally {
			try {
				is.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return true;
	}

	private static Vector<Elf32_Sym> parseSymtab(ByteBuffer symtab, ByteBuffer strtab) {
		Vector<Elf32_Sym> symbols = new Vector<Elf32_Sym>();
		while (symtab.remaining() >= 16) {
			Elf32_Sym symbol = new Elf32_Sym();
			symbol.st_name = symtab.getInt();
			symbol.st_value = symtab.getInt();
			symbol.st_size = symtab.getInt();
			symbol.st_info = symtab.get();
			symbol.st_other = symtab.get();
			symbol.st_shndx = symtab.getShort();
			symbol.name = DwarfLib.getString(strtab, symbol.st_name);
			symbols.add(symbol);
		}
		return symbols;
	}

	private LinkedHashMap<Integer, LinkedHashMap<Integer, Abbrev>> parseDebugAbbrev(ByteBuffer debug_abbrev_bytes) {
		LinkedHashMap<Integer, LinkedHashMap<Integer, Abbrev>> vector = new LinkedHashMap<Integer, LinkedHashMap<Integer, Abbrev>>();
		LinkedHashMap<Integer, Abbrev> abbrevList = new LinkedHashMap<Integer, Abbrev>();

		int acumalateOffset = debug_abbrev_bytes.position();
		while (debug_abbrev_bytes.hasRemaining()) {
			Abbrev abbrev = new Abbrev();
			int number = (int) DwarfLib.getULEB128(debug_abbrev_bytes);
			if (number == 0) {
				vector.put(acumalateOffset, abbrevList);
				abbrevList = new LinkedHashMap<Integer, Abbrev>();
				acumalateOffset = debug_abbrev_bytes.position();
				continue;
			}
			int tag = (int) DwarfLib.getULEB128(debug_abbrev_bytes);
			int has_children = debug_abbrev_bytes.get();
			abbrev.number = number;
			abbrev.tag = tag;
			if (has_children == Definition.DW_CHILDREN_yes) {
				abbrev.has_children = true;
			}

			abbrev.entries.clear();

			while (true) {
				AbbrevEntry abbrevEntry = new AbbrevEntry();
				//				tag = debug_abbrev_bytes.get();
				tag = (int) DwarfLib.getULEB128(debug_abbrev_bytes);
				int form = (int) DwarfLib.getULEB128(debug_abbrev_bytes);
				//				int form = debug_abbrev_bytes.get();
				if (tag == 0 && form == 0) {
					break;
				}
				abbrevEntry.at = tag;
				abbrevEntry.form = form;
				abbrev.entries.add(abbrevEntry);
			}
			abbrevList.put(number, abbrev);
		}
		return vector;
	}

	private int parseDebugInfo(Elf32_Shdr debugInfoSection, ByteBuffer debugInfoBytes) throws OutOfMemoryError {
		if (abbrevList == null) {
			throw new IllegalArgumentException("abbrevList is null, please call parseDebugAbbrev() first");
		}
		int r = calculationRelocation(debugInfoSection, debugInfoBytes, ".rel.debug_info");
		if (r > 0) {
			return r;
		}
		int start = 0;
		int initial_length_size = 0;
		while (debugInfoBytes.remaining() > 11) {
			CompileUnit cu = new CompileUnit();
			cu.offset = debugInfoBytes.position();
			cu.length = debugInfoBytes.getInt();
			cu.version = debugInfoBytes.getShort();
			cu.abbrev_offset = debugInfoBytes.getInt();
			cu.addr_size = debugInfoBytes.get();
			compileUnits.add(cu);

			if (cu.length == 0xffffffff) {
				cu.length = (int) debugInfoBytes.getLong();
				initial_length_size = 12;
			} else {
				initial_length_size = 4;
			}
			if (DwarfGlobal.debug) {
				System.out.println(Integer.toHexString(debugInfoBytes.position()) + " " + cu);
			}

			//			DebugInfoEntry currentDebugInfoEntry = null;
			Stack<Vector<DebugInfoEntry>> originalDebugInfoEntry = new Stack<Vector<DebugInfoEntry>>();
			Vector<DebugInfoEntry> currentDebugInfoEntry = cu.debugInfoEntries;
			Stack<Long> siblingValue = new Stack<Long>();

			while (debugInfoBytes.position() <= cu.offset + cu.length + 1) {
				loadingMessage = "parsing .debug_info " + debugInfoBytes.position() + " bytes";
				DebugInfoEntry debugInfoEntry = new DebugInfoEntry();

				debugInfoEntry.position = debugInfoBytes.position();

				if (siblingValue.size() > 0 && debugInfoEntry.position == siblingValue.peek()) {
					currentDebugInfoEntry = originalDebugInfoEntry.pop();
					siblingValue.pop();
				}

				debugInfoEntry.abbrevNo = (int) DwarfLib.getULEB128(debugInfoBytes);
				Abbrev abbrev = abbrevList.get(cu.abbrev_offset).get(debugInfoEntry.abbrevNo);
				if (abbrev == null) {
					continue;
				}
				debugInfoEntry.name = Definition.getTagName(abbrev.tag);

				if (DwarfGlobal.debug) {
					System.out.println(Integer.toHexString(debugInfoEntry.position) + " > " + debugInfoEntry.name);
					System.out.flush();
				}
				for (AbbrevEntry entry : abbrev.entries) {
					loadingMessage = "parsing .debug_info " + debugInfoBytes.position() + " bytes";

					DebugInfoAbbrevEntry debugInfoAbbrevEntry = new DebugInfoAbbrevEntry();
					debugInfoAbbrevEntry.name = Definition.getATName(entry.at);
					debugInfoEntry.debugInfoAbbrevEntries.put(debugInfoAbbrevEntry.name, debugInfoAbbrevEntry);
					debugInfoAbbrevEntry.form = entry.form;
					debugInfoAbbrevEntry.formStr = Definition.getFormName(entry.form);
					debugInfoAbbrevEntry.position = debugInfoBytes.position();

					//System.out.println("debugInfoAbbrevEntry="+debugInfoAbbrevEntry.position+","+debugInfoAbbrevEntry.name);

					if (DwarfGlobal.debug) {
						System.out.print("\t" + Integer.toHexString(debugInfoAbbrevEntry.position) + " > " + entry.form + " = " + debugInfoAbbrevEntry.name);
					}

					if (entry.form == Definition.DW_FORM_string) {
						byte temp;
						String value = "";
						while ((temp = debugInfoBytes.get()) != 0) {
							value += ((char) temp);
						}
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + value);
						}
						debugInfoAbbrevEntry.value = value;
					} else if (entry.form == Definition.DW_FORM_addr) {
						if (cu.addr_size == 4) {
							long address = debugInfoBytes.getInt();
							debugInfoAbbrevEntry.value = address;
						} else {
							debugInfoAbbrevEntry.value = null;
							System.err.println("debugInfoAbbrevEntry.value = null");
						}
					} else if (entry.form == Definition.DW_FORM_strp) {
						int stringOffset = debugInfoBytes.getInt();
						String s = DwarfLib.getString(debug_bytes, stringOffset);
						if (DwarfGlobal.debug) {
							System.out.printf("\t(indirect string, offset: %x):\t%s", stringOffset, s);
						}
						debugInfoAbbrevEntry.value = s;
					} else if (entry.form == Definition.DW_FORM_data1) {
						int data = debugInfoBytes.get() & 0xff;
						debugInfoAbbrevEntry.value = data;
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_data2) {
						short data = debugInfoBytes.getShort();
						debugInfoAbbrevEntry.value = Integer.toHexString(data);
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_data4) {
						int data = debugInfoBytes.getInt();
						debugInfoAbbrevEntry.value = Integer.toHexString(data);
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_data8) {
						long data = debugInfoBytes.getLong();
						debugInfoAbbrevEntry.value = Long.toHexString(data);
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data + cu.offset);
						}
					} else if (entry.form == Definition.DW_FORM_ref1) {
						byte data = debugInfoBytes.get();
						debugInfoAbbrevEntry.value = Integer.toHexString(data + cu.offset);
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data + cu.offset);
						}
					} else if (entry.form == Definition.DW_FORM_ref2) {
						short data = debugInfoBytes.getShort();
						debugInfoAbbrevEntry.value = Integer.toHexString(data + cu.offset);
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data + cu.offset);
						}
					} else if (entry.form == Definition.DW_FORM_ref4) {
						int data = debugInfoBytes.getInt();
						debugInfoAbbrevEntry.value = Integer.toHexString(data + cu.offset);
						if (DwarfGlobal.debug) {
							System.out.printf("\t:\t%x %x", data, data + cu.offset);
						}
					} else if (entry.form == Definition.DW_FORM_ref8) {
						long data = debugInfoBytes.getLong();
						debugInfoAbbrevEntry.value = Long.toHexString(data + cu.offset);
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_block) {
						long size = DwarfLib.getULEB128(debugInfoBytes);
						byte bytes[] = new byte[(int) size];
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t");
						}
						for (int z = 0; z < size; z++) {
							bytes[z] = (byte) (debugInfoBytes.get() & 0xff);
							if (DwarfGlobal.debug) {
								System.out.printf("%x\t", bytes[z]);
							}
						}
						debugInfoAbbrevEntry.value = bytes;
					} else if (entry.form == Definition.DW_FORM_block1) {
						int size = debugInfoBytes.get() & 0xff;
						byte bytes[] = new byte[(int) size];
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t");
						}
						for (int z = 0; z < size; z++) {
							bytes[z] = (byte) (debugInfoBytes.get() & 0xff);
							if (DwarfGlobal.debug) {
								System.out.printf("%x\t", bytes[z]);
							}
						}
						debugInfoAbbrevEntry.value = bytes;
					} else if (entry.form == Definition.DW_FORM_block2) {
						short size = debugInfoBytes.getShort();
						byte bytes[] = new byte[(int) size];
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t");
						}
						for (int z = 0; z < size; z++) {
							bytes[z] = (byte) (debugInfoBytes.get() & 0xff);
							if (DwarfGlobal.debug) {
								System.out.printf("%x\t", bytes[z]);
							}
						}
						debugInfoAbbrevEntry.value = bytes;
					} else if (entry.form == Definition.DW_FORM_block4) {
						int size = debugInfoBytes.getInt();
						byte bytes[] = new byte[(int) size];
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t");
						}
						for (int z = 0; z < size; z++) {
							bytes[z] = (byte) (debugInfoBytes.get() & 0xff);
							if (DwarfGlobal.debug) {
								System.out.printf("%x\t", bytes[z]);
							}
						}
						debugInfoAbbrevEntry.value = bytes;
					} else if (entry.form == Definition.DW_FORM_ref_udata) {
						long data = DwarfLib.getULEB128(debugInfoBytes);
						debugInfoAbbrevEntry.value = data;
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_flag) {
						byte flag = debugInfoBytes.get();
						debugInfoAbbrevEntry.value = flag;
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + flag);
						}
					} else if (entry.form == Definition.DW_FORM_sec_offset) {
						int value = debugInfoBytes.getInt();
						debugInfoAbbrevEntry.value = value;
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + value);
						}
					} else if (entry.form == Definition.DW_FORM_flag_present) {
						//						byte value = debugInfoBytes.get();
						debugInfoAbbrevEntry.value = 1;
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t1");
						}
					} else if (entry.form == Definition.DW_FORM_exprloc) {
						long size = DwarfLib.getULEB128(debugInfoBytes);
						byte bytes[] = new byte[(int) size];
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t");
						}
						debugInfoAbbrevEntry.value = "";
						for (int z = 0; z < size; z++) {
							bytes[z] = (byte) (debugInfoBytes.get() & 0xff);
							debugInfoAbbrevEntry.value += (bytes[z] & 0xFF) + ",";
							if (DwarfGlobal.debug) {
								System.out.print(bytes[z] + "\t");
							}
						}
					} else if (entry.form == Definition.DW_FORM_sdata) {
						long data = DwarfLib.getSLEB128(debugInfoBytes);
						debugInfoAbbrevEntry.value = data;
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data);
						}
					} else if (entry.form == Definition.DW_FORM_udata) {
						long data = DwarfLib.getULEB128(debugInfoBytes);
						debugInfoAbbrevEntry.value = data;
						if (DwarfGlobal.debug) {
							System.out.print("\t:\t" + data);
						}
					} else {
						System.out.println(" unsupport DW_FORM_? = 0x" + Integer.toHexString(entry.form));
						return 3;
					}

					if (debugInfoEntry.name.equals("DW_TAG_compile_unit")) {
						if (debugInfoAbbrevEntry.name.equals("DW_AT_producer")) {
							cu.DW_AT_producer = String.valueOf(debugInfoAbbrevEntry.value);
						} else if (debugInfoAbbrevEntry.name.equals("DW_AT_language")) {
							cu.DW_AT_language = (int) Long.parseLong(debugInfoAbbrevEntry.value.toString(), 16);
						} else if (debugInfoAbbrevEntry.name.equals("DW_AT_name")) {
							cu.DW_AT_name = String.valueOf(debugInfoAbbrevEntry.value);
						} else if (debugInfoAbbrevEntry.name.equals("DW_AT_comp_dir")) {
							cu.DW_AT_comp_dir = String.valueOf(debugInfoAbbrevEntry.value);
						} else if (debugInfoAbbrevEntry.name.equals("DW_AT_low_pc")) {
							cu.DW_AT_low_pc = Long.parseLong(debugInfoAbbrevEntry.value.toString(), 10);
						} else if (debugInfoAbbrevEntry.name.equals("DW_AT_high_pc")) {
							cu.DW_AT_high_pc = Long.parseLong(debugInfoAbbrevEntry.value.toString(), 16);
						} else if (debugInfoAbbrevEntry.name.equals("DW_AT_stmt_list")) {
							cu.DW_AT_stmt_list = String.valueOf(debugInfoAbbrevEntry.value);
						}
					}

					if (DwarfGlobal.debug) {
						System.out.println();
					}
				}
				currentDebugInfoEntry.add(debugInfoEntry);
				DebugInfoAbbrevEntry debugInfoAbbrevEntry = debugInfoEntry.debugInfoAbbrevEntries.get("DW_AT_sibling");
				if (debugInfoAbbrevEntry != null) {
					originalDebugInfoEntry.push(currentDebugInfoEntry);
					currentDebugInfoEntry = debugInfoEntry.debugInfoEntries;
					siblingValue.push(CommonLib.convertFilesize("0x" + debugInfoAbbrevEntry.value));
				}
			}

			start += cu.length + initial_length_size;
			debugInfoBytes.position(start);
		}
		return 0;
	}

	private int calculationRelocation(Elf32_Shdr debugInfoSection, ByteBuffer debugInfoBytes, String relocationInfoSectionName) {
		int originalPosition = debugInfoBytes.position();
		if (ehdr.e_type != Elf_Common.ET_REL) {
			return 0;
		}

		Elf32_Shdr debugInfoRelSection = null;
		for (Elf32_Shdr s : SectionFinder.getAllRelocationSection(file)) {
			if (s.sh_info == debugInfoSection.number) {
				debugInfoRelSection = s;
				break;
			}
		}
		if (debugInfoRelSection != null) {
			try {
				ByteBuffer byteBuffer = SectionFinder.findSectionByte(ehdr, file, relocationInfoSectionName);
				int size = Integer.MAX_VALUE;
				if (debugInfoRelSection.sh_type == Elf_Common.SHT_RELA) {
					size = 12;
				} else if (debugInfoRelSection.sh_type == Elf_Common.SHT_REL) {
					size = 8;
				}
				boolean is_rela;
				if (debugInfoRelSection.sh_type == Elf_Common.SHT_RELA) {
					is_rela = true;
				}
				if (ehdr.e_machine == Definition.EM_SH) {
					is_rela = false;
				}
				while (byteBuffer.remaining() >= size) {
					int offset = byteBuffer.getInt();
					int info = byteBuffer.getInt();

					int addend = 0;

					int relocationType = Elf_Common.ELF32_R_TYPE(info);

					debugInfoBytes.position(offset);
					if (debugInfoRelSection.sh_type != Elf_Common.SHT_RELA || (ehdr.e_machine == Definition.EM_XTENSA && relocationType == 1)
							|| ((ehdr.e_machine == Definition.EM_PJ || ehdr.e_machine == Definition.EM_PJ_OLD) && relocationType == 1)
							|| ((ehdr.e_machine == Definition.EM_D30V || ehdr.e_machine == Definition.EM_CYGNUS_D30V) && relocationType == 12)) {
						addend = debugInfoBytes.getInt();
					}
					if (DwarfGlobal.debug) {
						System.out.printf("%x\t", offset);
						System.out.printf("%x\t", info);
						if (debugInfoRelSection.sh_type == Elf_Common.SHT_RELA) {
							System.out.printf("%x\t", addend);
						}
						System.out.printf("%s\t", Elf_Common.getRelocationTypeName(relocationType));
						System.out.printf("%d\t", Elf_Common.ELF32_R_SYM(info));
						System.out.printf("%08x\t", symbols.get(Elf_Common.ELF32_R_SYM(info)).st_value);
					}

					// relocation
					int temp = debugInfoBytes.position();

					if (debugInfoBytes.remaining() >= 4) {
						debugInfoBytes.position(offset);
						int value = symbols.get(Elf_Common.ELF32_R_SYM(info)).st_value + addend;
						debugInfoBytes.putInt(value);
						debugInfoBytes.position(temp);
						if (DwarfGlobal.debug) {
							System.out.print(",replace offset " + offset + " to " + value + ", addend=" + Integer.toHexString(addend) + ", ");
						}
					}

					if (DwarfGlobal.debug) {
						//System.out.printf("%s\t", DwarfLib.getString(strtab_str, symbols.get(Elf_Common.ELF32_R_SYM(info)).st_name));
						//System.out.printf("\n");
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
				debugInfoBytes.position(originalPosition);
				return 1;
			}
		}
		debugInfoBytes.position(originalPosition);
		return 0;
	}

	private int parseHeader(ByteBuffer debugLineBytes, CompileUnit compileUnit, long memoryOffset) {
		try {
			final int begin = debugLineBytes.position();

			DwarfDebugLineHeader dwarfDebugLineHeader = new DwarfDebugLineHeader();
			dwarfDebugLineHeader.offset = debugLineBytes.position();
			dwarfDebugLineHeader.total_length = (long) debugLineBytes.getInt() & 0xFFFFFFFFL;
			dwarfDebugLineHeader.version = debugLineBytes.getShort() & 0xFFFF;
			dwarfDebugLineHeader.prologue_length = (long) debugLineBytes.getInt() & 0xFFFFFFFFL;
			dwarfDebugLineHeader.minimum_instruction_length = debugLineBytes.get() & 0xFF;

			final int end = (int) (begin + dwarfDebugLineHeader.total_length + 4);
			final int prologue_end = (int) (begin + dwarfDebugLineHeader.prologue_length + 9);

			if (dwarfDebugLineHeader.version >= 4) {
				dwarfDebugLineHeader.max_ops_per_insn = debugLineBytes.get();
				if (dwarfDebugLineHeader.max_ops_per_insn == 0) {
					System.out.println("Invalid maximum operations per insn.");
					return 5;
				}
			} else {
				dwarfDebugLineHeader.max_ops_per_insn = 1;
			}

			dwarfDebugLineHeader.default_is_stmt = debugLineBytes.get() != 0;
			dwarfDebugLineHeader.line_base = debugLineBytes.get();
			dwarfDebugLineHeader.line_range = debugLineBytes.get() & 0xFF;
			dwarfDebugLineHeader.opcode_base = debugLineBytes.get() & 0xFF;
			dwarfDebugLineHeader.standard_opcode_lengths = new byte[dwarfDebugLineHeader.opcode_base - 1];
			debugLineBytes.get(dwarfDebugLineHeader.standard_opcode_lengths);

			// Skip the directories; they end with a single null byte.
			String s;
			while ((s = DwarfLib.getString(debugLineBytes)).length() > 0) {
				dwarfDebugLineHeader.dirnames.add(s);
			}

			if (DwarfGlobal.debug) {
				System.out.println(dwarfDebugLineHeader);
				for (String dir : dwarfDebugLineHeader.dirnames) {
					System.out.println(dir);
				}
			}

			// Read the file names.
			int entryNo = 1;
			while (debugLineBytes.hasRemaining() && debugLineBytes.position() < prologue_end) {
				loadingMessage = "parsing .debug_line " + debugLineBytes.position() + " bytes";
				DwarfHeaderFilename f = new DwarfHeaderFilename();
				String fname = DwarfLib.getString(debugLineBytes);
				long u1 = DwarfLib.getULEB128(debugLineBytes);
				long u2 = DwarfLib.getULEB128(debugLineBytes);
				long u3 = DwarfLib.getULEB128(debugLineBytes);
				f.entryNo = entryNo;

				try {
					if (u1 == 0) {
						f.file = new File(compileUnit.DW_AT_comp_dir + File.separator + fname);
					} else if (new File(dwarfDebugLineHeader.dirnames.get((int) u1 - 1)).isAbsolute()) {
						f.file = new File(dwarfDebugLineHeader.dirnames.get((int) u1 - 1) + File.separator + fname);
					} else {
						f.file = new File(compileUnit.DW_AT_comp_dir + File.separator + dwarfDebugLineHeader.dirnames.get((int) u1 - 1) + File.separator + fname);
					}
					if (DwarfGlobal.debug && !f.file.exists()) {
						System.err.println(f.file.getAbsolutePath() + " is not exist");
					}
				} catch (Exception ex) {
					ex.printStackTrace();
					System.out.println(u1);
				}
				f.dir = u1;
				f.time = u2;
				f.len = u3;
				entryNo++;
				dwarfDebugLineHeader.filenames.add(f);

				if (DwarfGlobal.debug) {
					System.out.println(f.dir + "\t" + f.time + "\t" + f.len + "\t" + f.file);
				}
			}
			if (DwarfGlobal.debug) {
				System.out.println("--" + debugLineBytes.position());
			}

			debugLineBytes.get();

			BigInteger address = BigInteger.ZERO;
			long file_num = 0;
			int line_num = 1;
			long column_num = 0;
			boolean is_stmt = dwarfDebugLineHeader.default_is_stmt;
			boolean basic_block = false;
			int op_index = 0;
			boolean end_sequence = false;
			int last_file_entry = 0;

			while (debugLineBytes.hasRemaining() && debugLineBytes.position() < end) {
				if (DwarfGlobal.debug) {
					System.out.print("> 0x" + Integer.toHexString(debugLineBytes.position() - 0xf0) + " ");
				}
				int opcode = debugLineBytes.get() & 0xff;
				if (opcode >= dwarfDebugLineHeader.opcode_base) {
					opcode -= dwarfDebugLineHeader.opcode_base;
					int advance_address = ((opcode / dwarfDebugLineHeader.line_range) * dwarfDebugLineHeader.minimum_instruction_length);
					address = address.add(BigInteger.valueOf(advance_address));
					int advance_line = ((opcode % dwarfDebugLineHeader.line_range) + dwarfDebugLineHeader.line_base);
					line_num += advance_line;
					if (DwarfGlobal.debug) {
						System.out.println("Special opcode:" + opcode + ",\tadvance address by " + advance_address + " to 0x" + address.toString(16) + ", line by " + advance_line
								+ " to " + line_num);
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_extended_op) {
					long size = DwarfLib.getULEB128(debugLineBytes);
					if (size == 0) {
						System.out.println("Error: DW_LNS_extended_op size=0");
						return 11;
					}
					int code = debugLineBytes.get();
					if (code == Dwarf_line_number_x_ops.DW_LNE_end_sequence) {
						if (DwarfGlobal.debug) {
							System.out.println("Extended opcode:" + code + " End of sequence");
						}
						address = BigInteger.ZERO;
						op_index = 0;
						file_num = 1;
						line_num = 1;
						column_num = 0;
						is_stmt = dwarfDebugLineHeader.default_is_stmt;
						basic_block = false;
						end_sequence = false;
						last_file_entry = 0;
						continue;
					} else if (code == Dwarf_line_number_x_ops.DW_LNE_set_address) {
						address = BigInteger.valueOf(debugLineBytes.getInt());
						op_index = 0;
						if (DwarfGlobal.debug) {
							System.out.println("Extended opcode:" + code + ": set Address to 0x" + address.toString(16));
						}
						//					continue;
					} else if (code == Dwarf_line_number_x_ops.DW_LNE_define_file) {
						int dir_index = 0;

						++last_file_entry;
					} else if (code == Dwarf_line_number_x_ops.DW_LNE_set_discriminator) {
						int discriminator = debugLineBytes.get();
						if (DwarfGlobal.debug) {
							System.out.println("Extended opcode:" + code + ",\tset discriminator=" + discriminator);
						}
						continue;
					} else {
						if (DwarfGlobal.debug) {
							System.out.println("error, wrong size in address,\topcode=" + opcode + ", code=" + code);
						}
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_copy) {
					if (DwarfGlobal.debug) {
						System.out.println("Copy");
					}
					is_stmt = false;
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_advance_pc) {
					long adjust;
					if (dwarfDebugLineHeader.max_ops_per_insn == 1) {
						long advance_address = DwarfLib.getULEB128(debugLineBytes);
						adjust = dwarfDebugLineHeader.minimum_instruction_length * advance_address;
						address = address.add(BigInteger.valueOf(adjust));
					} else {
						adjust = DwarfLib.getULEB128(debugLineBytes);
						address = BigInteger.valueOf(((op_index + adjust) / dwarfDebugLineHeader.max_ops_per_insn) * dwarfDebugLineHeader.minimum_instruction_length);
						op_index = (int) ((op_index + adjust) % dwarfDebugLineHeader.max_ops_per_insn);
					}
					if (DwarfGlobal.debug) {
						System.out.println("advance pc by " + adjust + ", address=" + address.toString(16));
					}

					continue;
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_advance_line) {
					long advance_line = DwarfLib.getSLEB128(debugLineBytes);
					if (DwarfGlobal.debug) {
						System.out.println("Advance Line by " + advance_line + " to " + (line_num + advance_line));
					}
					line_num += advance_line;
					continue;
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_set_file) {
					long fileno = DwarfLib.getULEB128(debugLineBytes);
					file_num = fileno - 1;
					if (DwarfGlobal.debug) {
						System.out.println("set file, file=" + file_num);
					}
					continue;
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_set_column) {
					long colno = DwarfLib.getULEB128(debugLineBytes);
					column_num = colno;
					if (DwarfGlobal.debug) {
						System.out.println("set column, column=" + column_num);
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_negate_stmt) {
					is_stmt = !is_stmt;
					if (DwarfGlobal.debug) {
						System.out.println("!stmt, stmt=" + is_stmt);
					}
					continue;
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_set_basic_block) {
					basic_block = true;
					if (DwarfGlobal.debug) {
						System.out.println("set basic_block, basic_block=" + basic_block);
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_fixed_advance_pc) {
					int advance_address = debugLineBytes.getInt();
					address = address.add(BigInteger.valueOf(advance_address));
					op_index = 0;
					if (DwarfGlobal.debug) {
						System.out.println("fixed advance pc, address=" + address.toString(16));
					}
				} else if (opcode == Dwarf_Standard_Opcode_Type.DW_LNS_const_add_pc) {
					long advance_address;

					if (dwarfDebugLineHeader.max_ops_per_insn == 1) {
						advance_address = (dwarfDebugLineHeader.minimum_instruction_length * ((255 - dwarfDebugLineHeader.opcode_base) / dwarfDebugLineHeader.line_range));
						address = address.add(BigInteger.valueOf(advance_address));
					} else {
						long adjust = ((255 - dwarfDebugLineHeader.opcode_base) / dwarfDebugLineHeader.line_range);
						advance_address = dwarfDebugLineHeader.minimum_instruction_length * ((op_index + adjust) / dwarfDebugLineHeader.max_ops_per_insn);
						address = address.add(BigInteger.valueOf(advance_address));
						op_index = (int) ((op_index + adjust) % dwarfDebugLineHeader.max_ops_per_insn);
					}

					if (DwarfGlobal.debug) {
						System.out.println("Advance PC by constant " + advance_address + " to 0x" + address.toString(16));
					}

					continue;
				} else {
					if (DwarfGlobal.debug) {
						System.out.println("error, what? opcode=" + opcode);
					}
					return 14;
				}

				DwarfLine dwarfLine = new DwarfLine();
				dwarfLine.address = address.add(BigInteger.valueOf(memoryOffset));
				dwarfLine.file_num = file_num;
				dwarfLine.line_num = line_num;
				dwarfLine.column_num = column_num;
				dwarfLine.is_stmt = is_stmt;
				dwarfLine.basic_block = basic_block;
				dwarfDebugLineHeader.lines.add(dwarfLine);
			}
			Collections.sort(dwarfDebugLineHeader.lines);
			debugLineBytes.position(end);

			compileUnit.dwarfDebugLineHeader = dwarfDebugLineHeader;
			return 0;
		} catch (Exception ex) {
			return 18;
		}
	}

	@Override
	public String toString() {
		if (realFilename != null) {
			return realFilename;
		} else if (file != null) {
			return file.getName();
		}
		return super.toString();
	}

	//	int hashCode = -99999;
	//	Hashtable<Long, CompileUnit> ht;

	public CompileUnit getCompileUnit(long address) {
		//		if (hashCode != compileUnits.hashCode()) {
		//			ht = new Hashtable<Long, CompileUnit>();
		//			hashCode = compileUnits.hashCode();
		//		}
		//		if (ht.containsKey(address)) {
		//			return ht.get(address);
		//		}
		for (CompileUnit cu : compileUnits) {
			if (address >= cu.DW_AT_high_pc && address <= (cu.DW_AT_high_pc + cu.DW_AT_low_pc - 1)) {
				//				ht.put(address, cu);
				return cu;
			}
		}
		return null;
	}

	public Vector<DebugInfoEntry> getSubProgram(long address) {
		for (CompileUnit compileUnit : compileUnits) {
			if (compileUnit.DW_AT_low_pc == address) {
				return compileUnit.debugInfoEntries;
			}
		}
		return null;
	}

}
