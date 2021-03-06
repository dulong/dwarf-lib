package com.peterdwarf.dwarf;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Hashtable;
import java.util.Vector;

import com.peterar.AR;
import com.peterar.PeterAR;
import com.peterswing.CommonLib;

public class DwarfLib {
	private static final boolean WORDS_BIGENDIAN = ByteOrder.nativeOrder().equals(ByteOrder.BIG_ENDIAN);

	public static void main(String args[]) {
		long address = 0x161d400;
		final Vector<Dwarf> dwarfVector = DwarfLib.init(new File("../PeterI/kernel/kernel"), 0);
		Hashtable<String, DwarfParameter> parameters = getParameters(dwarfVector, address);
		System.out.println(parameters.size());
	}

	public static Hashtable<String, DwarfParameter> getParameters(Vector<Dwarf> dwarfVector, long address) {
		Hashtable<String, DwarfParameter> ht = new Hashtable<String, DwarfParameter>();
		for (Dwarf dwarf : dwarfVector) {
			for (CompileUnit cu : dwarf.compileUnits) {
				if (cu.DW_AT_low_pc <= address && address <= (cu.DW_AT_low_pc + cu.DW_AT_high_pc - 1)) {
					Vector<DebugInfoEntry> subprogramDebugInfoEntries = cu.debugInfoEntries.get(0).getDebugInfoEntryByName("DW_TAG_subprogram");
					for (DebugInfoEntry subprogramDebugInfoEntry : subprogramDebugInfoEntries) {
						if (subprogramDebugInfoEntry.debugInfoAbbrevEntries.get("DW_AT_low_pc") == null) {
							continue;
						}
						long subProgramAddress = (long) subprogramDebugInfoEntry.debugInfoAbbrevEntries.get("DW_AT_low_pc").value;
						if (subprogramDebugInfoEntry.debugInfoAbbrevEntries.get("DW_AT_name") == null) {
							// not every DW_TAG_subprogram has a DW_AT_name
							continue;
						}
						//System.out.println(subprogramDebugInfoEntry.debugInfoAbbrevEntries.get("DW_AT_name").value);
						if (address == subProgramAddress) {
							//CIE
							long cfsBaseOffset = -1;
							for (int x = 0; x < dwarf.ehFrames.get(0).fieDetailsKeys.size(); x++) {
								if (dwarf.ehFrames.get(0).fieDetailsKeys.get(x).equals("DW_CFA_def_cfa")) {
									cfsBaseOffset = (long) dwarf.ehFrames.get(0).fieDetails.get(x)[2];
									break;
								}
							}
							//CIE end

							Vector<DebugInfoEntry> parameters = subprogramDebugInfoEntry.getDebugInfoEntryByName("DW_TAG_formal_parameter");
							for (DebugInfoEntry parameterDebugInfoEntry : parameters) {
								if (parameterDebugInfoEntry.debugInfoAbbrevEntries.get("DW_AT_name") == null) {
									continue;
								}
								String name = (String) parameterDebugInfoEntry.debugInfoAbbrevEntries.get("DW_AT_name").value;
								//								System.out.println(name);
								DebugInfoAbbrevEntry locationdebugInfoAbbrevEntry = parameterDebugInfoEntry.debugInfoAbbrevEntries.get("DW_AT_location");
								String registerName = null;
								long offset = 0;
								if (locationdebugInfoAbbrevEntry.form == Definition.DW_FORM_exprloc) {
									String values[] = locationdebugInfoAbbrevEntry.value.toString().split(",");
									registerName = Definition.getOPName(CommonLib.string2int(values[0]));

									//								System.out.println(parameterDebugInfoEntry.debugInfoAbbrevEntries.get("DW_AT_name").value);
									//								System.out.println(parameterDebugInfoEntry.debugInfoAbbrevEntries.get("DW_AT_location").value);
									//								System.out.println("values[0]=" + values[0]);

									if (values.length > 1) {
										offset = Long.parseLong(values[1]);
									}
								} else if (locationdebugInfoAbbrevEntry.form == Definition.DW_FORM_sec_offset) {
									String values[] = locationdebugInfoAbbrevEntry.value.toString().split(",");
									DebugLocEntry debugLocEntry = DwarfLib.getDebugLocEntry(dwarf, CommonLib.string2int(values[0]));
									registerName = Definition.getOPName(debugLocEntry.unsignedBlocks[0]);
									//									System.out.println("debugLocEntry.blocks[0]=" + debugLocEntry.unsignedBlocks[0]);
									//									System.out.println("debugLocEntry=" + debugLocEntry);
									//									System.out.println("registerName=" + registerName);
									if (registerName == null) {
										System.exit(1);
									}
									if (registerName.equals("DW_OP_fbreg")) {
										offset = debugLocEntry.unsignedBlocks[1];
									}
								} else {
									System.err.println("Not support form=" + locationdebugInfoAbbrevEntry.form);
								}
								if (registerName == null) {
									System.exit(1);
								}
								if (registerName.equals("DW_OP_fbreg")) {
									//									System.out.println(name + ", " + (cfsBaseOffset + offset));
									offset = cfsBaseOffset + offset;
								} else {
									//									System.out.println("not support register=" + registerName);
									//System.exit(500);
								}
								ht.put(name,
										new DwarfParameter(name, registerName,
												DwarfLib.getParameterType(cu, CommonLib.string2int("0x" + parameterDebugInfoEntry.debugInfoAbbrevEntries.get("DW_AT_type").value)),
												DwarfLib.getParameterSize(cu, CommonLib.string2int("0x" + parameterDebugInfoEntry.debugInfoAbbrevEntries.get("DW_AT_type").value)),
												offset));
							}

							return ht;
						}
					}
				}
			}
		}
		return null;
	}

	public static Vector<Dwarf> init(File file, long memoryOffset) {
		Vector<Dwarf> dwarfVector = new Vector<Dwarf>();
		if (isArchive(file)) {
			PeterAR peterAR = new PeterAR();
			Vector<AR> data = peterAR.init(file);
			if (data != null) {
				for (AR ar : data) {
					try {
						File temp = File.createTempFile("peterDwarf", ".peterDwarf");
						FileOutputStream out = new FileOutputStream(temp);
						out.write(ar.bytes);
						out.close();
						Dwarf dwarf = new Dwarf();
						int r = dwarf.initElf(temp, ar.filename, memoryOffset);
						temp.delete();
						if (r > 0 && r != 24) {
							return null;
						}
						dwarfVector.add(dwarf);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		} else {
			Dwarf dwarf = new Dwarf();
			int r = dwarf.initElf(file, null, memoryOffset);
			if (r > 0) {
				System.err.println("Error code : " + r);
				return null;
			}
			dwarfVector.add(dwarf);
		}
		return dwarfVector;
	}

	public static boolean isArchive(File file) {
		InputStream is;
		try {
			is = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return false;
		}
		try {
			if (is.read() != 0x21 || is.read() != 0x3c || is.read() != 0x61 || is.read() != 0x72 || is.read() != 0x63 || is.read() != 0x68 || is.read() != 0x3e) {
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

	public static int readUHalf(RandomAccessFile f) throws IOException {
		if (WORDS_BIGENDIAN)
			return f.readUnsignedShort();
		else
			return f.readUnsignedByte() | (f.readUnsignedByte() << 8);
	}

	public static int readWord(RandomAccessFile f) throws IOException {
		if (WORDS_BIGENDIAN)
			return f.readInt();
		else
			return (f.readUnsignedByte() | (f.readUnsignedByte() << 8) | (f.readUnsignedByte() << 16) | (f.readUnsignedByte() << 24));
	}

	public static long readUWord(RandomAccessFile f) throws IOException {
		if (WORDS_BIGENDIAN)
			return (long) f.readInt() & 0xFFFFFFFFL;
		else {
			long l = (f.readUnsignedByte() | (f.readUnsignedByte() << 8) | (f.readUnsignedByte() << 16) | (f.readUnsignedByte() << 24));
			return (l & 0xFFFFFFFFL);
		}
	}

	public static BigInteger readU64Bits(RandomAccessFile f) throws IOException {
		if (WORDS_BIGENDIAN) {
			System.err.println("unsupport WORDS_BIGENDIAN");
			return BigInteger.valueOf(-1L);
		} else {
			byte b[] = new byte[8];
			f.readFully(b);
			return new BigInteger(b);
		}
	}

	public static void printBytes(byte[] bytes) {
		for (int x = 0; x < bytes.length; x++) {
			System.out.printf("%02x ", bytes[x]);
			if (x == 7) {
				System.out.print(" - ");
			} else if (x == 15) {
				System.out.println();
				x = 0;
				continue;
			}
		}
	}

	public static void printByteBuffer(ByteBuffer byteBuffer) {
		int position = byteBuffer.position();
		int x = 0;
		while (byteBuffer.hasRemaining()) {
			System.out.printf("%02x ", byteBuffer.get());
			//			System.out.printf("%c", byteBuffer.get());
			if (x == 7) {
				System.out.print(" - ");
			} else if (x == 15) {
				System.out.println();
				x = 0;
				continue;
			}
			x++;
		}
		System.out.println();
		byteBuffer.position(position);
	}

	public static String getString(ByteBuffer buf) {
		int pos = buf.position();
		int len = 0;
		while (buf.get() != 0) {
			len++;
		}
		byte[] bytes = new byte[len];
		buf.position(pos);
		buf.get(bytes);
		buf.get();
		return new String(bytes);
	}

	public static long getULEB128(ByteBuffer buffer) {
		long val = 0;
		byte b;
		int shift = 0;

		while (true) {
			b = buffer.get();
			val |= ((long) (b & 0x7f)) << shift;
			if ((b & 0x80) == 0)
				break;
			shift += 7;
		}

		return val;
	}

	public static int getULEB128Count(ByteBuffer buffer) {
		long val = 0;
		byte b;
		int shift = 0;

		int count = 0;

		while (true) {
			b = buffer.get();
			count++;
			val |= ((long) (b & 0x7f)) << shift;
			if ((b & 0x80) == 0)
				break;
			shift += 7;
		}

		return count;
	}

	public static int getSLEB128(ByteBuffer buffer) {
		int result = 0;
		for (int i = 0; i < 5; i++) {
			byte b = buffer.get();
			result |= ((b & 0x7f) << (7 * i));
			if ((b & 0x80) == 0) {
				int s = 32 - (7 * (i + 1));
				result = (result << s) >> s;
				break;
			}
		}
		return result;
	}

	public static int getSLEB128Count(ByteBuffer buffer) {
		int result = 0;
		int count = 0;
		for (int i = 0; i < 5; i++) {
			byte b = buffer.get();
			count++;
			result |= ((b & 0x7f) << (7 * i));
			if ((b & 0x80) == 0) {
				int s = 32 - (7 * (i + 1));
				result = (result << s) >> s;
				break;
			}
		}
		return count;
	}

	public static String getString(ByteBuffer buf, int offset) {
		try {
			buf.position(offset);

			byte temp;
			String r = "";
			while (buf.hasRemaining()) {
				temp = buf.get();
				if (temp == 0) {
					break;
				}
				r += (char) temp;
			}
			return r;
		} catch (Exception ex) {
			//			ex.printStackTrace();
			return null;
		}
	}

	public void printHeader(DwarfDebugLineHeader header) {
		System.out.println("total_length: " + header.total_length);
		System.out.println("version: " + header.version);
		System.out.println("prologue_length: " + header.prologue_length);
		System.out.println("minimum_instruction_length: " + header.minimum_instruction_length);
		System.out.println("default_is_stmt: " + header.default_is_stmt);
		System.out.println("line_base: " + header.line_base);
		System.out.println("line_range: " + header.line_range);
		System.out.println("opcode_base: " + header.opcode_base);
		System.out.print("standard_opcode_lengths: { ");
		System.out.print(header.standard_opcode_lengths[0]);
		System.out.print(header.standard_opcode_lengths[1]);
		System.out.print(header.standard_opcode_lengths[2]);
		System.out.print(header.standard_opcode_lengths[3]);
		System.out.print(header.standard_opcode_lengths[4]);
		System.out.print(header.standard_opcode_lengths[5]);
		System.out.print(header.standard_opcode_lengths[6]);
		System.out.print(header.standard_opcode_lengths[7]);
		System.out.print(header.standard_opcode_lengths[8]);
		System.out.print(header.standard_opcode_lengths[9]);
		System.out.print(header.standard_opcode_lengths[10]);
		System.out.print(header.standard_opcode_lengths[11]);
		System.out.println(" }");
	}

	public static DebugInfoEntry getSubProgram(Vector<Dwarf> dwarfVector, long address) {
		for (Dwarf dwarf : dwarfVector) {
			for (CompileUnit compileUnit : dwarf.compileUnits) {
				for (DebugInfoEntry debugInfoEntry : compileUnit.debugInfoEntries) {
					DebugInfoEntry result = searchSubProgram(debugInfoEntry, address);
					if (result != null) {
						return result;
					}
				}
			}
		}
		return null;
	}

	private static DebugInfoEntry searchSubProgram(DebugInfoEntry debugInfoEntry, long address) {
		if (debugInfoEntry.name.equals("DW_TAG_subprogram")) {
			if (debugInfoEntry.debugInfoAbbrevEntries.get("DW_AT_low_pc") != null && (long) debugInfoEntry.debugInfoAbbrevEntries.get("DW_AT_low_pc").value == address) {
				return debugInfoEntry;
			}
		}

		for (DebugInfoEntry d : debugInfoEntry.debugInfoEntries) {
			DebugInfoEntry result = searchSubProgram(d, address);
			if (result != null) {
				return result;
			}
		}
		return null;
	}

	public static String getParameterType(CompileUnit compileUnit, int value) {
		DebugInfoEntry temp = compileUnit.getDebugInfoEntryByPosition(value);

		if (temp != null && temp.name.equals("DW_TAG_union_type")) {
			return "union";
		} else if (temp != null && temp.name.equals("DW_TAG_enumeration_type")) {
			return "enum";
		}
		DebugInfoAbbrevEntry debugInfoAbbrevEntry = null;
		if (temp != null) {
			debugInfoAbbrevEntry = temp.debugInfoAbbrevEntries.get("DW_AT_name");
			if (debugInfoAbbrevEntry == null) {
				debugInfoAbbrevEntry = temp.debugInfoAbbrevEntries.get("DW_AT_type");

				if (debugInfoAbbrevEntry == null) {
					return null;
				}
				return getParameterType(compileUnit, CommonLib.string2int("0x" + debugInfoAbbrevEntry.value));
			}
		} else {
			return null;
		}

		String type = debugInfoAbbrevEntry.value.toString();
		return type;
	}

	public static int getParameterSize(CompileUnit compileUnit, int value) {
		DebugInfoEntry temp = compileUnit.getDebugInfoEntryByPosition(value);

		DebugInfoAbbrevEntry debugInfoAbbrevEntry = null;
		if (temp != null) {
			debugInfoAbbrevEntry = temp.debugInfoAbbrevEntries.get("DW_AT_byte_size");
			if (debugInfoAbbrevEntry == null) {
				debugInfoAbbrevEntry = temp.debugInfoAbbrevEntries.get("DW_AT_type");

				if (debugInfoAbbrevEntry == null) {
					return -1;
				}
				return getParameterSize(compileUnit, CommonLib.string2int("0x" + debugInfoAbbrevEntry.value));
			}
		} else {
			return -1;
		}

		int size = Integer.parseInt(debugInfoAbbrevEntry.value.toString());
		return size;
	}

	public static DebugLocEntry getDebugLocEntry(Dwarf dwarf, int offset) {
		for (DebugLocEntry debugLocEntry : dwarf.debugLocEntries) {
			if (debugLocEntry.offset == offset) {
				return debugLocEntry;
			}
		}
		return null;
	}
}
