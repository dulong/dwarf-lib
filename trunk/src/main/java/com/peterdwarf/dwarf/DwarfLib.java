package com.peterdwarf.dwarf;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Vector;

import com.peterar.AR;
import com.peterar.PeterAR;

public class DwarfLib {
	private static final boolean WORDS_BIGENDIAN = ByteOrder.nativeOrder().equals(ByteOrder.BIG_ENDIAN);

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

	public static long getULEB128(ByteBuffer buf) {
		long val = 0;
		byte b;
		int shift = 0;

		while (true) {
			b = buf.get();
			val |= ((long) (b & 0x7f)) << shift;
			if ((b & 0x80) == 0)
				break;
			shift += 7;
		}

		return val;
	}

	//	public static long getUleb128(ByteBuffer buf) {
	//		long result = 0;
	//		int num_read = 0;
	//		int shift = 0;
	//		int b;
	//
	//		int x = 0;
	//		do {
	//			b = buf.get();
	//			num_read++;
	//
	//			result |= ((long) (b & 0x7f)) << shift;
	//
	//			shift += 7;
	//
	//		} while ((b & 0x80) != 0);
	//
	////		length_return[0] = num_read;
	//
	////		if (sign != 0 && shift < 8 * 4 && (b & 0x40) != 0) {
	//			result |= -1L << shift;
	////		}
	//
	//		return result;
	//	}

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

}
