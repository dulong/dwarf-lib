package com.peterdwarf;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class DwarfLib {
	private static final boolean WORDS_BIGENDIAN = ByteOrder.nativeOrder().equals(ByteOrder.BIG_ENDIAN);

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

	public static void printMappedByteBuffer(ByteBuffer byteBuffer) {
		int position = byteBuffer.position();
		int x = 0;
		while (byteBuffer.hasRemaining()) {
			System.out.printf("%02x ", byteBuffer.get());
			if (x == 9) {
				System.out.println();
				x = 0;
			} else {
				x++;
			}
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

	public static long getUleb128(ByteBuffer buf) {
		long val = 0;
		byte b;
		int shift = 0;

		while (true) {
			b = buf.get();
			val |= (b & 0x7f) << shift;
			if ((b & 0x80) == 0)
				break;
			shift += 7;
		}

		return val;
	}
}
