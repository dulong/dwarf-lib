package com.peterdwarf;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;

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

	public static void printMappedByteBuffer(MappedByteBuffer byteBuffer) {
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
		byteBuffer.position(0);
	}
}
