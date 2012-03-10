package com.peterdwarf.dwarf;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.util.LinkedList;
import java.util.Vector;

import com.peterdwarf.elf.SectionFinder;

public class Dwarf {
	public MappedByteBuffer byteBuffer;
	public Vector<DwarfHeader> headers = new Vector<DwarfHeader>();

	public boolean init(File file, String sectionName) {
		try {
			byteBuffer = SectionFinder.findSection(file, sectionName);
			parseHeader(byteBuffer);
			parseHeader(byteBuffer);
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	public void parseHeader(ByteBuffer b) {
		final int begin = b.position();

		DwarfHeader header = new DwarfHeader();
		header.total_length = (long) b.getInt() & 0xFFFFFFFFL;
		header.version = b.getShort() & 0xFFFF;
		header.header_length = (long) b.getInt() & 0xFFFFFFFFL;
		header.minimum_instruction_length = b.get() & 0xFF;
		header.default_is_stmt = b.get() != 0;
		header.line_base = b.get();
		header.line_range = b.get() & 0xFF;
		header.opcode_base = b.get() & 0xFF;
		b.get(header.standard_opcode_lengths);

		final int end = (int) (begin + header.total_length + 4);
		final int prologue_end = (int) (begin + header.header_length + 9);

		// Skip the directories; they end with a single null byte.
		String s;
		while ((s = DwarfLib.getString(b)).length() > 0) {
			header.dirnames.add(s);
		}

		// Read the file names.
		LinkedList<String> fnames = new LinkedList<String>();
		while (b.hasRemaining() && b.position() < prologue_end) {
			DwarfHeader_filename f = new DwarfHeader_filename();
			String fname = DwarfLib.getString(b);

			fnames.add(fname);

			long u1 = DwarfLib.getUleb128(b);
			long u2 = DwarfLib.getUleb128(b);
			long u3 = DwarfLib.getUleb128(b);

			f.dir = u1;
			f.time = u2;
			f.len = u3;
			header.filenames.add(f);

		}
		System.out.println("--" + b.position());

		b.get();

		while (b.hasRemaining()) {
			int code = b.get() & 0xff;

			if (code == 0) {
				int size = b.get();
				int opcode = b.get();
				if (opcode == 2) {
					int address = b.getInt();
					System.out.println("Extended opcode:" + opcode + ", address=" + Long.toHexString(address));
				} else if (opcode == 4) {
					int discriminator = b.get();
					System.out.println("Extended opcode:" + opcode + ", set discriminator=" + discriminator);
				} else {
					System.out.println("error, wrong size in address");
					// System.exit(1);
				}
			} else if (code > header.opcode_base) {
				System.out.println("Special opcode:" + Integer.toHexString(code));
			}
		}
		DwarfLib.printMappedByteBuffer(b);
		b.position(end);
		System.out.println("++" + b.position());

		headers.add(header);
	}
}
