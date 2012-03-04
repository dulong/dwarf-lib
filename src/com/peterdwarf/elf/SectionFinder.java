package com.peterdwarf.elf;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.util.Arrays;
import java.util.Vector;

public class SectionFinder {
	private static final byte ELFMAG0 = 0x7f;
	private static final byte ELFMAG1 = (byte) 'E';
	private static final byte ELFMAG2 = (byte) 'L';
	private static final byte ELFMAG3 = (byte) 'F';

	public static Vector<String> getAllSection(File file) throws IOException {
		Vector<String> vector = new Vector<String>();
		RandomAccessFile f = new RandomAccessFile(file, "r");

		/** Read the ELF header. */
		Elf32_Ehdr ehdr = new Elf32_Ehdr();
		ehdr.read(f);
		if (ehdr.e_ident[0] != ELFMAG0 || ehdr.e_ident[1] != ELFMAG1 || ehdr.e_ident[2] != ELFMAG2 || ehdr.e_ident[3] != ELFMAG3) {
			f.close();
			throw new IOException(file + ": not an ELF file");
		}

		/* Read the string table section header. */
		Elf32_Shdr strtabhdr = new Elf32_Shdr();
		f.seek(ehdr.e_shoff + (ehdr.e_shstrndx * Elf32_Shdr.sizeof()));
		strtabhdr.read(f);

		Elf32_Shdr shdr = new Elf32_Shdr();

		outer: for (int i = 0; i < ehdr.e_shnum; i++) {
			// Read information about this section.
			f.seek(ehdr.e_shoff + (i * Elf32_Shdr.sizeof()));
			shdr.read(f);

			// Read the section name from the string table.
			f.seek(strtabhdr.sh_offset + shdr.sh_name);
			int bb;
			String sectionName = "";
			while ((bb = f.read()) != 0) {
				sectionName += (char) bb;
			}
			vector.add(sectionName);
		}
		return vector;
	}

	public static MappedByteBuffer findSection(File file, String section) throws IOException {
		RandomAccessFile f = new RandomAccessFile(file, "r");

		/** Read the ELF header. */
		Elf32_Ehdr ehdr = new Elf32_Ehdr();
		ehdr.read(f);
		if (ehdr.e_ident[0] != ELFMAG0 || ehdr.e_ident[1] != ELFMAG1 || ehdr.e_ident[2] != ELFMAG2 || ehdr.e_ident[3] != ELFMAG3) {
			f.close();
			throw new IOException(file + ": not an ELF file");
		}

		/* Read the string table section header. */
		Elf32_Shdr strtabhdr = new Elf32_Shdr();
		f.seek(ehdr.e_shoff + (ehdr.e_shstrndx * Elf32_Shdr.sizeof()));
		strtabhdr.read(f);

		Elf32_Shdr shdr = new Elf32_Shdr();
		byte[] target_bytes = section.getBytes("ISO8859-1");
		byte[] buf = new byte[target_bytes.length + 1];
		boolean found = false;

		outer: for (int i = 0; i < ehdr.e_shnum; i++) {
			// Read information about this section.
			f.seek(ehdr.e_shoff + (i * Elf32_Shdr.sizeof()));
			shdr.read(f);

			// Read the section name from the string table.
			f.seek(strtabhdr.sh_offset + shdr.sh_name);
			f.readFully(buf);

			if (!Arrays.equals(target_bytes, Arrays.copyOf(buf, target_bytes.length))) {
				continue outer;
			}
			if (buf[buf.length - 1] != '\0') {
				continue;
			}
			found = true;
			break;
		}

		if (!found) {
			f.close();
			throw new IOException("no section " + section + " found in " + file);
		}

		try {
			FileChannel chan = f.getChannel();
			MappedByteBuffer buffer = chan.map(FileChannel.MapMode.READ_ONLY, shdr.sh_offset, shdr.sh_size);
			buffer.order(ByteOrder.nativeOrder());
			chan.close();
			return buffer;
		} finally {
			f.close();
		}
	}

}
