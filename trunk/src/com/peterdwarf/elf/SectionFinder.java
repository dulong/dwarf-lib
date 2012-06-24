package com.peterdwarf.elf;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
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

	public static Vector<Elf32_Shdr> getAllSection(File file) throws IOException {
		Vector<Elf32_Shdr> vector = new Vector<Elf32_Shdr>();
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
		strtabhdr.read(ehdr.e_shstrndx, f);

		for (int i = 0; i < ehdr.e_shnum; i++) {
			Elf32_Shdr shdr = new Elf32_Shdr();
			// Read information about this section.
			f.seek(ehdr.e_shoff + (i * Elf32_Shdr.sizeof()));
			shdr.read(i, f);

			// Read the section name from the string table.
			f.seek(strtabhdr.sh_offset + shdr.sh_name);
			int bb;
			String sectionName = "";
			while ((bb = f.read()) != 0) {
				sectionName += (char) bb;
			}
			shdr.section_name = sectionName;
			vector.add(shdr);
		}
		return vector;
	}

	public static Vector<Elf32_Shdr> getAllRelocationSection(File file) {
		Vector<Elf32_Shdr> temp = new Vector<Elf32_Shdr>();
		Vector<Elf32_Shdr> sections = new Vector<Elf32_Shdr>();
		try {
			temp = getAllSection(file);
			for (Elf32_Shdr s : temp) {
				if (s.sh_type == 4 || s.sh_type == 9) {
					sections.add(s);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return sections;
	}

	public static ByteBuffer findSectionByte(File file, String section) throws IOException {
		RandomAccessFile f = new RandomAccessFile(file, "r");

		/** Read the ELF header. */
		Elf32_Ehdr ehdr = new Elf32_Ehdr();
		ehdr.read(f);
		if (ehdr.e_ident[0] != ELFMAG0 || ehdr.e_ident[1] != ELFMAG1 || ehdr.e_ident[2] != ELFMAG2 || ehdr.e_ident[3] != ELFMAG3) {
			f.close();
			return null;
		}

		/* Read the string table section header. */
		Elf32_Shdr strtabhdr = new Elf32_Shdr();
		f.seek(ehdr.e_shoff + (ehdr.e_shstrndx * Elf32_Shdr.sizeof()));
		strtabhdr.read(ehdr.e_shstrndx, f);

		Elf32_Shdr shdr = new Elf32_Shdr();
		byte[] target_bytes = section.getBytes("ISO8859-1");
		byte[] buf = new byte[target_bytes.length + 1];
		boolean found = false;

		outer: for (int i = 0; i < ehdr.e_shnum; i++) {
			// Read information about this section.
			f.seek(ehdr.e_shoff + (i * Elf32_Shdr.sizeof()));
			shdr.read(i, f);

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
			System.err.println("no section " + section + " found in " + file);
			return null;
		}

		try {
			System.out.println( shdr.sh_size);
			byte bytes[] = new byte[(int) shdr.sh_size];
			f = new RandomAccessFile(file, "r");

			f.seek(shdr.sh_offset);
			f.readFully(bytes);
			f.close();
			ByteBuffer buffer = ByteBuffer.wrap(bytes);
			buffer.order(ByteOrder.nativeOrder());
			return buffer;

			//			FileChannel inChannel = new RandomAccessFile(file, "rw").getChannel();
			//			MappedByteBuffer buffer = inChannel.map(FileChannel.MapMode.READ_WRITE, shdr.sh_offset, shdr.sh_size);
			//			buffer.order(ByteOrder.nativeOrder());
			//			return buffer;
		} finally {
			f.close();
		}
	}

}
