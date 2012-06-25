package com.peterdwarf;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;

import com.peterdwarf.dwarf.CompileUnit;
import com.peterdwarf.dwarf.DebugInfoAbbrevEntry;
import com.peterdwarf.dwarf.DebugInfoEntry;
import com.peterdwarf.dwarf.Dwarf;
import com.peterdwarf.dwarf.DwarfDebugLineHeader;
import com.peterdwarf.dwarf.DwarfHeaderFilename;
import com.peterdwarf.dwarf.DwarfLine;

public class TestPeterDwarf {
	public static void main(String[] args) {
		if (args.length == 0) {
			System.out.println("java -jar peter-dwarf.jar <your elf file path>");
			System.exit(6);
		}

		for (String str : args) {
			if (str.contains("-debug")) {
				Global.debug = true;
			}
		}

		Dwarf dwarf = new Dwarf();
		File file = new File(args[0]);

		int r = dwarf.init(file);
		if (r > 0) {
			System.out.println("dwarf init fail");
			System.exit(r);
		} else if (Global.debug) {
			for (DwarfDebugLineHeader header : dwarf.headers) {
				System.out.println();
				System.out.println(".debug_line:");
				System.out.println("length: " + header.total_length);
				System.out.println("dwarf version: " + header.version);
				System.out.println("header length: " + header.prologue_length);
				System.out.println("minimum instruction length: " + header.minimum_instruction_length);
				System.out.println("default is_stmt: " + header.default_is_stmt);
				System.out.println("line base: " + header.line_base);
				System.out.println("line range: " + header.line_range);
				System.out.println("opcode base: " + header.opcode_base);
				System.out.println();

				System.out.println("dirnames:");
				for (String s : header.dirnames) {
					System.out.println(s);
				}
				System.out.println();

				System.out.println("entry\tdir\ttime\tlen\tfilename");
				for (DwarfHeaderFilename filename : header.filenames) {
					System.out.println(filename.entryNo + "\t" + filename.dir + "\t" + filename.time + "\t" + filename.len + "\t" + filename.file.getAbsolutePath());
				}
				System.out.println();

				System.out.println("address\tfile no.\tline no.\tcolumn no.\taddress");

				for (DwarfLine line : header.lines) {
					System.out.println("\t" + line.file_num + "\t\t" + line.line_num + "\t\t" + line.column_num + "\t\t" + Long.toHexString(line.address));
				}
				System.out.println();
				System.out.println();
			}

			System.out.println();
			System.out.println(".debug_info:");
			for (CompileUnit compileUnit : dwarf.compileUnits) {
				System.out.printf("Compilation Unit @ offset 0x%x\n", compileUnit.offset);
				System.out.printf("Length: 0x%x\n", compileUnit.length);
				System.out.println("Version: " + compileUnit.version);
				System.out.printf("Abbrev Offset: 0x%x\n", compileUnit.offset);
				System.out.println("Pointer Size: " + compileUnit.addr_size);

				for (DebugInfoEntry debugInfoEntry : compileUnit.debugInfoEntry) {
					System.out.println("<" + debugInfoEntry.position + "> Abbrev Number: " + debugInfoEntry.abbrevNo + " (" + debugInfoEntry.name + ")");
					for (DebugInfoAbbrevEntry debugInfoAbbrevEntry : debugInfoEntry.debugInfoAbbrevEntry) {
						if (debugInfoAbbrevEntry.value == null) {
							System.out.printf("<%x>\t%s\tnull\n", debugInfoAbbrevEntry.position, debugInfoAbbrevEntry.name);
						} else if (debugInfoAbbrevEntry.value instanceof String) {
							System.out.printf("<%x>\t%s\t%s\n", debugInfoAbbrevEntry.position, debugInfoAbbrevEntry.name, debugInfoAbbrevEntry.value);
						} else if (debugInfoAbbrevEntry.value instanceof Byte || debugInfoAbbrevEntry.value instanceof Integer || debugInfoAbbrevEntry.value instanceof Long) {
							System.out.printf("<%x>\t%s\t%x\n", debugInfoAbbrevEntry.position, debugInfoAbbrevEntry.name, debugInfoAbbrevEntry.value);
						} else if (debugInfoAbbrevEntry.value instanceof byte[]) {
							byte[] bytes = (byte[]) debugInfoAbbrevEntry.value;
							System.out.printf("<%x>\t%s\t", debugInfoAbbrevEntry.position, debugInfoAbbrevEntry.name);
							for (byte b : bytes) {
								System.out.printf("%x ", b);
							}
							System.out.println();
						} else {
							System.out.println("not support value format : " + debugInfoAbbrevEntry.value.getClass().toString());
						}
					}
				}
			}
		}
		// DwarfLib.printMappedByteBuffer(dwarf.byteBuffer);

		// dwarf.printHeader();
	}
}
