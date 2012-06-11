package com.peterdwarf;

import java.io.File;

import com.peterdwarf.dwarf.CompileUnit;
import com.peterdwarf.dwarf.DebugInfoAbbrevEntry;
import com.peterdwarf.dwarf.DebugInfoEntry;
import com.peterdwarf.dwarf.Dwarf;
import com.peterdwarf.dwarf.DwarfHeaderFilename;
import com.peterdwarf.dwarf.DwarfLine;

public class TestPeterDwarf {
	public static void main(String[] args) {
		if (args.length == 0) {
			System.out.println("java -jar peter-dwarf.jar <your elf file path>");
			System.exit(-1);
		}
		Dwarf dwarf = new Dwarf();
		File file = new File(args[0]);

		if (!dwarf.init(file)) {
			System.out.println("dwarf init fail");
		} else {
			System.out.println();
			System.out.println(".debug_line:");
			System.out.println("length: " + dwarf.header.total_length);
			System.out.println("dwarf version: " + dwarf.header.version);
			System.out.println("header length: " + dwarf.header.prologue_length);
			System.out.println("minimum instruction length: " + dwarf.header.minimum_instruction_length);
			System.out.println("default is_stmt: " + dwarf.header.default_is_stmt);
			System.out.println("line base: " + dwarf.header.line_base);
			System.out.println("line range: " + dwarf.header.line_range);
			System.out.println("opcode base: " + dwarf.header.opcode_base);
			System.out.println();

			System.out.println("dirnames:");
			for (String s : dwarf.header.dirnames) {
				System.out.println(s);
			}
			System.out.println();

			System.out.println("entry\tdir\ttime\tlen\tfilename");
			for (DwarfHeaderFilename filename : dwarf.header.filenames) {
				System.out.println(filename.entryNo + "\t" + filename.dir + "\t" + filename.time + "\t" + filename.len + "\t" + filename.file.getAbsolutePath());
			}
			System.out.println();

			System.out.println("address\tfile no.\tline no.\tcolumn no.\taddress");
			for (DwarfLine line : dwarf.header.lines) {
				System.out.println("\t" + line.file_num + "\t\t" + line.line_num + "\t\t" + line.column_num + "\t\t" + Long.toHexString(line.address));
			}
			System.out.println();

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
