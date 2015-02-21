package com.peterdwarf;

import java.io.File;
import java.util.Enumeration;
import java.util.Vector;

import com.peterdwarf.dwarf.CompileUnit;
import com.peterdwarf.dwarf.DebugInfoAbbrevEntry;
import com.peterdwarf.dwarf.DebugInfoEntry;
import com.peterdwarf.dwarf.Dwarf;
import com.peterdwarf.dwarf.DwarfDebugLineHeader;
import com.peterdwarf.dwarf.DwarfHeaderFilename;
import com.peterdwarf.dwarf.DwarfLib;
import com.peterdwarf.dwarf.DwarfLine;

public class TestPeterDwarf {
	public static void main(String[] args) {
		if (args.length == 0) {
			System.out.println("java -jar peter-dwarf.jar <your elf file path>");
			System.exit(6);
		}

		for (String str : args) {
			if (str.contains("-debug")) {
				DwarfGlobal.debug = true;
			}
		}

		Dwarf dwarf = new Dwarf();
		File file = new File(args[0]);

		if (file.isDirectory()) {
			return;
		}

		Vector<Dwarf> dwarfLib = DwarfLib.init(file, 0);
		if (dwarfLib == null) {
			System.err.println("dwarf init fail");
			//$hide>>$
			System.exit(1);
			//$hide<<$
		} else if (DwarfGlobal.debug) {
			System.out.println(".debug_info:");
			for (CompileUnit compileUnit : dwarf.compileUnits) {
				System.out.printf("Compilation Unit @ offset 0x%x\n", compileUnit.offset);
				System.out.printf("Length: 0x%x\n", compileUnit.length);
				System.out.println("Version: " + compileUnit.version);
				System.out.printf("Abbrev Offset: 0x%x\n", compileUnit.offset);
				System.out.println("Pointer Size: " + compileUnit.addr_size);

				for (DebugInfoEntry debugInfoEntry : compileUnit.debugInfoEntries) {
					System.out.println("<" + debugInfoEntry.position + "> Abbrev Number: " + debugInfoEntry.abbrevNo + " (" + debugInfoEntry.name + ")");

					Enumeration<String> e = debugInfoEntry.debugInfoAbbrevEntries.keys();
					while (e.hasMoreElements()) {
						String key = e.nextElement();
						DebugInfoAbbrevEntry debugInfoAbbrevEntry = debugInfoEntry.debugInfoAbbrevEntries.get(key);
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

			System.out.println();

			for (DwarfDebugLineHeader header : dwarf.headers) {
				System.out.println();
				System.out.println(header);
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
					System.out.println("\t" + line.file_num + "\t\t" + line.line_num + "\t\t" + line.column_num + "\t\t" + line.address.toString(16));
				}
				System.out.println();
				System.out.println();
			}

		}
		// DwarfLib.printMappedByteBuffer(dwarf.byteBuffer);

		// dwarf.printHeader();
	}
}
