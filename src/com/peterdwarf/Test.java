package com.peterdwarf;

import java.io.File;
import java.io.IOException;
import java.util.Vector;

import com.peterdwarf.dwarf.Dwarf;
import com.peterdwarf.dwarf.DwarfHeader;
import com.peterdwarf.dwarf.DwarfLine;
import com.peterdwarf.elf.SectionFinder;

public class Test {
	public static void main(String[] args) {
		Dwarf dwarf = new Dwarf();
		File file = new File("/Users/peter/a.out");

		if (!dwarf.init(file, ".debug_line")) {
			System.out.println("dwarf init fail");
		} else {
			System.out.println("file no.\tline no.\tcolumn no.\taddress");

			for (DwarfHeader header : dwarf.headers) {
				for (DwarfLine line : header.lines) {
					System.out.println(line.file_num + "\t" + line.line_num + "\t" + line.column_num + "\t" + Long.toHexString(line.address));
				}
			}
		}
		// DwarfLib.printMappedByteBuffer(dwarf.byteBuffer);

		//dwarf.printHeader();
	}

}
