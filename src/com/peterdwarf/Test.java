package com.peterdwarf;

import java.io.File;

import com.peterdwarf.dwarf.Dwarf;
import com.peterdwarf.dwarf.DwarfHeader;
import com.peterdwarf.dwarf.DwarfHeader_filename;
import com.peterdwarf.dwarf.DwarfLine;

public class Test {
	public static void main(String[] args) {
		Dwarf dwarf = new Dwarf();
		File file = new File("/Users/peter/a.out");

		if (!dwarf.init(file, ".debug_line")) {
			System.out.println("dwarf init fail");
		} else {

			for (DwarfHeader header : dwarf.headers) {
				System.out.println("dir\ttime\tlen\tfilename");
				for (DwarfHeader_filename filename : header.filenames) {
					System.out.println(filename.dir + "\t" + filename.time + "\t" + filename.len + "\t" + filename.filename);
				}

				System.out.println("file no.\tline no.\tcolumn no.\taddress");
				for (DwarfLine line : header.lines) {
					System.out.println(line.file_num + "\t" + line.line_num + "\t" + line.column_num + "\t" + Long.toHexString(line.address));
				}
				System.out.println();
			}
		}
		// DwarfLib.printMappedByteBuffer(dwarf.byteBuffer);

		//dwarf.printHeader();
	}

}
