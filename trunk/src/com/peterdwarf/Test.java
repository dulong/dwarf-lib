package com.peterdwarf;

import java.io.File;

import com.peterdwarf.dwarf.CompileUnit;
import com.peterdwarf.dwarf.Dwarf;
import com.peterdwarf.dwarf.DwarfHeader;
import com.peterdwarf.dwarf.DwarfHeader_filename;
import com.peterdwarf.dwarf.DwarfLine;

public class Test {
	public static void main(String[] args) {
		Dwarf dwarf = new Dwarf();
		File file = new File(args[0]);

		if (!dwarf.init(file)) {
			System.out.println("dwarf init fail");
		} else {
			for (CompileUnit cu : dwarf.compileUnits) {
				System.out.println("compile unit");
				System.out.println("  length=0x" + Integer.toHexString(cu.length));
				System.out.println("  version=" + cu.version);
				System.out.println("  abbrev_offset=" + cu.abbrev_offset);
				System.out.println("  addr_size=" + cu.addr_size);
			}
			System.out.println();
			for (DwarfHeader header : dwarf.headers) {
				System.out.println("length: " + header.total_length);
				System.out.println("dwarf version: " + header.version);
				System.out.println("header length: " + header.header_length);
				System.out.println("minimum instruction length: " + header.minimum_instruction_length);
				System.out.println("default is_stmt: " + header.default_is_stmt);
				System.out.println("line base: " + header.line_base);
				System.out.println("line range: " + header.line_range);
				System.out.println("opcode base: " + header.opcode_base);
				System.out.println();

				System.out.println("dir\ttime\tlen\tfilename");
				for (DwarfHeader_filename filename : header.filenames) {
					System.out.println(filename.dir + "\t" + filename.time + "\t" + filename.len + "\t" + filename.filename);
				}
				System.out.println();

				System.out.println("file no.\tline no.\tcolumn no.\taddress");
				for (DwarfLine line : header.lines) {
					System.out.println(line.file_num + "\t" + line.line_num + "\t" + line.column_num + "\t" + Long.toHexString(line.address));
				}
				System.out.println();
			}
		}
		// DwarfLib.printMappedByteBuffer(dwarf.byteBuffer);

		// dwarf.printHeader();
	}

}
