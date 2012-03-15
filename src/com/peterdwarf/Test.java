package com.peterdwarf;

import java.io.File;
import java.io.IOException;
import java.util.Vector;

import com.peterdwarf.dwarf.Dwarf;
import com.peterdwarf.elf.SectionFinder;

public class Test {
	public static void main(String[] args) {
		Dwarf dwarf = new Dwarf();
		File file = new File("/Users/peter/a.out");

		try {
			Vector<String> vector = SectionFinder.getAllSection(file);

			//			for (String sectionName : vector) {
			// System.out.println(sectionName);
			//			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (!dwarf.init(file, ".debug_line")) {
			System.out.println("dwarf init fail");
		}
		// DwarfLib.printMappedByteBuffer(dwarf.byteBuffer);

		//dwarf.printHeader();
	}

}
