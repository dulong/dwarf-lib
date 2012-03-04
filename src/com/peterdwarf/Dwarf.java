package com.peterdwarf;

import java.io.File;
import java.io.IOException;
import java.nio.MappedByteBuffer;

import com.peterdwarf.elf.SectionFinder;

public class Dwarf {
	public MappedByteBuffer byteBuffer;

	public boolean init(File file, String sectionName) {
		try {
			byteBuffer = SectionFinder.findSection(file, sectionName);
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
}
