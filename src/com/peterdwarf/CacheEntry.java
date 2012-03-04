package com.peterdwarf;

import java.nio.ByteBuffer;
import java.util.LinkedList;

public class CacheEntry {
	final dw2_debug_line header;
	final LinkedList fileNames;
	final ByteBuffer section;

	CacheEntry(LinkedList fileNames, ByteBuffer section, dw2_debug_line header) {
		this.fileNames = fileNames;
		this.section = section;
		this.header = header;
	}
}
