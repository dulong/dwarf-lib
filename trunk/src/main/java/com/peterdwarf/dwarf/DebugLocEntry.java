package com.peterdwarf.dwarf;

import com.peterswing.CommonLib;

public class DebugLocEntry {
	public long start;
	public long end;
	public int blockSize;
	public byte[] blocks;
	public String name;
	public int op_count;
	public int offset;
	public int[] unsignedBlocks;

	public String toString() {
		return "offset=0x" + Integer.toHexString(offset) + ", start=0x" + Long.toHexString(start) + ", end=0x" + Long.toHexString(end) + ", blockSize=" + blockSize + ", name="
				+ name + ", op_count=" + op_count + " blocks=" + CommonLib.getHexString(unsignedBlocks, ", ");
	}
}
