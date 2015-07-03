package com.peterdwarf.dwarf;

public class DebugLocEntry {
	public long start;
	public long end;
	public int blockSize;
	public byte[] blocks;
	public String name;
	public int op_count;

	public String toString() {
		return "start=" + start + ", end=" + end + ", blockSize=" + blockSize + ", name=" + name + ", op_count=" + op_count;
	}
}
