package com.peterdwarf.elf;

public class Elf32_Phdr {
	public byte p_type[] = new byte[4]; /* Identifies program segment type */
	public byte p_offset[] = new byte[4]; /* Segment file offset */
	public byte p_vaddr[] = new byte[4]; /* Segment virtual address */
	public byte p_paddr[] = new byte[4]; /* Segment physical address */
	public byte p_filesz[] = new byte[4]; /* Segment size in file */
	public byte p_memsz[] = new byte[4]; /* Segment size in memory */
	public byte p_flags[] = new byte[4]; /* Segment flags */
	public byte p_align[] = new byte[4]; /* Segment alignment, file & memory */

}
