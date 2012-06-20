package com.peterdwarf;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.io.File;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.WindowConstants;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import com.peterdwarf.dwarf.CompileUnit;
import com.peterdwarf.dwarf.DebugInfoAbbrevEntry;
import com.peterdwarf.dwarf.DebugInfoEntry;
import com.peterdwarf.dwarf.Dwarf;
import com.peterdwarf.dwarf.DwarfHeaderFilename;
import com.peterdwarf.dwarf.DwarfLine;

/**
 * This code was edited or generated using CloudGarden's Jigloo SWT/Swing GUI
 * Builder, which is free for non-commercial use. If Jigloo is being used
 * commercially (ie, by a corporation, company or business for any purpose
 * whatever) then you should purchase a license for each developer using Jigloo.
 * Please visit www.cloudgarden.com for details. Use of Jigloo implies
 * acceptance of these licensing terms. A COMMERCIAL LICENSE HAS NOT BEEN
 * PURCHASED FOR THIS MACHINE, SO JIGLOO OR THIS CODE CANNOT BE USED LEGALLY FOR
 * ANY CORPORATE OR COMMERCIAL PURPOSE.
 */
public class PeterDwarfPanel extends javax.swing.JPanel {
	private JScrollPane jScrollPane1;
	private JTree jTree1;
	DefaultMutableTreeNode root = new DefaultMutableTreeNode("dwarf");
	DefaultTreeModel model = new DefaultTreeModel(root);

	/**
	 * Auto-generated main method to display this JPanel inside a new JFrame.
	 */
	public static void main(String[] args) {
		JFrame frame = new JFrame();
		frame.getContentPane().add(new PeterDwarfPanel());
		frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
		frame.pack();
		frame.setVisible(true);
	}

	public PeterDwarfPanel() {
		super();
		initGUI();
	}

	private void initGUI() {
		try {
			BorderLayout thisLayout = new BorderLayout();
			this.setLayout(thisLayout);
			setPreferredSize(new Dimension(400, 300));
			{
				jScrollPane1 = new JScrollPane();
				this.add(jScrollPane1, BorderLayout.CENTER);
				{
					jTree1 = new JTree(model);
					jScrollPane1.setViewportView(jTree1);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void init(File file) {
		Dwarf dwarf = new Dwarf();
		Global.debug = true;
		dwarf.init(file);

		System.out.println();
		System.out.println(".debug_line:");
		System.out.println("length: " + dwarf.header.total_length);
		System.out.println("dwarf version: " + dwarf.header.version);
		System.out.println("header length: " + dwarf.header.prologue_length);
		System.out.println("minimum instruction length: " + dwarf.header.minimum_instruction_length);
		System.out.println("default is_stmt: " + dwarf.header.default_is_stmt);
		System.out.println("line base: " + dwarf.header.line_base);
		System.out.println("line range: " + dwarf.header.line_range);
		System.out.println("opcode base: " + dwarf.header.opcode_base);
		System.out.println();

		System.out.println("dirnames:");
		for (String s : dwarf.header.dirnames) {
			System.out.println(s);
		}
		System.out.println();

		System.out.println("entry\tdir\ttime\tlen\tfilename");
		for (DwarfHeaderFilename filename : dwarf.header.filenames) {
			System.out.println(filename.entryNo + "\t" + filename.dir + "\t" + filename.time + "\t" + filename.len + "\t" + filename.file.getAbsolutePath());
		}
		System.out.println();

		System.out.println("address\tfile no.\tline no.\tcolumn no.\taddress");
		for (DwarfLine line : dwarf.header.lines) {
			System.out.println("\t" + line.file_num + "\t\t" + line.line_num + "\t\t" + line.column_num + "\t\t" + Long.toHexString(line.address));
		}
		System.out.println();
		System.exit(0);

		System.out.println();
		System.out.println(".debug_info:");
		for (CompileUnit compileUnit : dwarf.compileUnits) {
			System.out.printf("Compilation Unit @ offset 0x%x\n", compileUnit.offset);
			System.out.printf("Length: 0x%x\n", compileUnit.length);
			System.out.println("Version: " + compileUnit.version);
			System.out.printf("Abbrev Offset: 0x%x\n", compileUnit.offset);
			System.out.println("Pointer Size: " + compileUnit.addr_size);

			DefaultMutableTreeNode compileUnitNode = new DefaultMutableTreeNode(compileUnit.offset);
			root.add(compileUnitNode);
			model.reload();

			for (DebugInfoEntry debugInfoEntry : compileUnit.debugInfoEntry) {
				System.out.println("<" + debugInfoEntry.position + "> Abbrev Number: " + debugInfoEntry.abbrevNo + " (" + debugInfoEntry.name + ")");
				for (DebugInfoAbbrevEntry debugInfoAbbrevEntry : debugInfoEntry.debugInfoAbbrevEntry) {
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
	}

}
