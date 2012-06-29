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

public class PeterDwarfPanelOld extends javax.swing.JPanel {
	private JScrollPane jScrollPane1;
	private JTree jTree1;
	DefaultMutableTreeNode root = new DefaultMutableTreeNode("dwarf");
	DefaultTreeModel model = new DefaultTreeModel(root);

	public static void main(String[] args) {
		JFrame frame = new JFrame();
		frame.getContentPane().add(new PeterDwarfPanelOld());
		frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
		frame.pack();
		frame.setVisible(true);
	}

	public PeterDwarfPanelOld() {
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

	}

}
