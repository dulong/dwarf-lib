package com.peterdwarf.gui;

import java.awt.BorderLayout;
import java.io.File;
import java.util.Vector;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.WindowConstants;
import javax.swing.tree.DefaultTreeModel;

import com.peterdwarf.DwarfGlobal;
import com.peterdwarf.dwarf.Dwarf;

public class PeterDwarfPanel extends JPanel {
	DwarfTreeNode root = new DwarfTreeNode("Elf files");
	DefaultTreeModel treeModel = new DefaultTreeModel(root);
	Vector<File> files = new Vector<File>();

	public static void main(String args[]) {
		JFrame frame = new JFrame();
		PeterDwarfPanel peterDwarfPanel = new PeterDwarfPanel();
		frame.getContentPane().add(peterDwarfPanel);
		frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
		frame.setSize(800, 600);
		frame.setVisible(true);
		peterDwarfPanel.init("/Users/peter/Desktop/bochs");
	}

	/**
	 * Create the panel.
	 */
	public PeterDwarfPanel() {
		setLayout(new BorderLayout(0, 0));

		JScrollPane scrollPane = new JScrollPane();
		add(scrollPane, BorderLayout.CENTER);

		JTree tree = new JTree(treeModel);
		scrollPane.setViewportView(tree);

	}

	public void init(String filepath) {
		init(new File(filepath));
	}

	public void init(File file) {
		Dwarf dwarfEngine = new Dwarf();
		dwarfEngine.init(file);
		files.add(file);
		root.children.add(new DwarfTreeNode(file.getName()));
		treeModel.nodeChanged(root);
	}

}
