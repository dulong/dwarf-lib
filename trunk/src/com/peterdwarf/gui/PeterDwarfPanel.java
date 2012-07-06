package com.peterdwarf.gui;

import java.awt.BorderLayout;
import java.io.File;
import java.util.Vector;

import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.WindowConstants;
import javax.swing.tree.DefaultTreeModel;

import com.peterdwarf.dwarf.Dwarf;

public class PeterDwarfPanel extends JPanel {
	DwarfTreeCellRenderer treeCellRenderer = new DwarfTreeCellRenderer();
	DwarfTreeNode root = new DwarfTreeNode("Elf files");
	DefaultTreeModel treeModel = new DefaultTreeModel(root);
	JTree tree = new JTree(treeModel);
	Vector<File> files = new Vector<File>();

	public static void main(String args[]) {
		JFrame frame = new JFrame();
		PeterDwarfPanel peterDwarfPanel = new PeterDwarfPanel();
		frame.getContentPane().add(peterDwarfPanel);
		frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
		frame.setSize(800, 600);
		frame.setVisible(true);
		frame.setLocationRelativeTo(null);
//		peterDwarfPanel.init("/Users/peter/Desktop/bochs");
		peterDwarfPanel.init("/Users/peter/workspace/PeterI/kernel/kernel");
		peterDwarfPanel.init("/Users/peter/workspace/PeterI/kernel/kernel.o");
		peterDwarfPanel.init("/Users/peter/workspace/PeterI/app/pshell/pshell.o");
	}

	public PeterDwarfPanel() {
		setLayout(new BorderLayout(0, 0));

		JScrollPane scrollPane = new JScrollPane();
		add(scrollPane, BorderLayout.CENTER);

		tree.setShowsRootHandles(true);
		tree.setCellRenderer(treeCellRenderer);
		scrollPane.setViewportView(tree);
	}

	public void init(String filepath) {
		init(new File(filepath));
	}

	public void init(final File file) {
		final Dwarf dwarf = new Dwarf();
		new Thread() {
			public void run() {
								dwarf.init(file);
			}
		}.start();
		files.add(file);
		DwarfTreeNode node = new DwarfTreeNode(dwarf);
		node.setDwarf(dwarf);
		root.children.add(node);
		treeModel.nodeChanged(root);

	}

}
