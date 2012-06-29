package com.peterdwarf.gui;

import java.awt.BorderLayout;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.WindowConstants;

public class PeterDwarfPanel extends JPanel {
	DwarfTreeModel treeModel = new DwarfTreeModel();
	DwarfTreeNode root = new DwarfTreeNode();

	public static void main(String args[]) {
		JFrame frame = new JFrame();
		frame.getContentPane().add(new PeterDwarfPanel());
		frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
		frame.setSize(800, 600);
		frame.setVisible(true);
	}

	/**
	 * Create the panel.
	 */
	public PeterDwarfPanel() {
		setLayout(new BorderLayout(0, 0));

		JScrollPane scrollPane = new JScrollPane();
		add(scrollPane, BorderLayout.CENTER);

		JTree tree = new JTree(treeModel);
		treeModel.setRoot(root);
		scrollPane.setViewportView(tree);

	}

}
