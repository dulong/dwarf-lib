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
	/**
	 * @uml.property  name="jScrollPane1"
	 * @uml.associationEnd  multiplicity="(1 1)"
	 */
	private JScrollPane jScrollPane1;
	/**
	 * @uml.property  name="jTree1"
	 * @uml.associationEnd  multiplicity="(1 1)"
	 */
	private JTree jTree1;
	/**
	 * @uml.property  name="root"
	 * @uml.associationEnd  multiplicity="(1 1)"
	 */
	DefaultMutableTreeNode root = new DefaultMutableTreeNode("dwarf");
	/**
	 * @uml.property  name="model"
	 * @uml.associationEnd  multiplicity="(1 1)"
	 */
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

	}

}
