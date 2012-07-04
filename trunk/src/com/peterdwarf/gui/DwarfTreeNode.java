package com.peterdwarf.gui;

import java.util.Enumeration;
import java.util.Vector;

import javax.swing.ImageIcon;
import javax.swing.tree.TreeNode;

import com.peterdwarf.dwarf.Dwarf;

public class DwarfTreeNode implements TreeNode {
	ImageIcon loadingIcon = new ImageIcon(DwarfTreeCellRenderer.class.getResource("/com/peterdwarf/gui/ajax-loader.gif"));

	Vector<DwarfTreeNode> children = new Vector<DwarfTreeNode>();
	boolean allowsChildren;
	DwarfTreeNode parent;
	Dwarf dwarf;
	String text;

	boolean addImageObserver;

	public DwarfTreeNode(String text) {
		this.text = text;
	}

	public DwarfTreeNode(Dwarf dwarf) {
		this.dwarf = dwarf;
	}

	@Override
	public Enumeration children() {
		return children.elements();
	}

	@Override
	public boolean getAllowsChildren() {
		return allowsChildren;
	}

	@Override
	public TreeNode getChildAt(int x) {
		return children.get(x);
	}

	@Override
	public int getChildCount() {
		return children.size();
	}

	@Override
	public int getIndex(TreeNode node) {
		int x = 0;
		for (DwarfTreeNode treeNode : children) {
			if (treeNode == node) {
				return x;
			}
			x++;
		}
		return -1;
	}

	@Override
	public TreeNode getParent() {
		return parent;
	}

	@Override
	public boolean isLeaf() {
		return children.size() == 0;
	}

	public Dwarf getDwarf() {
		return dwarf;
	}

	public void setDwarf(Dwarf dwarf) {
		this.dwarf = dwarf;
	}

	public String getText() {
		return text;
	}

	public void setText(String text) {
		this.text = text;
	}

}
