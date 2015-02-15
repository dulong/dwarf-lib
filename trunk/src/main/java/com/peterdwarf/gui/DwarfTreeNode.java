package com.peterdwarf.gui;

import java.util.Enumeration;
import java.util.Vector;

import javax.swing.ImageIcon;
import javax.swing.tree.TreeNode;

import com.peterdwarf.dwarf.Dwarf;
import com.peterswing.FilterTreeNode;

public class DwarfTreeNode extends FilterTreeNode {
	ImageIcon loadingIcon = new ImageIcon(DwarfTreeCellRenderer.class.getResource("/com/peterdwarf/gui/ajax-loader.gif"));

	Vector<DwarfTreeNode> children = new Vector<DwarfTreeNode>();
	boolean allowsChildren;
	DwarfTreeNode parent;
	Dwarf dwarf;
	private String text;
	String tooltip;
	Object object;

	boolean addImageObserver;

	public DwarfTreeNode(String text, DwarfTreeNode parent, Object object) {
		this.text = text;
		this.parent = parent;
		this.object = object;
	}

	public DwarfTreeNode(Dwarf dwarf, DwarfTreeNode parent, Object object) {
		this.dwarf = dwarf;
		this.parent = parent;
		this.object = object;
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

	@Override
	public String toString() {
		if (dwarf == null) {
			return text;
		} else {
			return dwarf.toString();
		}
	}

}
