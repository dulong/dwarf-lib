package com.peterdwarf.gui;

import java.util.Enumeration;
import java.util.Vector;

import javax.swing.tree.TreeNode;

public class DwarfTreeNode implements TreeNode {
	Vector<DwarfTreeNode> children = new Vector<DwarfTreeNode>();
	boolean allowsChildren;
	DwarfTreeNode parent;
	private String text;

	private DwarfTreeNode() {

	}

	public DwarfTreeNode(String text) {
		this.text = text;
	}

	public String getText() {
		return text;
	}

	public void setText(String text) {
		this.text = text;
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

	public String toString() {
		return text;
	}
}
