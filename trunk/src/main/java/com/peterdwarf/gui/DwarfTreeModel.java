package com.peterdwarf.gui;

import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreePath;

public class DwarfTreeModel implements javax.swing.tree.TreeModel {
	DwarfTreeNode root;

	public DwarfTreeModel() {

	}

	public DwarfTreeModel(DwarfTreeNode root) {
		this.root = root;
	}

	public void setRoot(DwarfTreeNode root) {
		this.root = root;
	}

	@Override
	public Object getChild(Object node, int x) {
		return ((DwarfTreeNode) node).getChildAt(x);
	}

	@Override
	public int getChildCount(Object node) {
		System.out.println(((DwarfTreeNode) node).getChildCount());
		return ((DwarfTreeNode) node).getChildCount();
	}

	@Override
	public int getIndexOfChild(Object arg0, Object arg1) {
		return 0;
	}

	@Override
	public Object getRoot() {
		return root;
	}

	@Override
	public boolean isLeaf(Object node) {
		return ((DwarfTreeNode) node).isLeaf();
	}

	@Override
	public void removeTreeModelListener(TreeModelListener arg0) {

	}

	@Override
	public void addTreeModelListener(TreeModelListener arg0) {
	}

	@Override
	public void valueForPathChanged(TreePath arg0, Object arg1) {

	}

}
