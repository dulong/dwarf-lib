package com.peterdwarf.gui;

import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreeNode;

public class FilterTreeModel extends DefaultTreeModel {
	public String filter;
	private TreeModel delegate;

	public FilterTreeModel(TreeModel delegate) {
		super((TreeNode) delegate.getRoot());
		this.delegate = delegate;
	}

	public Object getChild(Object parent, int index) {
		int count = 0;
		for (int i = 0; i < delegate.getChildCount(parent); i++) {
			final Object child = delegate.getChild(parent, i);
			if (isShown(child)) {
				if (count++ == index) {
					return child;
				}
			} else {
				final Object child2 = getChild(child, index - count);
				if (child2 != null) {
					return child2;
				}
				count += getChildCount(child);
			}
		}
		return null;
	}

	public int getIndexOfChild(Object parent, Object child) {
		return delegate.getIndexOfChild(parent, child);
	}

	public int getChildCount(Object parent) {
		int count = 0;
		for (int i = 0; i < delegate.getChildCount(parent); i++) {
			final Object child = delegate.getChild(parent, i);
			if (isShown(child)) {
				count++;
			} else {
				count += getChildCount(child);
			}
		}
		return count;
	}

	public boolean isLeaf(Object node) {
		return delegate.isLeaf(node);
	}

	private boolean isShown(Object node) {
		final DwarfTreeNode treeNode = (DwarfTreeNode) node;
		if (treeNode == null) {
			return false;
		}
		if (treeNode.text == null) {
			if (treeNode.dwarf.file.getAbsolutePath().contains(filter)) {
				return true;
			} else {
				return false;
			}
		}
		if (filter == null || filter.equals("")) {
			return true;
		}
		return treeNode.text.contains(filter);
	}
}
