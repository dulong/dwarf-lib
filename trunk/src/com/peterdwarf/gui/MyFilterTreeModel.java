package com.peterdwarf.gui;

import javax.swing.tree.TreeModel;

import com.peterswing.FilterTreeModel;

public class MyFilterTreeModel extends FilterTreeModel {

	public MyFilterTreeModel(TreeModel delegate) {
		super(delegate);
	}

	@Override
	protected boolean isShown(Object node) {
		if (filter == null || filter.equals("")) {
			return true;
		}
		final DwarfTreeNode treeNode = (DwarfTreeNode) node;
		if (treeNode == null) {
			return false;
		} else if (treeNode.getText() == null) {
			return true;
		} else {
			return treeNode.getText().toLowerCase().contains(filter.toLowerCase());
		}
	}
}
