package com.peterdwarf.gui;

import javax.swing.tree.TreeModel;

import com.peterswing.FilterTreeModel;

public class MyFilterTreeModel extends FilterTreeModel {

	public MyFilterTreeModel(TreeModel delegate) {
		super(delegate);
	}

}
