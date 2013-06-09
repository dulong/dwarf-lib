package com.peterdwarf.gui;

import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.JTree;
import javax.swing.UIManager;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeCellRenderer;

public class DwarfTreeCellRenderer extends JLabel implements TreeCellRenderer {
	JTree tree;
	Thread animationThread;

	public DwarfTreeCellRenderer() {
		this.setOpaque(true);
	}

	@Override
	public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected, boolean expanded, boolean leaf, int row, boolean hasFocus) {
		this.tree = tree;
		if (value instanceof DwarfTreeNode) {
			DwarfTreeNode node = (DwarfTreeNode) value;
			//			if (!node.addImageObserver) {
			//				node.loadingIcon.setImageObserver(new AnimatedGifImageObserver(tree, node));
			//				node.addImageObserver = true;
			//			}
			//			if (animationThread == null && node.dwarf != null && node.dwarf.isLoading) {
			//				animationThread = new Thread(new AnimationThread(node));
			//				animationThread.start();
			//			}
			if (node.tooltip == null) {
				setToolTipText(null);
			} else {
				setToolTipText(node.tooltip);
			}
			if (node.getText() != null) {
				setText(node.getText());
			} else if (node.dwarf != null) {
//				if (node.dwarf.isLoading) {
//					setText(node.dwarf.loadingMessage);
//					//					setIcon(node.loadingIcon);
//				} else if (!node.dwarf.isLoading) {
//					setText(node.dwarf.file.getAbsolutePath());
//					//					setIcon(null);
//				} else 
				if (node.dwarf.realFilename != null) {
					setText(node.dwarf.realFilename);
				} else if (node.dwarf.file != null) {
					setText(node.dwarf.file.getName());
				}
			}

		}
		if (selected) {
			setForeground(UIManager.getColor("Tree.selectionForeground"));
			setBackground(UIManager.getColor("Tree.selectionBackground"));
		} else {
			setForeground(UIManager.getColor("Tree.textForeground"));
			setBackground(UIManager.getColor("Tree.textBackground"));
		}
		return this;
	}

	class AnimationThread implements Runnable {
		DwarfTreeNode node;

		private AnimationThread() {

		}

		public AnimationThread(DwarfTreeNode node) {
			this.node = node;
		}

		@Override
		public void run() {
			while (node.dwarf != null && node.dwarf.isLoading) {
				try {
					((DefaultTreeModel) tree.getModel()).nodeChanged(node.getParent());
					tree.repaint();
					Thread.currentThread().sleep(50);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
			System.out.println("animation thread end");
		}

	}
}
