package com.peterdwarf;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JToolBar;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;

import com.peterdwarf.gui.PeterDwarfPanel;

public class TestPeterDwarfJFrame extends javax.swing.JFrame {
	private JToolBar jToolBar1;
	private JButton jOpenButton;
	private PeterDwarfPanel peterDwarfPanel1;

	public static void main(String[] args) {
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				TestPeterDwarfJFrame inst = new TestPeterDwarfJFrame();
				inst.setLocationRelativeTo(null);
				inst.setVisible(true);
			}
		});
	}

	public TestPeterDwarfJFrame() {
		super();
		initGUI();
		jOpenButtonActionPerformed(null);
	}

	private void initGUI() {
		try {
			setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
			this.setTitle("Test Peter-dwarf Library");
			{
				jToolBar1 = new JToolBar();
				getContentPane().add(jToolBar1, BorderLayout.NORTH);
				{
					jOpenButton = new JButton();
					jToolBar1.add(jOpenButton);
					jOpenButton.setText("Open ELF");
					jOpenButton.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent evt) {
							jOpenButtonActionPerformed(evt);
						}
					});
				}
			}
			{
				peterDwarfPanel1 = new PeterDwarfPanel();
				getContentPane().add(peterDwarfPanel1, BorderLayout.CENTER);
			}
			pack();
			setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
			this.setSize(768, 596);
		} catch (Exception e) {
			//add your error handling code here
			e.printStackTrace();
		}
	}

	private void jOpenButtonActionPerformed(ActionEvent evt) {
		File file = new File("/Users/peter/workspace/PeterI/kernel/kernel");
		peterDwarfPanel1.init(file.getAbsolutePath());
	}

}
