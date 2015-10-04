package com.peterdwarf;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JToolBar;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;

import com.peterdwarf.dwarf.Dwarf;
import com.peterdwarf.gui.PeterDwarfPanel;
import javax.swing.UIManager;

public class TestPeterDwarfJFrame extends javax.swing.JFrame {

	private JToolBar toolBar1;
	private JButton openButton;
	private PeterDwarfPanel peterDwarfPanel1;
	static String[] args;

	public static void main(String[] args) {
		System.out.println("main");
		TestPeterDwarfJFrame.args = args;
		DwarfGlobal.debug = true;
		try {
			UIManager.setLookAndFeel("com.peterswing.white.PeterSwingWhiteLookAndFeel");
		} catch (Exception e) {
			e.printStackTrace();
		}
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
		addWindowListener(new WindowAdapter() {
			@Override
			public void windowOpened(WindowEvent e) {
				//				openButtonActionPerformed(null);
			}
		});
		System.out.println("initGUI");
		initGUI();
		System.out.println("initGUI end");
		if (args.length > 0) {
			peterDwarfPanel1.init(new File(args[0]), 0, true, this);
		}
	}

	private void initGUI() {
		try {
			setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
			this.setTitle("Test Peter-dwarf Library");
			{
				toolBar1 = new JToolBar();
				getContentPane().add(toolBar1, BorderLayout.NORTH);
				{
					openButton = new JButton();
					toolBar1.add(openButton);
					openButton.setText("Open ELF");
					openButton.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent evt) {
							openButtonActionPerformed(evt);
						}
					});
				}
			}
			{
				System.out.println("s1");
				peterDwarfPanel1 = new PeterDwarfPanel();
				System.out.println("s2");
				getContentPane().add(peterDwarfPanel1, BorderLayout.CENTER);
			}
			pack();
			setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
			this.setSize(900, 750);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void openButtonActionPerformed(ActionEvent evt) {
		//File file = new File("/Users/peter/linux-4.0-rc5/");
		//File file = new File("../PeterI/kernel/kernel");
		JFileChooser chooser = new JFileChooser();
		chooser.showSaveDialog(this);

		File file = chooser.getSelectedFile();
		if (file != null) {
			peterDwarfPanel1.init(file, 0, true, this);

			for (Dwarf dwarf : peterDwarfPanel1.dwarfs) {
				System.out.println(dwarf.getCompileUnitByFunction("itoa"));
			}
		}
	}

}
