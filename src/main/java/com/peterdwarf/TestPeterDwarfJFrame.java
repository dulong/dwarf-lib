package com.peterdwarf;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.util.Vector;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JToolBar;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.WindowConstants;

import com.peterdwarf.dwarf.DebugInfoEntry;
import com.peterdwarf.dwarf.DwarfLib;
import com.peterdwarf.gui.PeterDwarfPanel;
import com.peterswing.CommonLib;

public class TestPeterDwarfJFrame extends javax.swing.JFrame {
	private JToolBar toolBar1;
	private JButton openButton;
	private PeterDwarfPanel peterDwarfPanel1;

	public static void main(String[] args) {
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
				openButtonActionPerformed(null);
			}
		});
		initGUI();
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
				peterDwarfPanel1 = new PeterDwarfPanel();
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
		File file = new File("c:\\vmlinuz-3.8.0-29-generic");
		peterDwarfPanel1.init(file, 0, true, this);

		DebugInfoEntry debugInfoEntry = DwarfLib.getSubProgram(peterDwarfPanel1.dwarfs, CommonLib.convertFilesize("0x1600000"));
		Vector<DebugInfoEntry> v = debugInfoEntry.getDebugInfoEntryByName("DW_TAG_formal_parameter");
		for (DebugInfoEntry d : v) {
			System.out.println(d.debugInfoAbbrevEntries.get("DW_AT_name").value);
		}
	}

}
