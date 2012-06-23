package com.peterdwarf;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JToolBar;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;

import com.peterdwarf.dwarf.CompileUnit;
import com.peterdwarf.dwarf.DebugInfoAbbrevEntry;
import com.peterdwarf.dwarf.DebugInfoEntry;
import com.peterdwarf.dwarf.Dwarf;
import com.peterdwarf.dwarf.DwarfHeaderFilename;
import com.peterdwarf.dwarf.DwarfLine;

/**
 * This code was edited or generated using CloudGarden's Jigloo SWT/Swing GUI
 * Builder, which is free for non-commercial use. If Jigloo is being used
 * commercially (ie, by a corporation, company or business for any purpose
 * whatever) then you should purchase a license for each developer using Jigloo.
 * Please visit www.cloudgarden.com for details. Use of Jigloo implies
 * acceptance of these licensing terms. A COMMERCIAL LICENSE HAS NOT BEEN
 * PURCHASED FOR THIS MACHINE, SO JIGLOO OR THIS CODE CANNOT BE USED LEGALLY FOR
 * ANY CORPORATE OR COMMERCIAL PURPOSE.
 */
public class TestPeterDwarfJFrame extends javax.swing.JFrame {
	private JToolBar jToolBar1;
	private JButton jOpenButton;
	private PeterDwarfPanel peterDwarfPanel1;

	/**
	 * Auto-generated main method to display this JFrame
	 */
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
			this.setSize(768, 596);
		} catch (Exception e) {
			//add your error handling code here
			e.printStackTrace();
		}
	}

	private void jOpenButtonActionPerformed(ActionEvent evt) {
//		JFileChooser jFileChooser = new JFileChooser();
//		int returnVal = jFileChooser.showOpenDialog(this);
//		if (returnVal == JFileChooser.APPROVE_OPTION) {
//			File file = jFileChooser.getSelectedFile();
//			peterDwarfPanel1.init(file);
//		}
		
		File file = new File("/Users/peter/workspace/PeterI/kernel/kernel");
		peterDwarfPanel1.init(file);
	}

}
