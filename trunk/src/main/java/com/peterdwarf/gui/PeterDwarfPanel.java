package com.peterdwarf.gui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.File;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Vector;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import javax.swing.JTree;
import javax.swing.ToolTipManager;
import javax.swing.tree.DefaultTreeModel;

import com.peterdwarf.dwarf.Abbrev;
import com.peterdwarf.dwarf.AbbrevEntry;
import com.peterdwarf.dwarf.CompileUnit;
import com.peterdwarf.dwarf.DebugInfoEntry;
import com.peterdwarf.dwarf.Definition;
import com.peterdwarf.dwarf.Dwarf;
import com.peterdwarf.dwarf.DwarfDebugLineHeader;
import com.peterdwarf.dwarf.DwarfHeaderFilename;
import com.peterdwarf.dwarf.DwarfLib;
import com.peterdwarf.dwarf.DwarfLine;
import com.peterdwarf.elf.Elf32_Shdr;
import com.peterswing.CommonLib;
import com.peterswing.FilterTreeModel;
import com.peterswing.advancedswing.jprogressbardialog.JProgressBarDialog;
import com.peterswing.advancedswing.searchtextfield.JSearchTextField;

public class PeterDwarfPanel extends JPanel {
	DwarfTreeCellRenderer treeCellRenderer = new DwarfTreeCellRenderer();
	DwarfTreeNode root = new DwarfTreeNode("Elf files", null, null);
	DefaultTreeModel treeModel = new DefaultTreeModel(root);
	FilterTreeModel filterTreeModel = new FilterTreeModel(treeModel, 10, true);
	JTree tree = new JTree(filterTreeModel);
	Vector<File> files = new Vector<File>();
	public Vector<Dwarf> dwarfs = new Vector<Dwarf>();
	boolean showDialog;

	public PeterDwarfPanel() {
		setLayout(new BorderLayout(0, 0));

		JScrollPane scrollPane = new JScrollPane();
		add(scrollPane, BorderLayout.CENTER);

		tree.setShowsRootHandles(true);
		tree.setCellRenderer(treeCellRenderer);
		scrollPane.setViewportView(tree);

		JToolBar toolBar = new JToolBar();
		add(toolBar, BorderLayout.NORTH);

		JButton expandAllButton = new JButton("expand");
		expandAllButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				CommonLib.expandAll(tree, true, 4);
			}
		});
		toolBar.add(expandAllButton);

		JButton collapseButton = new JButton("collapse");
		collapseButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				filterTreeModel.reload();
				CommonLib.expandAll(tree, false);
			}
		});
		toolBar.add(collapseButton);

		final JSearchTextField searchTextField = new JSearchTextField();
		searchTextField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent e) {
				filterTreeModel.filter = searchTextField.getText();
				filterTreeModel.reload();
				CommonLib.expandAll(tree, true, 4);
			}
		});
		searchTextField.setMaximumSize(new Dimension(300, 20));
		toolBar.add(searchTextField);

		ToolTipManager.sharedInstance().registerComponent(tree);
	}

	public void init(String filepath) {
		init(new File(filepath), 0);
	}

	public void clear() {
		root.children.clear();
		treeModel.nodeChanged(root);
	}

	public void init(final File file, long memoryOffset) {
		init(file, memoryOffset, false, null);
	}

	public void init(final File file, long memoryOffset, final boolean showDialog, JFrame frame) {
		this.showDialog = showDialog;
		final Vector<Dwarf> dwarfVector = DwarfLib.init(file, memoryOffset);
		final ExecutorService exec = Executors.newFixedThreadPool(5);
		final JProgressBarDialog dialog = new JProgressBarDialog(frame, "Loading", true);
		dialog.progressBar.setIndeterminate(true);
		dialog.progressBar.setStringPainted(true);

		Thread longRunningThread = new Thread() {
			public void run() {
				try {
					for (final Dwarf dwarf : dwarfVector) {
						exec.submit(new Runnable() {
							@Override
							public void run() {
								dwarfs.add(dwarf);
								if (dwarfVector == null) {
									System.err.println("dwarf init fail");
									return;
								}
								files.add(file);
								DwarfTreeNode node = new DwarfTreeNode(dwarf, root, null);
								root.children.add(node);

								ExecutorService executorService = Executors.newFixedThreadPool(10);

								// init section nodes
								final DwarfTreeNode sectionNodes = new DwarfTreeNode("section", node, null);
								node.children.add(sectionNodes);
								for (final Elf32_Shdr section : dwarf.sections) {
									executorService.execute(new Runnable() {
										public void run() {
											if (showDialog) {
												dialog.progressBar.setString("Loading debug info : " + dwarf + ", section : " + section.section_name);
											}
											DwarfTreeNode sectionSubNode = new DwarfTreeNode(section.section_name + ", offset: 0x" + Long.toHexString(section.sh_offset)
													+ ", size: 0x" + Long.toHexString(section.sh_size) + ", addr: 0x" + Long.toHexString(section.sh_addr), sectionNodes, section);
											String str = "<html><table>";
											str += "<tr><td>no.</td><td>:</td><td>" + section.number + "</td></tr>";
											str += "<tr><td>name</td><td>:</td><td>" + section.section_name + "</td></tr>";
											str += "<tr><td>offset</td><td>:</td><td>0x" + Long.toHexString(section.sh_offset) + "</td></tr>";
											str += "<tr><td>size</td><td>:</td><td>0x" + Long.toHexString(section.sh_size) + "</td></tr>";
											str += "<tr><td>type</td><td>:</td><td>" + section.sh_type + "</td></tr>";
											str += "<tr><td>addr</td><td>:</td><td>0x" + Long.toHexString(section.sh_addr) + "</td></tr>";
											str += "<tr><td>addr align</td><td>:</td><td>" + section.sh_addralign + "</td></tr>";
											str += "<tr><td>ent. size</td><td>:</td><td>" + section.sh_entsize + "</td></tr>";
											str += "<tr><td>flags</td><td>:</td><td>" + section.sh_flags + "</td></tr>";
											str += "<tr><td>info</td><td>:</td><td>" + section.sh_info + "</td></tr>";
											str += "<tr><td>link</td><td>:</td><td>" + section.sh_link + "</td></tr>";
											str += "<tr><td>name idx</td><td>:</td><td>" + section.sh_name + "</td></tr>";
											str += "</table></html>";
											sectionSubNode.tooltip = str;
											sectionNodes.children.add(sectionSubNode);
										}
									});
								}
								while (dwarf.sections.size() != sectionNodes.children.size())
									;
								// enf init section nodes

								// init abbrev nodes
								final DwarfTreeNode abbrevNode = new DwarfTreeNode("abbrev", node, null);
								node.children.add(abbrevNode);

								final LinkedHashMap<Integer, LinkedHashMap<Integer, Abbrev>> abbrevList = dwarf.abbrevList;
								if (abbrevList != null) {
									for (final Integer abbrevOffset : abbrevList.keySet()) {
										executorService.execute(new Runnable() {
											public void run() {
												if (showDialog) {
													dialog.progressBar.setString("Loading debug info : " + dwarf + ", Abbrev offset : " + abbrevOffset);
												}
												DwarfTreeNode abbrevSubnode = new DwarfTreeNode("Abbrev offset=" + abbrevOffset, abbrevNode, null);
												abbrevNode.children.add(abbrevSubnode);
												LinkedHashMap<Integer, Abbrev> abbrevHashtable = abbrevList.get(abbrevOffset);
												for (Integer abbrevNo : abbrevHashtable.keySet()) {
													Abbrev abbrev = abbrevHashtable.get(abbrevNo);
													DwarfTreeNode abbrevSubnode2 = new DwarfTreeNode(abbrev.toString(), abbrevSubnode, abbrev);
													abbrevSubnode.children.add(abbrevSubnode2);
													for (AbbrevEntry entry : abbrev.entries) {
														DwarfTreeNode abbrevSubnode3 = new DwarfTreeNode(entry.at + ", " + entry.form + ", " + Definition.getATName(entry.at)
																+ ", " + Definition.getFormName(entry.form), abbrevSubnode2, entry);
														abbrevSubnode2.children.add(abbrevSubnode3);
													}

												}
											}
										});
									}
									while (abbrevList.size() != abbrevNode.children.size())
										;

									Collections.sort(abbrevNode.children, new Comparator<DwarfTreeNode>() {
										@Override
										public int compare(DwarfTreeNode o1, DwarfTreeNode o2) {
											String c1 = o1.getText().split("=")[1];
											String c2 = o2.getText().split("=")[1];
											return new Integer(c1).compareTo(new Integer(c2));
										}
									});
								}
								// end init abbrev nodes

								// init compile unit nodes
								final DwarfTreeNode compileUnitNode = new DwarfTreeNode("compile unit", node, null);
								node.children.add(compileUnitNode);

								Vector<CompileUnit> compileUnits = dwarf.compileUnits;
								for (final CompileUnit compileUnit : compileUnits) {
									executorService.execute(new Runnable() {
										public void run() {
											DwarfTreeNode compileUnitSubnode = new DwarfTreeNode("0x" + Long.toHexString(compileUnit.DW_AT_low_pc) + " - " + "0x"
													+ Long.toHexString(compileUnit.DW_AT_low_pc + compileUnit.DW_AT_high_pc - 1) + " - " + compileUnit.DW_AT_name + ", offset="
													+ compileUnit.abbrev_offset + ", length=" + compileUnit.length + " (size " + compileUnit.addr_size + ")", compileUnitNode,
													compileUnit);
											compileUnitNode.children.add(compileUnitSubnode);

											for (DebugInfoEntry debugInfoEntry : compileUnit.debugInfoEntries) {
												DwarfTreeNode compileUnitDebugInfoNode = new DwarfTreeNode(debugInfoEntry.toString(), compileUnitSubnode, debugInfoEntry);
												compileUnitSubnode.children.add(compileUnitDebugInfoNode);

												Enumeration<String> e = debugInfoEntry.debugInfoAbbrevEntries.keys();
												while (e.hasMoreElements()) {
													String key = e.nextElement();
													DwarfTreeNode compileUnitDebugInfoAbbrevEntrySubnode = new DwarfTreeNode(debugInfoEntry.debugInfoAbbrevEntries.get(key)
															.toString(), compileUnitDebugInfoNode, debugInfoEntry.debugInfoAbbrevEntries.get(key));
													compileUnitDebugInfoNode.children.add(compileUnitDebugInfoAbbrevEntrySubnode);
												}

												addTreeNode(compileUnitDebugInfoNode, debugInfoEntry);
											}

											//											Collections.sort(compileUnitSubnode.children, new Comparator<DwarfTreeNode>() {
											//												@Override
											//												public int compare(DwarfTreeNode o1, DwarfTreeNode o2) {
											//													DebugInfoEntry c1 = (DebugInfoEntry) o1.object;
											//													DebugInfoEntry c2 = (DebugInfoEntry) o2.object;
											//													return new Integer(c1.offset).compareTo(new Integer(c2.offset));
											//												}
											//											});
										}

										private void addTreeNode(DwarfTreeNode node, DebugInfoEntry debugInfoEntry) {
											if (showDialog) {
												dialog.progressBar.setString("Loading debug info : " + dwarf + ", " + node.getText().split(",")[0]);
											}
											if (debugInfoEntry.debugInfoEntries.size() == 0) {
												return;
											}

											for (DebugInfoEntry d : debugInfoEntry.debugInfoEntries) {
												DwarfTreeNode subNode = new DwarfTreeNode(d.toString(), node, d);
												node.children.add(subNode);

												Enumeration<String> e = d.debugInfoAbbrevEntries.keys();
												while (e.hasMoreElements()) {
													String key = e.nextElement();
													DwarfTreeNode compileUnitDebugInfoAbbrevEntrySubnode = new DwarfTreeNode(d.debugInfoAbbrevEntries.get(key).toString(), subNode,
															d.debugInfoAbbrevEntries.get(key));
													subNode.children.add(compileUnitDebugInfoAbbrevEntrySubnode);
												}

												addTreeNode(subNode, d);
											}
										}
									});
								}
								while (dwarf.compileUnits.size() != compileUnitNode.children.size())
									;
								Collections.sort(compileUnitNode.children, new Comparator<DwarfTreeNode>() {
									@Override
									public int compare(DwarfTreeNode o1, DwarfTreeNode o2) {
										CompileUnit c1 = (CompileUnit) o1.object;
										CompileUnit c2 = (CompileUnit) o2.object;
										return new Integer((int) c1.DW_AT_low_pc).compareTo(new Integer((int) c2.DW_AT_low_pc));
									}
								});
								// end init compile unit nodes

								// init headers
								final DwarfTreeNode headNode = new DwarfTreeNode("header", node, null);
								node.children.add(headNode);

								Vector<DwarfDebugLineHeader> headers = dwarf.headers;
								for (final DwarfDebugLineHeader header : headers) {
									executorService.execute(new Runnable() {
										public void run() {
											DwarfTreeNode headerSubnode = new DwarfTreeNode("offset=0x" + Long.toHexString(header.offset) + ", Length=" + header.total_length
													+ ", DWARF Version=" + header.version + ", Prologue Length=" + header.prologue_length + ", Minimum Instruction Length="
													+ header.minimum_instruction_length + ", Initial value of 'is_stmt'=" + (header.default_is_stmt ? 1 : 0) + ", Line Base="
													+ header.line_base + ", Line Range=" + header.line_range + ", Opcode Base=" + header.opcode_base, headNode, header);
											String str = "<html><table>";
											str += "<tr><td>offset</td><td>:</td><td>0x" + Long.toHexString(header.offset) + "</td></tr>";
											str += "<tr><td>total length</td><td>:</td><td>" + header.total_length + "</td></tr>";
											str += "<tr><td>DWARF Version</td><td>:</td><td>" + header.version + "</td></tr>";
											str += "<tr><td>Prologue Length</td><td>:</td><td>" + header.prologue_length + "</td></tr>";
											str += "<tr><td>Minimum Instruction Length</td><td>:</td><td>" + header.minimum_instruction_length + "</td></tr>";
											str += "<tr><td>Initial value of 'is_stmt'</td><td>:</td><td>" + (header.default_is_stmt ? 1 : 0) + "</td></tr>";
											str += "<tr><td>Line Base</td><td>:</td><td>" + header.line_base + "</td></tr>";
											str += "<tr><td>Line Range</td><td>:</td><td>" + header.line_range + "</td></tr>";
											str += "<tr><td>Opcode Base</td><td>:</td><td>" + header.opcode_base + "</td></tr>";
											str += "</table></html>";
											headerSubnode.tooltip = str;
											headNode.children.add(headerSubnode);

											DwarfTreeNode dirnamesNode = new DwarfTreeNode("dir name", headerSubnode, null);
											headerSubnode.children.add(dirnamesNode);
											for (String dir : header.dirnames) {
												dirnamesNode.children.add(new DwarfTreeNode(dir, dirnamesNode, null));
											}

											DwarfTreeNode filenamesNode = new DwarfTreeNode("file name", headerSubnode, null);
											headerSubnode.children.add(filenamesNode);
											for (DwarfHeaderFilename filename : header.filenames) {
												filenamesNode.children.add(new DwarfTreeNode(filename.file.getAbsolutePath(), filenamesNode, null));
											}

											DwarfTreeNode lineInfoNode = new DwarfTreeNode("line info", headerSubnode, null);
											headerSubnode.children.add(lineInfoNode);
											for (DwarfLine line : header.lines) {
												DwarfTreeNode lineSubnode = new DwarfTreeNode("file_num=" + line.file_num + ", line_num:" + line.line_num + ", column_num="
														+ line.column_num + ", address=0x" + line.address.toString(16), lineInfoNode, line);
												lineInfoNode.children.add(lineSubnode);
											}
										}
									});
								}

								while (headers.size() != headNode.children.size())
									;
								// end init headers
							}
						});
					}
				} finally {
					exec.shutdown();
				}
				try {
					while (!exec.awaitTermination(200, TimeUnit.SECONDS)) {
					}
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		};
		dialog.thread = longRunningThread;
		dialog.setVisible(true);

		filterTreeModel.nodeChanged(root);
	}

	//	private void showProgress(JDialog dialog, String message) {
	//		if (dialog != null) {
	//			((JLabel) dialog.getContentPane()).setText(message);
	//		}
	//	}

	public CompileUnit getCompileUnit(long address) {
		for (Dwarf dwarf : dwarfs) {
			CompileUnit cu = dwarf.getCompileUnit(address);
			if (cu != null) {
				return cu;
			}
		}
		return null;
	}
}
