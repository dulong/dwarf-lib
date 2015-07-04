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
import javax.swing.tree.TreePath;

import com.peterdwarf.dwarf.Abbrev;
import com.peterdwarf.dwarf.AbbrevEntry;
import com.peterdwarf.dwarf.CompileUnit;
import com.peterdwarf.dwarf.DebugInfoAbbrevEntry;
import com.peterdwarf.dwarf.DebugInfoEntry;
import com.peterdwarf.dwarf.DebugLocEntry;
import com.peterdwarf.dwarf.Definition;
import com.peterdwarf.dwarf.Dwarf;
import com.peterdwarf.dwarf.DwarfDebugLineHeader;
import com.peterdwarf.dwarf.DwarfHeaderFilename;
import com.peterdwarf.dwarf.DwarfLib;
import com.peterdwarf.dwarf.DwarfLine;
import com.peterdwarf.dwarf.FrameChunk;
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
	JSearchTextField searchTextField = new JSearchTextField();

	final int maxExpandLevel = 5;

	final int maxPoolSize = 16;

	ExecutorService pool;

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
				CommonLib.expandAll(tree, true, maxExpandLevel);
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

		searchTextField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent e) {
				if (searchTextField.getText().equals(filterTreeModel.filter)) {
					return;
				}
				filterTreeModel.filter = searchTextField.getText();
				filterTreeModel.reload();

				if (searchTextField.getText().equals("")) {
					expandFirstLevel();
				} else {
					CommonLib.expandAll(tree, true, maxExpandLevel);
				}
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
		treeModel.nodeStructureChanged(root);
	}

	public void init(final File file, long memoryOffset) {
		init(file, memoryOffset, false, null);
	}

	public void init(final File file, long memoryOffset, final boolean showDialog, JFrame frame) {
		this.showDialog = showDialog;
		final Vector<Dwarf> dwarfVector = DwarfLib.init(file, memoryOffset);
		final JProgressBarDialog dialog = new JProgressBarDialog(frame, "Loading", true);
		dialog.progressBar.setIndeterminate(true);
		dialog.progressBar.setStringPainted(true);

		Thread longRunningThread = new Thread() {
			public void run() {
				for (final Dwarf dwarf : dwarfVector) {
					dwarfs.add(dwarf);
					if (dwarfVector == null) {
						System.err.println("dwarf init fail");
						return;
					}
					files.add(file);
					DwarfTreeNode node = new DwarfTreeNode(dwarf, root, null);
					root.children.add(node);

					// init section nodes
					final DwarfTreeNode sectionNodes = new DwarfTreeNode("section", node, null);
					node.children.add(sectionNodes);
					for (final Elf32_Shdr section : dwarf.sections) {
						if (showDialog) {
							dialog.progressBar.setString("Loading debug info : " + dwarf + ", section : " + section.section_name);
						}
						DwarfTreeNode sectionSubNode = new DwarfTreeNode(section.section_name + ", offset: 0x" + Long.toHexString(section.sh_offset) + ", size: 0x"
								+ Long.toHexString(section.sh_size) + ", addr: 0x" + Long.toHexString(section.sh_addr), sectionNodes, section);
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
					while (dwarf.sections.size() != sectionNodes.children.size())
						;

					Collections.sort(sectionNodes.children, new Comparator<DwarfTreeNode>() {
						@Override
						public int compare(DwarfTreeNode o1, DwarfTreeNode o2) {
							Elf32_Shdr c1 = (Elf32_Shdr) o1.object;
							Elf32_Shdr c2 = (Elf32_Shdr) o2.object;
							return new Integer(c1.number).compareTo(new Integer(c2.number));
						}
					});
					// enf init section nodes

					// init abbrev nodes
					final DwarfTreeNode abbrevNode = new DwarfTreeNode("abbrev", node, null);
					node.children.add(abbrevNode);

					final LinkedHashMap<Integer, LinkedHashMap<Integer, Abbrev>> abbrevList = dwarf.abbrevList;
					if (abbrevList != null) {
						pool = Executors.newFixedThreadPool(maxPoolSize);
						for (final Integer abbrevOffset : abbrevList.keySet()) {
							pool.execute(new Runnable() {
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
											DwarfTreeNode abbrevSubnode3 = new DwarfTreeNode(entry.at + ", " + entry.form + ", " + Definition.getATName(entry.at) + ", "
													+ Definition.getFormName(entry.form), abbrevSubnode2, entry);
											abbrevSubnode2.children.add(abbrevSubnode3);
										}

									}

								}
							});
						}
						waitPoolFinish();

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
					pool = Executors.newFixedThreadPool(maxPoolSize);
					for (final CompileUnit compileUnit : compileUnits) {
						pool.execute(new Runnable() {
							public void run() {
								final DwarfTreeNode compileUnitSubnode = new DwarfTreeNode("0x" + Long.toHexString(compileUnit.DW_AT_low_pc) + " - " + "0x"
										+ Long.toHexString(compileUnit.DW_AT_low_pc + compileUnit.DW_AT_high_pc - 1) + " - " + compileUnit.DW_AT_name + ", offset="
										+ compileUnit.abbrev_offset + ", length=" + compileUnit.length + " (size " + compileUnit.addr_size + ")", compileUnitNode, compileUnit);
								compileUnitNode.children.add(compileUnitSubnode);

								// init headers
								final DwarfTreeNode headNode = new DwarfTreeNode("header", compileUnitSubnode, null);
								compileUnitSubnode.children.add(headNode);

								DwarfDebugLineHeader header = compileUnit.dwarfDebugLineHeader;
								DwarfTreeNode headerSubnode = new DwarfTreeNode(header.toString(), headNode, header);
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
									DwarfTreeNode lineSubnode = new DwarfTreeNode("file_num=" + line.file_num + ", line_num:" + line.line_num + ", column_num=" + line.column_num
											+ ", address=0x" + line.address.toString(16), lineInfoNode, line);
									lineInfoNode.children.add(lineSubnode);
								}
								// end init headers

								for (final DebugInfoEntry debugInfoEntry : compileUnit.debugInfoEntries) {
									final DwarfTreeNode compileUnitDebugInfoNode = new DwarfTreeNode(debugInfoEntry.toString(), compileUnitSubnode, debugInfoEntry);
									compileUnitSubnode.children.add(compileUnitDebugInfoNode);

									Enumeration<String> e = debugInfoEntry.debugInfoAbbrevEntries.keys();
									while (e.hasMoreElements()) {
										String key = e.nextElement();
										DwarfTreeNode compileUnitDebugInfoAbbrevEntrySubnode = new DwarfTreeNode(debugInfoEntry.debugInfoAbbrevEntries.get(key).toString(),
												compileUnitDebugInfoNode, debugInfoEntry.debugInfoAbbrevEntries.get(key));
										compileUnitDebugInfoNode.children.add(compileUnitDebugInfoAbbrevEntrySubnode);
									}

									Collections.sort(compileUnitDebugInfoNode.children, new Comparator<DwarfTreeNode>() {
										@Override
										public int compare(DwarfTreeNode o1, DwarfTreeNode o2) {
											DebugInfoAbbrevEntry c1 = (DebugInfoAbbrevEntry) o1.object;
											DebugInfoAbbrevEntry c2 = (DebugInfoAbbrevEntry) o2.object;
											return new Integer(c1.position).compareTo(new Integer(c2.position));
										}
									});

									addDebugInfoEntries(dialog, compileUnit, compileUnitDebugInfoNode, debugInfoEntry);
								}
							}
						});
					}

					waitPoolFinish();

					Collections.sort(compileUnitNode.children, new Comparator<DwarfTreeNode>() {
						@Override
						public int compare(DwarfTreeNode o1, DwarfTreeNode o2) {
							CompileUnit c1 = (CompileUnit) o1.object;
							CompileUnit c2 = (CompileUnit) o2.object;
							return new Integer((int) c1.DW_AT_low_pc).compareTo(new Integer((int) c2.DW_AT_low_pc));
						}
					});
					// end init compile unit nodes

					// init .eh_frame
					final DwarfTreeNode ehFrameTreeNode = new DwarfTreeNode(".eh_frame", node, null);
					node.children.add(ehFrameTreeNode);

					pool = Executors.newFixedThreadPool(maxPoolSize);
					for (final FrameChunk ehFrame : dwarf.ehFrames) {
						pool.execute(new Runnable() {
							public void run() {
								if (showDialog) {
									dialog.progressBar.setString("Loading .eh_frame : " + Long.toHexString(ehFrame.pc_begin_real) + " - "
											+ Long.toHexString(ehFrame.pc_begin_real + ehFrame.pc_range_real));
								}
								if (ehFrame.cieID != 0) {
									DwarfTreeNode ehFrameSubNode = new DwarfTreeNode(Long.toHexString(ehFrame.pc_begin_real) + " - "
											+ Long.toHexString(ehFrame.pc_begin_real + ehFrame.pc_range_real), ehFrameTreeNode, ehFrame);

									// for (Object key :
									// ehFrame.fieDetails.keySet()) {
									for (int x = 0; x < ehFrame.fieDetailsKeys.size(); x++) {
										String key = ehFrame.fieDetailsKeys.get(x);
										Object objects[] = ehFrame.fieDetails.get(x);
										String s = "";
										for (Object object : objects) {
											if (!s.equals("")) {
												s += ", ";
											}
											s += object;
										}
										DwarfTreeNode ehFrameFieSubNode = new DwarfTreeNode(key + " : " + s, ehFrameSubNode, ehFrame);
										ehFrameSubNode.children.add(ehFrameFieSubNode);
									}

									ehFrameTreeNode.children.add(ehFrameSubNode);
								} else {
									DwarfTreeNode ehFrameSubNode = new DwarfTreeNode("CIE", ehFrameTreeNode, ehFrame);

									DwarfTreeNode ehFrameCieSubNode;

									ehFrameCieSubNode = new DwarfTreeNode("Version : " + ehFrame.version, ehFrameSubNode, ehFrame);
									ehFrameSubNode.children.add(ehFrameCieSubNode);

									ehFrameCieSubNode = new DwarfTreeNode("Augmentation : " + ehFrame.augmentation, ehFrameSubNode, ehFrame);
									ehFrameSubNode.children.add(ehFrameCieSubNode);

									ehFrameCieSubNode = new DwarfTreeNode("Code factor : " + ehFrame.code_factor, ehFrameSubNode, ehFrame);
									ehFrameSubNode.children.add(ehFrameCieSubNode);

									ehFrameCieSubNode = new DwarfTreeNode("Data factor : " + ehFrame.data_factor, ehFrameSubNode, ehFrame);
									ehFrameSubNode.children.add(ehFrameCieSubNode);

									ehFrameCieSubNode = new DwarfTreeNode("Return address column : " + ehFrame.ra, ehFrameSubNode, ehFrame);
									ehFrameSubNode.children.add(ehFrameCieSubNode);

									String augmentationDataStr = "";
									for (byte b : ehFrame.augmentationData) {
										augmentationDataStr += b + ",";
									}
									ehFrameCieSubNode = new DwarfTreeNode("Augmentation data : " + augmentationDataStr, ehFrameSubNode, ehFrame);
									ehFrameSubNode.children.add(ehFrameCieSubNode);

									// ehFrameFieSubNode = new
									// DwarfTreeNode("DW_CFA_def_cfa : " +
									// ehFrame.cfa_reg, ehFrameSubNode,
									// ehFrame);
									// ehFrameSubNode.children.add(ehFrameFieSubNode);
									//
									// ehFrameFieSubNode = new
									// DwarfTreeNode("DW_CFA_def_cfa : " +
									// ehFrame.cfa_offset, ehFrameSubNode,
									// ehFrame);
									// ehFrameSubNode.children.add(ehFrameFieSubNode);

									ehFrameTreeNode.children.add(ehFrameSubNode);
								}
							}
						});
					}

					waitPoolFinish();

					Collections.sort(ehFrameTreeNode.children, new Comparator<DwarfTreeNode>() {
						@Override
						public int compare(DwarfTreeNode o1, DwarfTreeNode o2) {
							if (o1.toString().equals("CIE")) {
								return -1;
							}
							if (o2.toString().equals("CIE")) {
								return 1;
							}
							return o1.toString().compareTo(o2.toString());
						}
					});
					// end init .eh_frame

					// init .debug_loc
					final DwarfTreeNode debugLocTreeNode = new DwarfTreeNode(".debug_loc", node, null);
					node.children.add(debugLocTreeNode);

					pool = Executors.newFixedThreadPool(maxPoolSize);
					for (final DebugLocEntry debugLocEntry : dwarf.debugLocEntries) {
						pool.execute(new Runnable() {
							public void run() {
								if (showDialog) {
									dialog.progressBar.setString("Loading .debug_loc : " + debugLocEntry);
								}

								DwarfTreeNode debugLocChildNode = new DwarfTreeNode(debugLocEntry.toString(), debugLocTreeNode, debugLocEntry);
								debugLocTreeNode.children.add(debugLocChildNode);
							}
						});
					}

					waitPoolFinish();

					Collections.sort(debugLocTreeNode.children, new Comparator<DwarfTreeNode>() {
						@Override
						public int compare(DwarfTreeNode o1, DwarfTreeNode o2) {
							DebugLocEntry debugLocEntry1 = (DebugLocEntry) o1.object;
							DebugLocEntry debugLocEntry2 = (DebugLocEntry) o2.object;
							return Integer.valueOf(debugLocEntry1.offset).compareTo(Integer.valueOf(debugLocEntry2.offset));
						}
					});
					// end init .debug_loc
				}

				expandFirstLevel();
			}
		};
		dialog.thread = longRunningThread;
		dialog.setVisible(true);
	}

	void waitPoolFinish() {
		pool.shutdown();
		try {
			if (!pool.awaitTermination(600, TimeUnit.SECONDS)) {
				pool.shutdownNow();
				if (!pool.awaitTermination(60, TimeUnit.SECONDS)) {
					System.err.println("Pool did not terminate");
				}
			}
		} catch (InterruptedException ie) {
			pool.shutdownNow();
			Thread.currentThread().interrupt();
		}
	}

	void expandFirstLevel() {
		Enumeration<DwarfTreeNode> topLevelNodes = ((DwarfTreeNode) tree.getModel().getRoot()).children();
		while (topLevelNodes.hasMoreElements()) {
			DwarfTreeNode node = (DwarfTreeNode) topLevelNodes.nextElement();
			tree.expandPath(new TreePath(node.getPath()));
		}
	}

	private void addDebugInfoEntries(JProgressBarDialog dialog, final CompileUnit compileUnit, DwarfTreeNode node, DebugInfoEntry debugInfoEntry) {
		if (showDialog) {
			dialog.progressBar.setString("Loading debug info : cu, " + compileUnit.offset + ", " + new File(compileUnit.DW_AT_name).getName());
		}
		if (debugInfoEntry.debugInfoEntries.size() == 0) {
			return;
		}

		for (final DebugInfoEntry d : debugInfoEntry.debugInfoEntries) {
			final DwarfTreeNode subNode = new DwarfTreeNode(d.toString(), node, d);
			node.children.add(subNode);

			Enumeration<String> e = d.debugInfoAbbrevEntries.keys();
			while (e.hasMoreElements()) {
				String key = e.nextElement();
				DwarfTreeNode compileUnitDebugInfoAbbrevEntrySubnode;

				DebugInfoAbbrevEntry debugInfoAbbrevEntry = d.debugInfoAbbrevEntries.get(key);

				if (debugInfoAbbrevEntry.name.equals("DW_AT_decl_file")) {
					compileUnitDebugInfoAbbrevEntrySubnode = new DwarfTreeNode(debugInfoAbbrevEntry.toString() + ", "
							+ compileUnit.dwarfDebugLineHeader.filenames.get(Integer.parseInt(debugInfoAbbrevEntry.value.toString()) - 1).file.getAbsolutePath(), subNode,
							debugInfoAbbrevEntry);
				} else if (debugInfoAbbrevEntry.name.equals("DW_AT_type")) {
					int value = CommonLib.string2int("0x" + debugInfoAbbrevEntry.value.toString());
					String type = DwarfLib.getParameterType(compileUnit, value);
					if (type == null) {
						compileUnitDebugInfoAbbrevEntrySubnode = new DwarfTreeNode(debugInfoAbbrevEntry.toString(), subNode, debugInfoAbbrevEntry);
					} else {
						compileUnitDebugInfoAbbrevEntrySubnode = new DwarfTreeNode(debugInfoAbbrevEntry.toString() + ", " + type, subNode, debugInfoAbbrevEntry);
					}
				} else if (debugInfoAbbrevEntry.name.equals("DW_AT_location")) {
					String values[] = debugInfoAbbrevEntry.value.toString().split(",");
					String value = "";
					if (values.length > 1) {
						value = Definition.getOPName(CommonLib.string2int(values[0]));
						value += " +" + values[1];
					} else {
						value = Definition.getOPName(CommonLib.string2int(values[0]));
					}
					compileUnitDebugInfoAbbrevEntrySubnode = new DwarfTreeNode(debugInfoAbbrevEntry.toString() + ", " + value, subNode, debugInfoAbbrevEntry);
				} else {
					compileUnitDebugInfoAbbrevEntrySubnode = new DwarfTreeNode(debugInfoAbbrevEntry.toString(), subNode, debugInfoAbbrevEntry);
				}
				subNode.children.add(compileUnitDebugInfoAbbrevEntrySubnode);
			}
			addDebugInfoEntries(dialog, compileUnit, subNode, d);
		}
	}

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
