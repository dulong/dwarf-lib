import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.JScrollPane;
import javax.swing.JTree;

import com.peterdwarf.gui.DwarfTreeNode;
import com.peterswing.FilterTreeModel;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class TestTree extends JFrame {
	DwarfTreeNode root = new DwarfTreeNode("Elf files", null, null);
	DefaultTreeModel treeModel = new DefaultTreeModel(root);
	FilterTreeModel filterTreeModel = new FilterTreeModel(treeModel, 10, true);
	private JPanel contentPane;

	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					TestTree frame = new TestTree();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	public TestTree() {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 785, 653);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(new BorderLayout(0, 0));
		setContentPane(contentPane);

		JScrollPane scrollPane = new JScrollPane();
		contentPane.add(scrollPane, BorderLayout.CENTER);

		JTree tree = new JTree(filterTreeModel);
		scrollPane.setViewportView(tree);

		JPanel panel = new JPanel();
		contentPane.add(panel, BorderLayout.NORTH);

		JButton btnNewButton = new JButton("New button");
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				DwarfTreeNode node1 = new DwarfTreeNode("node1", null, null);
				root.children.add(node1);
				filterTreeModel.nodeChanged(root);
			}
		});
		panel.add(btnNewButton);
	}

}
