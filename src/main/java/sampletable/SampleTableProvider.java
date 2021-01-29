/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sampletable;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.*;


import ghidra.framework.plugintool.dialog.KeyBindingsPanel;
import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.*;
import docking.actions.KeyBindingUtils;
import docking.tool.ToolConstants;
import ghidra.app.util.PluginConstants;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;

// TODO: rename to GFred and remove dead code
public class SampleTableProvider extends DialogComponentProvider {

	private static final String OPTIONS_TITLE = "Sample Table test ASDDFSDFASDFASDFASFSFASD";
	private static final String RESET_TABLE_DATA_OPTION = "Reset Table Data";
	private static final String FRONT_END_FILE_NAME = "_code_browser.tcd";
	private static final KeyStroke ESC_KEYSTROKE = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0);

	private SampleTablePlugin plugin;
    private DockingAction showPalette;
	private KeyBindingsPanel panel;
	private PluginTool tool;

	private boolean resetTableData;
	

	public SampleTableProvider(SampleTablePlugin plugin) {

		super("CommandDialog.Foofoo", true, false, true, false);
//		super("Command Palette");
		this.plugin = plugin;
		tool = plugin.getTool();

    	Msg.info(tool.toString(), "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBbbbb");


		buildCommandPanel();
		addWorkPanel(panel);

//		createActions();

//		initializeOptions();

		setTitle("Command Palette");
		setBackground(Color.black);
		setMinimumSize(1000, 600);
//		installEscapeAction();

		// TODO: set initial focus on filter field
//		setFocusComponent(panel.getFocusComponent());
		//opt = new OptionsManager(tool);
		//ToolOptions optionsManager = tool.getOptions("TOOL");
		
		//  TODO: There is an alert containing "Multiple actions have been mapped to..."
		//        it executes the selected command and can be used to learn how to call individual commands from a popup
		
		// TODO: fix error when closing Ghidra

	}

//	Component getFocusComponent() {
//	    return gTree.getFilterField();
//    }

//	void dispose() {
//		removeFromTool();
//	}
	
//	private void installEscapeAction() {
//		Action escAction = new AbstractAction("ESCAPE") {
//			@Override
//			public void actionPerformed(ActionEvent ev) {
//				setVisible(false);
//			}
//		};
//
//		KeyBindingUtils.registerAction(rootPanel, ESC_KEYSTROKE, escAction,
//			JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
//	}

	// TODO: dress up panel and make it nicer
	
	
//	private void build() {
//
////		JPanel panel = new JPanel(new BorderLayout());
////		panel.add(buildCommandPanel(), BorderLayout.CENTER);
//		addWorkPanel(buildCommandPanel());
//	}
	

	public void dispose() {
		panel.dispose();
	}

//	@Override
//	protected void escapeCallback() {
//    	Msg.info(tool.toString(), "REEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEee");
//
//		close();
//	}

//	private Component buildControlPanel() {
//		JPanel panel = new JPanel(new BorderLayout());
//		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
//		panel.add(buildKeybindingsPanel(), BorderLayout.CENTER);
//
//		return panel;
//	}
	
	// TODO: remove excess widgets (custom panel implementation)
	private void buildCommandPanel() {
		// Msg.info(tool.getOptions(ToolConstants.KEY_BINDINGS).toString(), "keybind info");
		panel = new KeyBindingsPanel(tool, tool.getOptions(ToolConstants.KEY_BINDINGS));
	}

//	private JPanel buildButtonsPanel() {
//		JPanel buttonPanel = new JPanel(new BorderLayout());
//
//		String defaultOuptutFilePath =
//			System.getProperty("user.home") + File.separator + "SampleTablePluginOutput.txt";
//		String preferencesKey = "sample.table.plugin.output.file";
//		fileChooserPanel = new GhidraFileChooserPanel("Output File", preferencesKey,
//			defaultOuptutFilePath, true, GhidraFileChooserPanel.OUTPUT_MODE);
//
//		JButton runButton = new JButton("Run Algorithms");
//		runButton.addActionListener(e -> model.reload());
//
//		JPanel runButtonPanel = new JPanel(new MiddleLayout());
//		runButtonPanel.add(runButton);
//
//		buttonPanel.add(fileChooserPanel, BorderLayout.NORTH);
//		buttonPanel.add(runButtonPanel, BorderLayout.CENTER);
//		return buttonPanel;
//	}
//
//	private List<FunctionAlgorithm> findAlgorithms() {
//		return new ArrayList<>(ClassSearcher.getInstances(FunctionAlgorithm.class));
//	}
//
//	private Component buildTablePanel() {
//		JPanel panel = new JPanel(new BorderLayout());
//		panel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
//
//		model = new SampleTableModel(plugin);
//		filterTable = new GFilterTable<>(model);
//		panel.add(filterTable);
//
//		return panel;
//	}

	// TODO: add keybind for executing selected option on enter
	// TODO: select filter box by default
	// TODO: remove Plugin name from matches?
	private void createActions() {
		
		SampleTableProvider cmdDialog = this;
        showPalette = new DockingAction("cmd-palette show", plugin.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
            	Msg.info(context.toString(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaa");
//            	build();
            	//tool.showDialog(cmdDialog);
//            	tool.showDialog(cmdDialog, tool.getActiveWindow().getFocusOwner());
                tool.showDialog( cmdDialog, tool.getComponentProvider( 
                        PluginConstants.CODE_BROWSER ));

            }
        };			
        showPalette.setEnabled(true);
        showPalette.setKeyBindingData(new KeyBindingData(KeyEvent.VK_P, InputEvent.ALT_DOWN_MASK));
		// TODO: add help info	
		
		
//		DockingAction optionsAction = new DockingAction("Refresh", plugin.getName()) {
//
//			@Override
//			public void actionPerformed(ActionContext context) {
//				kbp = new KeyBindingsPanel(tool, tool.getOptions(ToolConstants.KEY_BINDINGS));
//				Msg.info(tool.getOptions(ToolConstants.KEY_BINDINGS).toString(), "keybind info");
//			}
//
//			@Override
//			public boolean isEnabledForContext(ActionContext context) {
//				return tool.getService(OptionsService.class) != null;
//			}
//
//		};
//		ImageIcon icon = ResourceManager.loadImage("images/table.png");
//		optionsAction.setToolBarData(new ToolBarData(icon));
//
//		DockingAction saveTableDataAction = new DockingAction("Save Table Data", plugin.getName()) {
//			@Override
//			public void actionPerformed(ActionContext context) {
//
//				StringBuilder buffer = new StringBuilder();
//				buffer.append("Writing the following objects to file: ");
//				buffer.append(HTMLUtilities.escapeHTML(fileChooserPanel.getFileName()));
//
//				List<FunctionStatsRowObject> selectedObjects = filterTable.getSelectedRowObjects();
//				for (FunctionStatsRowObject stats : selectedObjects) {
//					buffer.append("\nData: " + stats.getAlgorithmName());
//				}
//
//				Msg.showInfo(this, filterTable, "Example Dialog",
//					HTMLUtilities.toHTML(buffer.toString()));
//			}
//
//			@Override
//			public boolean isEnabledForContext(ActionContext context) {
//				return filterTable.getSelectedRowObjects().size() > 0;
//			}
//
//			@Override
//			public boolean isAddToPopup(ActionContext context) {
//				Object sourceObject = context.getSourceObject();
//				if (sourceObject instanceof JTable) {
//					return true;
//				}
//
//				return SwingUtilities.isDescendingFrom((Component) sourceObject, filterTable);
//			}
//		};
//		icon = ResourceManager.loadImage("images/disk.png");
//		saveTableDataAction.setToolBarData(new ToolBarData(icon));
//		saveTableDataAction.setPopupMenuData(new MenuData(new String[] { "Save Data" }));

//		addLocalAction(optionsAction);

		plugin.getTool().addAction(showPalette);
		//tool.addAction(showPalette);

//		addLocalAction(saveTableDataAction);
	}

	@Override
	public JComponent getComponent() {
//		loadToolConfigurationFromDisk();
//		opt.editOptions();
//		Msg.info(opt.getOptions(), "opt processed", null);
		return rootPanel;
	}
	
	
//    public JPanel createPanel() {
//
//        JPanel rpanel = new JPanel();
//        rpanel.setLayout(new BorderLayout());
//
////        JPanel p = new JPanel();
//
////        p.add(panel);
//        rpanel.add(panel, BorderLayout.CENTER);
//
//        return rpanel;
//    }

//	public List<FunctionAlgorithm> getAlgorithms() {
//
//		List<FunctionAlgorithm> list = new ArrayList<>();
//		for (int i = 0; i < checkBoxes.length; i++) {
//			JCheckBox checkBox = checkBoxes[i];
//			if (checkBox.isSelected()) {
//				list.add(discoveredAlgorithms.get(i));
//			}
//		}
//
//		return list;
//	}

	public boolean resetExistingTableData() {
		return resetTableData;
	}
	
//	private void loadToolConfigurationFromDisk() {
//		File saveFile = new File(Application.getUserSettingsDirectory(), FRONT_END_FILE_NAME);
//		if (!saveFile.exists()) {
//			Msg.error(saveFile, "FRONTEND FILE NOT FOUND");
//			return;
//		}
//		try {
//			InputStream is = new FileInputStream(saveFile);
//			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
//
//			Element root = sax.build(is).getRootElement();
//			GhidraToolTemplate template = new GhidraToolTemplate(
//				(Element) root.getChildren().get(0), saveFile.getAbsolutePath());
//			refresh(template);
//		}
//		catch (JDOMException e) {
//			Msg.showError(this, null, "Error", "Error in XML reading front end configuration", e);
//		}
//		catch (IOException e) {
//			Msg.showError(this, null, "Error", "Error reading front end configuration", e);
//		}
//	}
//	
//	private void refresh(ToolTemplate tc) {
//		Element root = tc.saveToXml();
//		Element elem = root.getChild("TOOL");
//		Msg.info(elem.toString(), "should contain options");
//		restoreOptionsFromXml(elem);
//		//winMgr.restoreFromXML(tc.getToolElement());
//
//		//setConfigChanged(false);
//	}
	
//	protected void restoreOptionsFromXml(Element root) {
//		opt.setConfigState(root.getChild("OPTIONS"));
//	}

//==================================================================================================
// Options Methods
//==================================================================================================

//	private void initializeOptions() {
//		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
//		HelpLocation help = new HelpLocation("SampleTablePlugin", "Reset_Options");
//
//		opt.registerOption(RESET_TABLE_DATA_OPTION, true, help,
//			"When toggled on the sample table will clear " +
//				"any existing data before showing algorithm results");
//
//		resetTableData = opt.getBoolean(RESET_TABLE_DATA_OPTION, true);
//
//		opt.addOptionsChangeListener(this);
//	}
//
//	// Options changed callback
//	@Override
//	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
//			Object newValue) {
//		if (RESET_TABLE_DATA_OPTION.equals(optionName)) {
//			resetTableData = (Boolean) newValue;
//		}
//	}

}
