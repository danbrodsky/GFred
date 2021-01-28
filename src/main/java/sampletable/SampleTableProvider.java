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
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import org.jdom.Element;
import org.jdom.JDOMException;
import org.jdom.input.SAXBuilder;

import ghidra.framework.plugintool.dialog.KeyBindingsPanel;
import ghidra.framework.plugintool.mgr.OptionsManager;
import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.filechooser.GhidraFileChooserPanel;
import docking.widgets.table.GFilterTable;
import ghidra.framework.Application;
import ghidra.framework.model.ToolTemplate;
import ghidra.framework.options.Options;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.framework.project.tool.GhidraToolTemplate;
import ghidra.util.*;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.layout.MiddleLayout;
import ghidra.util.xml.XmlUtilities;
import resources.ResourceManager;

// TODO: rename to GFred and remove dead code
public class SampleTableProvider extends ComponentProviderAdapter implements OptionsChangeListener {

	private static final String OPTIONS_TITLE = "Sample Table test ASDDFSDFASDFASDFASFSFASD";
	private static final String RESET_TABLE_DATA_OPTION = "Reset Table Data";
	private static final String FRONT_END_FILE_NAME = "_code_browser.tcd";

	private SampleTablePlugin plugin;
	private OptionsManager opt;

	private JComponent component;
	private GFilterTable<FunctionStatsRowObject> filterTable;
	private SampleTableModel model;

	private List<FunctionAlgorithm> discoveredAlgorithms;
	private GCheckBox[] checkBoxes;

	private GhidraFileChooserPanel fileChooserPanel;

	private boolean resetTableData;
	
	private KeyBindingsPanel kbp;

	public SampleTableProvider(SampleTablePlugin plugin, OptionsManager opt) {
		super(plugin.getTool(), "Sample Table Provider", plugin.getName());
		this.plugin = plugin;
		this.opt = opt;

		discoveredAlgorithms = findAlgorithms();
		

		component = build();

		createActions();

		initializeOptions();
		//opt = new OptionsManager(tool);
		//ToolOptions optionsManager = tool.getOptions("TOOL");

	}

	void dispose() {
		filterTable.dispose();
		removeFromTool();
	}

	// TODO: clean up and improve UI (convert to popup maybe?)
	private JComponent build() {
		JPanel panel = new JPanel(new BorderLayout());

		panel.add(buildTablePanel(), BorderLayout.CENTER);
		panel.add(buildControlPanel(), BorderLayout.NORTH);

		return panel;
	}

	private Component buildControlPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		panel.add(buildAlgorithmsPanel(), BorderLayout.WEST);
		panel.add(buildButtonsPanel(), BorderLayout.CENTER); // run button
		panel.add(buildKeybindingsPanel(), BorderLayout.CENTER);

		return panel;
	}
	
	// TODO: remove excess widgets (custom panel implementation)
	private JPanel buildKeybindingsPanel() {
		Msg.info(tool.getOptions(ToolConstants.KEY_BINDINGS).toString(), "keybind info");
		kbp = new KeyBindingsPanel(tool, tool.getOptions(ToolConstants.KEY_BINDINGS));
		return kbp;
	}

	private JPanel buildAlgorithmsPanel() {

		JPanel checkBoxPanel = new JPanel(new GridLayout(0, 1));
		checkBoxPanel.setBorder(BorderFactory.createTitledBorder("Discovered Algorithms"));
		checkBoxes = new GCheckBox[discoveredAlgorithms.size()];
		for (int i = 0; i < discoveredAlgorithms.size(); i++) {
			checkBoxes[i] = new GCheckBox(discoveredAlgorithms.get(i).getName());
			checkBoxPanel.add(checkBoxes[i]);
		}

		return checkBoxPanel;
	}

	private JPanel buildButtonsPanel() {
		JPanel buttonPanel = new JPanel(new BorderLayout());

		String defaultOuptutFilePath =
			System.getProperty("user.home") + File.separator + "SampleTablePluginOutput.txt";
		String preferencesKey = "sample.table.plugin.output.file";
		fileChooserPanel = new GhidraFileChooserPanel("Output File", preferencesKey,
			defaultOuptutFilePath, true, GhidraFileChooserPanel.OUTPUT_MODE);

		JButton runButton = new JButton("Run Algorithms");
		runButton.addActionListener(e -> model.reload());

		JPanel runButtonPanel = new JPanel(new MiddleLayout());
		runButtonPanel.add(runButton);

		buttonPanel.add(fileChooserPanel, BorderLayout.NORTH);
		buttonPanel.add(runButtonPanel, BorderLayout.CENTER);
		return buttonPanel;
	}

	private List<FunctionAlgorithm> findAlgorithms() {
		return new ArrayList<>(ClassSearcher.getInstances(FunctionAlgorithm.class));
	}

	private Component buildTablePanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));

		model = new SampleTableModel(plugin);
		filterTable = new GFilterTable<>(model);
		panel.add(filterTable);

		return panel;
	}

	// TODO: add keybind for executing selected option on enter
	// TODO: add keybind for palette
	// TODO: select filter box by default
	// TODO: remove Plugin name from matches?
	private void createActions() {
		DockingAction optionsAction = new DockingAction("Refresh", plugin.getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				kbp = new KeyBindingsPanel(tool, tool.getOptions(ToolConstants.KEY_BINDINGS));
				Msg.info(tool.getOptions(ToolConstants.KEY_BINDINGS).toString(), "keybind info");
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return tool.getService(OptionsService.class) != null;
			}

		};
		ImageIcon icon = ResourceManager.loadImage("images/table.png");
		optionsAction.setToolBarData(new ToolBarData(icon));

		DockingAction saveTableDataAction = new DockingAction("Save Table Data", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {

				StringBuilder buffer = new StringBuilder();
				buffer.append("Writing the following objects to file: ");
				buffer.append(HTMLUtilities.escapeHTML(fileChooserPanel.getFileName()));

				List<FunctionStatsRowObject> selectedObjects = filterTable.getSelectedRowObjects();
				for (FunctionStatsRowObject stats : selectedObjects) {
					buffer.append("\nData: " + stats.getAlgorithmName());
				}

				Msg.showInfo(this, filterTable, "Example Dialog",
					HTMLUtilities.toHTML(buffer.toString()));
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return filterTable.getSelectedRowObjects().size() > 0;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				Object sourceObject = context.getSourceObject();
				if (sourceObject instanceof JTable) {
					return true;
				}

				return SwingUtilities.isDescendingFrom((Component) sourceObject, filterTable);
			}
		};
		icon = ResourceManager.loadImage("images/disk.png");
		saveTableDataAction.setToolBarData(new ToolBarData(icon));
		saveTableDataAction.setPopupMenuData(new MenuData(new String[] { "Save Data" }));

		addLocalAction(optionsAction);
		addLocalAction(saveTableDataAction);
	}

	@Override
	public JComponent getComponent() {
//		loadToolConfigurationFromDisk();
//		opt.editOptions();
//		Msg.info(opt.getOptions(), "opt processed", null);
		return build();
	}

	public List<FunctionAlgorithm> getAlgorithms() {

		List<FunctionAlgorithm> list = new ArrayList<>();
		for (int i = 0; i < checkBoxes.length; i++) {
			JCheckBox checkBox = checkBoxes[i];
			if (checkBox.isSelected()) {
				list.add(discoveredAlgorithms.get(i));
			}
		}

		return list;
	}

	public boolean resetExistingTableData() {
		return resetTableData;
	}
	
	private void loadToolConfigurationFromDisk() {
		File saveFile = new File(Application.getUserSettingsDirectory(), FRONT_END_FILE_NAME);
		if (!saveFile.exists()) {
			Msg.error(saveFile, "FRONTEND FILE NOT FOUND");
			return;
		}
		try {
			InputStream is = new FileInputStream(saveFile);
			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);

			Element root = sax.build(is).getRootElement();
			GhidraToolTemplate template = new GhidraToolTemplate(
				(Element) root.getChildren().get(0), saveFile.getAbsolutePath());
			refresh(template);
		}
		catch (JDOMException e) {
			Msg.showError(this, null, "Error", "Error in XML reading front end configuration", e);
		}
		catch (IOException e) {
			Msg.showError(this, null, "Error", "Error reading front end configuration", e);
		}
	}
	
	private void refresh(ToolTemplate tc) {
		Element root = tc.saveToXml();
		Element elem = root.getChild("TOOL");
		Msg.info(elem.toString(), "should contain options");
		restoreOptionsFromXml(elem);
		//winMgr.restoreFromXML(tc.getToolElement());

		//setConfigChanged(false);
	}
	
	protected void restoreOptionsFromXml(Element root) {
		opt.setConfigState(root.getChild("OPTIONS"));
	}

//==================================================================================================
// Options Methods
//==================================================================================================

	private void initializeOptions() {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		HelpLocation help = new HelpLocation("SampleTablePlugin", "Reset_Options");

		opt.registerOption(RESET_TABLE_DATA_OPTION, true, help,
			"When toggled on the sample table will clear " +
				"any existing data before showing algorithm results");

		resetTableData = opt.getBoolean(RESET_TABLE_DATA_OPTION, true);

		opt.addOptionsChangeListener(this);
	}

	// Options changed callback
	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (RESET_TABLE_DATA_OPTION.equals(optionName)) {
			resetTableData = (Boolean) newValue;
		}
	}

}
