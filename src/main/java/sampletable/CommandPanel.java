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
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import org.apache.commons.lang3.exception.ExceptionUtils;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.DockingDialog;
import docking.DockingUtils;
import docking.DockingWindowManager;
import docking.ExecutableAction;
import docking.KeyEntryTextField;
import docking.MultiActionDialog;
import docking.action.ComponentBasedDockingAction;
import docking.action.DockingActionIf;
import docking.action.KeyBindingData;
import docking.actions.KeyBindingUtils;
import docking.help.Help;
import docking.help.HelpService;
import docking.tool.util.DockingToolConstants;
import docking.widgets.*;
import docking.widgets.label.GIconLabel;
import docking.widgets.table.*;
import generic.util.WindowUtilities;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;
import resources.Icons;
import resources.ResourceManager;

/**
 * Panel to show the key bindings for the plugin actions.
 */
public class CommandPanel extends JPanel {

	private static final int STATUS_LABEL_HEIGHT = 60;

	private final static int ACTION_NAME = 0;
	private final static int PLUGIN_NAME = 1;
	private final static int CONTEXT = 2;

	private static final int FONT_SIZE = 30;

	private JTextPane statusLabel;
	private GTable actionTable;
//	private JPanel infoPanel;
//	private MultiLineLabel collisionLabel;
	private CommandTableModel tableModel;
	private ListSelectionModel selectionModel;
	private Options options;
	private ActionContext context;

	private Map<String, List<DockingActionIf>> actionsByFullName;
	private Map<String, List<String>> actionNamesByKeyStroke = new HashMap<>();
	private Map<String, KeyStroke> keyStrokesByFullName = new HashMap<>();
	private Map<String, KeyStroke> originalValues = new HashMap<>(); // to know what has been changed
	private List<DockingActionIf> tableActions = new ArrayList<>();
	
	private List<ActionData> actions = new ArrayList<>();
	private Map<String, ExecutableAction> executableActions;

//	private KeyEntryTextField ksField;
//	private boolean unappliedChanges;

	private PluginTool tool;
	private boolean firingTableDataChanged;
	private PropertyChangeListener propertyChangeListener;
	private GTableFilterPanel<DockingActionIf> tableFilterPanel;
//	private EmptyBorderButton helpButton;

	public CommandPanel(PluginTool tool, Options options, ActionContext context) {
		this.tool = tool;
		this.options = options;
		this.context = context;


		populateActions();
		createPanelComponents();
		createActionMap();
		buildActions(null);
		addListeners();
	}
	
	// TODO: decompile context actions don't play well with arbitrary execution
	//       As a result, no decompile context actions are functional
	private void populateActions() {

		// get local actions first
		Set<DockingActionIf> allActions = tool.getToolActions().getAllActions();
		for (DockingActionIf action: allActions) {
			try {
				if (action.isEnabledForContext(context)) {
					actions.add(new ActionData(action, context.getComponentProvider()));
				}
			} catch (Exception e) {
				Msg.debug(action.toString(), "| Failed to load Action {GFred}");
			}
		}
		
		actions = getOrderedActionsForCurrentOrDefaultContext();
	}

	public void setOptionsPropertyChangeListener(PropertyChangeListener listener) {
		this.propertyChangeListener = listener;
	}

	public void dispose() {
		tableFilterPanel.dispose();
		tableModel.dispose();
		actionTable.dispose();
		propertyChangeListener = null;
	}
	
	public GTableFilterPanel getTableFilterPanel() {
		return tableFilterPanel;
	}


	public void reload() {
		Swing.runLater(() -> {
			// clear the current user key stroke so that it does not appear as though the 
			// user is editing while restoring
			actionTable.clearSelection();

		});
	}

	private void createActionMap() {

		String longestName = "";

//		actionsByFullName = KeyBindingUtils.getAllActionsByFullName(tool);
//		Set<DockingActionIf> allActions = tool.getToolActions().getAllActions();
//		Set<Entry<String, List<DockingActionIf>>> entries = actionsByFullName.entrySet();
		for (ActionData action : actions) {

			// pick one action, they are all conceptually the same
			tableActions.add(action.action);
			
//			tableActions.sort(ActionComparator);

//			String actionName = entry.getKey();
//			KeyStroke ks = options.getKeyStroke(actionName, null);
//			keyStrokesByFullName.put(actionName, ks);
//			addToKeyMap(ks, actionName);
//			originalValues.put(actionName, ks);

			String shortName = action.getName();
			if (shortName.length() > longestName.length()) {
				longestName = shortName;
			}
		}

		Font f = actionTable.getFont();
		FontMetrics fm = actionTable.getFontMetrics(f);
		int maxWidth = 0;
		for (int i = 0; i < longestName.length(); i++) {
			char c = longestName.charAt(i);
			maxWidth += fm.charWidth(c);
		}
		TableColumn col = actionTable.getColumnModel().getColumn(ACTION_NAME);
		col.setPreferredWidth(maxWidth);
		tableModel.fireTableDataChanged();
	}
	
	public GTable getActionTable() {
		return actionTable;
	}

	private void createPanelComponents() {
		setLayout(new BorderLayout(10, 10));

		tableModel = new CommandTableModel();
		actionTable = new GTable(tableModel);
		Font f = new Font("SansSerif", Font.PLAIN, FONT_SIZE);
		actionTable.setFont(f);

		JScrollPane sp = new JScrollPane(actionTable);
		actionTable.setPreferredScrollableViewportSize(new Dimension(400, 100));
		actionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		actionTable.setHTMLRenderingEnabled(true);
		
//		TableRowSorter<CommandTableModel> sorter = new TableRowSorter<CommandTableModel>(tableModel);
//		List<RowSorter.SortKey> sortKeys = new ArrayList<>(25);
//		sortKeys.add(new RowSorter.SortKey(2, SortOrder.DESCENDING));
//		sortKeys.add(new RowSorter.SortKey(0, SortOrder.ASCENDING));
//		sorter.setSortKeys(sortKeys);

//		actionTable.setRowSorter(sorter);


		adjustTableColumns();

		// middle panel - filter field and import/export buttons
//		JPanel importExportPanel = createImportExportPanel();
		tableFilterPanel = new GTableFilterPanel<>(actionTable, tableModel);
		JPanel middlePanel = new JPanel(new BorderLayout());
		middlePanel.add(tableFilterPanel, BorderLayout.NORTH);
//		middlePanel.add(importExportPanel, BorderLayout.SOUTH);

		// contains the upper panel (table) and the middle panel)
		JPanel centerPanel = new JPanel(new BorderLayout());
		centerPanel.add(sp, BorderLayout.CENTER);
		centerPanel.add(middlePanel, BorderLayout.SOUTH);

		// lower panel - key entry panel and status panel
//		JPanel keyPanel = createKeyEntryPanel();
//		JComponent statusPanel = createStatusPanel(keyPanel);

		add(centerPanel, BorderLayout.CENTER);
//		add(statusPanel, BorderLayout.SOUTH);
	}



	private void buildActions(final ActionEvent event) {
		// Build list of actions which are valid in current context
		executableActions = getActionsForCurrentOrDefaultContext(event);
	}
	
	
	private Map<String, ExecutableAction> getActionsForCurrentOrDefaultContext(Object eventSource) {

		DockingWindowManager dwm = tool.getWindowManager();
		Window window = getWindow(dwm, null);
		ComponentProvider localProvider = getProvider(dwm, null);
		ActionContext localContext = getLocalContext(localProvider);
		localContext.setSourceObject(null);
		ActionContext globalContext = tool.getDefaultToolContext();
		Map<String, ExecutableAction> validActions = getValidContextActions(localContext, globalContext);
		return validActions;
	}

	private List<ActionData> getOrderedActionsForCurrentOrDefaultContext() {

		ComponentProvider localProvider = tool.getActiveComponentProvider();
		ActionContext localContext = getLocalContext(localProvider);
		localContext.setSourceObject(null);
		ActionContext globalContext = tool.getDefaultToolContext();
		List<ActionData> validActions = getOrderedValidContextActions(localContext, globalContext);
		return validActions;
	}
	

	private Window getWindow(DockingWindowManager dwm, Object eventSource) {
		if (eventSource instanceof Component) {
			return WindowUtilities.windowForComponent((Component) eventSource);
		}
		return dwm.getActiveWindow();
	}
	
	private ComponentProvider getProvider(DockingWindowManager dwm, Object eventSource) {
		if (eventSource instanceof Component) {
			return dwm.getProvider((Component) eventSource);
		}
		return dwm.getActiveComponentProvider();
	}

	private ActionContext getLocalContext(ComponentProvider localProvider) {
		if (localProvider == null) {
			return new ActionContext();
		}

		ActionContext actionContext = localProvider.getActionContext(null);
		if (actionContext != null) {
			return actionContext;
		}

		return new ActionContext(localProvider, null);
	}

	
	public ExecutableAction getAction() {
		String name = getSelectedActionName();
		Msg.info(name, "selected action name");
		if (name == null) {
			return null;
		}

		return executableActions.get(name);

	}
	

	private List<ActionData> getOrderedValidContextActions(ActionContext localContext,
			ActionContext globalContext) {
		List<ActionData> list = new ArrayList<>();

		// 
		// 1) Prefer local actions for the active provider
		// 
		for (ActionData actionData : actions) {
			if (actionData.isMyProvider(localContext)) {
				if (isValidAndEnabled(actionData, localContext)) {
					list.add(actionData);
				}
			}
		}
		

		//
		// 2) Check for actions local to the source component 
		// 
		for (ActionData actionData : actions) {
			if (!(actionData.action instanceof ComponentBasedDockingAction)) {
				continue;
			}

			ComponentBasedDockingAction componentAction =
				(ComponentBasedDockingAction) actionData.action;
			if (componentAction.isValidComponentContext(localContext)) {
				if (isValidAndEnabled(actionData, localContext)) {
					list.add(actionData);
				}
			}
		}

		// 
		// 3) Check for global actions
		// 
		for (ActionData actionData : actions) {
			if (actionData.isGlobalAction()) {
				// When looking for context matches, we prefer local context, even though this
				// is a 'global' action.  This allows more specific context to be used when
				// available
				if (isValidAndEnabled(actionData, localContext)) {
					list.add(actionData);
				}
				else if (isValidAndEnabledGlobally(actionData, globalContext)) {
					list.add(actionData);
				}
			}
		}
		return list;
	}

	private Map<String, ExecutableAction> getValidContextActions(ActionContext localContext,
			ActionContext globalContext) {
		Map<String, ExecutableAction> list = new HashMap<>();

		// 
		// 1) Prefer local actions for the active provider
		// 
		for (ActionData actionData : actions) {
			if (actionData.isMyProvider(localContext)) {
				if (isValidAndEnabled(actionData, localContext)) {
					list.put(actionData.getName(), new ExecutableAction(actionData.action, localContext));
				}
			}
		}
		
		//
		// 2) Check for actions local to the source component 
		// 
		for (ActionData actionData : actions) {
			if (!(actionData.action instanceof ComponentBasedDockingAction)) {
				continue;
			}

			ComponentBasedDockingAction componentAction =
				(ComponentBasedDockingAction) actionData.action;
			if (componentAction.isValidComponentContext(localContext)) {
				if (isValidAndEnabled(actionData, localContext)) {
					list.put(actionData.getName(), new ExecutableAction(actionData.action, localContext));
				}
			}
		}

		// 
		// 3) Check for global actions
		// 
		for (ActionData actionData : actions) {
			if (actionData.isGlobalAction()) {
				// When looking for context matches, we prefer local context, even though this
				// is a 'global' action.  This allows more specific context to be used when
				// available
				if (isValidAndEnabled(actionData, localContext)) {
					list.put(actionData.getName(), new ExecutableAction(actionData.action, localContext));
				}
				else if (isValidAndEnabledGlobally(actionData, globalContext)) {
					list.put(actionData.getName(), new ExecutableAction(actionData.action, globalContext));
				}
			}
		}
		return list;
	}


	private boolean isValidAndEnabled(ActionData actionData, ActionContext context) {
		DockingActionIf a = actionData.action;
		return a.isValidContext(context) && a.isEnabledForContext(context);
	}

	private boolean isValidAndEnabledGlobally(ActionData actionData, ActionContext context) {
		// the context may be null when we don't want global action such as when getting actions
		// for a dialog
		if (context == null) {
			return false;
		}
		return actionData.supportsDefaultToolContext() && isValidAndEnabled(actionData, context);
	}


	private class ActionData {
		DockingActionIf action;
		ComponentProvider provider;

		ActionData(DockingActionIf action, ComponentProvider provider) {
			this.action = action;
			this.provider = provider;
		}

		boolean isGlobalAction() {
			return provider == null;
		}

		boolean isMyProvider(ActionContext localContext) {
			ComponentProvider otherProvider = localContext.getComponentProvider();
			return provider == otherProvider;
		}

		boolean supportsDefaultToolContext() {
			return action.supportsDefaultToolContext();
		}

		@Override
		public String toString() {
			String providerString = provider == null ? "" : provider.toString() + " - ";
			return providerString + action;
		}
		
		String getName() {
			return action.getFullName();
		}

	}

//	private JPanel createImportExportPanel() {
//		JButton importButton = new JButton("Import...");
//		importButton.setToolTipText("Load key binding settings from a file");
//		importButton.addActionListener(event -> {
//			// prompt user to apply changes before importing
//			boolean continueImport = showImportPrompt();
//
//			if (!continueImport) {
//				return;
//			}
//
//			// give Swing a chance to repaint
//			Swing.runLater(() -> {
//				// clear the current user key stroke so that it does not appear as though the 
//				// user is editing while importing
//				actionTable.clearSelection();
//				processKeyBindingsFromOptions(KeyBindingUtils.importKeyBindings());
//			});
//		});
//
//		JButton exportButton = new JButton("Export...");
//		exportButton.setToolTipText("Save key binding settings to a file");
//		exportButton.addActionListener(event -> {
//
//			// prompt user to apply changes before exporting
//			boolean continueExport = showExportPrompt();
//
//			if (!continueExport) {
//				return;
//			}
//
//			// give Swing a chance to repaint
//			Swing.runLater(() -> {
//				ToolOptions keyBindingOptions = tool.getOptions(DockingToolConstants.KEY_BINDINGS);
//				KeyBindingUtils.exportKeyBindings(keyBindingOptions);
//			});
//		});
//
//		JPanel containerPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
//		containerPanel.add(importButton);
//		containerPanel.add(exportButton);
//
//		return containerPanel;
//	}

//	private boolean showExportPrompt() {
//		boolean continueOperation = true;
//		if (unappliedChanges) {
//			int userChoice = OptionDialog.showYesNoCancelDialog(KeyBindingsPanel.this,
//				"Apply Changes?", "Apply current key binding changes?");
//
//			// Option One--'Yes'
//			if (userChoice == OptionDialog.OPTION_ONE) {
//				apply();
//			}
//			else if (userChoice == OptionDialog.CANCEL_OPTION) {
//				continueOperation = false;
//			}
//		}
//
//		return continueOperation;
//	}

//	private boolean showImportPrompt() {
//		int userChoice = OptionDialog.showYesNoDialog(KeyBindingsPanel.this, "Continue Import?",
//			"Importing key bindings will overwrite the current settings.\n" +
//				"Do you want to continue?");
//
//		// option one is the yes dialog
//		return (userChoice == OptionDialog.OPTION_ONE);
//	}

	// puts all of the key binding options from the given options object into
	// a mapping of the option name to the key stroke for that name
	private Map<String, KeyStroke> createActionNameToKeyStrokeMap(Options keyBindingOptions) {

		Map<String, KeyStroke> localActionMap = new HashMap<>();

		List<String> optionNames = keyBindingOptions.getOptionNames();

		for (String element : optionNames) {
			KeyStroke newKeyStroke = keyBindingOptions.getKeyStroke(element, null);
			localActionMap.put(element, newKeyStroke);
		}

		return localActionMap;
	}

	/**
	 * Size the columns.
	 */
	private void adjustTableColumns() {
		actionTable.doLayout();
		TableColumn column = actionTable.getColumn(actionTable.getColumnName(ACTION_NAME));
		column.setPreferredWidth(250);
		column = actionTable.getColumn(actionTable.getColumnName(PLUGIN_NAME));
		column.setPreferredWidth(150);
	}

	private void addListeners() {
		selectionModel = actionTable.getSelectionModel();
		selectionModel.addListSelectionListener(new TableSelectionListener());
	}

	private boolean checkAction(String actionName, KeyStroke keyStroke) {
		String ksName = KeyEntryTextField.parseKeyStroke(keyStroke);

		// remove old keystroke for action name
		KeyStroke oldKs = keyStrokesByFullName.get(actionName);
		if (oldKs != null) {
			String oldName = KeyEntryTextField.parseKeyStroke(oldKs);
			if (oldName.equals(ksName)) {
				return false;
			}
			removeFromKeyMap(oldKs, actionName);
		}
		addToKeyMap(keyStroke, actionName);

		keyStrokesByFullName.put(actionName, keyStroke);
//		changesMade(true);
		return true;
	}

	// signals that there are unapplied changes
//	private void changesMade(boolean changes) {
//		propertyChangeListener.propertyChange(
//			new PropertyChangeEvent(this, "apply.enabled", unappliedChanges, changes));
//		unappliedChanges = changes;
//	}

	public DockingActionIf getSelectedAction() {
		if (selectionModel.isSelectionEmpty()) {
			return null;
		}
		int selectedRow = actionTable.getSelectedRow();
		int modelRow = tableFilterPanel.getModelRow(selectedRow);
		return tableActions.get(modelRow);
	}

	public String getSelectedActionName() {
		DockingActionIf action = getSelectedAction();
		if (action == null) {
			return null;
		}
		return action.getFullName();
	}

	private void addToKeyMap(KeyStroke ks, String actionName) {
		if (ks == null) {
			return;
		}
		String ksName = KeyEntryTextField.parseKeyStroke(ks);
		List<String> list = actionNamesByKeyStroke.get(ksName);
		if (list == null) {
			list = new ArrayList<>();
			actionNamesByKeyStroke.put(ksName, list);
		}
		if (!list.contains(actionName)) {
			list.add(actionName);
		}
	}

	private void removeFromKeyMap(KeyStroke ks, String actionName) {
		if (ks == null) {
			return;
		}
		String ksName = KeyEntryTextField.parseKeyStroke(ks);
		List<String> list = actionNamesByKeyStroke.get(ksName);
		if (list != null) {
			list.remove(actionName);
			if (list.isEmpty()) {
				actionNamesByKeyStroke.remove(ksName);
			}
		}
	}

	private void showActionsMappedToKeyStroke(String ksName) {
		List<String> list = actionNamesByKeyStroke.get(ksName);
		if (list == null) {
			return;
		}
		if (list.size() > 0) {
			StringBuffer sb = new StringBuffer();
			sb.append("Actions mapped to key " + ksName + ":\n");
			for (int i = 0; i < list.size(); i++) {
				sb.append("  ");
				sb.append(list.get(i));
				if (i < list.size() - 1) {
					sb.append("\n");
				}
			}
			updateInfoPanel(sb.toString());
		}
		else {
			clearInfoPanel();
		}
	}

	private void clearInfoPanel() {
		updateInfoPanel(" ");
	}

	private void updateInfoPanel(String text) {
//		infoPanel.removeAll();
//		infoPanel.repaint();
//		collisionLabel = new MultiLineLabel(text);
//		collisionLabel.setName("CollisionLabel");
//		infoPanel.add(collisionLabel);
//		infoPanel.invalidate();
		validate();
	}

	private void processKeyBindingsFromOptions(Options keyBindingOptions) {
		if (keyBindingOptions == null) {
			return;
		}

		Map<String, KeyStroke> keyBindingsMap = createActionNameToKeyStrokeMap(keyBindingOptions);
		if (keyBindingsMap == null) {
			return;
		}

		boolean changes = false;

		// add each new key stroke mapping
		Iterator<String> iterator = keyBindingsMap.keySet().iterator();
		while (iterator.hasNext()) {

			String name = iterator.next();
			KeyStroke keyStroke = keyBindingsMap.get(name);
			keyStroke = KeyBindingUtils.validateKeyStroke(keyStroke);

			// prevent non-existing keybindings from being added to Ghidra (this can happen
			// when actions exist in the imported bindings, but have been removed from
			// Ghidra
			if (!keyStrokesByFullName.containsKey(name)) {
				continue;
			}

			// check to see if the key stroke results in a change and
			// record that value
			changes |= processKeyStroke(name, keyStroke);
		}

//		if (changes) {
//			changesMade(true);
//		}
	}

	/**
	 * Processes KeyStroke entry from the text field.
	 */
	private void processKeyStrokeEntry(KeyStroke ks) {
		clearInfoPanel();

		// An action must be selected
		if (selectionModel.isSelectionEmpty()) {
			statusLabel.setText("No action is selected.");
			return;
		}

		if (ks != null && ReservedKeyBindings.isReservedKeystroke(ks)) {
			statusLabel.setText(KeyEntryTextField.parseKeyStroke(ks) + " is a reserved keystroke");
//			ksField.clearField();
			return;
		}

		String selectedActionName = getSelectedActionName();
		if (selectedActionName != null) {
			if (processKeyStroke(selectedActionName, ks)) {
				String keyStrokeText = KeyEntryTextField.parseKeyStroke(ks);
				showActionsMappedToKeyStroke(keyStrokeText);
				tableModel.fireTableDataChanged();
			}
		}
	}

	// returns true if the key stroke is a new value
	private boolean processKeyStroke(String actionName, KeyStroke keyStroke) {
		// Clear entry if enter or backspace
		if (keyStroke == null) {
			removeKeystroke(actionName);
		}
		else {
			char keyChar = keyStroke.getKeyChar();
			if (Character.isWhitespace(keyChar) ||
				Character.getType(keyChar) == Character.DIRECTIONALITY_LEFT_TO_RIGHT_OVERRIDE) {
				removeKeystroke(actionName);
			}
			else {
				// check the action to see if is different than the current value
				return checkAction(actionName, keyStroke);
			}
		}

		return false;
	}

	private void removeKeystroke(String selectedActionName) {
//		ksField.setText("");

		if (keyStrokesByFullName.containsKey(selectedActionName)) {
			KeyStroke stroke = keyStrokesByFullName.get(selectedActionName);
			if (stroke == null) {
				// nothing to remove; nothing has changed
				return;
			}

			removeFromKeyMap(stroke, selectedActionName);
			keyStrokesByFullName.put(selectedActionName, null);
			tableModel.fireTableDataChanged();
//			changesMade(true);
		}
	}

	Map<String, KeyStroke> getKeyStrokeMap() {
		return keyStrokesByFullName;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	/**
	 * Selection listener class for the table model.
	 */
	private class TableSelectionListener implements ListSelectionListener {
		@Override
		public void valueChanged(ListSelectionEvent e) {
			if (e.getValueIsAdjusting() || firingTableDataChanged) {
				return;
			}

//			helpButton.setEnabled(false);
			String fullActionName = getSelectedActionName();
			if (fullActionName == null) {
//				statusLabel.setText("");
				return;
			}

//			helpButton.setEnabled(true);
			KeyStroke ks = keyStrokesByFullName.get(fullActionName);
			String ksName = "";
			clearInfoPanel();

			if (ks != null) {
				ksName = KeyEntryTextField.parseKeyStroke(ks);
				showActionsMappedToKeyStroke(ksName);
			}

//			ksField.setText(ksName);

			// make sure the label gets enough space
//			statusLabel.setPreferredSize(
//				new Dimension(statusLabel.getPreferredSize().width, STATUS_LABEL_HEIGHT));

			// pick one action, they are all conceptually the same
//			List<DockingActionIf> actions = actionsByFullName.get(fullActionName);
//			DockingActionIf action = actions.get(0);
//			String description = action.getDescription();
//			if (description == null || description.trim().isEmpty()) {
//				description = action.getName();
//			}

//			statusLabel.setText("<html>" + HTMLUtilities.escapeHTML(description));
		}
	}

	private class CommandTableModel extends AbstractSortedTableModel<DockingActionIf> {
		private final String[] columnNames =
			{ "Action Name", "Plugin Name", "Context" };

		CommandTableModel() {
			super(0);
		}

		@Override
		public String getName() {
			return "Command Palette";
		}
		

		@Override
		public Object getColumnValueForRow(DockingActionIf action, int columnIndex) {

			switch (columnIndex) {
				case ACTION_NAME:
					return action.getName();
				case PLUGIN_NAME:
					return action.getOwnerDescription();
				case CONTEXT:
					return getContext(action);
			}
			return "Unknown Column!";
		}
		
		private String getContext(DockingActionIf action) {
			
			ActionContext globalContext = tool.getDefaultToolContext();
			if (action.isEnabledForContext(context) && !action.isEnabledForContext(globalContext)) {
				return "global";
			}

			if (action.isEnabledForContext(context) && action.isEnabledForContext(globalContext)) {
				return "local";
			}
			return "unknown";
		}

		@Override
		public List<DockingActionIf> getModelData() {
			return tableActions;
		}

		@Override
		public boolean isSortable(int columnIndex) {
			return true;
		}

		@Override
		public String getColumnName(int column) {
			return columnNames[column];
		}

		@Override
		public int getColumnCount() {
			return columnNames.length;
		}

		@Override
		public int getRowCount() {
			return tableActions.size();
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			return String.class;
		}
	}
}

//static class ActionComparator implements Comparator<DockingActionIf>
//{
//    public int compare(DockingActionIf a1, DockingActionIf a2)
//    {
//        return c1.getColor().compareTo(c2.getColor());
//    }
//}