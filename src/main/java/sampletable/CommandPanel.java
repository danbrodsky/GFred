package sampletable;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.DockingWindowManager;
import docking.ExecutableAction;
import docking.action.ComponentBasedDockingAction;
import docking.action.DockingActionIf;
import docking.widgets.table.*;
import generic.util.WindowUtilities;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;

/**
 * Panel to show the commands available in the given context
 */
public class CommandPanel extends JPanel {

	private final static int ACTION_NAME = 0;
	private final static int PLUGIN_NAME = 1;
	private final static int CONTEXT = 2;

	private static final int FONT_SIZE = 30;

	private GTable actionTable;
	private CommandTableModel tableModel;
	private ActionContext context;

	private List<DockingActionIf> tableActions = new ArrayList<>();
	
	private List<ActionData> actions = new ArrayList<>();
	private Map<String, ExecutableAction> executableActions;

	private PluginTool tool;
	private GTableFilterPanel<DockingActionIf> tableFilterPanel;

	public CommandPanel(PluginTool tool, ActionContext context) {
		this.tool = tool;
		this.context = context;


		populateActions();
		createPanelComponents();
		createActionMap();
		buildActions(null);
	}
	
	// TODO: decompile context actions don't play well with arbitrary execution
	//       As a result, no decompile context actions are functional
	private void populateActions() {

		Set<DockingActionIf> allActions = tool.getToolActions().getAllActions();
		for (DockingActionIf action: allActions) {
			try {
				if (!(context instanceof DecompilerActionContext) && action.isEnabledForContext(context)) {
						actions.add(new ActionData(action, context.getComponentProvider()));
				}
			} catch (Exception e) {
				Msg.debug(action.toString(), ", Failed to load Action | GFred");
			}
		}
		
	// TODO: MultipleKeyAction gets ordering of actions by their context,
	//       improve UI by sorting actions by their context and/or history.
    //       It looks like the way context is pulled in here doesn't work,
    //       will need to fix context so that it matches to the last window selected
    //		 actions = getOrderedActionsForCurrentOrDefaultContext();
	}


	public void dispose() {
		tableFilterPanel.dispose();
		tableModel.dispose();
		actionTable.dispose();
	}
	
	public GTableFilterPanel getTableFilterPanel() {
		return tableFilterPanel;
	}


	private void createActionMap() {

		String longestName = "";

		for (ActionData action : actions) {

			tableActions.add(action.action);
			
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
		// FIX: font size does not increase
		Font f = new Font("SansSerif", Font.PLAIN, FONT_SIZE);
		actionTable.setFont(f);

		JScrollPane sp = new JScrollPane(actionTable);
		actionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		actionTable.setHTMLRenderingEnabled(true);
		
        // FIX: sort table by context
//		TableRowSorter<CommandTableModel> sorter = new TableRowSorter<CommandTableModel>(tableModel);
//		List<RowSorter.SortKey> sortKeys = new ArrayList<>();
//		sortKeys.add(new RowSorter.SortKey(2, SortOrder.DESCENDING));
//		sortKeys.add(new RowSorter.SortKey(0, SortOrder.ASCENDING));
//		sorter.setSortKeys(sortKeys);
//		actionTable.setRowSorter(sorter);

		adjustTableColumns();

		// middle panel - filter field 
		tableFilterPanel = new GTableFilterPanel<>(actionTable, tableModel);
		JPanel middlePanel = new JPanel(new BorderLayout());
		middlePanel.add(tableFilterPanel, BorderLayout.NORTH);

		// contains the upper panel (table) and the middle panel)
		JPanel centerPanel = new JPanel(new BorderLayout());
		centerPanel.add(sp, BorderLayout.CENTER);
		centerPanel.add(middlePanel, BorderLayout.SOUTH);

		add(centerPanel, BorderLayout.CENTER);
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

	/**
	 * Size the columns.
	 */
	private void adjustTableColumns() {
		actionTable.doLayout();
		TableColumn column = actionTable.getColumn(actionTable.getColumnName(ACTION_NAME));
		column.setPreferredWidth(250);
		column = actionTable.getColumn(actionTable.getColumnName(PLUGIN_NAME));
		column.setPreferredWidth(250);
		column = actionTable.getColumn(actionTable.getColumnName(CONTEXT));
		column.setPreferredWidth(100);
	}

	public DockingActionIf getSelectedAction() {
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


//==================================================================================================
// Inner Classes
//==================================================================================================
	/**
	 * Selection listener class for the table model.
	 */

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
			
			
			try {
			ActionContext globalContext = tool.getDefaultToolContext();
			if (action.isEnabledForContext(context) && action.isEnabledForContext(globalContext)) {
				return "global";
			}

			if (action.isEnabledForContext(context) && !action.isEnabledForContext(globalContext)) {
				return "local";
			}
			} catch (Exception e) {
				return "global";
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