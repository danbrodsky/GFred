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

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.Set;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.util.PluginConstants;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.mgr.OptionsManager;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Sample Table Plugin",
	description = "Sample plugin for creating and manipulating a table"
)
//@formatter:on
public class SampleTablePlugin extends ProgramPlugin {

	private SampleTableProvider provider;
	private Function currentFunction;
	private OptionsManager optionsMgr;

	public SampleTablePlugin(PluginTool tool) {
		super(tool, true /*location changes*/, true/*selection changes*/);

		this.tool = tool;
		
		createActions();
	}

	@Override
	protected void locationChanged(ProgramLocation location) {
		if (location == null) {
			currentFunction = null;
			return;
		}

		FunctionManager functionManager = currentProgram.getFunctionManager();
		currentFunction = functionManager.getFunctionContaining(location.getAddress());
	}

	@Override
	protected void selectionChanged(ProgramSelection selection) {
		Msg.info(this, "selectionChanged(): " + selection);
	}
	
	protected void addOptionsAction() {
		DockingAction optionsAction = new DockingAction("Edit Options", ToolConstants.TOOL_OWNER) {

			@Override
			public void actionPerformed(ActionContext context) {
				optionsMgr.editOptions();
			}

			@Override
			public boolean shouldAddToWindow(boolean isMainWindow, Set<Class<?>> contextTypes) {
				return isMainWindow || !contextTypes.isEmpty();
			}
		};
		optionsAction.setHelpLocation(
			new HelpLocation(ToolConstants.FRONT_END_HELP_TOPIC, "Tool Options"));
		MenuData menuData =
			new MenuData(new String[] { ToolConstants.MENU_EDIT, "&AAAAAAAAAAAAAAAAAAAAAAAAA..." }, null,
				ToolConstants.TOOL_OPTIONS_MENU_GROUP);
		menuData.setMenuSubGroup(ToolConstants.TOOL_OPTIONS_MENU_GROUP);
		optionsAction.setMenuBarData(menuData);

		optionsAction.setEnabled(true);
		tool.addAction(optionsAction);
	}

	// FIX: setting keybinds should be delegated to providers that are added to plugins
	//      However, adding a DialogComponentProvider directly to a plugin does not seem possible
	//      so this would need an intermediary provider class that can be added to a plugin
    private void createActions() {
		
    	SampleTablePlugin plugin = this;
        DockingAction showPalette = new DockingAction("cmd-palette show", tool.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
            	Msg.debug(context.toString(), "command palette opened | GFred");

            	// FIX: The dialog window does not stay at a fixed coordinate, but instead moves upwards each reopen
				SampleTableProvider cmdDialog = new SampleTableProvider(plugin, context);
				Swing.runLater(() -> DockingWindowManager.showDialog(cmdDialog));
            }
        };			
        showPalette.setEnabled(true);
        showPalette.setKeyBindingData(new KeyBindingData(KeyEvent.VK_P, InputEvent.ALT_DOWN_MASK));
		// TODO: add help info	
		
		tool.addAction(showPalette);
	}

	public Function getFunction() {
		return currentFunction;
	}

	public boolean resetExisingTableData() {
		return provider.resetExistingTableData();
	}

	@Override
	protected void dispose() {
		provider.dispose();
	}


}
