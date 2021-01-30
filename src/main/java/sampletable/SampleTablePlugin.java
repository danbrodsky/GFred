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
import ghidra.app.services.ConsoleService;
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

	public SampleTablePlugin(PluginTool tool) {
		super(tool, true /*location changes*/, true/*selection changes*/);

		this.tool = tool;
		
		createActions();
	}

	@Override
	protected void selectionChanged(ProgramSelection selection) {
		Msg.info(this, "selectionChanged(): " + selection);
	}
	
	// FIX: setting keybinds should be delegated to providers that are added to plugins
	//      However, adding a DialogComponentProvider directly to a plugin does not seem possible
	//      so this would need an intermediary provider class that can be added to a plugin
    private void createActions() {
		
    	SampleTablePlugin plugin = this;
        DockingAction showPalette = new DockingAction("cmd-palette show", tool.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
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

	@Override
	protected void dispose() {
	}


}
