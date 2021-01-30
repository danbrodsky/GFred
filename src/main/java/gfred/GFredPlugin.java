package gfred;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.Swing;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = "GFred",
	category = PluginCategoryNames.NAVIGATION,
	shortDescription = "Command Palette for Ghidra",
	description = "Select and execute any available Action"
)
//@formatter:on
public class GFredPlugin extends ProgramPlugin {

	public GFredPlugin(PluginTool tool) {
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
		
    	GFredPlugin plugin = this;
        DockingAction showPalette = new DockingAction("command palette show", tool.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
            	// FIX: The dialog window does not stay at a fixed coordinate, but instead moves upwards each reopen
				CommandPaletteProvider cmdDialog = new CommandPaletteProvider(plugin, context);
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
