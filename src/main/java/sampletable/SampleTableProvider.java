package sampletable;

import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;

import javax.swing.*;


import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.ExecutableAction;
import docking.event.mouse.GMouseListenerAdapter;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;

// TODO: rename to GFred and remove dead code
public class SampleTableProvider extends DialogComponentProvider {

	private CommandPanel panel;
	private PluginTool tool;
	private SampleTablePlugin plugin;
	

	public SampleTableProvider(SampleTablePlugin plugin,  ActionContext context) {

		super("CommandDialog.Foofoo", true, false, true, true);
		tool = plugin.getTool();
		this.plugin = plugin;

    	Msg.debug(tool.toString(), "Command palette opened | GFred");

		buildCommandPanel(context);
		addWorkPanel(panel);

		setTitle("Command Palette");
		// FIX: background color not changing when this option is set (darcula conflict?)
		setBackground(Color.gray);
		setMinimumSize(1000, 600);

		// TODO: set initial focus on filter field
		setFocusComponent(panel.getTableFilterPanel());
		
		// TODO: fix error when closing Ghidra

	}

	public void dispose() {
		panel.dispose();
	}

	// TODO: remove excess widgets (custom panel implementation)
	private void buildCommandPanel(ActionContext context) {
		panel = new CommandPanel(tool, context);

		panel.getActionTable().addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent evt) {
				if (evt.getKeyCode() == KeyEvent.VK_ESCAPE) {
					evt.consume();
					close();
				}
				else if (evt.getKeyCode() == KeyEvent.VK_ENTER) {
					evt.consume();
					okCallback();
				}

			}
		});

		panel.getActionTable().addMouseListener(new GMouseListenerAdapter() {
			@Override
			public void doubleClickTriggered(MouseEvent e) {
				maybeDoAction();
			}
		});
	}
	
	@Override
	public void okCallback() {
		maybeDoAction();
	}

	private void maybeDoAction() {
		String name = panel.getSelectedActionName();
		if (name == null) {
			return;
		}

		ExecutableAction action = panel.getAction();
		if (action == null)
			return;

		close();
		
		try {
			action.execute();
		} catch (Exception e) {
			tool.getService(ConsoleService.class)
			.printlnError("{GFred} Action Execution Failed: " + e.getMessage());
		}
	}

	// TODO: add keybind for executing selected option on enter
	// TODO: select filter box by default
	// TODO: remove Plugin name from matches?
//	private void createActions() {
//		
//		SampleTableProvider cmdDialog = this;
//        showPalette = new DockingAction("command palette show", plugin.getName()) {
//            @Override
//            public void actionPerformed(ActionContext context) {
//            	Msg.debug(context.toString(), "command palette opened | GFred");
//                tool.showDialog( cmdDialog, tool.getComponentProvider( 
//                        PluginConstants.CODE_BROWSER ));
//
//            }
//        };			
//        showPalette.setEnabled(true);
//        showPalette.setKeyBindingData(new KeyBindingData(KeyEvent.VK_P, InputEvent.ALT_DOWN_MASK));
//		// TODO: add help info	
//		
//		plugin.getTool().addAction(showPalette);
//	}

//	@Override
//	public JComponent getComponent() {
//		return panel;
//	}

}
