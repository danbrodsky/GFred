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
import java.awt.event.InputEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;

import javax.swing.*;


import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.ExecutableAction;
import docking.action.*;
import docking.event.mouse.GMouseListenerAdapter;
import ghidra.app.util.PluginConstants;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;

// TODO: rename to GFred and remove dead code
public class SampleTableProvider extends DialogComponentProvider {

	private SampleTablePlugin plugin;
    private DockingAction showPalette;
	private CommandPanel panel;
	private PluginTool tool;

	private boolean resetTableData;
	

	public SampleTableProvider(SampleTablePlugin plugin,  ActionContext context) {

		super("CommandDialog.Foofoo", true, false, true, true);
		this.plugin = plugin;
		tool = plugin.getTool();

    	Msg.info(tool.toString(), "Command palette opened | GFred");


		buildCommandPanel(context);
		addWorkPanel(panel);

		setTitle("Command Palette");
		// FIX: background color not changing when this option is set (darcula conflict?)
		setBackground(Color.black);
		setMinimumSize(1000, 600);

		// TODO: set initial focus on filter field
		setFocusComponent(panel.getTableFilterPanel());
		
		//  TODO: There is an alert containing "Multiple actions have been mapped to..."
		//        it executes the selected command and can be used to learn how to call individual commands from a popup
		
		// TODO: fix error when closing Ghidra

	}

	public void dispose() {
		panel.dispose();
	}

	// TODO: remove excess widgets (custom panel implementation)
	private void buildCommandPanel(ActionContext context) {
		// Msg.info(tool.getOptions(ToolConstants.KEY_BINDINGS).toString(), "keybind info");
		panel = new CommandPanel(tool, context);

		panel.getActionTable().addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent evt) {
				if (evt.getKeyCode() == KeyEvent.VK_ENTER) {
					evt.consume();
					okCallback();

				}
				else if (evt.getKeyCode() == KeyEvent.VK_ESCAPE) {
					evt.consume();
					close();
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

		action.execute();
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

	@Override
	public JComponent getComponent() {
		return rootPanel;
	}
	
	public boolean resetExistingTableData() {
		return resetTableData;
	}

}
