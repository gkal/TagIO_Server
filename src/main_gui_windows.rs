use native_windows_gui as nwg;
use native_windows_derive::*;
use std::sync::{Arc, Mutex};
use anyhow::Result;
use std::thread;
use std::cell::RefCell;

// Import modules properly from the tagio library
use tagio::screen_capture;
use tagio::streaming;
use tagio::input;
use tagio::gui;
use tagio::network_speed;
use tagio::config;
use tagio::relay;
use tagio::VERSION;

// Windows UI Component definitions
#[derive(Default, NwgUi, Clone)]
pub struct TagIOApp {
    // Window
    #[nwg_control(size: (500, 400), title: "TagIO Remote Desktop", flags: "WINDOW|VISIBLE")]
    #[nwg_events(OnWindowClose: [TagIOApp::exit])]
    window: nwg::Window,

    // Application icon
    #[nwg_resource(source_file: Some("dist/icons/app_icon.ico"))]
    icon: nwg::Icon,

    // Menu
    #[nwg_control(parent: window)]
    menu: nwg::Menu,

    #[nwg_control(parent: menu, text: "File")]
    file_menu: nwg::MenuItem,

    #[nwg_control(parent: file_menu, text: "Exit")]
    #[nwg_events(OnMenuItemSelected: [TagIOApp::exit])]
    file_exit: nwg::MenuItem,

    #[nwg_control(parent: menu, text: "Settings")]
    settings_menu: nwg::MenuItem,
    
    #[nwg_control(parent: settings_menu, text: "Switch to eframe UI")]
    #[nwg_events(OnMenuItemSelected: [TagIOApp::switch_ui_style])]
    switch_ui: nwg::MenuItem,

    #[nwg_control(parent: menu, text: "Help")]
    help_menu: nwg::MenuItem,

    #[nwg_control(parent: help_menu, text: "About")]
    #[nwg_events(OnMenuItemSelected: [TagIOApp::show_about])]
    help_about: nwg::MenuItem,

    // Status bar
    #[nwg_control(parent: window, dock: nwg::DockStyle::Bottom)]
    status_bar: nwg::StatusBar,

    // Main controls
    #[nwg_layout(parent: window, margin: [10, 10, 10, 10])]
    main_layout: nwg::GridLayout,

    // Title
    #[nwg_control(parent: window, text: &format!("TagIO Remote Desktop v{}", VERSION))]
    #[nwg_layout_item(layout: main_layout, row: 0, col: 0, col_span: 2)]
    title_label: nwg::Label,

    // Connection status
    #[nwg_control(parent: window, text: "Status:")]
    #[nwg_layout_item(layout: main_layout, row: 1, col: 0)]
    status_label: nwg::Label,

    #[nwg_control(parent: window, text: "Ready")]
    #[nwg_layout_item(layout: main_layout, row: 1, col: 1)]
    connection_status: nwg::Label,

    // Your TagIO ID
    #[nwg_control(parent: window, text: "Your TagIO ID:")]
    #[nwg_layout_item(layout: main_layout, row: 2, col: 0)]
    local_id_label: nwg::Label,

    #[nwg_control(parent: window, text: "")]
    #[nwg_layout_item(layout: main_layout, row: 2, col: 1)]
    local_id: nwg::TextInput,

    #[nwg_control(parent: window, text: "Change ID")]
    #[nwg_layout_item(layout: main_layout, row: 2, col: 2)]
    #[nwg_events(OnButtonClick: [TagIOApp::change_id])]
    change_id_button: nwg::Button,

    // Relay server
    #[nwg_control(parent: window, text: "Relay Server:")]
    #[nwg_layout_item(layout: main_layout, row: 3, col: 0)]
    relay_server_label: nwg::Label,

    #[nwg_control(parent: window, text: "")]
    #[nwg_layout_item(layout: main_layout, row: 3, col: 1)]
    relay_server: nwg::TextInput,

    #[nwg_control(parent: window, text: "Update")]
    #[nwg_layout_item(layout: main_layout, row: 3, col: 2)]
    #[nwg_events(OnButtonClick: [TagIOApp::update_relay])]
    update_relay_button: nwg::Button,

    // Remote ID
    #[nwg_control(parent: window, text: "Remote TagIO ID:")]
    #[nwg_layout_item(layout: main_layout, row: 4, col: 0)]
    remote_id_label: nwg::Label,

    #[nwg_control(parent: window, text: "")]
    #[nwg_layout_item(layout: main_layout, row: 4, col: 1)]
    remote_id: nwg::TextInput,

    // Connect button
    #[nwg_control(parent: window, text: "Connect")]
    #[nwg_layout_item(layout: main_layout, row: 5, col: 0, col_span: 3)]
    #[nwg_events(OnButtonClick: [TagIOApp::connect])]
    connect_button: nwg::Button,

    // Internal data
    #[nwg_data]
    config: RefCell<Option<config::Config>>,
    
    #[nwg_data]
    tokio_runtime: RefCell<Option<tokio::runtime::Runtime>>,
}

impl TagIOApp {
    fn init(&self) {
        // Setup status bar
        self.status_bar.set_text(0, "TagIO Ready");
        
        // Create Tokio runtime
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .ok();
        
        *self.tokio_runtime.borrow_mut() = runtime;
        
        // Load config
        let config = config::load_config().unwrap_or_default();
        *self.config.borrow_mut() = Some(config.clone());
        
        // Update UI with config values
        self.local_id.set_text(&config.local_key);
        self.relay_server.set_text(&config.relay_server);
        
        // Set window icon
        self.window.set_icon(Some(&self.icon));
    }
    
    fn exit(&self) {
        nwg::stop_thread_dispatch();
    }
    
    fn show_about(&self) {
        let mut about = nwg::MessageParams::default();
        about.title = "About TagIO";
        about.content = &format!("TagIO Remote Desktop v{}\n\nA secure remote desktop application", VERSION);
        about.buttons = nwg::MessageButtons::Ok;
        about.icons = nwg::MessageIcons::Info;
        
        nwg::message(&about);
    }
    
    fn change_id(&self) {
        let new_id = self.local_id.text();
        
        if new_id.is_empty() {
            self.show_error("TagIO ID cannot be empty");
            return;
        }
        
        if let Some(mut config) = self.config.borrow_mut().as_mut() {
            config.local_key = new_id;
            if let Err(e) = config::save_config(config) {
                self.show_error(&format!("Error: {}", e));
            } else {
                self.connection_status.set_text("TagIO ID updated successfully");
                self.status_bar.set_text(0, "TagIO ID updated successfully");
            }
        }
    }
    
    fn update_relay(&self) {
        let new_relay = self.relay_server.text();
        
        if new_relay.is_empty() {
            self.show_error("Relay server cannot be empty");
            return;
        }
        
        if let Some(mut config) = self.config.borrow_mut().as_mut() {
            config.relay_server = new_relay;
            if let Err(e) = config::save_config(config) {
                self.show_error(&format!("Error: {}", e));
            } else {
                self.connection_status.set_text("Relay server updated successfully");
                self.status_bar.set_text(0, "Relay server updated successfully");
            }
        }
    }
    
    fn connect(&self) {
        let remote_key = self.remote_id.text();
        
        // Validation
        if remote_key.is_empty() {
            self.show_error("Remote TagIO ID cannot be empty");
            return;
        }
        
        let local_key = self.local_id.text();
        if remote_key == local_key {
            self.show_error("Cannot connect to your own TagIO ID");
            return;
        }
        
        // Update status
        self.connection_status.set_text(&format!("Connecting to TagIO ID {}...", remote_key));
        self.status_bar.set_text(0, &format!("Connecting to TagIO ID {}...", remote_key));
        
        // Get config
        let config = match &*self.config.borrow() {
            Some(cfg) => cfg.clone(),
            None => {
                self.show_error("Failed to load configuration");
                return;
            }
        };
        
        let relay_server = config.relay_server.clone();
        let app = self.clone();
        
        // Get runtime
        let runtime = match &*self.tokio_runtime.borrow() {
            Some(rt) => rt,
            None => {
                self.show_error("Failed to initialize async runtime");
                return;
            }
        };
        
        // Spawn connection task
        let handle = runtime.spawn(async move {
            match Self::start_connection(local_key, remote_key, relay_server, app.clone()).await {
                Ok(_) => {
                    println!("Connection ended normally");
                },
                Err(e) => {
                    eprintln!("Connection error: {}", e);
                }
            }
        });
        
        // Update status from thread
        let app_clone = self.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(std::time::Duration::from_millis(100));
                // If connection handle is done, exit the loop
                if handle.is_finished() {
                    break;
                }
            }
        });
    }
    
    async fn start_connection(
        local_key: String, 
        remote_key: String, 
        relay_server: String,
        app: TagIOApp
    ) -> Result<()> {
        println!("Connecting to relay server ({}) and looking for {}", relay_server, remote_key);
        
        // Update status
        app.connection_status.set_text(&format!("Connecting via relay {}...", relay_server));
        app.status_bar.set_text(0, &format!("Connecting via relay {}...", relay_server));
        
        // Connect to the relay server
        let mut stream = match relay::connect_via_relay(
            local_key.clone(), remote_key.clone(), Some(relay_server.clone())
        ).await {
            Ok(stream) => {
                println!("Connection request sent. Waiting for remote approval...");
                // Update status
                app.connection_status.set_text("Waiting for remote approval...");
                app.status_bar.set_text(0, "Waiting for remote approval...");
                stream
            },
            Err(e) => {
                let err_msg = format!("Failed to connect to relay: {}", e);
                println!("{}", err_msg);
                
                // Update status
                app.connection_status.set_text(&err_msg);
                app.status_bar.set_text(0, &err_msg);
                
                return Err(anyhow::anyhow!("Relay connection failed"));
            }
        };
        
        // Rest of the connection logic would go here...
        // This is a placeholder for the actual connection implementation
        
        Ok(())
    }
    
    fn show_error(&self, message: &str) {
        let mut params = nwg::MessageParams::default();
        params.title = "Error";
        params.content = message;
        params.buttons = nwg::MessageButtons::Ok;
        params.icons = nwg::MessageIcons::Error;
        
        nwg::message(&params);
    }

    fn switch_ui_style(&self) {
        // Show confirmation dialog
        let mut dialog = nwg::MessageParams::default();
        dialog.title = "Switch UI Style";
        dialog.content = "Switch to eframe UI style? This will restart the application.";
        dialog.buttons = nwg::MessageButtons::YesNo;
        dialog.icons = nwg::MessageIcons::Question;
        
        if nwg::message(&dialog) == nwg::MessageChoice::Yes {
            // Update config to use eframe
            if let Some(mut config) = self.config.borrow_mut().as_mut() {
                if let Err(e) = config.set_ui_style("eframe") {
                    self.show_error(&format!("Failed to update UI style: {}", e));
                    return;
                }
                
                if let Err(e) = config::save_config(config) {
                    self.show_error(&format!("Failed to save config: {}", e));
                    return;
                }
                
                // Exit application - user will need to restart
                self.exit();
            }
        }
    }
}

pub fn main() -> Result<()> {
    nwg::init().expect("Failed to init Native Windows GUI");
    nwg::Font::set_global_family("Segoe UI").expect("Failed to set default font");
    
    let app = TagIOApp::build_ui(Default::default()).expect("Failed to build UI");
    app.init();
    
    nwg::dispatch_thread_events();
    
    Ok(())
} 