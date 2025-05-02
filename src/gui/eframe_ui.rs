use eframe::egui;
use super::eframe_app::TagIOApp;
use crate::config;
use crate::VERSION;

impl eframe::App for TagIOApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Attempt to initialize relay registration on first update
        static mut REGISTRATION_INITIALIZED: bool = false;
        unsafe {
            if !REGISTRATION_INITIALIZED {
                REGISTRATION_INITIALIZED = true;
                self.initialize_relay_registration(ctx.clone());
                log::info!("Initializing relay registration on first update cycle");
            }
        }
        
        // Add menu bar
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("About").clicked() {
                        self.show_about_dialog = true;
                        ui.close_menu();
                    }
                    if ui.button("Exit").clicked() {
                        std::process::exit(0);
                    }
                });
            });
        });
        
        // Check if we need to attempt connection for the first time
        if !self.remote_id.is_empty() && !self.connection_attempted && self.tokio_runtime.is_some() {
            log::info!("Auto-connecting to remote ID: {}", self.remote_id);
            self.connect();
        }
        
        // Check for status updates
        if let Some(status_rx) = &self.status_rx {
            if let Ok(status) = status_rx.try_recv() {
                self.connection_status = status;
                ctx.request_repaint(); // Ensure UI updates
            }
        }
        
        // Show about dialog if open
        self.render_about_dialog(ctx);
        
        // Render main UI panel
        egui::CentralPanel::default().show(ctx, |ui| {
            self.render_main_panel(ui, ctx);
        });
        
        // Show authentication dialog if open
        self.render_auth_dialog(ctx);
    }
}

impl TagIOApp {
    // Render the about dialog
    fn render_about_dialog(&mut self, ctx: &egui::Context) {
        if self.show_about_dialog {
            egui::Window::new("About TagIO")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!("TagIO Remote Desktop v{}", VERSION));
                    ui.label("A secure remote desktop application");
                    ui.add_space(10.0);
                    if ui.button("Close").clicked() {
                        self.show_about_dialog = false;
                    }
                });
        }
    }
    
    // Render the main panel
    fn render_main_panel(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) {
        // Title
        ui.heading(format!("TagIO Remote Desktop v{}", VERSION));
        ui.separator();
        
        // Connection status
        ui.horizontal(|ui| {
            ui.label("Status:");
            ui.label(&self.connection_status);
        });
        ui.add_space(10.0);
        
        // Your TagIO ID
        ui.horizontal(|ui| {
            ui.label("Your TagIO ID:");
            ui.text_edit_singleline(&mut self.local_id);
            if ui.button("Change ID").clicked() {
                if let Some(config) = &mut self.config {
                    config.local_key = self.local_id.clone();
                    if let Err(e) = config::save_config(config) {
                        self.connection_status = format!("Error: {}", e);
                    } else {
                        self.connection_status = "TagIO ID updated successfully".to_string();
                    }
                }
            }
        });
        
        // Relay server
        ui.horizontal(|ui| {
            ui.label("Relay Server:");
            ui.text_edit_singleline(&mut self.relay_server);
            if ui.button("Update").clicked() {
                if let Some(config) = &mut self.config {
                    config.relay_server = self.relay_server.clone();
                    if let Err(e) = config::save_config(config) {
                        self.connection_status = format!("Error: {}", e);
                    } else {
                        self.connection_status = "Relay server updated successfully".to_string();
                    }
                }
            }
        });
        
        // Auth token configuration
        ui.horizontal(|ui| {
            ui.label("Authentication:");
            if ui.button("Configure Auth Token").clicked() {
                self.show_auth_dialog = true;
            }
        });
        
        // Connection section
        ui.separator();
        ui.heading("Connect");
        
        // Remote TagIO ID
        ui.horizontal(|ui| {
            ui.label("Remote TagIO ID:");
            ui.text_edit_singleline(&mut self.remote_id);
            
            // Security mode checkbox
            ui.checkbox(&mut self.secure_mode, "Secure Mode");
            
            if ui.button("Connect").clicked() {
                if self.remote_id.is_empty() {
                    self.connection_status = "Error: Remote TagIO ID cannot be empty".to_string();
                } else if self.remote_id == self.local_id {
                    self.connection_status = "Error: Cannot connect to your own TagIO ID".to_string();
                } else {
                    self.connect();
                }
            }
        });
        
        ui.label("Note: Connect to another TagIO instance using their unique ID.");
        ui.label("The connection will be established via the relay server.");
    }
    
    // Render the authentication dialog
    fn render_auth_dialog(&mut self, ctx: &egui::Context) {
        if self.show_auth_dialog {
            egui::Window::new("Authentication Token")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("Set the authentication token for secure connections.");
                    ui.label("Both sides must use the same token to connect.");
                    ui.text_edit_singleline(&mut self.auth_token);
                    
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            if let Some(config) = &mut self.config {
                                config.auth_token = Some(self.auth_token.clone());
                                if let Err(e) = config::save_config(config) {
                                    self.connection_status = format!("Error: {}", e);
                                } else {
                                    self.connection_status = "Authentication token updated".to_string();
                                }
                            }
                            self.show_auth_dialog = false;
                        }
                        
                        if ui.button("Cancel").clicked() {
                            // Reset to saved token
                            if let Some(config) = &self.config {
                                self.auth_token = config.auth_token.clone()
                                    .unwrap_or_else(|| crate::config::DEFAULT_AUTH_SECRET.to_string());
                            }
                            self.show_auth_dialog = false;
                        }
                    });
                });
        }
    }
}

#[allow(dead_code)]
pub fn draw_about_dialog(ui: &mut egui::Ui, open: &mut bool, _ctx: &egui::Context) {
    // Only draw dialog if it's open
    if !*open {
        return;
    }
    
    // Create window
    egui::Window::new("About TagIO")
        .collapsible(false)
        .resizable(false)
        .show(ui.ctx(), |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("TagIO");
                ui.label(format!("Version {}", crate::VERSION));
                ui.add_space(10.0);
                ui.label("A secure peer-to-peer remote desktop application");
                ui.add_space(5.0);
                ui.label("© 2024");
                ui.add_space(10.0);
                if ui.button("Close").clicked() {
                    *open = false;
                }
            });
        });
} 