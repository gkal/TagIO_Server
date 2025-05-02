use std::sync::{Arc, Mutex};
use std::thread;
use anyhow::{Result, anyhow};
use rfd::MessageDialog;
use tokio::sync::mpsc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use eframe::egui;

use super::eframe_app::TagIOApp;
use crate::relay;
use crate::config;
use crate::streaming;
use crate::gui;

impl TagIOApp {
    // Initialize relay registration
    pub fn initialize_relay_registration(&mut self, ctx: egui::Context) {
        // Check for tokio runtime
        if self.tokio_runtime.is_none() {
            return;
        }
        
        // Clone needed variables for the async task
        let runtime = self.tokio_runtime.as_ref().unwrap().clone();
        let local_id = self.local_id.clone();
        let relay_server = self.relay_server.clone();
        let secure_mode = self.secure_mode;
        
        // Create channels for status updates
        let (status_tx, status_rx) = std::sync::mpsc::channel();
        self.status_rx = Some(status_rx);
        
        // Clone the context to request repaints when the status changes
        let ctx_clone = ctx.clone();
        
        // Launch registration in a separate thread
        thread::spawn(move || {
            runtime.spawn(async move {
                // Attempt to register with the relay server
                match relay::start_nat_traversal_listener(&local_id, secure_mode).await {
                    Ok(_) => {
                        log::info!("Successfully registered with relay server: {}", relay_server);
                        let _ = status_tx.send("Registered with relay server".to_string());
                    }
                    Err(e) => {
                        log::error!("Failed to register with relay server: {}", e);
                        let _ = status_tx.send(format!("Failed to register with relay server: {}", e));
                    }
                }
            });
            
            // Loop to request repaints periodically to update the UI with new status messages
            loop {
                ctx_clone.request_repaint();
                thread::sleep(std::time::Duration::from_millis(500));
            }
        });
    }
    
    // Initiate a connection to a remote peer
    pub fn connect(&mut self) {
        self.connection_attempted = true;
        
        // Check for tokio runtime
        if self.tokio_runtime.is_none() {
            self.connection_status = "Error: Tokio runtime not available".to_string();
            return;
        }
        
        // Clone needed variables for the async task
        let runtime = self.tokio_runtime.as_ref().unwrap().clone();
        let local_id = self.local_id.clone();
        let remote_id = self.remote_id.clone();
        let relay_server = self.relay_server.clone();
        let secure_mode = self.secure_mode;
        
        // Create a shared status for updating from the async task
        let status = Arc::new(Mutex::new(String::from("Connecting...")));
        let status_for_thread = status.clone();
        
        // Update the UI with the initial status
        self.connection_status = "Connecting...".to_string();
        
        // Show a UI prompt indicating connection is in progress
        let _dialog = MessageDialog::new()
            .set_title("TagIO Connection")
            .set_description(format!("Connecting to TagIO ID: {}", remote_id))
            .set_buttons(rfd::MessageButtons::Ok)
            .set_level(rfd::MessageLevel::Info);
        
        // Launch connection task
        thread::spawn(move || {
            if let Err(e) = runtime.block_on(start_connection(
                local_id, remote_id, relay_server, status_for_thread, secure_mode
            )) {
                log::error!("Connection error: {}", e);
                // Show error dialog
                let err_dialog = MessageDialog::new()
                    .set_title("Connection Error")
                    .set_description(format!("Failed to connect: {}", e))
                    .set_buttons(rfd::MessageButtons::Ok)
                    .set_level(rfd::MessageLevel::Error);
                let _ = err_dialog.show();
            }
        });
    }
}

// Start the connection process (async task)
async fn start_connection(
    local_key: String, 
    remote_key: String, 
    relay_server: String,
    status: Arc<Mutex<String>>,
    secure_mode: bool,
) -> Result<()> {
    // Update status
    {
        let mut status_guard = status.lock().unwrap();
        *status_guard = "Initiating connection...".to_string();
    }
    
    // Get a connection to the remote peer
    let stream = relay::connect_via_relay(&local_key, &remote_key, Some(relay_server), secure_mode).await?;
    
    // Update status
    {
        let mut status_guard = status.lock().unwrap();
        *status_guard = "Connected! Establishing secure channel...".to_string();
    }
    
    // Send authentication message
    let auth_token = config::load_config()?.auth_token
        .unwrap_or_else(|| config::DEFAULT_AUTH_SECRET.to_string());
    
    let mut stream = stream;
    let auth_msg = format!("AUTH:{}\n", auth_token);
    stream.write_all(auth_msg.as_bytes()).await?;
    
    // Read authentication response
    let mut response = [0u8; 20]; // Large enough for OK or ERROR message
    let n = stream.read(&mut response).await?;
    let response_str = String::from_utf8_lossy(&response[0..n]);
    
    if !response_str.starts_with("OK") {
        return Err(anyhow!("Authentication failed: {}", response_str));
    }
    
    // Update status
    {
        let mut status_guard = status.lock().unwrap();
        *status_guard = "Authenticated. Starting screen sharing...".to_string();
    }
    
    // Set up screen sharing
    let (frame_tx, frame_rx) = mpsc::channel(10);
    
    // Start streaming client
    tokio::spawn(async move {
        if let Err(e) = streaming::run_client(stream, frame_tx).await {
            log::error!("Streaming error: {}", e);
        }
    });
    
    // Update status
    {
        let mut status_guard = status.lock().unwrap();
        *status_guard = "Connection established, starting viewer...".to_string();
    }
    
    // Initialize the native window viewer
    let viewer_result = gui::init_native_window(frame_rx).await;
    
    if let Err(e) = viewer_result {
        return Err(anyhow!("Failed to initialize viewer: {}", e));
    }
    
    Ok(())
}

// Show a dialog when connection error occurs
#[allow(dead_code)]
pub fn show_connection_error(message: &str) -> bool {
    // Dialog is unused, mark with underscore
    let _dialog = MessageDialog::new()
        .set_title("Connection Error")
        .set_description(message)
        .set_buttons(rfd::MessageButtons::Ok)
        .set_level(rfd::MessageLevel::Error)
        .show();
    
    false
} 