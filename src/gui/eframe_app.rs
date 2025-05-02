use std::sync::Arc;
use rand;

// Import from library
use crate::config;

// Simple application state
pub struct TagIOApp {
    pub config: Option<config::Config>,
    pub connection_status: String,
    pub remote_id: String,
    pub relay_server: String,
    pub local_id: String,
    pub auth_token: String, // New field for authentication
    pub tokio_runtime: Option<Arc<tokio::runtime::Runtime>>, // Changed to Arc to allow sharing
    pub show_about_dialog: bool,
    pub status_rx: Option<std::sync::mpsc::Receiver<String>>, // Channel for status updates
    pub secure_mode: bool, // New field to track secure connection mode
    pub connection_attempted: bool, // New flag to track if we've attempted connection
    pub show_auth_dialog: bool, // New field for auth dialog
}

impl Default for TagIOApp {
    fn default() -> Self {
        // Initialize tokio runtime
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(rt) => Some(Arc::new(rt)),
            Err(e) => {
                eprintln!("Failed to create tokio runtime: {}", e);
                None
            }
        };
        
        // Load config file
        let mut config = config::load_config().ok();
        let mut local_id = config.as_ref().map_or(String::new(), |c| c.local_key.clone());
        let mut relay_server = config.as_ref().map_or(String::new(), |c| c.relay_server.clone());
        let secure_mode = config.as_ref().map_or(true, |c| c.secure_mode);
        let auth_token = config.as_ref().map_or_else(
            || crate::config::DEFAULT_AUTH_SECRET.to_string(),
            |c| c.auth_token.clone().unwrap_or_else(|| crate::config::DEFAULT_AUTH_SECRET.to_string())
        );
        
        // Generate new ID if none exists
        if local_id.is_empty() {
            local_id = format!("{}", rand::random::<u32>() % 10000);
            if let Some(cfg) = &mut config {
                cfg.local_key = local_id.clone();
                let _ = config::save_config(cfg);
            }
        }
        
        // Set default relay server if empty
        if relay_server.is_empty() {
            relay_server = "tagio.onrender.com:443".to_string();
            if let Some(cfg) = &mut config {
                cfg.relay_server = relay_server.clone();
                let _ = config::save_config(cfg);
            }
        }
        
        TagIOApp {
            config,
            connection_status: "Disconnected".to_string(),
            remote_id: String::new(),
            relay_server,
            local_id,
            auth_token,
            tokio_runtime: runtime,
            show_about_dialog: false,
            status_rx: None,
            secure_mode,
            connection_attempted: false,
            show_auth_dialog: false,
        }
    }
} 