use std::fs;
use std::io::{self, Write};
use std::path::Path;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use serde_json::Value;

// Define default relay server with standard HTTPS port for better firewall traversal
pub const DEFAULT_RELAY_SERVER: &str = "tagio.onrender.com:443";

// Define the default authentication secret (duplicate from relay to avoid circular dependencies)
pub const DEFAULT_AUTH_SECRET: &str = "tagio_default_secret";

// Add this struct to handle old config files without relay_server field
#[derive(Deserialize)]
struct LegacyConfig {
    local_key: String,
    port: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub local_key: String,
    pub port: u16,
    pub relay_server: String,
    #[serde(default)]
    pub extra_values: HashMap<String, Value>,
    #[serde(default)]
    pub secure_mode: bool,
    pub auth_token: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        // Generate a random 4-digit key
        let random_key = format!("{:04}", rand::random::<u16>() % 10000);
        
        Self {
            local_key: random_key,
            port: 8080,
            relay_server: DEFAULT_RELAY_SERVER.to_string(),
            extra_values: HashMap::new(),
            secure_mode: true,
            auth_token: Some(DEFAULT_AUTH_SECRET.to_string()),
        }
    }
}

#[allow(dead_code)]
impl Config {
    // Set an extra value in the config
    pub fn set_extra_value<T: Serialize>(&mut self, key: &str, value: T) -> Result<()> {
        let value_json = serde_json::to_value(value)?;
        self.extra_values.insert(key.to_string(), value_json);
        Ok(())
    }
    
    // Get an extra value from the config
    pub fn get_extra_value(&self, key: &str) -> Option<&Value> {
        self.extra_values.get(key)
    }
    
    // Set UI style preference
    pub fn set_ui_style(&mut self, style: &str) -> Result<()> {
        self.set_extra_value("ui_style", style)
    }
    
    // Get UI style preference
    pub fn get_ui_style(&self) -> String {
        self.get_extra_value("ui_style")
            .and_then(|v| v.as_str())
            .unwrap_or("eframe")
            .to_string()
    }
}

pub fn load_config() -> Result<Config> {
    let config_path = get_config_path();
    
    // Check if config file exists
    if !config_path.exists() {
        // Create a default config file if it doesn't exist
        let default_config = Config::default();
        save_config(&default_config)?;
        return Ok(default_config);
    }
    
    // Read config file
    let config_content = fs::read_to_string(&config_path)?;
    
    // Try to parse as Config, if it fails try to parse as LegacyConfig
    match serde_json::from_str::<Config>(&config_content) {
        Ok(mut config) => {
            // Check if using outdated ports (6568 or 7568) and update to new default (443)
            if config.relay_server.ends_with(":6568") || config.relay_server.ends_with(":7568") {
                // Extract host and update port
                if let Some(host) = config.relay_server.split(':').next() {
                    config.relay_server = format!("{}:443", host);
                    // Save the updated config
                    let _ = save_config(&config);
                    println!("Updated relay server to use port 443 for better connectivity");
                }
            }
            
            Ok(config)
        },
        Err(_) => {
            // Try to parse as LegacyConfig
            let legacy_config: LegacyConfig = serde_json::from_str(&config_content)?;
            
            // Convert to new config format
            let config = Config {
                local_key: legacy_config.local_key,
                port: legacy_config.port,
                relay_server: DEFAULT_RELAY_SERVER.to_string(),
                extra_values: HashMap::new(),
                secure_mode: true,
                auth_token: Some(DEFAULT_AUTH_SECRET.to_string()),
            };
            
            // Save the updated config
            save_config(&config)?;
            
            Ok(config)
        }
    }
}

pub fn save_config(config: &Config) -> Result<()> {
    let config_path = get_config_path();
    
    // Create parent directories if they don't exist
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .context("Failed to create config directory")?;
    }
    
    let config_str = serde_json::to_string_pretty(config)
        .context("Failed to serialize config")?;
    
    fs::write(&config_path, config_str)
        .context("Failed to write config file")?;
    
    Ok(())
}

fn get_config_path() -> std::path::PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| Path::new(".").to_path_buf());
    home.join(".tagio").join("config.json")
}

/// Update the local key in the configuration
#[allow(dead_code)]
pub fn update_local_key() -> Result<Config> {
    let mut config = load_config()?;
    
    println!("Current key: {}", config.local_key);
    print!("Enter new key (or press Enter to keep current): ");
    io::stdout().flush()?;
    
    let mut key = String::new();
    io::stdin().read_line(&mut key)?;
    let key = key.trim().to_string();
    
    if !key.is_empty() {
        config.local_key = key;
        save_config(&config)?;
        println!("Key updated successfully!");
    }
    
    Ok(config)
}

/// Update the relay server in the configuration
#[allow(dead_code)]
pub fn update_relay_server() -> Result<Config> {
    let mut config = load_config()?;
    
    println!("Current relay server: {}", config.relay_server);
    print!("Enter new relay server address (or press Enter to keep current): ");
    io::stdout().flush()?;
    
    let mut server = String::new();
    io::stdin().read_line(&mut server)?;
    let server = server.trim().to_string();
    
    if !server.is_empty() {
        config.relay_server = server;
        save_config(&config)?;
        println!("Relay server updated successfully!");
    }
    
    Ok(config)
} 