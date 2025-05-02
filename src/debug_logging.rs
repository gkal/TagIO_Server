use log::{LevelFilter, debug, info, warn, error, trace};
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use chrono::Local;
use env_logger;
use env_logger::Env;
use anyhow::Result;

// Global log file handle
static LOG_FILE: once_cell::sync::Lazy<Arc<Mutex<Option<File>>>> = 
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(None)));

/// Public init function for use in the main entry point
pub fn init() -> Result<()> {
    init_debug_logging();
    Ok(())
}

/// Initializes enhanced debug logging
pub fn init_debug_logging() {
    // Always use trace level logging by default
    let _debug_level = LevelFilter::Trace;

    // Set up file logging
    let log_path = match env::var("TAGIO_LOG_FILE") {
        Ok(path) => PathBuf::from(path),
        Err(_) => {
            // Default to logs directory in config path or current directory
            let config_dir = dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("tagio");
            
            std::fs::create_dir_all(&config_dir).unwrap_or_else(|e| {
                eprintln!("Warning: Could not create log directory: {}", e);
            });
            
            config_dir.join("tagio_debug.log")
        }
    };

    // Create log file
    let file = match File::create(&log_path) {
        Ok(file) => {
            println!("Debug logging to: {}", log_path.display());
            Some(file)
        },
        Err(e) => {
            eprintln!("Warning: Could not create log file: {}", e);
            None
        }
    };

    // Store log file handle in global
    if let Some(file) = file {
        *LOG_FILE.lock().unwrap() = Some(file);
    }

    // Configure env_logger
    let mut builder = env_logger::Builder::new();
    
    // Set format to include timestamp
    builder.format(|buf, record| {
        // Filter out mouse movement logs - completely skip them
        if record.target().starts_with("eframe::native::run") && 
           (record.args().to_string().contains("MouseMotion") || 
            record.args().to_string().contains("Motion") ||
            record.args().to_string().contains("event_result: Wait") ||
            record.args().to_string().contains("NewEvents")) {
            return Ok(());
        }
        
        let timestamp = Local::now().format("%d/%m/%Y %H:%M:%S%.3f");
        let formatted = format!("{} {} [{}] {}\n", 
            timestamp, 
            record.level(),
            record.target(),
            record.args()
        );
        
        // Write to stderr
        let _ = buf.write_all(formatted.as_bytes());
        
        // Also write to file if available
        if let Ok(mut guard) = LOG_FILE.lock() {
            if let Some(file) = guard.as_mut() {
                let _ = file.write_all(formatted.as_bytes());
            }
        }
        
        Ok(())
    });
    
    // Set default level to INFO to reduce noise
    builder.filter_level(LevelFilter::Info);
    
    // Set all relevant module levels to appropriate values
    builder.filter(Some("tagio::nat_traversal"), LevelFilter::Debug);
    builder.filter(Some("tagio::p2p_tls"), LevelFilter::Debug);
    builder.filter(Some("tagio::relay"), LevelFilter::Debug);
    builder.filter(Some("tagio"), LevelFilter::Debug);
    builder.filter(Some("tagio_gui"), LevelFilter::Debug);
    
    // Completely silence noisy UI frameworks
    builder.filter(Some("eframe"), LevelFilter::Error);
    builder.filter(Some("winit"), LevelFilter::Error);
    builder.filter(Some("wgpu"), LevelFilter::Error);
    
    // Initialize the logger
    if let Err(e) = builder.try_init() {
        eprintln!("Warning: Could not initialize logger: {}", e);
    }
    
    info!("Debug logging initialized at level: Debug");
}

// Helper functions to log TLS-specific details
pub fn log_tls_handshake_start(peer: &str) {
    debug!("TLS handshake starting with peer: {}", peer);
}

pub fn log_tls_handshake_complete(peer: &str) {
    info!("TLS handshake completed successfully with peer: {}", peer);
}

pub fn log_tls_handshake_error(peer: &str, error: &str) {
    error!("TLS handshake failed with peer {}: {}", peer, error);
}

pub fn log_certificate_info(subject: &str, issuer: &str, expiry: &str) {
    debug!("Certificate - Subject: {}, Issuer: {}, Expiry: {}", subject, issuer, expiry);
}

pub fn log_tls_data_send(peer: &str, bytes: usize) {
    trace!("Sent {} bytes to {} over TLS", bytes, peer);
}

pub fn log_tls_data_recv(peer: &str, bytes: usize) {
    trace!("Received {} bytes from {} over TLS", bytes, peer);
}

pub fn log_p2p_connection_attempt(method: &str, target: &str) {
    debug!("Attempting P2P connection via {} to {}", method, target);
}

pub fn log_p2p_connection_success(method: &str, target: &str) {
    info!("P2P connection established via {} to {}", method, target);
}

pub fn log_p2p_connection_failure(method: &str, target: &str, error: &str) {
    warn!("P2P connection attempt via {} to {} failed: {}", method, target, error);
}

pub fn log_relay_message(direction: &str, message_type: &str, content: &str) {
    debug!("Relay {} - Type: {}, Content: {}", direction, message_type, content);
}

pub fn log_hole_punch_attempt(addr: &str) {
    debug!("Attempting NAT hole punching to {}", addr);
}

pub fn memory_hex_dump(data: &[u8], max_len: usize) -> String {
    let len = std::cmp::min(data.len(), max_len);
    let mut s = String::with_capacity(len * 3);
    
    for (i, byte) in data[..len].iter().enumerate() {
        if i > 0 && i % 16 == 0 {
            s.push('\n');
        }
        s.push_str(&format!("{:02x} ", byte));
    }
    
    if data.len() > max_len {
        s.push_str("\n... (truncated)");
    }
    
    s
}

pub fn set_debug_level(_debug_level: i32) {
    // Implementation
}

pub fn init_logger() -> Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "debug");
    }
    
    // Configure the custom filter that includes the time
    let _debug_level = LevelFilter::Trace;
    
    env_logger::Builder::from_env(Env::default().default_filter_or("debug"))
        .format(|buf, record| {
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            writeln!(
                buf,
                "[{} {} {}:{}] {}",
                timestamp,
                record.level(),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .init();
    
    debug!("Logger initialized");
    Ok(())
} 