// Server-only binary for TagIO relay server
// This file should not import any GUI dependencies
#![cfg(feature = "server")]

use std::env;
use std::net::IpAddr;
use std::io::{self, Write};
use std::str::FromStr;
use anyhow::{Result, anyhow};
use log::{info, warn};
use clap::{Parser, ArgAction};

mod constants;
mod messages;
mod server;

// Custom logging filter module
mod log_filter {
    use log::{Record, Metadata, Level, LevelFilter};
    use std::net::IpAddr;
    use std::str::FromStr;
    
    // Function to check if a log message contains a localhost IP
    pub fn contains_localhost(message: &str) -> bool {
        message.contains("127.0.0.1") || 
        message.contains("localhost") ||
        // Also check for IPv6 localhost
        message.contains("::1")
    }
    
    // Check if an IP address string represents localhost
    pub fn is_localhost_ip(ip_str: &str) -> bool {
        if let Ok(ip) = IpAddr::from_str(ip_str) {
            ip.is_loopback()
        } else {
            // Check for common localhost strings
            ip_str == "localhost" || ip_str.starts_with("127.")
        }
    }
    
    // Extract any IP address from a log message
    pub fn extract_ip(message: &str) -> Option<String> {
        // Common IP address patterns
        let patterns = [
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", // IPv4
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", // IPv6
            r"\blocalhost\b" // Literal localhost
        ];
        
        for pattern in patterns {
            if let Some(captures) = regex::Regex::new(pattern)
                .ok()
                .and_then(|re| re.captures(message)) {
                if let Some(m) = captures.get(0) {
                    return Some(m.as_str().to_string());
                }
            }
        }
        None
    }
    
    // Custom logger that filters out localhost messages
    pub struct LocalhostFilter {
        inner: env_logger::Logger,
    }
    
    impl log::Log for LocalhostFilter {
        fn enabled(&self, metadata: &Metadata) -> bool {
            self.inner.enabled(metadata)
        }
        
        fn log(&self, record: &Record) {
            // Skip any logs containing localhost references
            let message = format!("{}", record.args());
            
            // Check for localhost in the message
            if contains_localhost(&message) {
                return;
            }
            
            // Extract IP and check if it's localhost
            if let Some(ip) = extract_ip(&message) {
                if is_localhost_ip(&ip) {
                    return;
                }
            }
            
            // Forward to inner logger
            self.inner.log(record);
        }
        
        fn flush(&self) {
            self.inner.flush();
        }
    }
    
    // Initialize with our filter
    pub fn init(log_level: Option<LevelFilter>) -> Result<(), log::SetLoggerError> {
        let level = log_level.unwrap_or(LevelFilter::Info);
        
        let env_logger = env_logger::Builder::new()
            .format(|buf, record| {
                use std::io::Write;
                writeln!(buf, "[ T ] {} | {}", record.level(), record.args())
            })
            .filter(None, level)
            .build();
        
        let logger = LocalhostFilter { inner: env_logger };
        
        log::set_boxed_logger(Box::new(logger))?;
        log::set_max_level(level);
        
        Ok(())
    }
}

use constants::DEFAULT_BIND_ADDRESS;
use server::RelayServer;
use messages::PROTOCOL_VERSION;

// Cloud server's known public IP address - set this explicitly for NAT traversal
const CLOUD_SERVER_IP: &str = "18.156.158.53";

/// TagIO Relay Server - NAT traversal and relay server for TagIO remote desktop
/// Designed to run on tagio-server.onrender.com in production
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about=None)]
struct CliArgs {
    /// Bind address for the server (default: 0.0.0.0:10000)
    #[clap(short, long, value_name = "ADDRESS:PORT")]
    bind: Option<String>,
    
    /// Public IP address of the server (used for NAT traversal)
    #[clap(short, long, value_name = "IP")]
    public_ip: Option<String>,
    
    /// Authentication secret for client connections
    #[clap(short, long, value_name = "SECRET")]
    auth: Option<String>,

    /// Enable verbose logging
    #[clap(short, long, action = ArgAction::SetTrue)]
    verbose: bool,
    
    /// Run interactively (prompt for configuration)
    #[clap(short, long, action = ArgAction::SetTrue)]
    interactive: bool,
    
    /// Force use of the hardcoded cloud server IP (18.156.158.53)
    #[clap(long, action = ArgAction::SetTrue)]
    force_cloud_ip: bool,
    
    /// Disable NAT traversal (relay mode only)
    #[clap(long, action = ArgAction::SetTrue)]
    relay_only: bool,
}

/// Prompt for user input with a given message
fn prompt_input(prompt: &str) -> String {
    print!("{}: ", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

/// Attempt to detect the public IP address
async fn detect_public_ip() -> Result<String> {
    // Try different services for public IP detection
    let services = vec![
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com",
    ];
    
    for service in services {
        match tokio::task::spawn_blocking(move || {
            match ureq::get(service).call() {
                Ok(res) => res.into_string().ok(),
                Err(_) => None,
            }
        }).await {
            Ok(Some(ip)) if !ip.is_empty() => {
                let ip = ip.trim().to_string();
                // Validate that it's a valid IP address
                if IpAddr::from_str(&ip).is_ok() {
                    return Ok(ip);
                }
            },
            _ => continue,
        }
    }
    
    Err(anyhow!("Failed to detect public IP from all services"))
}

/// Prompt for yes/no confirmation
fn prompt_yes_no(prompt: &str) -> bool {
    loop {
        print!("{} (y/n): ", prompt);
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        match input.trim().to_lowercase().as_str() {
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => println!("Please enter 'y' or 'n'"),
        }
    }
}

/// Main entry point
#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = CliArgs::parse();
    
    // Print banner immediately to console
    println!("===== STARTING TAGIO RELAY SERVER v{} =====", env!("CARGO_PKG_VERSION"));
    
    // Check if running in Render cloud environment
    let is_render = env::var("RENDER").is_ok() || env::var("RENDER_SERVICE_ID").is_ok();
    
    // Configure log level - ensure it's verbose in cloud environments
    let log_level = if args.verbose || is_render {
        // Use verbose logging in Render environment
        if is_render {
            println!("RENDER ENV: Setting TRACE log level");
            log::LevelFilter::Trace
        } else {
            log::LevelFilter::Info
        }
    } else {
        log::LevelFilter::Warn
    };
    
    // Initialize custom logger with localhost filtering
    if let Err(e) = log_filter::init(Some(log_level)) {
        eprintln!("Warning: Failed to initialize logger: {}", e);
    }
    
    println!("LOGGER: Initialized");
    info!("Starting TagIO relay server initialization...");
    
    // Initialize variables with default values
    let mut bind_addr = DEFAULT_BIND_ADDRESS.to_string();
    let mut public_ip = None;
    let mut auth_secret = None;
    
    // Check if we're running in a cloud environment
    let is_cloud = env::var("RENDER").is_ok() || env::var("RENDER_SERVICE_ID").is_ok();
    
    // If running in cloud environment or force_cloud_ip flag is set, use the known public IP
    if args.force_cloud_ip || is_cloud {
        info!("Cloud environment detected or cloud IP forced - using known cloud server IP");
        println!("CLOUD MODE: Using cloud server IP {}", CLOUD_SERVER_IP);
        public_ip = Some(CLOUD_SERVER_IP.to_string());
    }
    
    // Try to get the PORT environment variable for cloud environments
    let cloud_port = env::var("PORT").ok().and_then(|port_str| port_str.parse::<u16>().ok());
    
    // Define preferred ports for binding in order of preference
    // Non-privileged ports first, then fallback to privileged ones if running with sufficient permissions
    let _preferred_ports = [10000, 8080, 3000, 443, 80];
    
    // In a cloud environment, prioritize the PORT environment variable if available
    if is_cloud && cloud_port.is_some() {
        let port = cloud_port.unwrap();
        println!("CLOUD PORT: Using environment PORT={}", port);
        bind_addr = format!("0.0.0.0:{}", port);
        
        // Make sure users know the correct port to use for clients
        if is_render {
            println!("RENDER NOTE: Although binding to port {}, external clients should connect on port 443", port);
            info!("IMPORTANT: TagIO clients should connect to tagio.onrender.com:443 (not port {})", port);
        }
    } else if let Some(ref b) = args.bind {
        // Command-line bind address overrides defaults
        bind_addr = b.clone();
    }
    
    // Special handling for Render - force internal binding to port 10000 if not specified otherwise
    if is_render && cloud_port.is_none() && args.bind.is_none() {
        bind_addr = "0.0.0.0:10000".to_string();
        println!("RENDER ENV: Defaulting to standard port 10000 for internal binding");
        println!("RENDER NOTE: External clients should connect on port 443");
        info!("IMPORTANT: TagIO clients should connect to tagio.onrender.com:443");
    }
    
    // If interactive mode is enabled, prompt for configuration
    if args.interactive {
        println!("=== TagIO Relay Server Interactive Setup ===");
        
        // Bind address
        let input_bind = prompt_input("Enter bind address (default: 0.0.0.0:10000)");
        if !input_bind.is_empty() {
            bind_addr = input_bind;
        }
        
        // Public IP if not already set by force_cloud_ip
        if public_ip.is_none() {
            let detect_ip = prompt_yes_no("Attempt to detect public IP?");
            if detect_ip {
                match detect_public_ip().await {
                    Ok(ip) => {
                        println!("Detected public IP: {}", ip);
                        if prompt_yes_no("Use this IP?") {
                            public_ip = Some(ip);
                        }
                    },
                    Err(e) => {
                        eprintln!("Failed to detect public IP: {}", e);
                    }
                }
            }
            
            if public_ip.is_none() {
                let use_cloud_ip = prompt_yes_no("Use cloud server IP (18.156.158.53)?");
                if use_cloud_ip {
                    public_ip = Some(CLOUD_SERVER_IP.to_string());
                } else {
                    let input_ip = prompt_input("Enter public IP (leave empty to skip)");
                    if !input_ip.is_empty() {
                        // Validate the IP
                        match IpAddr::from_str(&input_ip) {
                            Ok(_) => public_ip = Some(input_ip),
                            Err(_) => {
                                eprintln!("Invalid IP address: {}", input_ip);
                                return Err(anyhow!("Invalid IP address"));
                            }
                        }
                    }
                }
            }
        }
        
        // Authentication
        if prompt_yes_no("Enable authentication?") {
            let secret = prompt_input("Enter authentication secret");
            if !secret.is_empty() {
                auth_secret = Some(secret);
            } else {
                eprintln!("Empty secret not allowed for authentication");
                return Err(anyhow!("Empty authentication secret"));
            }
        }
    } else {
        // Use command line arguments
        if let Some(ref b) = args.bind {
            bind_addr = b.clone();
        }
        
        // If not using cloud IP mode, check command line provided IP
        if public_ip.is_none() {
            public_ip = args.public_ip;
        }
        
        auth_secret = args.auth;
    }
    
    // Always use the cloud server IP when running in the cloud for reliability
    if public_ip.is_none() && is_cloud {
        warn!("Running in cloud environment with no public IP specified. Using cloud server IP.");
        public_ip = Some(CLOUD_SERVER_IP.to_string());
    }
    
    // Run the server - use logger instead of println!
    info!("Starting TagIO relay server...");
    println!("===== TagIO Cloud Relay Server v{} =====", env!("CARGO_PKG_VERSION"));
    info!("=== TagIO Cloud Relay Server v{} ===", env!("CARGO_PKG_VERSION"));
    info!("Protocol Version: {}", PROTOCOL_VERSION);
    println!("Protocol Version: {}", PROTOCOL_VERSION);
    info!("Bind Address: {}", bind_addr);
    println!("Bind Address: {}", bind_addr);
    println!("IMPORTANT: Port 10000 must be accessible for TagIO clients to connect");
    println!("IMPORTANT: Make sure your firewall allows TCP traffic on port 10000");
    if let Some(ip) = &public_ip {
        info!("Public IP: {} (explicitly configured)", ip);
        println!("Public IP: {} (explicitly configured)", ip);
    } else {
        info!("Public IP: Auto-detect mode (may cause NAT traversal issues)");
        println!("Public IP: Auto-detect mode (may cause NAT traversal issues)");
    }
    if auth_secret.is_some() {
        info!("Authentication: Enabled with custom secret");
        println!("Authentication: Enabled with custom secret");
    } else {
        info!("Authentication: Enabled with default secret");
        println!("Authentication: Enabled with default secret");
    }
    if args.relay_only {
        info!("NAT Traversal: DISABLED (relay mode only)");
        println!("NAT Traversal: DISABLED (relay mode only)");
    } else {
        info!("NAT Traversal: ENABLED");
        println!("NAT Traversal: ENABLED");
    }
    println!("==========================================");
    info!("==========================================");
    println!("PROTOCOL FORMAT: Using length-prefixed messages (4-byte BE uint32 + magic bytes + payload)");
    info!("PROTOCOL FORMAT: Using length-prefixed messages (4-byte BE uint32 + magic bytes + payload)");
    println!("CLIENT NOTE: The server now adds a 4-byte length prefix to each message");
    info!("CLIENT NOTE: The server now adds a 4-byte length prefix to each message");
    println!("PORT NOTE: Clients should connect to port 10000 for TagIO protocol");
    info!("PORT NOTE: Clients should connect to port 10000 for TagIO protocol");
    println!("PORT NOTE: Ports 443, 80, and 8888 are for HTTP health checks only");
    info!("PORT NOTE: Ports 443, 80, and 8888 are for HTTP health checks only");
    println!("==========================================");
    info!("==========================================");
    
    // Create server with cloned values
    let server = RelayServer::new(public_ip.clone(), auth_secret.clone());
    
    // Run the server
    server.run(&bind_addr).await?;
    
    Ok(())
} 