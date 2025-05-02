// Server-only binary for TagIO relay server
// This file should not import any GUI dependencies
#![cfg(feature = "server")]

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::io::{self, Write};
use std::str::FromStr;
use anyhow::{Result, anyhow};
use log::{info, warn};
use clap::{Parser, ArgAction};
use tokio;

mod constants;
mod messages;
mod server;
mod protocol_detect;
mod http_tunnel;

// Custom logging filter module
#[allow(dead_code)]
mod logging_filter;

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
    
    /// Enable protocol detection to handle both HTTP and TagIO traffic on the same port
    #[clap(long, action = ArgAction::SetTrue)]
    enable_protocol_detection: bool,

    /// Enable HTTP tunneling for TagIO protocol
    #[clap(long, default_value_t = false)]
    enable_http_tunneling: bool,
}

/// Prompt for user input with a given message
#[allow(dead_code)]
fn prompt_input(prompt: &str) -> String {
    print!("{}: ", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

/// Attempt to detect the public IP address
#[allow(dead_code)]
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
#[allow(dead_code)]
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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Print the title banner
    println!("===== STARTING TAGIO RELAY SERVER v{} =====", env!("CARGO_PKG_VERSION"));
    
    // Parse the command line arguments
    let args = CliArgs::parse();
    
    // Set up the logger
    let log_level = match args.verbose {
        true => {
            println!("RENDER ENV: Setting TRACE log level");
            log::LevelFilter::Trace
        }
        false => log::LevelFilter::Info,
    };
    
    // Initialize custom logger with localhost filtering
    if let Err(e) = logging_filter::init(Some(log_level)) {
        eprintln!("Warning: Failed to initialize logger: {}", e);
    }
    
    println!("LOGGER: Initialized");
    info!("Starting TagIO relay server initialization...");
    
    // Determine if we're running in a cloud environment
    let is_cloud_env = env::var("RENDER").is_ok() || args.force_cloud_ip;
    
    // Get the public IP address
    let public_ip = if let Some(ip) = args.public_ip {
        info!("Using provided public IP: {}", ip);
        Some(ip)
    } else if is_cloud_env {
        info!("Cloud environment detected or cloud IP forced - using known cloud server IP");
        println!("CLOUD MODE: Using cloud server IP {}", CLOUD_SERVER_IP);
        Some(CLOUD_SERVER_IP.to_string())
    } else {
        // Auto-detect public IP (simplified - use local IP for this example)
        match local_ip_address::local_ip() {
            Ok(ip) => {
                info!("Auto-detected local IP: {}", ip);
                Some(ip.to_string())
            }
            Err(e) => {
                warn!("Failed to auto-detect local IP: {}", e);
                None
            }
        }
    };
    
    // Get the port from environment (for cloud deployment) or command line
    let port = if let Ok(port_str) = env::var("PORT") {
        info!("Using environment PORT={}", port_str);
        if is_cloud_env {
            println!("CLOUD PORT: Using environment PORT={}", port_str);
            println!("RENDER NOTE: Although binding to port {}, external clients should connect on port 443", port_str);
            info!("IMPORTANT: TagIO clients should connect to tagio.onrender.com:443 (not port {})", port_str);
        }
        port_str.parse().unwrap_or(10000)
    } else {
        args.bind.and_then(|b| b.parse::<u16>().ok()).unwrap_or(10000)
    };
    
    // Get the authentication secret
    let auth_secret = args.auth.unwrap_or_else(|| {
        let secret = "tagio_default_secret".to_string();
        info!("Using default authentication secret");
        secret
    });
    
    // Determine the bind address
    let bind_addr = SocketAddr::new(
        std::net::IpAddr::from_str("0.0.0.0").unwrap(),
        port
    );
    
    // Run the server in the appropriate mode
    if args.enable_http_tunneling {
        info!("Starting server with HTTP tunneling support on port {}", port);
        println!("Starting HTTP tunneling server on port {}", port);
        println!("Clients should POST TagIO protocol messages to /tagio endpoint");
        http_tunnel::start_http_tunnel_server(bind_addr).await?;
    } else {
        // Create and initialize the server
        let mut server = server::RelayServer::new(public_ip, Some(auth_secret));
        
        // Configure protocol detection if enabled
        if args.enable_protocol_detection {
            info!("Protocol detection is enabled - server will accept both HTTP and TagIO connections");
            println!("Protocol detection ENABLED - server will accept both HTTP and TagIO connections");
            server.set_protocol_detection(true);
        }
        
        // Run the server
        server.run(&bind_addr.to_string()).await?;
    }
    
    Ok(())
} 