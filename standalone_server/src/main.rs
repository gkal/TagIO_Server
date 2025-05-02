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
    
    // Configure logging
    if args.verbose {
        env::set_var("RUST_LOG", "info");
    } else {
        env::set_var("RUST_LOG", "warn");
    }
    
    // Initialize custom logger with [ T ] prefix for easy identification in Render's logs
    env_logger::builder()
        .format(|buf, record| {
            let timestamp = buf.timestamp();
            let level = record.level();
            let target = record.target();
            writeln!(
                buf,
                "[ T ] {} {} {} - {}",
                timestamp,
                level,
                target,
                record.args()
            )
        })
        .init();
    
    info!("Starting TagIO relay server initialization...");
    
    // Initialize variables with default values for cloud deployment
    let mut bind_addr = DEFAULT_BIND_ADDRESS.to_string();
    let mut public_ip = None;
    let mut auth_secret = None;
    
    // Check if we're running in a cloud environment
    let is_cloud = env::var("RENDER").is_ok() || env::var("RENDER_SERVICE_ID").is_ok();
    
    // If running in cloud environment or force_cloud_ip flag is set, use the known public IP
    if args.force_cloud_ip || is_cloud {
        info!("Cloud environment detected or cloud IP forced - using known cloud server IP");
        public_ip = Some(CLOUD_SERVER_IP.to_string());
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
        if let Some(b) = args.bind {
            bind_addr = b;
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
    
    // Run the server
    info!("Starting TagIO relay server...");
    println!("=== TagIO Cloud Relay Server v{} ===", env!("CARGO_PKG_VERSION"));
    println!("Protocol Version: {}", PROTOCOL_VERSION);
    println!("Bind Address: {}", bind_addr);
    if let Some(ip) = &public_ip {
        println!("Public IP: {} (explicitly configured)", ip);
    } else {
        println!("Public IP: Auto-detect mode (may cause NAT traversal issues)");
    }
    if auth_secret.is_some() {
        println!("Authentication: Enabled with custom secret");
    } else {
        println!("Authentication: Enabled with default secret");
    }
    if args.relay_only {
        println!("NAT Traversal: DISABLED (relay mode only)");
    } else {
        println!("NAT Traversal: ENABLED");
    }
    println!("==========================================");
    
    // Create server with cloned values
    let server = RelayServer::new(public_ip.clone(), auth_secret.clone());
    
    // Run the server
    server.run(&bind_addr).await?;
    
    Ok(())
} 