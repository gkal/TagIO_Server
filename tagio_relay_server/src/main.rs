// Server-only binary for TagIO relay server
// This file should not import any GUI dependencies
#![cfg(feature = "server")]

use std::env;
use std::net::IpAddr;
use std::io::{self, Write};
use std::str::FromStr;
use anyhow::{Result, anyhow};
use log::info;
use clap::{Parser, ArgAction};

mod constants;
mod messages;
mod server;

use constants::DEFAULT_BIND_ADDRESS;
use server::RelayServer;

/// TagIO Relay Server - NAT traversal and relay server for TagIO remote desktop
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about=None)]
struct CliArgs {
    /// Bind address for the server (default: 0.0.0.0:443)
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
    // Try to get the public IP from an external service
    let public_ip = match tokio::task::spawn_blocking(|| {
        ureq::get("https://api.ipify.org")
            .call()
            .map(|res| res.into_string().unwrap_or_default())
    }).await {
        Ok(Ok(ip)) if !ip.is_empty() => ip,
        _ => return Err(anyhow!("Failed to detect public IP"))
    };
    
    // Validate that it's a valid IP address
    match IpAddr::from_str(&public_ip) {
        Ok(_) => Ok(public_ip),
        Err(_) => Err(anyhow!("Invalid public IP: {}", public_ip))
    }
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
    env_logger::init();
    
    // Initialize variables with default values
    let mut bind_addr = DEFAULT_BIND_ADDRESS.to_string();
    let mut public_ip = None;
    let mut auth_secret = None;
    
    // If interactive mode is enabled, prompt for configuration
    if args.interactive {
        println!("=== TagIO Relay Server Interactive Setup ===");
        
        // Bind address
        let input_bind = prompt_input("Enter bind address (default: 0.0.0.0:443)");
        if !input_bind.is_empty() {
            bind_addr = input_bind;
        }
        
        // Public IP
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
        
        public_ip = args.public_ip;
        auth_secret = args.auth;
    }
    
    // Initialize the relay server
    let server = RelayServer::new(public_ip, auth_secret);
    
    // Run the server
    info!("Starting TagIO relay server...");
    server.run(&bind_addr).await?;
    
    Ok(())
} 