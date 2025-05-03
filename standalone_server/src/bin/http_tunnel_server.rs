use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use anyhow::Result;
use clap::Parser;
use log::{info, error, debug, LevelFilter};
use tokio;

// Import the HTTP tunnel module from the package
use tagio_relay_server::http_tunnel;

#[derive(Parser)]
#[clap(author = "TagIO Team", version, about = "TagIO HTTP Tunnel Server")]
struct Args {
    /// Port to bind to
    #[clap(short, long, default_value_t = 10000)]
    port: u16,
    
    /// Log level
    #[clap(short, long, default_value = "info")]
    log_level: String,
    
    /// Log to file
    #[clap(long)]
    log_file: Option<PathBuf>,
}

/// Initialize the logger
fn setup_logger(level: LevelFilter, log_file: Option<PathBuf>) -> Result<(), fern::InitError> {
    // Check if RUST_LOG is explicitly set
    let rust_log = std::env::var("RUST_LOG").ok();
    
    // Set default log level if RUST_LOG is not set
    if rust_log.is_none() {
        std::env::set_var("RUST_LOG", "debug");
    }
    
    println!("Initializing TagIO HTTP tunnel logger at level: {:?}", level);
    
    let mut builder = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[T] {} {} [{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                record.target(),
                message
            ))
        })
        .level(level)
        // Set more verbose log levels for our modules
        .level_for("tagio_relay_server", log::LevelFilter::Debug)
        .level_for("tagio_relay_server::http_tunnel", log::LevelFilter::Debug)
        .level_for("tagio_relay_server::server", log::LevelFilter::Debug)
        .level_for("tagio_relay_server::messages", log::LevelFilter::Debug);
    
    // Log to stdout
    builder = builder.chain(std::io::stdout());
    
    // Log to file if specified
    if let Some(log_file) = log_file {
        println!("Logging to file: {}", log_file.display());
        builder = builder.chain(fern::log_file(log_file)?);
    }
    
    // Apply configuration
    builder.apply()?;
    
    // Print a startup message to confirm logging is working
    info!("TagIO HTTP Tunnel Server logging initialized");
    debug!("Debug logging is enabled");
    
    Ok(())
}

/// Main entry point
#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();
    
    // Force debug logging if explicitly requested
    if args.log_level.to_lowercase() == "debug" {
        std::env::set_var("RUST_LOG", "debug");
    }
    
    // Setup logger
    let log_level = match args.log_level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };
    
    if let Err(e) = setup_logger(log_level, args.log_file.clone()) {
        eprintln!("Warning: Failed to initialize logger: {}", e);
    }
    
    // Print starting message with detailed information
    info!("Starting TagIO HTTP Tunnel Server v{}", env!("CARGO_PKG_VERSION"));
    info!("Binding to port {}", args.port);
    debug!("Debug logging enabled");
    
    if let Some(log_file) = &args.log_file {
        info!("Logging to file: {}", log_file.display());
    }
    
    // Print current time for log correlation
    debug!("Server startup time: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S.%3f"));
    
    // Create bind address
    let bind_addr = SocketAddr::new(
        std::net::IpAddr::from_str("0.0.0.0").unwrap_or_else(|_| {
            error!("Failed to parse IP address, using default");
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))
        }),
        args.port
    );
    
    debug!("Server configuration complete, starting HTTP tunnel server...");
    
    // Start the HTTP tunnel server using our improved implementation
    match http_tunnel::start_http_tunnel_server(bind_addr).await {
        Ok(_) => {
            info!("Server stopped normally");
            Ok(())
        },
        Err(e) => {
            error!("Server error: {}", e);
            Err(e)
        }
    }
}