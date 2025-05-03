use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use anyhow::Result;
use clap::Parser;
use log::{info, error, LevelFilter};
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
    let mut builder = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[T] {} {} [{}] {}",
                chrono::Local::now().format("%a %d/%m/%Y %H:%M:%S"),
                record.level(),
                record.target(),
                message
            ))
        })
        .level(level);
    
    // Log to stdout
    builder = builder.chain(std::io::stdout());
    
    // Log to file if specified
    if let Some(log_file) = log_file {
        builder = builder.chain(fern::log_file(log_file)?);
    }
    
    // Apply configuration
    builder.apply()?;
    
    Ok(())
}

/// Main entry point
#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();
    
    // Setup logger
    let log_level = match args.log_level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };
    
    if let Err(e) = setup_logger(log_level, args.log_file) {
        eprintln!("Warning: Failed to initialize logger: {}", e);
    }
    
    // Print starting message
    info!("Starting TagIO HTTP Tunnel Server v{}", env!("CARGO_PKG_VERSION"));
    info!("Binding to port {}", args.port);
    
    // Create bind address
    let bind_addr = SocketAddr::new(
        std::net::IpAddr::from_str("0.0.0.0").unwrap_or_else(|_| {
            error!("Failed to parse IP address, using default");
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))
        }),
        args.port
    );
    
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