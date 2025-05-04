use anyhow;
use clap::Parser;
use hyper::{Body, Request, Response, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use hyper::server::conn::AddrStream;
use log::{debug, info, error, warn, LevelFilter};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use tokio::net::TcpListener;

// Import our modularized code
use http_tunnel_server::lib::client::{cleanup_stale_clients};
use http_tunnel_server::lib::logger::setup_logger;
use http_tunnel_server::lib::protocol::{print_tagio_protocol_spec, find_tagio_magic};
use http_tunnel_server::lib::http::{extract_tagio_from_http, serve_status_page, handle_tagio_over_http};
use http_tunnel_server::lib::websocket::handle_websocket_with_immediate_ack;
use http_tunnel_server::lib::client::{generate_unique_tagio_id, log_msg};
use http_tunnel_server::lib::protocol;

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

    /// Enable HTTPS/TLS support
    #[clap(long)]
    use_tls: bool,
    
    /// Path to TLS certificate file
    #[clap(long)]
    cert_file: Option<PathBuf>,
    
    /// Path to TLS private key file
    #[clap(long)]
    key_file: Option<PathBuf>,
}

/// Handle an incoming HTTP request, determining if it's a TagIO protocol message
async fn handle_http_request(req: Request<Body>, _debug_mode: bool) -> Result<Response<Body>, hyper::http::Error> {
    // Extract client information
    let host = req.headers().get("host")
        .map(|h| h.to_str().unwrap_or("unknown"))
        .unwrap_or("unknown")
        .to_string();
    
    // Extract headers early before consuming the request
    let headers = req.headers().clone();
    
    // Check for WebSocket upgrade request
    if hyper_tungstenite::is_upgrade_request(&req) {
        info!("Detected WebSocket upgrade request from {}", host);
        
        // Extract client IP from headers
        let client_ip = headers.get("x-forwarded-for")
            .and_then(|h| h.to_str().ok())
            .or_else(|| headers.get("x-real-ip")
                .and_then(|h| h.to_str().ok()))
            .map(|ip| {
                // Take the first IP if there are multiple in X-Forwarded-For
                if let Some(pos) = ip.find(',') {
                    ip[0..pos].trim()
                } else {
                    ip.trim()
                }
            }).unwrap_or("unknown").to_string();
            
        info!("WebSocket client connecting from IP: {}", client_ip);
        
        // Convert IP string to a SocketAddr for passing to the handler
        let peer_addr = client_ip.parse::<std::net::IpAddr>().ok().map(|addr| {
            SocketAddr::new(addr, 0) // Port isn't important for logging
        });
        
        // Handle the WebSocket connection
        let upgrade_result = hyper_tungstenite::upgrade(req, None);
        
        match upgrade_result {
            Ok((response, websocket)) => {
                // Generate a unique TagIO ID for immediate use
                let tagio_id = generate_unique_tagio_id().await;
                info!("Generated TagIO ID {} for WebSocket client {}", tagio_id, client_ip);
                
                // Create ACK response with the TagIO ID
                let ack_message = protocol::create_tagio_ack_response(tagio_id);
                
                // Log the ACK message for debugging
                info!("ACK message prepared for immediate sending after handshake - {} bytes", ack_message.len());
                
                // Spawn a new task to handle the WebSocket connection
                tokio::spawn(async move {
                    match websocket.await {
                        Ok(ws_stream) => {
                            info!("WebSocket connection established, sending immediate ACK with TagIO ID {}", tagio_id);
                            // Handle the WebSocket connection with immediate ACK message
                            if let Err(e) = handle_websocket_with_immediate_ack(ws_stream, peer_addr, tagio_id, ack_message).await {
                                error!("Error in WebSocket connection: {}", e);
                            }
                        },
                        Err(e) => {
                            error!("Error upgrading WebSocket connection: {}", e);
                        }
                    }
                });
                
                // Return the response to complete the WebSocket handshake
                return Ok(response);
            },
            Err(e) => {
                error!("Failed to upgrade WebSocket connection from {}: {}", client_ip, e);
                return Ok::<_, hyper::http::Error>(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(format!("Failed to upgrade to WebSocket: {}", e)))
                    .unwrap());
            }
        }
    }
    
    // Special case for GET requests to root or status
    if req.method() == hyper::Method::GET && 
       (req.uri().path() == "/" || req.uri().path() == "/status") {
        debug!("Serving status page");
        return match serve_status_page().await {
            Ok(response) => Ok(response),
            Err(e) => {
                error!("Error serving status page: {}", e);
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Internal server error"))
                    .unwrap())
            }
        };
    }

    // Get the request body directly
    let body_bytes = match hyper::body::to_bytes(req.into_body()).await {
        Ok(bytes) => {
            let bytes_vec = bytes.to_vec();
            info!("Received request body of {} bytes", bytes_vec.len());
            if !bytes_vec.is_empty() && bytes_vec.len() < 100 {
                info!("Request body hex dump: {}", protocol::hex_dump(&bytes_vec, bytes_vec.len()));
            }
            bytes_vec
        },
        Err(e) => {
            error!("Failed to read request body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(format!("Failed to read request body: {}", e)))
                .unwrap());
        }
    };
    
    // Check for TagIO protocol indicators
    let is_tagio = extract_tagio_from_http(&headers, &body_bytes) || 
                  find_tagio_magic(&body_bytes).is_some();
    
    if is_tagio {
        info!("Found TagIO protocol data in request of {} bytes", body_bytes.len());
        
        match handle_tagio_over_http(body_bytes, Some(&headers)).await {
            Ok(response) => {
                return Ok(response);
            },
            Err(e) => {
                error!("Error handling TagIO over HTTP: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(format!("Error handling TagIO over HTTP: {}", e)))
                    .unwrap());
            }
        }
    } else {
        info!("Non-TagIO request received, responding with echo");
        
        // Return a simple response for testing
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain")
            .body(Body::from("This is a TagIO HTTP tunnel server. Send TagIO protocol messages in the body of POST requests."))
            .unwrap())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args = Args::parse();
    
    // Set up the logger
    let log_level = match args.log_level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };
    
    setup_logger(log_level, args.log_file.clone())?;
    
    // Print banner
    println!("[ T ] ===== STARTING TAGIO HTTP TUNNEL SERVER v0.3.2 =====");
    println!("[ T ] Build timestamp: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
    info!("TagIO HTTP Tunnel Server v0.3.2 starting up with log level: {}", args.log_level);
    info!("Fixed ACK message format and added REGL/REGLACK protocol support");

    // Print protocol specification
    print_tagio_protocol_spec();
    
    // Check for PORT environment variable (for cloud platforms like Render)
    let port = match std::env::var("PORT") {
        Ok(val) => match val.parse::<u16>() {
            Ok(port) => {
                info!("Using PORT environment variable: {}", port);
                port
            },
            Err(_) => {
                warn!("Invalid PORT environment variable: {}, using command line port: {}", val, args.port);
                args.port
            }
        },
        Err(_) => args.port,
    };
    
    // Determine the bind address
    let bind_addr = SocketAddr::new(
        std::net::IpAddr::from_str("0.0.0.0").unwrap(),
        port
    );
    
    // Use a boolean flag for debug mode to avoid lifetime issues
    let debug_enabled = log_level == LevelFilter::Debug || log_level == LevelFilter::Trace;
    
    // Start the background task to clean up stale clients
    tokio::spawn(cleanup_stale_clients());
    
    // Create the HTTP service
    let make_svc = make_service_fn(move |_conn| {
        // Create a clone for moving into the service_fn closure
        let debug_mode = debug_enabled;
        
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                // Clone for the async block
                let debug_mode = debug_mode;
                
                async move {
                    // Log all incoming requests with detailed information 
                    let method = req.method().clone();
                    let path = req.uri().path().to_string();
                    let host = req.headers().get("host")
                        .map(|h| h.to_str().unwrap_or("unknown"))
                        .unwrap_or("unknown")
                        .to_string();
                    
                    info!("Received HTTP request: {} {} from {:?}", method, path, host);
                    
                    // Handle the request
                    handle_http_request(req, debug_mode).await
                }
            }))
        }
    });
    
    // Create and start the server
    let server = hyper::Server::bind(&bind_addr)
        .serve(make_svc);
    
    info!("HTTP tunneling server listening on {}", bind_addr);
    println!("[ T ] HTTP tunneling server listening on {}", bind_addr);
    println!("[ T ] Clients should POST TagIO protocol messages to any endpoint");
    
    if let Err(e) = server.await {
        error!("Server error: {}", e);
        return Err(anyhow::anyhow!("Server error: {}", e));
    }
    
    Ok(())
} 