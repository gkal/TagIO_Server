use anyhow;
use clap::Parser;
use hyper::{Body, Request, Response, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use log::{debug, info, error, warn, LevelFilter};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};

// Constants for protocol magic
const PROTOCOL_MAGIC: &[u8] = b"TAGIO";

// Client registry to track connected clients
#[derive(Clone)]
#[allow(dead_code)] // Allow unused fields as they may be useful in the future
struct ClientInfo {
    tagio_id: u32,
    ip_address: String,
    last_seen: Instant,
}

// Global client registry
lazy_static::lazy_static! {
    static ref CLIENT_REGISTRY: Arc<RwLock<HashMap<u32, ClientInfo>>> = Arc::new(RwLock::new(HashMap::new()));
}

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

/// Helper function to format bytes as a hex dump for logging
fn hex_dump(bytes: &[u8], max_len: usize) -> String {
    let preview_len = std::cmp::min(bytes.len(), max_len);
    let preview: Vec<String> = bytes.iter()
        .take(preview_len)
        .map(|b| format!("{:02X}", b))
        .collect();
    
    let preview_str = preview.join(" ");
    if bytes.len() > max_len {
        format!("{} ... ({} more bytes)", preview_str, bytes.len() - max_len)
    } else {
        preview_str
    }
}

/// Extract TagIO protocol data from HTTP headers and body
fn extract_tagio_from_http(headers: &hyper::HeaderMap, body: &[u8]) -> bool {
    // Check for TagIO protocol indicators in headers
    let has_tagio_header = headers.get("X-TagIO-Protocol").is_some();
    let has_tagio_upgrade = headers.get("Upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("TagIO"))
        .unwrap_or(false);
    let has_tagio_content = headers.get("Content-Type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/tagio"))
        .unwrap_or(false);
    
    // Check for TagIO magic in body
    let has_tagio_magic = body.len() >= PROTOCOL_MAGIC.len() && 
                          &body[0..PROTOCOL_MAGIC.len()] == PROTOCOL_MAGIC;
    
    // Return true if any of the TagIO indicators are present
    has_tagio_header || has_tagio_upgrade || has_tagio_content || has_tagio_magic
}

/// Helper function to register a client in the client registry
async fn register_client(tagio_id: u32, ip_address: String) {
    info!("Registering client with TagIO ID: {} from IP: {}", tagio_id, ip_address);
    
    let mut registry = CLIENT_REGISTRY.write().await;
    registry.insert(tagio_id, ClientInfo {
        tagio_id,
        ip_address,
        last_seen: Instant::now(),
    });
    
    info!("Client registry now contains {} clients", registry.len());
}

/// Helper function to update client's last seen timestamp
async fn update_client_timestamp(tagio_id: u32) {
    if let Some(client) = CLIENT_REGISTRY.write().await.get_mut(&tagio_id) {
        client.last_seen = Instant::now();
        debug!("Updated last seen timestamp for client {}", tagio_id);
    }
}

/// Helper function to get client info by TagIO ID
async fn get_client_by_id(tagio_id: u32) -> Option<ClientInfo> {
    CLIENT_REGISTRY.read().await.get(&tagio_id).cloned()
}

/// Handles HTTP POST requests containing TagIO protocol messages
async fn handle_tagio_over_http(body_bytes: Vec<u8>, headers: Option<&hyper::HeaderMap>) -> Result<Response<Body>, hyper::http::Error> {
    if body_bytes.is_empty() {
        error!("Received empty request body");
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Empty request body"))
            .unwrap());
    }

    debug!("Processing TagIO over HTTP with {} bytes", body_bytes.len());
    debug!("Message hex dump: {}", hex_dump(&body_bytes, 64));

    // Extract client's IP address from headers
    let client_ip = if let Some(headers) = headers {
        headers.get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string()
    } else {
        "unknown".to_string()
    };

    // Log if we have the magic bytes
    if body_bytes.len() >= PROTOCOL_MAGIC.len() {
        let magic_slice = &body_bytes[0..PROTOCOL_MAGIC.len()];
        if magic_slice == PROTOCOL_MAGIC {
            info!("Valid TagIO protocol message received (magic: {})", 
                 String::from_utf8_lossy(magic_slice));
            
            // Add more detailed logging about the client connection
            if let Some(headers) = headers {
                if let Some(client_ip) = headers.get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok()) {
                    info!("Client connecting from IP: {}", client_ip);
                }
            }
            
            // Check for PING message after TAGIO magic bytes
            // TAGIO protocol header is typically 9 bytes:
            // - 5 bytes for "TAGIO" 
            // - 4 bytes for protocol version (00 00 00 01)
            if body_bytes.len() >= PROTOCOL_MAGIC.len() + 4 {
                let msg_type_offset = PROTOCOL_MAGIC.len() + 4;
                let msg_type_bytes = &body_bytes[msg_type_offset..];
                
                // Try to decode the message type as ASCII
                let msg_type = String::from_utf8_lossy(&msg_type_bytes[..std::cmp::min(msg_type_bytes.len(), 10)]);
                info!("TagIO message type: {}", msg_type);
                
                // If client sent PING message, we should send ACK
                if msg_type.contains("PING") {
                    info!("Received PING from client, sending ACK response");
                    
                    // Extract TagIO ID if included in the message (should be right after "PING")
                    if body_bytes.len() >= msg_type_offset + 4 + 4 {  // 4 bytes for "PING" + 4 bytes for ID
                        let id_offset = msg_type_offset + 4;
                        let tagio_id_bytes = &body_bytes[id_offset..id_offset + 4];
                        if tagio_id_bytes.len() == 4 {
                            let tagio_id = u32::from_le_bytes([
                                tagio_id_bytes[0], tagio_id_bytes[1], 
                                tagio_id_bytes[2], tagio_id_bytes[3]
                            ]);
                            
                            // Update client activity
                            update_client_timestamp(tagio_id).await;
                        }
                    }
                    
                    // Create ACK response
                    // Protocol format: TAGIO + protocol version (4 bytes) + "ACK" message
                    let mut response = Vec::with_capacity(12);
                    // Add TAGIO magic bytes
                    response.extend_from_slice(PROTOCOL_MAGIC);
                    // Add protocol version (same as received)
                    if body_bytes.len() >= PROTOCOL_MAGIC.len() + 4 {
                        response.extend_from_slice(&body_bytes[PROTOCOL_MAGIC.len()..PROTOCOL_MAGIC.len() + 4]);
                    } else {
                        // Default to version 1 if not provided
                        response.extend_from_slice(&[0, 0, 0, 1]);
                    }
                    // Add ACK message
                    response.extend_from_slice(b"ACK");
                    
                    debug!("Sending ACK response: {}", hex_dump(&response, response.len()));
                    
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/octet-stream")
                        .header("X-TagIO-Raw-Protocol", "true")
                        .body(Body::from(response))
                        .unwrap());
                }
                // Add handling for REGISTER message with IP and TagIO ID
                else if msg_type.contains("REGISTER") {
                    info!("Received REGISTER from client with IP and TagIO ID");
                    
                    // Extract and log TagIO ID if included in the message
                    if body_bytes.len() >= msg_type_offset + 8 + 4 {  // 8 bytes offset for REGISTER + 4 bytes for ID
                        let id_offset = msg_type_offset + 8;
                        let tagio_id_bytes = &body_bytes[id_offset..id_offset + 4];
                        let tagio_id = u32::from_le_bytes([
                            tagio_id_bytes[0], tagio_id_bytes[1], 
                            tagio_id_bytes[2], tagio_id_bytes[3]
                        ]);
                        
                        // Register this client in our registry
                        register_client(tagio_id, client_ip).await;
                        
                        // For REGISTER message, respond with REG_ACK
                        let mut response = Vec::with_capacity(16);
                        // Add TAGIO magic bytes
                        response.extend_from_slice(PROTOCOL_MAGIC);
                        // Add protocol version (same as received)
                        if body_bytes.len() >= PROTOCOL_MAGIC.len() + 4 {
                            response.extend_from_slice(&body_bytes[PROTOCOL_MAGIC.len()..PROTOCOL_MAGIC.len() + 4]);
                        } else {
                            // Default to version 1 if not provided
                            response.extend_from_slice(&[0, 0, 0, 1]);
                        }
                        // Add REG_ACK message
                        response.extend_from_slice(b"REG_ACK");
                        
                        debug!("Sending REG_ACK response: {}", hex_dump(&response, response.len()));
                        
                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", "application/octet-stream")
                            .header("X-TagIO-Raw-Protocol", "true")
                            .body(Body::from(response))
                            .unwrap());
                    }
                }
                // If the message contains a target client ID, look up that client
                else if msg_type.contains("MSG") && body_bytes.len() >= msg_type_offset + 3 + 4 { // "MSG" + 4 bytes for target ID
                    let target_id_offset = msg_type_offset + 3; // Skip "MSG"
                    let target_id_bytes = &body_bytes[target_id_offset..target_id_offset + 4];
                    let target_id = u32::from_le_bytes([
                        target_id_bytes[0], target_id_bytes[1], 
                        target_id_bytes[2], target_id_bytes[3]
                    ]);
                    
                    info!("Message targeted at client ID: {}", target_id);
                    
                    // Update activity for the target client
                    update_client_timestamp(target_id).await;
                    
                    // Look up the target client in our registry
                    if let Some(target_client) = get_client_by_id(target_id).await {
                        info!("Found target client {} at IP: {}", target_id, target_client.ip_address);
                        // In a real implementation, you might route the message differently
                        // based on the target client's information
                    } else {
                        warn!("Target client {} not found in registry", target_id);
                    }
                }
            }
        } else {
            warn!("Invalid protocol magic: {}", hex_dump(magic_slice, magic_slice.len()));
            warn!("Expected magic: {}", hex_dump(PROTOCOL_MAGIC, PROTOCOL_MAGIC.len()));
        }
    } else {
        warn!("Message too short ({} bytes) to contain TagIO protocol magic", body_bytes.len());
    }

    // If we get here and it's a valid TagIO message but not a recognized type,
    // just echo back the original message
    debug!("Sending generic response with {} bytes", body_bytes.len());
    debug!("Generic response hex dump: {}", hex_dump(&body_bytes, 64));

    // IMPORTANT: Return raw bytes for TagIO protocol without HTTP wrapping
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .header("X-TagIO-Raw-Protocol", "true")
        .body(Body::from(body_bytes))
        .unwrap())
}

/// Serves an HTML status page with TagIO connection instructions
async fn serve_status_page() -> Result<Response<Body>, hyper::http::Error> {
    // Get current count of connected clients
    let client_count = CLIENT_REGISTRY.read().await.len();
    
    let html = format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TagIO HTTP Tunnel Server</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }}
        .status {{
            background-color: #e8f5e9;
            border-left: 5px solid #4caf50;
            padding: 15px;
            margin: 20px 0;
        }}
        pre {{
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
        }}
        .note {{
            background-color: #fff8e1;
            border-left: 5px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
        }}
        .clients {{
            background-color: #e3f2fd;
            border-left: 5px solid #2196f3;
            padding: 15px;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <h1>TagIO HTTP Tunnel Server</h1>
    
    <div class="status">
        <h2>Server Status: Online</h2>
        <p>The TagIO HTTP tunnel server is running and ready to accept connections.</p>
    </div>
    
    <div class="clients">
        <h2>Connected Clients: {}</h2>
        <p>Number of TagIO clients currently registered with the server.</p>
    </div>
    
    <h2>Connection Information</h2>
    <p>To connect to this TagIO HTTP tunnel server, use the following information:</p>
    
    <pre>
Server: This domain (same as in your browser address bar)
Port: 443 (HTTPS)
Protocol: TagIO over HTTP tunneling
</pre>
    
    <div class="note">
        <h3>Important Note for Client Applications</h3>
        <p>This server implements TagIO protocol tunneling over HTTPS. Client applications must wrap TagIO protocol messages 
        in HTTP POST requests to any endpoint. The server is accessible only via HTTPS on the standard port 443.</p>
        <p>You do NOT need to specify any special port in your client configuration.</p>
    </div>
    
    <h2>For Developers</h2>
    <p>TagIO clients should:</p>
    <ol>
        <li>Connect to this server via HTTPS (port 443)</li>
        <li>Send TagIO protocol messages in the body of POST requests</li>
        <li>Read responses from the HTTP response body</li>
        <li>Do not attempt to connect directly to internal port 10000</li>
    </ol>
    
    <p>For more information, please refer to the TagIO documentation.</p>
</body>
</html>
    "#, client_count);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(Body::from(html))
        .unwrap())
}

// Helper function to find a subsequence in a byte array
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    
    'outer: for i in 0..=haystack.len() - needle.len() {
        for (j, &b) in needle.iter().enumerate() {
            if haystack[i + j] != b {
                continue 'outer;
            }
        }
        return Some(i);
    }
    
    None
}

/// Task to clean up stale clients from the registry
async fn cleanup_stale_clients() {
    let stale_timeout = Duration::from_secs(3600); // 1 hour timeout
    
    loop {
        tokio::time::sleep(Duration::from_secs(300)).await; // Run every 5 minutes
        
        let now = Instant::now();
        let mut to_remove = Vec::new();
        
        // Find stale clients
        {
            let registry = CLIENT_REGISTRY.read().await;
            for (&id, client) in registry.iter() {
                if now.duration_since(client.last_seen) > stale_timeout {
                    to_remove.push(id);
                }
            }
        }
        
        // Remove stale clients
        if !to_remove.is_empty() {
            let mut registry = CLIENT_REGISTRY.write().await;
            for id in to_remove.iter() {
                if let Some(client) = registry.remove(id) {
                    info!("Removed stale client {} from IP {} (last seen {} minutes ago)",
                          id, client.ip_address, 
                          now.duration_since(client.last_seen).as_secs() / 60);
                }
            }
            info!("Cleaned up {} stale clients, {} active clients remaining", 
                  to_remove.len(), registry.len());
        }
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
    println!("[T] ===== STARTING TAGIO HTTP TUNNEL SERVER v0.2.1 =====");
    info!("TagIO HTTP Tunnel Server starting up with log level: {}", args.log_level);
    
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
                    
                    // Check Render-specific headers for SSL termination info
                    let x_forwarded_proto = req.headers().get("x-forwarded-proto")
                        .map(|h| h.to_str().unwrap_or("unknown"))
                        .unwrap_or("unknown");
                    let is_https = x_forwarded_proto == "https";
                    
                    if debug_mode {
                        debug!("X-Forwarded-Proto: {}, Is HTTPS: {}", x_forwarded_proto, is_https);
                        debug!("All request headers: {:?}", req.headers());
                    }
                    
                    // Log all important headers related to proxy behavior
                    info!("Proxy headers - X-Forwarded-Proto: {}, X-Forwarded-For: {:?}, X-Real-IP: {:?}",
                        x_forwarded_proto,
                        req.headers().get("x-forwarded-for"),
                        req.headers().get("x-real-ip"));
                    
                    // Check headers for TagIO protocol indicators
                    let headers = req.headers().clone();
                    let is_http_upgrade_to_tagio = extract_tagio_from_http(&headers, &[]);
                    
                    // Special case for GET requests to root or status
                    if req.method() == hyper::Method::GET && 
                       (req.uri().path() == "/" || req.uri().path() == "/status") {
                        debug!("Serving status page");
                        match serve_status_page().await {
                            Ok(response) => return Ok::<_, hyper::http::Error>(response),
                            Err(e) => {
                                error!("Error serving status page: {}", e);
                                return Ok::<_, hyper::http::Error>(Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Body::from("Internal server error"))
                                    .unwrap());
                            }
                        }
                    }

                    // Get the request body directly
                    let body_bytes = match hyper::body::to_bytes(req.into_body()).await {
                        Ok(bytes) => {
                            let bytes_vec = bytes.to_vec();
                            info!("Received request body of {} bytes", bytes_vec.len());
                            if !bytes_vec.is_empty() && bytes_vec.len() < 100 {
                                info!("Request body hex dump: {}", hex_dump(&bytes_vec, bytes_vec.len()));
                            } else if !bytes_vec.is_empty() {
                                info!("Request body preview: {}", hex_dump(&bytes_vec, 50));
                            }
                            bytes_vec
                        },
                        Err(e) => {
                            error!("Failed to read request body: {}", e);
                            return Ok::<_, hyper::http::Error>(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Failed to read request body: {}", e)))
                                .unwrap());
                        }
                    };
                    
                    // Look for TagIO protocol markers in headers or body
                    let is_tagio_magic = body_bytes.len() >= PROTOCOL_MAGIC.len() && 
                                   body_bytes.starts_with(PROTOCOL_MAGIC);
                    
                    // Always check the entire body for the magic bytes
                    let has_tagio_magic_anywhere = if !is_tagio_magic && body_bytes.len() >= PROTOCOL_MAGIC.len() {
                        match find_subsequence(&body_bytes, PROTOCOL_MAGIC) {
                            Some(pos) => {
                                info!("Found TagIO magic at position {}", pos);
                                true
                            },
                            None => false
                        }
                    } else {
                        is_tagio_magic
                    };
                    
                    let is_tagio = is_tagio_magic || is_http_upgrade_to_tagio || 
                                   extract_tagio_from_http(&headers, &body_bytes) ||
                                   has_tagio_magic_anywhere;
                    
                    if is_tagio {
                        info!("Found TagIO protocol data in request of {} bytes", body_bytes.len());
                        
                        // Skip HTTP headers if they exist, find the TagIO protocol data
                        let actual_body = if !is_tagio_magic && body_bytes.len() > 5 {
                            // Try to find TAGIO marker in the body
                            if let Some(pos) = find_subsequence(&body_bytes, PROTOCOL_MAGIC) {
                                debug!("Using TagIO data starting at position {}", pos);
                                &body_bytes[pos..]
                            } else {
                                debug!("No TagIO magic found in body, using entire body");
                                &body_bytes
                            }
                        } else {
                            &body_bytes
                        };
                        
                        info!("Processing TagIO protocol message of {} bytes", actual_body.len());
                        
                        // Collect actual_body bytes into a new Vec for passing ownership
                        let actual_body_owned = actual_body.to_vec();
                        
                        match handle_tagio_over_http(actual_body_owned, Some(&headers)).await {
                            Ok(response) => {
                                return Ok(response);
                            },
                            Err(e) => {
                                error!("Error handling TagIO over HTTP: {}", e);
                                return Ok::<_, hyper::http::Error>(Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Body::from(format!("Error handling TagIO over HTTP: {}", e)))
                                    .unwrap());
                            }
                        }
                    } else {
                        debug!("No TagIO protocol data found in the request");
                        info!("Non-TagIO request received, responding with echo");
                        
                        // Return a simple response for testing
                        Ok::<_, hyper::http::Error>(Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", "text/plain")
                            .body(Body::from("This is a TagIO HTTP tunnel server. Send TagIO protocol messages in the body of POST requests."))
                            .unwrap())
                    }
                }
            }))
        }
    });
    
    // Create and start the server
    let server = hyper::Server::bind(&bind_addr)
        .serve(make_svc);
    
    info!("HTTP tunneling server listening on {}", bind_addr);
    println!("[T] HTTP tunneling server listening on {}", bind_addr);
    println!("[T] Clients should POST TagIO protocol messages to any endpoint");
    
    if let Err(e) = server.await {
        error!("Server error: {}", e);
        return Err(anyhow::anyhow!("Server error: {}", e));
    }
    
    Ok(())
}