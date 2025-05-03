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
use rand::Rng;
use futures::{SinkExt, StreamExt};
use hyper_tungstenite::tungstenite::Message as WsMessage;
use hyper_tungstenite::WebSocketStream;

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
                "[ T ] {} {} [{}] {}",
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

/// Generate a unique TagIO ID between 5000-9999 that's not already in use
async fn generate_unique_tagio_id() -> u32 {
    // Use a thread-safe random number generator for async contexts
    let tagio_id = {
        // Scope the RNG so it's dropped before the await points
        let mut rng = rand::thread_rng();
        rng.gen_range(5000..10000)
    };
    
    // Check if the ID already exists in the registry
    let registry = CLIENT_REGISTRY.read().await;
    
    // If the randomly generated ID already exists, find the next available one
    let final_id = if registry.contains_key(&tagio_id) {
        // Try sequential IDs until we find an unused one
        let mut available_id = tagio_id;
        for i in 0..5000 { // Maximum 5000 attempts (covers the entire range of 5000-9999)
            let next_id = 5000 + ((tagio_id - 5000 + i) % 5000);
            if !registry.contains_key(&next_id) {
                available_id = next_id;
                break;
            }
        }
        available_id
    } else {
        tagio_id
    };
    
    // Log the generated ID
    info!("Generated unique TagIO ID: {}", final_id);
    final_id
}

/// Create a TagIO ACK response message
fn create_tagio_ack_response(tagio_id: u32) -> Vec<u8> {
    let mut response = Vec::with_capacity(16);
    // Add TAGIO magic bytes
    response.extend_from_slice(PROTOCOL_MAGIC);
    // Use protocol version 1
    response.extend_from_slice(&[0, 0, 0, 1]);
    // Add ACK message
    response.extend_from_slice(b"ACK");
    // Add TagIO ID in big-endian format instead of little-endian
    response.extend_from_slice(&tagio_id.to_be_bytes());
    response
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
                
                // If client sent PING message, we should send ACK with a unique ID
                if msg_type.contains("PING") {
                    info!("Received PING from client, sending ACK response with assigned TagIO ID");
                    
                    // Generate a unique TagIO ID
                    let tagio_id = generate_unique_tagio_id().await;
                    
                    // Register this client in our registry
                    register_client(tagio_id, client_ip).await;
                    
                    // Create ACK response with the TagIO ID
                    // Protocol format: TAGIO + protocol version (4 bytes) + "ACK" message + TagIO ID (4 bytes)
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
                    // Add ACK message
                    response.extend_from_slice(b"ACK");
                    // Add TagIO ID in big-endian format
                    response.extend_from_slice(&tagio_id.to_be_bytes());
                    
                    debug!("Sending ACK response with TagIO ID {}: {}", tagio_id, hex_dump(&response, response.len()));
                    
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
                        let tagio_id = u32::from_be_bytes([
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
                    let target_id = u32::from_be_bytes([
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
    
    // Simple HTML template that can be expanded if needed
    let html = format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TagIO HTTP Tunnel Server</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; line-height: 1.6; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .status {{ background-color: #e8f5e9; border-left: 5px solid #4caf50; padding: 15px; margin: 20px 0; }}
        .clients {{ background-color: #e3f2fd; border-left: 5px solid #2196f3; padding: 15px; margin: 20px 0; }}
        pre {{ background-color: #f5f5f5; padding: 15px; border-radius: 4px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>TagIO HTTP Tunnel Server</h1>
    
    <div class="status">
        <h2>Server Status: Online</h2>
        <p>The TagIO server is running and ready to accept connections through either HTTP tunneling or WebSocket.</p>
    </div>
    
    <div class="clients">
        <h2>Connected Clients: {}</h2>
        <p>Number of TagIO clients currently registered with the server.</p>
    </div>
    
    <h2>Connection Methods</h2>
    <p>To connect to TagIO, use either:</p>
    <ul>
        <li>HTTP Tunnel: Send TagIO protocol messages in HTTP POST requests</li>
        <li>WebSocket: Connect to /ws endpoint for real-time communication (recommended)</li>
            </ul>
    
    <p>For detailed documentation, please refer to the <a href="https://github.com/YourOrg/TagIO/docs">TagIO documentation</a>.</p>
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

/// Print out the TagIO protocol specification for debugging
fn print_tagio_protocol_spec() {
    println!("[ T ] ===== TAGIO WEBSOCKET PROTOCOL SPECIFICATION =====");
    println!("[ T ] WebSocket clients must follow this binary protocol:");
    println!("[ T ]");
    println!("[ T ] 1. Message Format:");
    println!("[ T ]    All messages start with: TAGIO + Version(4 bytes) + Message Type + [Payload]");
    println!("[ T ]");
    println!("[ T ] 2. To register with server:");
    println!("[ T ]    a. Connect to WebSocket endpoint");
    println!("[ T ]    b. Send any message to receive TagIO ID");
    println!("[ T ]    c. Server will respond with ACK containing your TagIO ID");
    println!("[ T ]    d. Client should confirm by sending REGL with REGISTER:<assigned_id>");
    println!("[ T ]    e. Server will respond with REGLACK message");
    println!("[ T ]");
    println!("[ T ] 3. PING message format (client to server):");
    println!("[ T ]    TAGIO + Version(00 00 00 01) + \"PING\"");
    println!("[ T ]    Binary: 54 41 47 49 4F 00 00 00 01 50 49 4E 47");
    println!("[ T ]");
    println!("[ T ] 4. ACK message format (server to client):");
    println!("[ T ]    TAGIO + Version(00 00 00 01) + \"ACK\" + TagIO ID (4 bytes, big-endian)");
    println!("[ T ]    Example: 54 41 47 49 4F 00 00 00 01 41 43 4B XX XX XX XX");
    println!("[ T ]");
    println!("[ T ] 5. REGL message format (client to server):");
    println!("[ T ]    TAGIO + Version(00 00 00 01) + \"REGL\" + \"REGISTER:<assigned_id>\"");
    println!("[ T ]    Example: 54 41 47 49 4F 00 00 00 01 52 45 47 4C 52 45 47 49 53 54 45 52 3A 37 38 39 30");
    println!("[ T ]");
    println!("[ T ] 6. REGLACK message format (server to client):");
    println!("[ T ]    TAGIO + Version(00 00 00 01) + \"REGLACK\"");
    println!("[ T ]    Example: 54 41 47 49 4F 00 00 00 01 52 45 47 4C 41 43 4B");
    println!("[ T ]");
    println!("[ T ] 7. REGLERR message format (server to client on error):");
    println!("[ T ]    TAGIO + Version(00 00 00 01) + \"REGLERR\" + [Error message]");
    println!("[ T ]    Error types: ID_MISMATCH, INVALID_ID, MISSING_ID, MISSING_REGISTER, INVALID_FORMAT");
    println!("[ T ]    Example: 54 41 47 49 4F 00 00 00 01 52 45 47 4C 45 52 52 49 44 5F 4D 49 53 4D 41 54 43 48");
    println!("[ T ]");
    println!("[ T ] 8. MSG message format (bidirectional):");
    println!("[ T ]    TAGIO + Version(00 00 00 01) + \"MSG\" + Target ID (4 bytes) + [Payload]");
    println!("[ T ]    Example: 54 41 47 49 4F 00 00 00 01 4D 53 47 XX XX XX XX [payload data]");
    println!("[ T ]");
    println!("[ T ] Note: All messages must be sent as BINARY WebSocket frames, not text frames");
    println!("[ T ] ===================================================");
}

/// Find TagIO magic bytes in a byte array, searching the entire array if needed
fn find_tagio_magic(data: &[u8]) -> Option<usize> {
    if data.len() < PROTOCOL_MAGIC.len() {
        return None;
    }
    
    // Check if TAGIO is at the beginning
    if data.starts_with(PROTOCOL_MAGIC) {
        return Some(0);
    }
    
    // Otherwise search through the whole buffer
    find_subsequence(data, PROTOCOL_MAGIC)
}

/// Handle an incoming HTTP request, determining if it's a TagIO protocol message
async fn handle_http_request(req: Request<Body>, debug_mode: bool) -> Result<Response<Body>, hyper::http::Error> {
    // Extract client information
                    let host = req.headers().get("host")
                        .map(|h| h.to_str().unwrap_or("unknown"))
                        .unwrap_or("unknown")
                        .to_string();
                    
                    // Check for WebSocket upgrade request
                    if hyper_tungstenite::is_upgrade_request(&req) {
                        info!("Detected WebSocket upgrade request from {}", host);
                        
        // Extract client IP from headers and save it before moving req
                        let client_ip = req.headers().get("x-forwarded-for")
                            .and_then(|h| h.to_str().ok())
                            .or_else(|| req.headers().get("x-real-ip")
                                .and_then(|h| h.to_str().ok()))
                            .map(|ip| {
                                // Take the first IP if there are multiple in X-Forwarded-For
                                if let Some(pos) = ip.find(',') {
                                    ip[0..pos].trim()
                                } else {
                                    ip.trim()
                                }
                            });
                            
        // Store the client_ip as an owned String for later use
        let client_ip_str = client_ip.unwrap_or("unknown").to_string();
        info!("WebSocket client connecting from IP: {}", client_ip_str);
                        
                        // Convert IP string to a SocketAddr for passing to the handler
                        let peer_addr = client_ip.and_then(|ip| {
                            ip.parse::<std::net::IpAddr>().ok().map(|addr| {
                                SocketAddr::new(addr, 0) // Port isn't important for logging
                            })
                        });
                        
        // Store headers for debugging if needed
        let headers_debug_str = if debug_mode {
            format!("{:#?}", req.headers())
        } else {
            String::new()
        };
        
        // Handle the WebSocket connection
        let upgrade_result = hyper_tungstenite::upgrade(req, None);
        
        match upgrade_result {
            Ok((response, websocket)) => {
                        // Spawn a new task to handle the WebSocket connection
                        tokio::spawn(async move {
                            match websocket.await {
                                Ok(ws_stream) => {
                                    info!("WebSocket connection established");
                                    if let Err(e) = handle_websocket_client_registration(ws_stream, peer_addr).await {
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
                error!("Failed to upgrade WebSocket connection from {}: {}", client_ip_str, e);
                error!("WebSocket upgrade error details: {:#?}", e);
                if debug_mode {
                    error!("WebSocket upgrade failed, request headers were: {}", headers_debug_str);
                }
                return Ok::<_, hyper::http::Error>(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(format!("Failed to upgrade to WebSocket: {}", e)))
                    .unwrap());
            }
        }
                    }
                    
                    // Check Render-specific headers for SSL termination info
                    let x_forwarded_proto = req.headers().get("x-forwarded-proto")
                        .map(|h| h.to_str().unwrap_or("unknown"))
                        .unwrap_or("unknown");
                    let is_https = x_forwarded_proto == "https";
                    
                    if debug_mode {
                        debug!("X-Forwarded-Proto: {}, Is HTTPS: {}", x_forwarded_proto, is_https);
                        debug!("All request headers: {:?}", req.headers());
                    }
                    
    // Log proxy headers
                    info!("Proxy headers - X-Forwarded-Proto: {}, X-Forwarded-For: {:?}, X-Real-IP: {:?}",
                        x_forwarded_proto,
                        req.headers().get("x-forwarded-for"),
                        req.headers().get("x-real-ip"));
                    
    // Enhanced debug logging
                    if debug_mode {
                        info!("Full request details for debugging:");
                        info!("  Method: {}", req.method());
                        info!("  Path: {}", req.uri().path());
                        info!("  Query: {:?}", req.uri().query());
                        info!("  Version: {:?}", req.version());
                        info!("  Headers:");
                        for (name, value) in req.headers() {
                            if let Ok(value_str) = value.to_str() {
                                info!("    {}: {}", name, value_str);
                            } else {
                                info!("    {}: <binary value>", name);
                            }
                        }
                    }
                    
                    // Check headers for TagIO protocol indicators
                    let headers = req.headers().clone();
                    let is_http_upgrade_to_tagio = extract_tagio_from_http(&headers, &[]);
                    
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
                                info!("Request body hex dump: {}", hex_dump(&bytes_vec, bytes_vec.len()));
                            } else if !bytes_vec.is_empty() {
                                info!("Request body preview: {}", hex_dump(&bytes_vec, 50));
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
                    
                    // Look for TagIO protocol markers in headers or body
                    let is_tagio_magic = body_bytes.len() >= PROTOCOL_MAGIC.len() && 
                                   body_bytes.starts_with(PROTOCOL_MAGIC);
                    
                    // Always check the entire body for the magic bytes
    let has_tagio_magic_anywhere = if !is_tagio_magic {
        match find_tagio_magic(&body_bytes) {
                            Some(pos) => {
                                info!("Found TagIO magic at position {}", pos);
                                true
                            },
                            None => false
                        }
                    } else {
        true
                    };
                    
                    let is_tagio = is_tagio_magic || is_http_upgrade_to_tagio || 
                                   extract_tagio_from_http(&headers, &body_bytes) ||
                                   has_tagio_magic_anywhere;
                    
                    if is_tagio {
                        info!("Found TagIO protocol data in request of {} bytes", body_bytes.len());
                        
                        // Skip HTTP headers if they exist, find the TagIO protocol data
                        let actual_body = if !is_tagio_magic && body_bytes.len() > 5 {
                            // Try to find TAGIO marker in the body
            if let Some(pos) = find_tagio_magic(&body_bytes) {
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
                return Ok(Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Body::from(format!("Error handling TagIO over HTTP: {}", e)))
                                    .unwrap());
                            }
                        }
                    } else {
                        debug!("No TagIO protocol data found in the request");
                        info!("Non-TagIO request received, responding with echo");
                        
                        // Return a simple response for testing
        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", "text/plain")
                            .body(Body::from("This is a TagIO HTTP tunnel server. Send TagIO protocol messages in the body of POST requests."))
                            .unwrap())
                    }
}

/// Handle binary WebSocket messages
async fn handle_ws_binary_message(
    data: Vec<u8>, 
    tagio_id: u32, 
    client_ip: &str, 
    ws_sender: &mut futures::stream::SplitSink<WebSocketStream<hyper::upgrade::Upgraded>, WsMessage>
) -> Result<(), anyhow::Error> {
    info!("Received binary WebSocket message with {} bytes from {}", data.len(), client_ip);
    info!("Binary message hex dump: {}", hex_dump(&data, data.len().min(100)));
    
    // Check if the data is a valid TagIO protocol message
    let has_tagio_magic = if data.len() >= PROTOCOL_MAGIC.len() {
        if &data[0..PROTOCOL_MAGIC.len()] == PROTOCOL_MAGIC {
            true
        } else {
            // Try to find TAGIO marker anywhere in the data
            find_tagio_magic(&data).is_some()
        }
    } else {
        false
    };
    
    // Extract the message type if possible
    let msg_type = if has_tagio_magic && data.len() >= PROTOCOL_MAGIC.len() + 4 + 3 { 
        let magic_pos = find_tagio_magic(&data).unwrap_or(0);
        let msg_type_offset = magic_pos + PROTOCOL_MAGIC.len() + 4;
        
        if msg_type_offset < data.len() {
            let msg_type_bytes = &data[msg_type_offset..];
            String::from_utf8_lossy(&msg_type_bytes[..std::cmp::min(msg_type_bytes.len(), 10)]).to_string()
        } else {
            "UNKNOWN".to_string()
        }
    } else {
        "UNKNOWN".to_string()
    };
    
    info!("TagIO message type via WebSocket from {}: {}", client_ip, msg_type);
    
    // Handle REGL message specifically
    if msg_type.contains("REGL") {
        info!("Received REGL message from client {}, handling registration confirmation", client_ip);
        
        // Track if we successfully extracted a valid ID
        let mut id_valid = false;
        let mut error_msg = "INVALID_FORMAT";
        
        // Extract client ID if included in REGISTER message
        if let Some(register_info) = msg_type.find("REGISTER:") {
            if register_info + 9 < msg_type.len() {
                match msg_type[register_info + 9..].parse::<u32>() {
                    Ok(client_provided_id) => {
                        info!("Client provided TagIO ID: {}", client_provided_id);
                        
                        // Verify that the client is using the same ID we assigned
                        if client_provided_id == tagio_id {
                            info!("Client confirmed the correct TagIO ID: {}", tagio_id);
                            id_valid = true;
                        } else {
                            error_msg = "ID_MISMATCH";
                            warn!("Client provided TagIO ID {} doesn't match the assigned ID {}", 
                                  client_provided_id, tagio_id);
                        }
                        
                        // Register or update this client with their provided ID
                        register_client(client_provided_id, client_ip.to_string()).await;
                    },
                    Err(e) => {
                        error_msg = "INVALID_ID";
                        error!("Failed to parse TagIO ID from REGISTER message: {}", e);
                    }
                }
            } else {
                error_msg = "MISSING_ID";
                error!("REGISTER message format invalid, missing ID value");
            }
        } else {
            error_msg = "MISSING_REGISTER";
            error!("REGL message doesn't contain REGISTER instruction");
        }
        
        // Create appropriate response based on validation result
        let mut response = Vec::with_capacity(32);
        // Add TAGIO magic bytes
        response.extend_from_slice(PROTOCOL_MAGIC);
        // Use protocol version 1
        response.extend_from_slice(&[0, 0, 0, 1]);
        
        if id_valid {
            // Add REGLACK message
            response.extend_from_slice(b"REGLACK");
            info!("Sending REGLACK response to client {}", client_ip);
        } else {
            // Add REGLERR message with error reason
            response.extend_from_slice(b"REGLERR");
            response.extend_from_slice(error_msg.as_bytes());
            error!("Sending REGLERR response to client {}: {}", client_ip, error_msg);
        }
        
        info!("Response hex dump: {}", hex_dump(&response, response.len()));
        
        if let Err(e) = ws_sender.send(WsMessage::Binary(response.clone())).await {
            error!("Error sending registration response to {}: {}", client_ip, e);
            return Err(anyhow::anyhow!("Failed to send registration response: {}", e));
        } else {
            info!("Successfully sent registration response to client {}", client_ip);
            return Ok(());
        }
    }
    
    // For other message types, send the standard ACK response
    let response = create_tagio_ack_response(tagio_id);
    
    info!("Sending ACK response with TagIO ID {} via WebSocket to {}", tagio_id, client_ip);
    info!("ACK response hex dump: {}", hex_dump(&response, response.len()));
    
    // Send TagIO protocol data wrapped in a WebSocket binary frame
    if let Err(e) = ws_sender.send(WsMessage::Binary(response.clone())).await {
        error!("Error sending WebSocket ACK response to {}: {}", client_ip, e);
        return Err(anyhow::anyhow!("Failed to send WebSocket ACK response: {}", e));
    } else {
        info!("Successfully sent ACK response with TagIO ID {} to client {}", tagio_id, client_ip);
    }
    
    // Only do additional protocol processing if we detected TagIO data
    if has_tagio_magic {
        info!("Received TagIO protocol message of {} bytes via WebSocket from {}", data.len(), client_ip);
    }
    
    Ok(())
}

/// Handle text WebSocket messages
async fn handle_ws_text_message(
    text: String, 
    tagio_id: u32, 
    client_ip: &str, 
    ws_sender: &mut futures::stream::SplitSink<WebSocketStream<hyper::upgrade::Upgraded>, WsMessage>
) -> Result<(), anyhow::Error> {
    info!("Received text WebSocket message from {}: {}", client_ip, text);
    
    // Create an ACK response for the text message
    let response = create_tagio_ack_response(tagio_id);
    
    info!("Sending ACK response with TagIO ID {} via WebSocket to {}", tagio_id, client_ip);
    info!("ACK response hex dump: {}", hex_dump(&response, response.len()));
    
    // Send ACK as a binary WebSocket message
    if let Err(e) = ws_sender.send(WsMessage::Binary(response)).await {
        error!("Error sending WebSocket ACK response to {}: {}", client_ip, e);
        return Err(anyhow::anyhow!("Failed to send WebSocket ACK response: {}", e));
    } else {
        info!("Successfully sent ACK response with TagIO ID {} to client {}", tagio_id, client_ip);
    }
    
    Ok(())
}

/// Handle WebSocket client registration and message exchange
async fn handle_websocket_client_registration(ws_stream: WebSocketStream<hyper::upgrade::Upgraded>, peer_addr: Option<SocketAddr>) -> Result<(), anyhow::Error> {
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    
    info!("Handling WebSocket connection for TagIO client");
    
    // Generate a unique TagIO ID for this client
    let tagio_id = generate_unique_tagio_id().await;
    let client_ip = match peer_addr {
        Some(addr) => addr.ip().to_string(),
        None => "unknown".to_string()
    };
    
    info!("Client connecting from IP: {}", client_ip);
    
    // Register this client
    register_client(tagio_id, client_ip.clone()).await;
    
    info!("Registered WebSocket client with TagIO ID: {}", tagio_id);
    
    // Send an initial ACK response immediately upon connection to reduce latency
    let response = create_tagio_ack_response(tagio_id);
    
    info!("Sending immediate ACK response with TagIO ID {} via WebSocket to {}", tagio_id, client_ip);
    info!("ACK response hex dump: {}", hex_dump(&response, response.len()));
    
    // CRITICAL FIX: Ensure we're properly wrapping our data in WebSocket binary frames
    // Send the response via WebSocket, wrapped in a binary frame
    if let Err(e) = ws_sender.send(WsMessage::Binary(response.clone())).await {
        error!("Error sending initial WebSocket ACK response to {}: {}", client_ip, e);
        return Ok(());
    } else {
        info!("Successfully sent initial ACK response with TagIO ID {} to client {}", tagio_id, client_ip);
    }
    
    // Wait for client messages
    while let Some(msg_result) = ws_receiver.next().await {
        let msg = match msg_result {
            Ok(msg) => msg,
            Err(e) => {
                error!("Error receiving WebSocket message from {}: {}", client_ip, e);
                error!("WebSocket connection error details: {:#?}", e);
                break;
            }
        };
        
        // Handle different types of WebSocket messages
        let continue_loop = match msg {
            WsMessage::Binary(data) => {
                // Log the received binary data for debugging
                info!("Received binary WebSocket data: {} bytes", data.len());
                if data.len() >= 5 {
                    info!("First 5 bytes: {:02X} {:02X} {:02X} {:02X} {:02X}", 
                          data.get(0).unwrap_or(&0), 
                          data.get(1).unwrap_or(&0),
                          data.get(2).unwrap_or(&0),
                          data.get(3).unwrap_or(&0),
                          data.get(4).unwrap_or(&0));
                }
                
                if let Err(e) = handle_ws_binary_message(data, tagio_id, &client_ip, &mut ws_sender).await {
                    error!("Error handling binary message: {}", e);
                    false
                } else {
                    true
                }
            },
            WsMessage::Text(text) => {
                if let Err(e) = handle_ws_text_message(text, tagio_id, &client_ip, &mut ws_sender).await {
                    error!("Error handling text message: {}", e);
                    false
                } else {
                    true
                }
            },
            WsMessage::Ping(data) => {
                // Respond to ping with pong
                info!("Received WebSocket ping from {}, sending pong", client_ip);
                if let Err(e) = ws_sender.send(WsMessage::Pong(data)).await {
                    error!("Error sending WebSocket pong to {}: {}", client_ip, e);
                    false
                } else {
                    true
                }
            },
            WsMessage::Pong(_) => {
                // Just log pongs
                debug!("Received WebSocket pong from {}", client_ip);
                true
            },
            WsMessage::Close(_) => {
                info!("Received WebSocket close frame from {}", client_ip);
                false
            },
            _ => {
                // Unknown message type
                debug!("Received unknown WebSocket message type from {}", client_ip);
                true
            }
        };
        
        if !continue_loop {
            break;
        }
        
        // Update client's last seen timestamp after each message
        update_client_timestamp(tagio_id).await;
    }
    
    // Remove client from registry when WebSocket closes
    let mut registry = CLIENT_REGISTRY.write().await;
    if let Some(_client) = registry.values().find(|c| c.tagio_id == tagio_id) {
        info!("WebSocket connection closed for client {} with IP {}, removing from registry", tagio_id, client_ip);
        registry.retain(|_, c| c.tagio_id != tagio_id);
    }
    
    info!("WebSocket connection closed for {}", client_ip);
    Ok(())
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
    println!("[ T ] ===== STARTING TAGIO HTTP TUNNEL SERVER v0.3.1 =====");
    info!("TagIO HTTP Tunnel Server starting up with log level: {}", args.log_level);

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