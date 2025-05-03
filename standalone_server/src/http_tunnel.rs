use anyhow::Result;
use hyper::{Body, Request, Response, StatusCode};
use log::{debug, info, error};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};
use rand::Rng;
use crate::constants::PROTOCOL_MAGIC;

// Define message types for the TagIO protocol
const PING_MESSAGE: u32 = 7;
const ACK_MESSAGE: u32 = 8;
const REGISTER_MESSAGE: u32 = 9;
const REGISTERED_MESSAGE: u32 = 10;
const ERROR_MESSAGE: u32 = 99;

// Client information
#[derive(Clone)]
pub struct ClientInfo {
    #[allow(dead_code)]
    pub client_id: String,
    pub public_addr: SocketAddr,
    pub last_seen: Instant,
}

// Global client registry
pub type ClientRegistry = Arc<Mutex<HashMap<String, ClientInfo>>>;

// Initialize the client registry
pub fn create_client_registry() -> ClientRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

// Start a periodic cleanup task for the client registry
pub async fn start_client_cleanup(registry: ClientRegistry, cleanup_interval: Duration, client_timeout: Duration) {
    info!("Starting client registry cleanup task (interval: {:?}, timeout: {:?})", 
          cleanup_interval, client_timeout);
          
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(cleanup_interval).await;
            debug!("Running periodic client registry cleanup");
            cleanup_stale_clients(registry.clone(), client_timeout).await;
        }
    });
}

// Remove clients that haven't been active within the timeout period
async fn cleanup_stale_clients(registry: ClientRegistry, timeout: Duration) {
    let now = Instant::now();
    
    let mut reg = registry.lock().await;
    let client_count = reg.len();
    debug!("Client registry cleanup: checking {} clients", client_count);
    
    let stale_ids: Vec<String> = reg
        .iter()
        .filter(|(_, info)| {
            let elapsed = now.duration_since(info.last_seen);
            let is_stale = elapsed > timeout;
            if is_stale {
                debug!("Client ID {} inactive for {:?}, marking as stale", info.client_id, elapsed);
            }
            is_stale
        })
        .map(|(id, _)| id.clone())
        .collect();
    
    let stale_count = stale_ids.len();
    
    for id in stale_ids {
        if let Some(info) = reg.remove(&id) {
            info!("Removed stale client ID {} from registry (IP: {})", id, info.public_addr);
        }
    }
    
    debug!("Client registry cleanup: {} total clients, {} stale clients removed", 
           client_count, stale_count);
}

// Generate a unique random client ID (numeric format: 10000-99999)
fn generate_unique_client_id(registry: &HashMap<String, ClientInfo>) -> String {
    let mut rng = rand::thread_rng();
    let id = rng.gen_range(10000..100000).to_string();
    
    // Keep generating IDs until we find one that isn't used
    if registry.contains_key(&id) {
        return generate_unique_client_id(registry);
    }
    
    id
}

/// Handles HTTP POST requests containing TagIO protocol messages
pub async fn handle_tagio_over_http(req: Request<Body>, client_registry: ClientRegistry, client_addr: SocketAddr) -> Result<Response<Body>> {
    // Get the request body
    let body_bytes = hyper::body::to_bytes(req.into_body()).await?;
    
    debug!("Received TagIO over HTTP request with {} bytes from {}", body_bytes.len(), client_addr);
    info!("Processing TagIO request from client {}", client_addr);

    // Initialize response with a 200 OK status by default
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream");

    // Create response based on the request content
    let response_bytes = if body_bytes.is_empty() {
        // Empty request - return a simple error message
        error!("Empty request received from {}", client_addr);
        let mut error_response = Vec::new();
        error_response.extend_from_slice(&PROTOCOL_MAGIC);
        error_response.extend_from_slice(&ERROR_MESSAGE.to_be_bytes());
        error_response.extend_from_slice(b"Empty request body");
        error_response
    } else if body_bytes.len() < PROTOCOL_MAGIC.len() || !body_bytes.starts_with(&PROTOCOL_MAGIC) {
        // Invalid protocol - return an error with the correct magic header
        error!("Invalid protocol data from {}: missing or incorrect magic bytes", client_addr);
        let mut error_response = Vec::new();
        error_response.extend_from_slice(&PROTOCOL_MAGIC);
        error_response.extend_from_slice(&ERROR_MESSAGE.to_be_bytes());
        error_response.extend_from_slice(b"Invalid TagIO protocol data");
        error_response
    } else {
        // Valid protocol - parse the message
        debug!("Valid TagIO protocol message from {}, processing...", client_addr);
        process_tagio_message(&body_bytes, client_registry, client_addr).await
    };

    debug!("Sending response with {} bytes to {}", response_bytes.len(), client_addr);
    
    // Return the response
    Ok(response.body(Body::from(response_bytes))?)
}

/// Process TagIO protocol messages
async fn process_tagio_message(message: &[u8], registry: ClientRegistry, client_addr: SocketAddr) -> Vec<u8> {
    // Skip the magic header
    let data = &message[PROTOCOL_MAGIC.len()..];
    
    // Not enough data for a message type
    if data.len() < 4 {
        error!("Invalid message format from {}: message too short ({} bytes)", client_addr, data.len());
        let mut error_response = Vec::new();
        error_response.extend_from_slice(&PROTOCOL_MAGIC);
        error_response.extend_from_slice(&ERROR_MESSAGE.to_be_bytes());
        error_response.extend_from_slice(b"Invalid message format");
        return error_response;
    }
    
    // Extract message type
    let message_type = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    debug!("Processing message type {} from {}", message_type, client_addr);
    
    // Process based on message type
    match message_type {
        // PING: Client initiates connection
        PING_MESSAGE => {
            let mut response = Vec::new();
            let reg = registry.lock().await;
            
            // Generate a new unique ID for this client
            let client_id = generate_unique_client_id(&reg);
            
            info!("New client connection from {}, assigning ID: {}", client_addr, client_id);
            debug!("Client {} sent PING message, responding with ACK", client_addr);
            
            // Add protocol magic
            response.extend_from_slice(&PROTOCOL_MAGIC);
            
            // Add ACK message type
            response.extend_from_slice(&ACK_MESSAGE.to_be_bytes());
            
            // Add client ID length and the ID itself
            response.extend_from_slice(&(client_id.len() as u32).to_be_bytes());
            response.extend_from_slice(client_id.as_bytes());
            
            debug!("Sending ACK response with ID {} to client {}", client_id, client_addr);
            response
        },
        
        // REGISTER: Client registers with assigned ID
        REGISTER_MESSAGE => {
            debug!("Client {} sent REGISTER message", client_addr);
            let mut response = Vec::new();
            response.extend_from_slice(&PROTOCOL_MAGIC);
            
            // Skip message type bytes (4 bytes)
            let register_data = &data[4..];
            
            // Check if there's enough data for ID length
            if register_data.len() < 4 {
                error!("Invalid registration data from {}: data too short", client_addr);
                response.extend_from_slice(&ERROR_MESSAGE.to_be_bytes());
                response.extend_from_slice(b"Invalid registration data");
                return response;
            }
            
            // Get ID length
            let id_len = u32::from_be_bytes([
                register_data[0], register_data[1], 
                register_data[2], register_data[3]
            ]) as usize;
            
            // Check if there's enough data for the ID
            if register_data.len() < 4 + id_len {
                error!("Invalid ID length from {}: expected {} bytes but got {}", 
                      client_addr, id_len, register_data.len() - 4);
                response.extend_from_slice(&ERROR_MESSAGE.to_be_bytes());
                response.extend_from_slice(b"Invalid ID length");
                return response;
            }
            
            // Extract the client ID
            let client_id = match std::str::from_utf8(&register_data[4..4+id_len]) {
                Ok(id) => id.to_string(),
                Err(_) => {
                    error!("Invalid ID encoding from {}", client_addr);
                    response.extend_from_slice(&ERROR_MESSAGE.to_be_bytes());
                    response.extend_from_slice(b"Invalid ID encoding");
                    return response;
                }
            };
            
            debug!("Client {} is registering with ID {}", client_addr, client_id);
            
            // Register the client
            let mut reg = registry.lock().await;
            
            // Update or add client info
            reg.insert(client_id.clone(), ClientInfo {
                client_id: client_id.clone(),
                public_addr: client_addr,
                last_seen: Instant::now(),
            });
            
            info!("Client ID {} registered from IP {}", client_id, client_addr);
            
            // Send registration acknowledgment
            response.extend_from_slice(&REGISTERED_MESSAGE.to_be_bytes());
            
            // Add client ID for confirmation
            response.extend_from_slice(&(client_id.len() as u32).to_be_bytes());
            response.extend_from_slice(client_id.as_bytes());
            
            // Add client IP and port
            let ip_str = client_addr.ip().to_string();
            response.extend_from_slice(&(ip_str.len() as u32).to_be_bytes());
            response.extend_from_slice(ip_str.as_bytes());
            response.extend_from_slice(&client_addr.port().to_be_bytes());
            
            debug!("Sending REGISTERED response to client {} with ID {}", client_addr, client_id);
            response
        },
        
        // Unknown message type
        _ => {
            error!("Unknown message type {} from {}", message_type, client_addr);
            let mut response = Vec::new();
            response.extend_from_slice(&PROTOCOL_MAGIC);
            response.extend_from_slice(&ERROR_MESSAGE.to_be_bytes());
            response.extend_from_slice(b"Unknown message type");
            response
        }
    }
}

/// Serves an HTML status page with TagIO connection instructions
pub async fn serve_status_page() -> Result<Response<Body>> {
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TagIO Relay Server</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .status {
            background-color: #e8f5e9;
            border-left: 5px solid #4caf50;
            padding: 15px;
            margin: 20px 0;
        }
        pre {
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
        }
        .note {
            background-color: #fff8e1;
            border-left: 5px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <h1>TagIO Relay Server</h1>
    
    <div class="status">
        <h2>Server Status: Online</h2>
        <p>The TagIO relay server is running and ready to accept connections.</p>
    </div>
    
    <h2>Connection Information</h2>
    <p>To connect to this TagIO relay server, use the following information:</p>
    
    <pre>
Server: This domain (same as in your browser address bar)
Port: 80 (HTTP) or 443 (HTTPS)
Protocol: TagIO over HTTP tunneling
    </pre>
    
    <div class="note">
        <h3>Important Note for Client Applications</h3>
        <p>This server implements TagIO protocol tunneling over HTTP. Client applications must wrap TagIO protocol messages 
        in HTTP POST requests to the /tagio endpoint.</p>
    </div>
    
    <h2>For Developers</h2>
    <p>TagIO clients should:</p>
    <ol>
        <li>Connect to this server via HTTP or HTTPS</li>
        <li>Send TagIO protocol messages in the body of POST requests to /tagio</li>
        <li>Read responses from the HTTP response body</li>
    </ol>
    
    <p>For more information, please refer to the TagIO documentation.</p>
</body>
</html>
    "#;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(Body::from(html))
        .unwrap())
}

/// Start an HTTP server that can accept TagIO protocol messages over HTTP
pub async fn start_http_tunnel_server(bind_addr: SocketAddr) -> Result<()> {
    // Create the client registry
    info!("Initializing TagIO HTTP tunnel server on {}", bind_addr);
    debug!("Creating client registry");
    let client_registry = create_client_registry();
    
    // Start client cleanup task - check every 5 minutes, timeout after 30 minutes of inactivity
    debug!("Configuring client cleanup parameters");
    let cleanup_interval = Duration::from_secs(5 * 60); // 5 minutes between cleanup cycles
    let client_timeout = Duration::from_secs(30 * 60);  // 30 minutes client timeout
    
    info!("Starting client cleanup task (interval: {}s, timeout: {}s)",
          cleanup_interval.as_secs(), client_timeout.as_secs());
    
    start_client_cleanup(
        client_registry.clone(),
        cleanup_interval,
        client_timeout
    ).await;
    
    // Create the HTTP service
    debug!("Setting up HTTP service handler");
    let registry = client_registry.clone();
    let make_svc = hyper::service::make_service_fn(move |conn: &hyper::server::conn::AddrStream| {
        let registry = registry.clone();
        let client_addr = conn.remote_addr();
        debug!("New connection from {}", client_addr);
        
        async move {
            Ok::<_, std::convert::Infallible>(hyper::service::service_fn(move |req: Request<Body>| {
                let registry = registry.clone();
                debug!("Handling {} request to {} from {}", 
                      req.method(), req.uri().path(), client_addr);
                
                async move {
                    // Route the request based on the path
                    let response = match (req.method(), req.uri().path()) {
                        (&hyper::Method::GET, "/") | (&hyper::Method::GET, "/status") => {
                            info!("Serving status page to {}", client_addr);
                            serve_status_page().await
                        }
                        (_, "/tagio") => {
                            debug!("Handling TagIO request from {}", client_addr);
                            handle_tagio_over_http(req, registry.clone(), client_addr).await
                        }
                        _ => {
                            info!("Request to unknown path {} from {}", req.uri().path(), client_addr);
                            // Return 404 for any other path, but keep it as 200 OK for compatibility
                            Ok(Response::builder()
                                .status(StatusCode::OK)
                                .body(Body::from("Not Found - The requested resource does not exist"))
                                .unwrap())
                        }
                    };
                    
                    match response {
                        Ok(resp) => Ok::<Response<Body>, hyper::http::Error>(resp),
                        Err(e) => {
                            error!("Error handling HTTP request from {}: {}", client_addr, e);
                            // Create a simple error response, but use 200 OK for better client compatibility
                            let error_response = Response::builder()
                                .status(StatusCode::OK)
                                .body(Body::from(format!("Error processing request: {}", e)))
                                .unwrap();
                            Ok::<Response<Body>, hyper::http::Error>(error_response)
                        }
                    }
                }
            }))
        }
    });
    
    // Create and run the server
    info!("Creating HTTP server on {}", bind_addr);
    let server = hyper::Server::bind(&bind_addr)
        .serve(make_svc);
    
    info!("HTTP tunneling server for TagIO started successfully on {}", bind_addr);
    info!("Ready to accept connections...");
    
    // Run the server
    match server.await {
        Ok(_) => {
            info!("HTTP server shut down gracefully");
            Ok(())
        },
        Err(e) => {
            error!("HTTP server error: {}", e);
            Err(anyhow::anyhow!("HTTP server error: {}", e))
        }
    }
} 