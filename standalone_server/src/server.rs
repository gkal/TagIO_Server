use anyhow::{Result, anyhow};
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use std::{
    net::{SocketAddr, IpAddr},
    sync::Arc,
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
};
use log::{debug, error, info, warn, trace};
use crate::messages::{NatMessage, NatTraversalType, NatType, PROTOCOL_VERSION};
use crate::constants::{
    DEFAULT_AUTH_SECRET,
    PROTOCOL_MAGIC,
    MAX_PORT_PREDICTION_RANGE,
    FALLBACK_PORT,
};
use hyper::{Body, Request, Response, StatusCode, service::service_fn};
use hyper::service::make_service_fn;
use std::convert::Infallible;
use crate::protocol_detect;
use crate::http_tunnel;

// Keep alive timeout
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(60);
// Buffer size for reading from clients
const READ_BUFFER_SIZE: usize = 8192;
// Health check server ports
const HEALTH_CHECK_PORTS: [u16; 3] = [8888, 8080, 3000];

// Add allow attribute to silence the warning
#[allow(dead_code)]
const MAX_UNAUTHORIZED_ATTEMPTS: usize = 10;

// Define protocol modes for the server
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProtocolMode {
    Standard,
    HttpTunneling,
}

// Information about a connected client
struct ClientInfo {
    public_addr: SocketAddr,
    control_sender: mpsc::Sender<NatMessage>,
}

// Relay session for direct data forwarding - only the data_sender is needed
struct RelaySession {
    data_sender: mpsc::Sender<Vec<u8>>,
}

// NAT traversal server - runs as a standalone server to facilitate connections
#[derive(Clone)]
pub struct RelayServer {
    clients: Arc<TokioMutex<HashMap<String, ClientInfo>>>,
    relay_sessions: Arc<TokioMutex<HashMap<String, RelaySession>>>,
    public_ip: Option<String>, // Store the server's public IP address
    auth_secret: String, // Authentication secret
    unauthorized_attempts: Arc<AtomicUsize>, // Track unauthorized connection attempts
    #[allow(dead_code)]
    nat_traversal_enabled: bool, // Whether NAT traversal is enabled
    protocol_detection_enabled: bool, // Whether protocol detection is enabled
}

impl RelayServer {
    pub fn new(public_ip: Option<String>, auth_secret: Option<String>) -> Self {
        Self {
            clients: Arc::new(TokioMutex::new(HashMap::new())),
            relay_sessions: Arc::new(TokioMutex::new(HashMap::new())),
            public_ip,
            auth_secret: auth_secret.unwrap_or_else(|| DEFAULT_AUTH_SECRET.to_string()),
            unauthorized_attempts: Arc::new(AtomicUsize::new(0)),
            nat_traversal_enabled: true,
            protocol_detection_enabled: false,
        }
    }
    
    // Set whether NAT traversal is enabled
    #[allow(dead_code)]
    pub fn set_nat_traversal_enabled(&mut self, enabled: bool) {
        self.nat_traversal_enabled = enabled;
    }
    
    // Set whether protocol detection is enabled
    pub fn set_protocol_detection(&mut self, enabled: bool) {
        self.protocol_detection_enabled = enabled;
    }
    
    // Run the server and start accepting connections
    pub async fn run(&self, bind_addr: &str) -> Result<()> {
        println!("STARTING SERVER: Binding to {}", bind_addr);
        info!("Starting NAT traversal relay server...");
        info!("This server is designed to run on tagio-server.onrender.com");
        
        // Try to extract the IP part without the port
        let base_ip = match bind_addr.rsplit_once(':') {
            Some((ip, port_str)) => {
                let port = port_str.parse::<u16>().unwrap_or(10000);
                (ip.to_string(), port)
            },
            None => ("0.0.0.0".to_string(), 10000) // Default to all interfaces if format is invalid
        };
        
        info!("Base IP for binding: {}", base_ip.0);
        
        // Start health check server on a separate task
        let health_server = Self::start_health_check_server(base_ip.0.clone());
        tokio::spawn(health_server);
        
        // Attempt to bind to the primary port
        let primary_addr = format!("{}:{}", base_ip.0, base_ip.1);
        let primary_listener_result = TcpListener::bind(&primary_addr).await;
        
        // Also attempt to bind to the fallback port (443) if different
        let fallback_addr = format!("{}:{}", base_ip.0, FALLBACK_PORT);
        let fallback_listener_result = if base_ip.1 != FALLBACK_PORT {
            TcpListener::bind(&fallback_addr).await.ok()
        } else {
            None
        };
        
        // Check if either binding succeeded
        let primary_listener = match primary_listener_result {
            Ok(listener) => {
                info!("Successfully bound to primary address: {}", primary_addr);
                Some(listener)
            },
            Err(e) => {
                warn!("Failed to bind to primary address {}: {}", primary_addr, e);
                None
            }
        };
        
        let fallback_listener = match fallback_listener_result {
            Some(listener) => {
                info!("Successfully bound to fallback address: {}", fallback_addr);
                Some(listener)
            },
            None => {
                if base_ip.1 != FALLBACK_PORT {
                    warn!("Failed to bind to fallback address {}", fallback_addr);
                }
                None
            }
        };
        
        // Ensure we have at least one working listener
        if primary_listener.is_none() && fallback_listener.is_none() {
            error!("Failed to bind to any port");
            return Err(anyhow!("Failed to bind to any port"));
        }
        
        // Spawn tasks to handle connections on both ports
        let server_clone = self.clone();
        if let Some(listener) = primary_listener {
            let server_for_primary = server_clone.clone();
            tokio::spawn(async move {
                server_for_primary.accept_connections(listener).await;
            });
        }
        
        if let Some(listener) = fallback_listener {
            let server_for_fallback = server_clone.clone();
            tokio::spawn(async move {
                server_for_fallback.accept_connections(listener).await;
            });
        }
        
        // Wait indefinitely
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }
    
    // Start a health check HTTP server that can be used by cloud providers to verify the service is running
    async fn start_health_check_server(base_ip: String) -> Result<()> {
        info!("Starting health check HTTP server...");
        println!("HEALTH: Starting health check server on ports {:?}", HEALTH_CHECK_PORTS);
        
        // Try each port in sequence
        for port in HEALTH_CHECK_PORTS.iter() {
            let addr = format!("{}:{}", base_ip, port);
            match TcpListener::bind(&addr).await {
                Ok(listener) => {
                    info!("Health check server successfully bound to {}", addr);
                    println!("HEALTH: Server bound to port {}", port);
                    
                    // Spawn the health check server loop
                    tokio::spawn(async move {
                        loop {
                            match listener.accept().await {
                                Ok((mut socket, addr)) => {
                                    if !is_localhost(&addr) {
                                        debug!("Health check request from {}", addr);
                                    } else {
                                        // Skip logging for localhost health checks entirely
                                        // or log at trace level if needed for debugging
                                        trace!("Health check request from localhost");
                                    }
                                    
                                    // Spawn a task to handle this health check request
                                    tokio::spawn(async move {
                                        let mut buffer = [0; 1024];
                                        
                                        // Read the HTTP request
                                        match socket.read(&mut buffer).await {
                                            Ok(n) if n > 0 => {
                                                // Simple HTTP server that responds to any request with 200 OK
                                                let response_body = "TagIO Relay Server v0.2.1 Healthy (Render)
                                                
Server Status: Running
Protocol: TagIO NAT Traversal Protocol v1
Binding: 0.0.0.0:10000 (internal)
External Access: Port 443 (https) for TagIO protocol
              Port 80 (http) as fallback
              
CLIENT NOTE: Connect to tagio.onrender.com:443 using TagIO protocol
";
                                                let response = format!("HTTP/1.1 200 OK\r\n\
                                                               Content-Type: text/plain\r\n\
                                                               Content-Length: {}\r\n\
                                                               Connection: close\r\n\
                                                               \r\n\
                                                               {}", response_body.len(), response_body);
                                                
                                                if let Err(e) = socket.write_all(response.as_bytes()).await {
                                                    if !is_localhost(&addr) {
                                                        error!("Failed to send health check response: {}", e);
                                                    }
                                                }
                                            },
                                            Ok(_) => {
                                                // Empty request, just ignore
                                                if !is_localhost(&addr) {
                                                    debug!("Empty health check request");
                                                }
                                            },
                                            Err(e) => {
                                                if !is_localhost(&addr) {
                                                    error!("Error reading health check request: {}", e);
                                                }
                                            }
                                        }
                                    });
                                },
                                Err(e) => {
                                    error!("Error accepting health check connection: {}", e);
                                }
                            }
                        }
                    });
                    
                    // Return success after starting the server
                    return Ok(());
                },
                Err(e) => {
                    warn!("Failed to bind health check server to {}: {}", addr, e);
                    println!("HEALTH: Failed to bind to port {} - trying next port", port);
                    // Continue with next port
                }
            }
        }
        
        warn!("Failed to start health check server on any port");
        println!("HEALTH WARNING: Could not bind to any health check ports");
        // Don't fail the main server just because health check failed
        Ok(())
    }
    
    // Handle a client connection
    async fn handle_client(&self, socket: TcpStream, addr: SocketAddr) -> Result<()> {
        // Skip ALL logging for localhost connections
        let is_local = is_localhost(&addr);
        
        // Only log for non-localhost connections
        if !is_local {
            println!("CLIENT: New connection from {}", addr);
            trace!("Handling new client connection from {}", addr);
        }
        
        let peer_addr = socket.peer_addr()?;
        
        // Determine public address for this client (for NAT traversal)
        let public_addr = if let Some(ip_str) = &self.public_ip {
            match ip_str.parse::<IpAddr>() {
                Ok(ip) => SocketAddr::new(ip, peer_addr.port()),
                Err(_) => {
                    // Only log warnings for non-localhost connections
                    if !is_local {
                        warn!("Invalid configured public IP: {}. Using client reported address.", ip_str);
                    }
                    peer_addr
                }
            }
        } else {
            peer_addr
        };
        
        // Set up communication channels for this client
        let (control_tx, mut control_rx) = mpsc::channel::<NatMessage>(100);
        
        // Split the socket for concurrent reading and writing
        let (mut read, write) = tokio::io::split(socket);
        
        // Create a channel for HTTP responses that need to be sent outside the task
        let (http_tx, mut http_rx) = mpsc::channel::<String>(5);
        
        // Spawn a task for sending messages to the client
        let write_task = {
            let mut write = write; // Move write into the task
            let is_local = is_local; // Capture is_local for the async closure
            tokio::spawn(async move {
                // Handle any HTTP responses sent through the channel
                let mut check_http = true;
                
                while check_http || control_rx.recv().await.is_some() {
                    // Check for HTTP response first
                    if check_http {
                        match tokio::time::timeout(Duration::from_millis(1), http_rx.recv()).await {
                            Ok(Some(http_response)) => {
                                if !is_local {
                                    debug!("Sending HTTP response to {}", addr);
                                }
                                if let Err(e) = write.write_all(http_response.as_bytes()).await {
                                    if !is_local {
                                        error!("Error writing HTTP response to {}: {}", addr, e);
                                    }
                                    break;
                                }
                                // After sending HTTP response, close the connection
                                break;
                            }
                            _ => {
                                // No HTTP response waiting, continue with normal protocol
                                check_http = false;
                            }
                        }
                    }
                    
                    // Process normal client messages
                    if let Some(message) = control_rx.recv().await {
                        // Only print auth-related messages for non-localhost connections
                        if !is_local {
                            match &message {
                                NatMessage::Authenticate { client_id, .. } => {
                                    println!("AUTH: Attempt from client {} at {}", client_id, addr);
                                },
                                NatMessage::AuthAck { .. } => {
                                    println!("AUTH: Success response to {}", addr);
                                },
                                NatMessage::AuthError { .. } => {
                                    println!("AUTH: Failure response to {}", addr);
                                },
                                _ => {} // Don't log other message types
                            }
                            
                            trace!("Sending message to {}: {:?}", addr, message);
                        }
                        
                        match bincode::serialize(&message) {
                            Ok(data) => {
                                // Add magic bytes at the beginning of every message for protocol verification
                                let mut message_data = Vec::with_capacity(PROTOCOL_MAGIC.len() + data.len());
                                message_data.extend_from_slice(&PROTOCOL_MAGIC);
                                message_data.extend_from_slice(&data);
                                
                                // Calculate the total length and prepend it as a 4-byte big-endian uint32
                                let message_len = message_data.len() as u32;
                                let len_bytes = message_len.to_be_bytes(); // Big-endian (network) byte order
                                
                                // Only log non-localhost connections
                                if !is_local {
                                    println!("===== SENDING DATA: length prefix {} bytes + message {} bytes to {} =====", 
                                        len_bytes.len(), message_data.len(), addr);
                                }
                                
                                // First write the length prefix
                                if let Err(e) = write.write_all(&len_bytes).await {
                                    if !is_local {
                                        println!("===== ERROR: Failed to write length prefix to {} =====", addr);
                                        error!("Error writing length prefix to client {}: {}", addr, e);
                                    }
                                    break;
                                }
                                
                                // Then write the actual message (magic bytes + serialized data)
                                if let Err(e) = write.write_all(&message_data).await {
                                    if !is_local {
                                        println!("===== ERROR: Failed to write message to {} =====", addr);
                                        error!("Error writing message to client {}: {}", addr, e);
                                    }
                                    break;
                                }
                                
                                if !is_local {
                                    println!("===== SENT SUCCESSFULLY: {} bytes to {} =====", 
                                        len_bytes.len() + message_data.len(), addr);
                                    trace!("Successfully sent message with length {} to {}", message_len, addr);
                                }
                            }
                            Err(e) => {
                                if !is_local {
                                    println!("ERROR: Serialization failed for {}: {}", addr, e);
                                    error!("Error serializing message for {}: {}", addr, e);
                                }
                                break;
                            }
                        }
                    }
                }
                if !is_local {
                    debug!("Client sender task for {} terminated", addr);
                }
            })
        };
        
        // Buffer for incoming data
        let mut buffer = vec![0u8; READ_BUFFER_SIZE];
        let mut client_id = String::new();
        let mut authenticated = false;
        let mut _version_checked = false;
        let mut protocol_verified = false; // Track if we've verified this is a TagIO protocol client
        
        if !is_local {
            debug!("Waiting for client {} to identify protocol", addr);
        }
        
        // Process messages from the client
        loop {
            // Read with timeout to detect dead connections
            match timeout(KEEP_ALIVE_TIMEOUT, read.read(&mut buffer)).await {
                Ok(Ok(0)) => {
                    // Connection closed
                    info!("Connection closed by client {}", addr);
                    break;
                },
                Ok(Ok(n)) => {
                    // After the client connection, look for the HTTP-like header from the TagIO client
                    if !authenticated && n >= 20 && buffer.starts_with(b"POST /tagio HTTP/1.1") {
                        // This might be a TagIO client using HTTP headers to bypass proxies
                        
                        // Convert to string to check for TagIO protocol headers
                        if let Ok(header_str) = std::str::from_utf8(&buffer[..std::cmp::min(512, n)]) {
                            if header_str.contains("X-TagIO-Protocol:") && 
                               header_str.contains("Content-Type: application/tagio") {
                                // This is our TagIO client using HTTP headers
                                if !is_local {
                                    info!("Detected TagIO client using HTTP headers from {}", addr);
                                }
                                
                                // Don't treat this as HTTP, allow authentication to proceed
                                protocol_verified = true;
                                
                                // No need to send HTTP response, wait for authentication
                                continue;
                            }
                        }
                    }

                    // If we didn't detect TagIO protocol, check if this is standard HTTP
                    if !authenticated && (
                        buffer.starts_with(b"GET ") || 
                        buffer.starts_with(b"POST ") && !buffer.starts_with(b"POST /tagio") || 
                        buffer.starts_with(b"HTTP") ||
                        buffer.starts_with(b"HEAD ") ||
                        buffer.starts_with(b"PUT ") ||
                        buffer.starts_with(b"DELETE ") ||
                        buffer.starts_with(b"OPTIONS ")
                    ) {
                        // This is an HTTP request, not a TagIO protocol message
                        if !is_local {
                            info!("Received HTTP request from {}. Dropping connection without response.", addr);
                        }
                        // Silently drop the connection without sending a response
                        break;
                    }

                    // First, check if we have at least 4 bytes for the length prefix
                    if n < 4 {
                        if !is_local {
                            println!("===== ERROR: Received too few bytes for length prefix: {} from {} =====", n, addr);
                            error!("Received too few bytes for length prefix: {} from {}", n, addr);
                        }
                        continue;
                    }

                    // Extract message length from first 4 bytes
                    let message_len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
                    
                    // Verify the length is reasonable to prevent attacks
                    if message_len > READ_BUFFER_SIZE - 4 {
                        if !is_local {
                            println!("===== ERROR: Message too large: {} bytes from {} =====", message_len, addr);
                            error!("Message too large: {} bytes", message_len);
                        }
                        continue;
                    }
                    
                    // Check if we have the complete message
                    if n < 4 + message_len {
                        if !is_local {
                            println!("===== ERROR: Incomplete message: got {} bytes, expected {} bytes from {} =====", 
                                n, 4 + message_len, addr);
                            error!("Incomplete message: got {} bytes, expected {} bytes", 
                                n, 4 + message_len);
                        }
                        continue;
                    }
                    
                    // Check for protocol magic bytes
                    if message_len >= PROTOCOL_MAGIC.len() && 
                        buffer[4..4 + PROTOCOL_MAGIC.len()] == PROTOCOL_MAGIC {
                        
                        if !is_local {
                            println!("===== PROTOCOL: Valid TagIO message detected from {} =====", addr);
                        }
                        
                        // If this is the first valid TagIO message we've received, send version check
                        if !protocol_verified {
                            protocol_verified = true;
                            
                            if !is_local {
                                info!("Valid TagIO protocol client detected from {}", addr);
                                
                                // Send version check message after confirming TagIO protocol
                                if let Err(e) = control_tx.send(NatMessage::VersionCheck { 
                                    version: PROTOCOL_VERSION 
                                }).await {
                                    error!("Failed to send version check message: {}", e);
                                    break;
                                }
                            }
                        }
                        
                        // Handle the message contents after magic bytes
                        let message_data = &buffer[4 + PROTOCOL_MAGIC.len()..4 + message_len];
                        
                        // Deserialize the message
                        match bincode::deserialize::<NatMessage>(message_data) {
                            Ok(message) => {
                                match message {
                                    NatMessage::Authenticate { secret, client_id: id } => {
                                        if !is_local {
                                            println!("===== AUTH: Attempt from {} with ID {} =====", addr, id);
                                        }
                                        
                                        // Verify the authentication secret
                                        if secret == self.auth_secret {
                                            authenticated = true;
                                            client_id = id.clone();
                                            
                                            // Register the client in our tracking system
                                            if let Err(e) = self.register_client(client_id.clone(), public_addr, control_tx.clone()).await {
                                                if !is_local {
                                                    println!("===== ERROR: Failed to register client {} =====", client_id);
                                                    error!("Failed to register client {}: {}", client_id, e);
                                                }
                                                break;
                                            }
                                            
                                            if !is_local {
                                                println!("===== CLIENT REGISTERED: {} at {} =====", client_id, public_addr);
                                            }
                                            
                                            // Send authentication acknowledgment with public address info
                                            if !is_local {
                                                println!("===== SENDING AUTH ACK to {} =====", client_id);
                                            }
                                            if let Err(e) = control_tx.send(NatMessage::AuthAck { 
                                                public_addr, 
                                                message: format!("Authenticated as {} from {}", client_id, public_addr) 
                                            }).await {
                                                if !is_local {
                                                    println!("===== ERROR: Failed to send auth ack to {} =====", client_id);
                                                    error!("Failed to send auth ack: {}", e);
                                                }
                                                break;
                                            }
                                            
                                            // Try to detect NAT type
                                            if let Err(e) = self.detect_nat_type(&client_id, public_addr, control_tx.clone()).await {
                                                if !is_local {
                                                    debug!("Failed to detect NAT type: {}", e);
                                                }
                                                // Continue even if NAT detection fails
                                            }
                                            
                                        } else {
                                            // Track unauthorized attempts
                                            let attempts = self.unauthorized_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                                            if !is_local {
                                                println!("===== AUTH FAIL: Invalid authentication from {} (attempt #{}) =====", addr, attempts);
                                                error!("Invalid authentication from {}, attempt #{}", addr, attempts);
                                            }
                                            
                                            // Send error
                                            if !is_local {
                                                println!("===== SENDING AUTH ERROR to {} =====", addr);
                                            }
                                            if let Err(e) = control_tx.send(NatMessage::AuthError { 
                                                message: "Invalid authentication secret".to_string() 
                                            }).await {
                                                if !is_local {
                                                    println!("===== ERROR: Failed to send auth error to {} =====", addr);
                                                    error!("Failed to send auth error: {}", e);
                                                }
                                                break;
                                            }
                                            
                                            // Wait a moment to prevent brute-force attempts
                                            tokio::time::sleep(Duration::from_millis(1000)).await;
                                            break;
                                        }
                                    },
                                    NatMessage::ConnectRequest { target_id } => {
                                        // Client must be authenticated first
                                        if authenticated {
                                            if let Err(e) = self.handle_connect_request(&client_id, &target_id, control_tx.clone()).await {
                                                if !is_local {
                                                    debug!("Error handling connect request: {}", e);
                                                }
                                            }
                                        } else {
                                            if !is_local {
                                                warn!("Unauthenticated client tried to initiate connection");
                                            }
                                            // Ignore requests from unauthenticated clients
                                        }
                                    },
                                    NatMessage::RelayRequest { target_id, session_id } => {
                                        // Client must be authenticated first
                                        if authenticated {
                                            if let Err(e) = self.handle_relay_request(&client_id, &target_id, &session_id, control_tx.clone()).await {
                                                if !is_local {
                                                    debug!("Error handling relay request: {}", e);
                                                }
                                            }
                                        } else {
                                            if !is_local {
                                                warn!("Unauthenticated client tried to request relay");
                                            }
                                            // Ignore requests from unauthenticated clients
                                        }
                                    },
                                    NatMessage::RelayData { session_id, data } => {
                                        // Client must be authenticated first
                                        if authenticated {
                                            if let Err(e) = self.handle_relay_data(&session_id, data).await {
                                                if !is_local {
                                                    trace!("Error handling relay data: {}", e);
                                                }
                                            }
                                        } else {
                                            if !is_local {
                                                warn!("Unauthenticated client tried to send relay data");
                                            }
                                            // Ignore requests from unauthenticated clients
                                        }
                                    },
                                    NatMessage::VersionCheck { .. } => {
                                        _version_checked = true;
                                        // Version is compatible, continue
                                    },
                                    _ => {
                                        // Ignore other message types not intended for server
                                        if !is_local {
                                            debug!("Ignoring client message type that's not processed by server: {:?}", message);
                                        }
                                    }
                                }
                            },
                            Err(e) => {
                                if !is_local {
                                    println!("===== ERROR: Failed to deserialize message from {} =====", addr);
                                    error!("Failed to deserialize message: {}", e);
                                }
                                // Wait a moment to prevent potential spam
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    } else {
                        // Invalid protocol magic bytes - this could be a client that doesn't use the TagIO protocol
                        if !is_local {
                            println!("===== PROTOCOL ERROR: Missing or invalid magic bytes from {} =====", addr);
                        }
                        
                        // For backward compatibility, try to interpret as an older protocol version
                        // that might not use magic bytes
                        if !authenticated {
                            match bincode::deserialize::<NatMessage>(&buffer[..n]) {
                                Ok(NatMessage::Authenticate { secret, client_id: id }) => {
                                    if !is_local {
                                        println!("===== LEGACY PROTOCOL: Detected authentication attempt without magic bytes from {} =====", addr);
                                    }
                                    
                                    // Verify the authentication secret
                                    if secret == self.auth_secret {
                                        authenticated = true;
                                        client_id = id.clone();
                                        
                                        if !is_local {
                                            println!("===== AUTH SUCCESS (LEGACY): Client {} authenticated from {} =====", id, addr);
                                        }
                                        
                                        // Register the client
                                        if let Err(e) = self.register_client(client_id.clone(), public_addr, control_tx.clone()).await {
                                            if !is_local {
                                                println!("===== ERROR: Failed to register legacy client {} =====", id);
                                                error!("Failed to register legacy client {}: {}", id, e);
                                            }
                                            break;
                                        }
                                    } else {
                                        // Send auth error for legacy client
                                        if !is_local {
                                            println!("===== AUTH FAIL (LEGACY): Invalid authentication from {} =====", addr);
                                        }
                                        if let Err(e) = control_tx.send(NatMessage::AuthError { 
                                            message: "Invalid authentication secret (legacy protocol)".to_string() 
                                        }).await {
                                            if !is_local {
                                                error!("Failed to send legacy auth error: {}", e);
                                            }
                                            break;
                                        }
                                    }
                                },
                                _ => {
                                    // Not a legacy authentication attempt, so it's unknown protocol
                                    if !is_local {
                                        error!("Unknown protocol from {}: first bytes: {:?}", 
                                            addr, &buffer[..std::cmp::min(16, n)]);
                                    }
                                    
                                    // Send an HTTP-like error response in case this is a web browser
                                    let http_error = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nIncompatible Protocol: This is a TagIO relay server that requires the TagIO protocol.";
                                    
                                    if let Err(e) = http_tx.send(http_error.to_string()).await {
                                        if !is_local {
                                            error!("Failed to send protocol error response: {}", e);
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                },
                Ok(Err(e)) => {
                    if !is_local {
                        error!("Error reading from socket: {}", e);
                    }
                    break;
                },
                Err(_) => {
                    // Timeout - client is inactive
                    if !is_local {
                        debug!("Client {} timed out after {} seconds of inactivity", 
                            addr, KEEP_ALIVE_TIMEOUT.as_secs());
                    }
                    break;
                }
            }
        }
        
        // Wait for the write task to complete
        // Warning: this could hang if the write task is blocked indefinitely
        // We use a timeout to avoid hanging the server
        match timeout(Duration::from_secs(5), write_task).await {
            Ok(_) => {},
            Err(_) => {
                if !is_local {
                    debug!("Write task for {} did not complete within timeout", addr);
                }
            }
        }
        
        if !is_local {
            debug!("Client connection from {} ended", addr);
        }
        
        Ok(())
    }
    
    // Register a client with the server
    async fn register_client(&self, client_id: String, public_addr: SocketAddr, control_sender: mpsc::Sender<NatMessage>) -> Result<()> {
        let mut clients = self.clients.lock().await;
        
        // Check if client ID already exists
        if clients.contains_key(&client_id) {
            warn!("Client ID {} already registered, overwriting", client_id);
        }
        
        // Store client information
        clients.insert(client_id.clone(), ClientInfo {
            public_addr,
            control_sender,
        });
        
        Ok(())
    }
    
    // Handle a connect request from one client to another
    async fn handle_connect_request(&self, client_id: &str, target_id: &str, control_sender: mpsc::Sender<NatMessage>) -> Result<()> {
        let clients = self.clients.lock().await;
        
        // Check if target client exists
        if let Some(target_client) = clients.get(target_id) {
            debug!("Found target client {}, sending connection request", target_id);
            
            // Get requestor information
            let req_client = match clients.get(client_id) {
                Some(client) => client,
                None => return Err(anyhow!("Requestor client not found")),
            };
            
            // Detailed connection information for NAT traversal
            let req_addr = req_client.public_addr;
            let target_addr = target_client.public_addr;
            
            // Send connection request to target client
            if let Err(e) = target_client.control_sender.send(NatMessage::ConnectionRequest {
                client_id: client_id.to_string(),
                addr: req_addr,
                nat_type: NatTraversalType::HolePunch, // Start with hole punch
            }).await {
                error!("Failed to send connection request to target: {}", e);
                return Err(anyhow!("Failed to send connection request"));
            }
            
            // Send target information to requester
            if let Err(e) = control_sender.send(NatMessage::ConnectionInfo {
                target_id: target_id.to_string(),
                addr: target_addr,
                nat_type: NatTraversalType::HolePunch, // Start with hole punch
                predicted_ports: Self::predict_nat_ports(target_addr.port()), // Add port prediction for symmetric NATs
            }).await {
                error!("Failed to send target info to requester: {}", e);
                return Err(anyhow!("Failed to send target info"));
            }
            
            Ok(())
        } else {
            // Target client not found
            debug!("Target client {} not found", target_id);
            if let Err(e) = control_sender.send(NatMessage::TargetNotFound {
                target_id: target_id.to_string(),
            }).await {
                error!("Failed to send target not found message: {}", e);
            }
            Err(anyhow!("Target client not found"))
        }
    }
    
    // Predict possible NAT ports for symmetric NATs
    // Returns a list of likely port numbers the NAT might use
    fn predict_nat_ports(base_port: u16) -> Vec<u16> {
        let mut predicted_ports = Vec::with_capacity(MAX_PORT_PREDICTION_RANGE as usize * 2 + 3);
        
        // Add the known port
        predicted_ports.push(base_port);
        
        // Common port allocation strategies:
        // 1. Sequential allocation (most common)
        for i in 1..MAX_PORT_PREDICTION_RANGE {
            predicted_ports.push(base_port.wrapping_add(i));
        }
        
        // Some NATs skip over even/odd ports or use specific increments
        for i in 1..5 {
            predicted_ports.push(base_port.wrapping_add(i * 2)); // even increment
            predicted_ports.push(base_port.wrapping_add(i * 2 + 1)); // odd increment
        }
        
        // Some NATs decrement instead
        for i in 1..5 {
            predicted_ports.push(base_port.wrapping_sub(i));
        }
        
        // 2. Port preservation with fallback
        // Some NATs try to preserve the same port number across mappings
        let preserved_port = base_port;
        if !predicted_ports.contains(&preserved_port) {
            predicted_ports.push(preserved_port);
        }
        
        // Remove duplicates and sort for more efficient connection attempts
        predicted_ports.sort_unstable();
        predicted_ports.dedup();
        
        predicted_ports
    }
    
    // Handle a relay request for direct data forwarding
    async fn handle_relay_request(&self, client_id: &str, target_id: &str, session_id: &str, control_sender: mpsc::Sender<NatMessage>) -> Result<()> {
        debug!("Relay request from {} to {} with session {}", client_id, target_id, session_id);
        
        // Get client info
        let clients = self.clients.lock().await;
        
        // Get target client info
        if let Some(target_client) = clients.get(target_id) {
            // Create data channels for the relay
            let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(100);
            
            // Store the relay session
            {
                let mut sessions = self.relay_sessions.lock().await;
                sessions.insert(session_id.to_string(), RelaySession {
                    data_sender: data_tx.clone(),
                });
            }
            
            // Clone target sender for the relay task
            let target_sender = target_client.control_sender.clone();
            // Clone the session_id for the spawned task
            let session_id_for_task = session_id.to_string();
            
            // Create task for relay forwarding
            tokio::spawn(async move {
                while let Some(data) = data_rx.recv().await {
                    if let Err(e) = target_sender.send(NatMessage::RelayData {
                        session_id: session_id_for_task.clone(),
                        data,
                    }).await {
                        error!("Failed to relay data: {}", e);
                        break;
                    }
                }
                debug!("Relay forwarding task for session {} terminated", session_id_for_task);
            });
            
            // Notify both clients about the relay
            control_sender.send(NatMessage::RelayEstablished {
                session_id: session_id.to_string(),
                target_id: target_id.to_string(),
            }).await?;
            
            target_client.control_sender.send(NatMessage::RelayRequested {
                session_id: session_id.to_string(),
                client_id: client_id.to_string(),
            }).await?;
            
            info!("Relay established between {} and {} with session {}", client_id, target_id, session_id);
        } else {
            // Target client not found
            warn!("Relay request for unknown client: {}", target_id);
            control_sender.send(NatMessage::Error {
                message: format!("Target client {} not found", target_id),
            }).await?;
        }
        
        Ok(())
    }
    
    // Handle relay data forwarding
    async fn handle_relay_data(&self, session_id: &str, data: Vec<u8>) -> Result<()> {
        trace!("Relay data for session {} ({} bytes)", session_id, data.len());
        
        // Get relay session
        let sessions = self.relay_sessions.lock().await;
        
        // Forward data if session exists
        if let Some(session) = sessions.get(session_id) {
            if let Err(e) = session.data_sender.send(data).await {
                error!("Failed to forward relay data for session {}: {}", session_id, e);
                return Err(anyhow!("Failed to forward relay data"));
            }
        } else {
            // Session not found
            warn!("Relay data for unknown session: {}", session_id);
            return Err(anyhow!("Unknown relay session"));
        }
        
        Ok(())
    }
    
    // Detect the NAT type of a client
    async fn detect_nat_type(&self, client_id: &str, public_addr: SocketAddr, control_sender: mpsc::Sender<NatMessage>) -> Result<()> {
        debug!("Detecting NAT type for client {}", client_id);
        
        // In a real implementation, we would do multiple tests to determine NAT type
        // For now, we use a simplified detection method based on the available information
        
        // Get the client's registered data
        let clients = self.clients.lock().await;
        let _client_info = match clients.get(client_id) {
            Some(info) => info,
            None => return Err(anyhow!("Client not found")),
        };
        
        // Determine NAT type
        // For a real implementation, we would:
        // 1. Send binding requests from different IPs and ports to detect mapping behavior
        // 2. Check if client can receive unsolicited packets
        // 3. Test for hairpin translation
        
        // For this simplified implementation, we'll just assume common NAT types based on pattern
        let nat_type = if let Some(ref server_ip) = self.public_ip {
            if public_addr.ip().to_string() == *server_ip {
                // Client IP is the same as server's public IP
                // Likely to be Open Internet or Full Cone NAT
                if public_addr.port() < 1024 {
                    // Low ports are often directly mapped, indicating Open Internet
                    NatType::OpenInternet
                } else {
                    // Higher ports often indicate NAT, but with good mapping
                    NatType::FullCone
                }
            } else if public_addr.ip().is_loopback() || is_private_ip(&public_addr.ip()) {
                // Client appears to be in a private network
                // Most likely a Symmetric NAT
                NatType::SymmetricNat
            } else {
                // Default to the most common NAT type (Port Restricted Cone)
                NatType::PortRestrictedCone
            }
        } else {
            // Without server's public IP, we can't make good guesses
            NatType::Unknown
        };
        
        debug!("Detected NAT type for client {}: {:?}", client_id, nat_type);
        
        // Send the detected NAT type to the client
        if let Err(e) = control_sender.send(NatMessage::NatTypeDetected { nat_type }).await {
            error!("Failed to send NAT type to client {}: {}", client_id, e);
            return Err(anyhow!("Failed to send NAT type"));
        }
        
        Ok(())
    }

    // New method to handle accepting connections on a listener
    async fn accept_connections(&self, listener: TcpListener) {
        let local_addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                error!("Failed to get local address: {}", e);
                return;
            }
        };
        
        info!("Server now accepting connections on {}", local_addr);
        
        if let Some(public_ip) = &self.public_ip {
            info!("Server configured with explicit public IP: {}", public_ip);
            info!("Using this IP for all NAT traversal operations");
        } else {
            warn!("No public IP configured. NAT traversal will use cloud provider's assigned IP.");
            info!("For cloud deployment, the server will determine client's public addresses automatically.");
        }
        
        // Accept incoming connections
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    // Completely skip logging for localhost connections
                    if !is_localhost(&addr) {
                        // Only log non-localhost connections
                        println!("===== NEW CONNECTION: Client connected from {} =====", addr);
                        info!("NEW CONNECTION: Client connected from {}", addr);
                        
                        // Clone necessary state for the client handler
                        let server = self.clone();
                        
                        // Handle each client in a separate task
                        tokio::spawn(async move {
                            if let Err(e) = server.handle_client(socket, addr).await {
                                error!("Error handling client {}: {}", addr, e);
                            }
                        });
                    } else {
                        // For localhost connections, just handle them silently
                        let server = self.clone();
                        tokio::spawn(async move {
                            let _ = server.handle_client(socket, addr).await;
                        });
                    }
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                    // Small delay to prevent tight loop in case of persistent error
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

// Utility function to check if an IP address is private
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            // Check RFC1918 private ranges
            ip.octets()[0] == 10 || // 10.0.0.0/8
            (ip.octets()[0] == 172 && (ip.octets()[1] >= 16 && ip.octets()[1] <= 31)) || // 172.16.0.0/12
            (ip.octets()[0] == 192 && ip.octets()[1] == 168) || // 192.168.0.0/16
            // Check other special-use IPv4 addresses
            (ip.octets()[0] == 169 && ip.octets()[1] == 254) || // 169.254.0.0/16 link-local
            ip.octets()[0] == 127 // 127.0.0.0/8 loopback
        },
        IpAddr::V6(ip) => {
            // IPv6 private addresses
            ip.is_unspecified() || 
            ip.is_loopback() || 
            ip.is_unicast_link_local() || 
            ip.is_unique_local() || 
            // The is_unicast_site_local method is deprecated
            // Instead check for prefix fc00::/7 which is used for unique local addresses
            (ip.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

// Utility function to check if an IP address is localhost
fn is_localhost(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => ip.is_loopback() || ip.octets()[0] == 127,
        IpAddr::V6(ip) => ip.is_loopback()
    }
}

// Helper function to detect HTTP protocol
#[allow(dead_code)]
fn is_http_protocol(data: &[u8]) -> bool {
    // Check for common HTTP request methods
    if data.len() < 4 {
        return false;
    }
    
    data.starts_with(b"GET ") || 
    data.starts_with(b"POST") || 
    data.starts_with(b"HEAD") || 
    data.starts_with(b"PUT ") || 
    data.starts_with(b"HTTP")
}

/// Starts the server in standard mode (direct TCP connections)
#[allow(dead_code)]
pub async fn start_server(
    bind_addr: SocketAddr,
    public_ip: IpAddr,
    auth_secret: Option<String>,
    _enable_nat_traversal: bool,
    enable_protocol_detection: bool,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let server = RelayServer::new(Some(public_ip.to_string()), auth_secret);
    
    let server_handle = tokio::spawn(async move {
        server.run_standard_mode(&bind_addr, enable_protocol_detection).await
    });
    
    Ok(server_handle)
}

/// Starts the server with HTTP tunneling support
#[allow(dead_code)]
pub async fn start_server_with_http_tunneling(
    bind_addr: SocketAddr,
    public_ip: IpAddr,
    auth_secret: Option<String>,
    _enable_nat_traversal: bool,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let server = RelayServer::new(Some(public_ip.to_string()), auth_secret);
    
    let server_handle = tokio::spawn(async move {
        server.run_http_tunneling_mode(&bind_addr).await
    });
    
    Ok(server_handle)
}

/// Dummy implementation - this will be replaced with actual functionality
#[allow(dead_code)]
async fn handle_http_request(_socket: TcpStream, _buffer: &[u8]) -> Result<()> {
    Ok(())
}

/// Dummy implementation - this will be replaced with actual functionality
#[allow(dead_code)]
async fn handle_tagio_connection(_socket: TcpStream, _buffer: &[u8]) -> Result<()> {
    Ok(())
}

impl RelayServer {
    /// Run the server in standard mode (direct TCP connections)
    #[allow(dead_code)]
    pub async fn run_standard_mode(&self, bind_addr: &SocketAddr, enable_protocol_detection: bool) -> Result<()> {
        // Bind to the specified address
        let listener = TcpListener::bind(bind_addr).await?;
        info!("Successfully bound to primary address: {}", bind_addr);
        
        // Create a health check HTTP server for the relay server
        Self::start_health_check_server(bind_addr.ip().to_string()).await?;
        
        // Accept and handle connections
        info!("Server now accepting connections on {}", bind_addr);
        if let Some(public_ip) = &self.public_ip {
            info!("Server configured with explicit public IP: {}", public_ip);
            info!("Using this IP for all NAT traversal operations");
        }
        
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    let server = self.clone();
                    
                    // Handle each client in a separate task
                    tokio::spawn(async move {
                        if enable_protocol_detection {
                            if let Err(e) = server.handle_connection_with_protocol_detection(socket, addr).await {
                                error!("Error handling connection from {}: {}", addr, e);
                            }
                        } else {
                            if let Err(e) = server.handle_client(socket, addr).await {
                                error!("Error handling connection from {}: {}", addr, e);
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }
    }
    
    /// Alias for handle_client to maintain compatibility
    #[allow(dead_code)]
    pub async fn handle_connection(&self, socket: TcpStream, addr: SocketAddr) -> Result<()> {
        self.handle_client(socket, addr).await
    }
    
    /// Run the server with HTTP tunneling support
    #[allow(dead_code)]
    pub async fn run_http_tunneling_mode(&self, bind_addr: &SocketAddr) -> Result<()> {
        // Create a channel for communication between HTTP handler and TagIO protocol handler
        let (tagio_tx, mut tagio_rx) = mpsc::channel::<(Vec<u8>, mpsc::Sender<Vec<u8>>)>(100);
        let tagio_tx = Arc::new(TokioMutex::new(Some(tagio_tx)));
        
        // Create a clone of the server for the TagIO protocol handler
        let server = self.clone();
        
        // Start the TagIO protocol handler
        let protocol_handler = tokio::spawn(async move {
            info!("Starting TagIO protocol handler for HTTP tunneling");
            
            while let Some((request_bytes, response_tx)) = tagio_rx.recv().await {
                // Process the TagIO protocol message
                match server.handle_binary_message(request_bytes).await {
                    Ok(response) => {
                        if let Err(e) = response_tx.send(response).await {
                            error!("Failed to send TagIO response: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Error processing TagIO message: {}", e);
                        // Send an error response
                        let error_msg = format!("Error: {}", e);
                        if let Err(e) = response_tx.send(error_msg.into_bytes()).await {
                            error!("Failed to send TagIO error response: {}", e);
                        }
                    }
                }
            }
            
            info!("TagIO protocol handler shut down");
            Ok::<(), anyhow::Error>(())
        });
        
        // Start the health check server on a different port
        Self::start_health_check_server(bind_addr.ip().to_string()).await?;
        
        // Create the HTTP server
        let addr = bind_addr.clone();
        
        // Create a modified version of handle_tagio_over_http that accepts our channel
        let make_svc = make_service_fn(move |_conn| {
            let tagio_tx = tagio_tx.clone();
            
            async {
                Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                    let _tagio_tx = tagio_tx.clone();
                    
                    async move {
                        // Route the request
                        match (req.method(), req.uri().path()) {
                            (&hyper::Method::GET, "/") | (&hyper::Method::GET, "/status") => {
                                http_tunnel::serve_status_page().await
                            }
                            (_, "/tagio") => {
                                // Handle with standard function for now
                                http_tunnel::handle_tagio_over_http(req).await
                            }
                            _ => {
                                // Return 404 for any other path
                                Ok(Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Body::from("Not Found"))
                                    .unwrap())
                            }
                        }
                    }
                }))
            }
        });
        
        // Create and run the HTTP server
        let server = hyper::Server::bind(&addr)
            .serve(make_svc);
        
        info!("HTTP tunneling server listening on {}", addr);
        
        // Run the HTTP server
        if let Err(e) = server.await {
            error!("HTTP server error: {}", e);
        }
        
        // Wait for the protocol handler to finish
        if let Err(e) = protocol_handler.await {
            error!("Protocol handler error: {}", e);
        }
        
        Ok(())
    }
    
    /// Process a TagIO protocol binary message
    #[allow(dead_code)]
    async fn handle_binary_message(&self, request_bytes: Vec<u8>) -> Result<Vec<u8>> {
        // Check if the message has the TagIO protocol magic bytes
        if request_bytes.len() < 4 + PROTOCOL_MAGIC.len() {
            return Err(anyhow!("Message too short"));
        }
        
        // Skip the first 4 bytes (length) and check the magic bytes
        let magic_start = 4;
        let magic_end = magic_start + PROTOCOL_MAGIC.len();
        
        if request_bytes[magic_start..magic_end] != PROTOCOL_MAGIC[..] {
            return Err(anyhow!("Invalid protocol magic bytes"));
        }
        
        // For now, just echo back the request with an acknowledgment
        let mut response_bytes = Vec::with_capacity(request_bytes.len() + 32);
        response_bytes.extend_from_slice(&PROTOCOL_MAGIC);
        response_bytes.extend_from_slice(b"ACKNOWLEDGED");
        response_bytes.extend_from_slice(&request_bytes);
        
        Ok(response_bytes)
    }
    
    /// Handle a connection with protocol detection (HTTP or TagIO)
    #[allow(dead_code)]
    async fn handle_connection_with_protocol_detection(&self, mut socket: TcpStream, addr: SocketAddr) -> Result<()> {
        // Read the first few bytes to detect the protocol
        let mut buffer = [0u8; 512];
        let n = match socket.read(&mut buffer).await {
            Ok(n) => {
                if n == 0 {
                    return Err(anyhow!("Connection closed before protocol detection"));
                }
                n
            }
            Err(e) => return Err(anyhow!("Failed to read from socket: {}", e)),
        };
        
        debug!("Read {} bytes for protocol detection", n);
        
        // Check if this is an HTTP request
        if protocol_detect::is_http_request(&buffer[..n]) {
            debug!("Detected HTTP request from {}", addr);
            handle_http_request(socket, &buffer[..n]).await
        } else if protocol_detect::is_tagio_protocol_http(&buffer[..n]) {
            debug!("Detected TagIO over HTTP header from {}", addr);
            handle_tagio_connection(socket, &buffer[..n]).await
        } else {
            // Assume it's a TagIO protocol connection
            debug!("Detected TagIO protocol connection from {}", addr);
            self.handle_connection(socket, addr).await
        }
    }
} 