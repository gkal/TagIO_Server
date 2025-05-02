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

// Keep alive timeout
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(60);
// Buffer size for reading from clients
const READ_BUFFER_SIZE: usize = 8192;
// Maximum number of unauthorized attempts before logging a warning
const MAX_UNAUTHORIZED_ATTEMPTS: usize = 10;
// Health check server ports
const HEALTH_CHECK_PORTS: [u16; 3] = [8888, 8080, 3000];

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
}

impl RelayServer {
    pub fn new(public_ip: Option<String>, auth_secret: Option<String>) -> Self {
        Self {
            clients: Arc::new(TokioMutex::new(HashMap::new())),
            relay_sessions: Arc::new(TokioMutex::new(HashMap::new())),
            public_ip,
            auth_secret: auth_secret.unwrap_or_else(|| DEFAULT_AUTH_SECRET.to_string()),
            unauthorized_attempts: Arc::new(AtomicUsize::new(0)),
        }
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
                                    debug!("Health check request from {}", addr);
                                    
                                    // Spawn a task to handle this health check request
                                    tokio::spawn(async move {
                                        let mut buffer = [0; 1024];
                                        
                                        // Read the HTTP request
                                        match socket.read(&mut buffer).await {
                                            Ok(n) if n > 0 => {
                                                // Simple HTTP server that responds to any request with 200 OK
                                                let response_body = "TagIO Relay Server v0.2.1 Healthy (Render)";
                                                let response = format!("HTTP/1.1 200 OK\r\n\
                                                               Content-Type: text/plain\r\n\
                                                               Content-Length: {}\r\n\
                                                               Connection: close\r\n\
                                                               \r\n\
                                                               {}", response_body.len(), response_body);
                                                
                                                if let Err(e) = socket.write_all(response.as_bytes()).await {
                                                    error!("Failed to send health check response: {}", e);
                                                }
                                            },
                                            Ok(_) => {
                                                // Empty request, just ignore
                                                debug!("Empty health check request");
                                            },
                                            Err(e) => {
                                                error!("Error reading health check request: {}", e);
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
        println!("CLIENT: New connection from {}", addr);
        trace!("Handling new client connection from {}", addr);
        
        let peer_addr = socket.peer_addr()?;
        
        // Determine public address for this client (for NAT traversal)
        let public_addr = if let Some(ip_str) = &self.public_ip {
            match ip_str.parse::<IpAddr>() {
                Ok(ip) => SocketAddr::new(ip, peer_addr.port()),
                Err(_) => {
                    warn!("Invalid configured public IP: {}. Using client reported address.", ip_str);
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
            tokio::spawn(async move {
                // Handle any HTTP responses sent through the channel
                let mut check_http = true;
                
                while check_http || control_rx.recv().await.is_some() {
                    // Check for HTTP response first
                    if check_http {
                        match tokio::time::timeout(Duration::from_millis(1), http_rx.recv()).await {
                            Ok(Some(http_response)) => {
                                debug!("Sending HTTP response to {}", addr);
                                if let Err(e) = write.write_all(http_response.as_bytes()).await {
                                    error!("Error writing HTTP response to {}: {}", addr, e);
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
                        // Only print auth-related messages to reduce output
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
                        match bincode::serialize(&message) {
                            Ok(data) => {
                                // Add magic bytes at the beginning of every message for protocol verification
                                let mut message_data = Vec::with_capacity(PROTOCOL_MAGIC.len() + data.len());
                                message_data.extend_from_slice(&PROTOCOL_MAGIC);
                                message_data.extend_from_slice(&data);
                                
                                // Calculate the total length and prepend it as a 4-byte big-endian uint32
                                let message_len = message_data.len() as u32;
                                let len_bytes = message_len.to_be_bytes(); // Big-endian (network) byte order
                                
                                println!("===== SENDING DATA: length prefix {} bytes + message {} bytes to {} =====", 
                                    len_bytes.len(), message_data.len(), addr);
                                
                                // First write the length prefix
                                if let Err(e) = write.write_all(&len_bytes).await {
                                    println!("===== ERROR: Failed to write length prefix to {} =====", addr);
                                    error!("Error writing length prefix to client {}: {}", addr, e);
                                    break;
                                }
                                
                                // Then write the actual message (magic bytes + serialized data)
                                if let Err(e) = write.write_all(&message_data).await {
                                    println!("===== ERROR: Failed to write message to {} =====", addr);
                                    error!("Error writing message to client {}: {}", addr, e);
                                    break;
                                }
                                
                                println!("===== SENT SUCCESSFULLY: {} bytes to {} =====", 
                                    len_bytes.len() + message_data.len(), addr);
                                trace!("Successfully sent message with length {} to {}", message_len, addr);
                            }
                            Err(e) => {
                                println!("ERROR: Serialization failed for {}: {}", addr, e);
                                error!("Error serializing message for {}: {}", addr, e);
                                break;
                            }
                        }
                    }
                }
                debug!("Client sender task for {} terminated", addr);
            })
        };
        
        // Send version check message immediately upon connection
        if let Err(e) = control_tx.send(NatMessage::VersionCheck { version: PROTOCOL_VERSION }).await {
            println!("===== ERROR: Failed to send version check to {} =====", addr);
            error!("Failed to send version check to {}: {}", addr, e);
            return Err(anyhow!("Failed to send version check"));
        }
        
        // Buffer for incoming data
        let mut buffer = vec![0u8; READ_BUFFER_SIZE];
        let mut client_id = String::new();
        let mut authenticated = false;
        let mut _version_checked = false;
        
        info!("PROTOCOL CHECK: Waiting for client {} to identify protocol", addr);
        
        // Process messages from the client
        loop {
            // Read with timeout to detect dead connections
            match timeout(KEEP_ALIVE_TIMEOUT, read.read(&mut buffer)).await {
                Ok(Ok(0)) => {
                    // Connection closed by client
                    println!("===== CLIENT DISCONNECTED: {} =====", addr);
                    debug!("Client {} disconnected", addr);
                    break;
                },
                Ok(Ok(n)) => {
                    println!("===== RECEIVED DATA: {} bytes from {} =====", n, addr);
                    // Check for HTTP request (clients sometimes try HTTP first)
                    if !authenticated && (
                        buffer.starts_with(b"GET ") || 
                        buffer.starts_with(b"POST ") || 
                        buffer.starts_with(b"HTTP") ||
                        // Also detect other common HTTP methods
                        buffer.starts_with(b"HEAD ") ||
                        buffer.starts_with(b"PUT ") ||
                        buffer.starts_with(b"DELETE ") ||
                        buffer.starts_with(b"OPTIONS ")
                    ) {
                        info!("PROTOCOL DETECTED: HTTP client from {}, sending health response", addr);
                        let response_body = "TagIO Relay Server v0.2.1 Healthy (Render)";
                        let response = format!("HTTP/1.1 200 OK\r\n\
                                               Content-Type: text/plain\r\n\
                                               Content-Length: {}\r\n\
                                               Connection: close\r\n\
                                               \r\n\
                                               {}", response_body.len(), response_body);
                        if let Err(e) = http_tx.send(response).await {
                            error!("Failed to send HTTP response: {}", e);
                        }
                        break;
                    }

                    // Try to read a complete message using the length-prefix protocol
                    // First, check if we have at least 4 bytes for the length prefix
                    if n < 4 {
                        println!("===== ERROR: Received too few bytes for length prefix: {} from {} =====", n, addr);
                        error!("Received too few bytes for length prefix: {} from {}", n, addr);
                        continue;
                    }

                    // Parse the message length from the first 4 bytes
                    let message_len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
                    
                    // Verify the length is reasonable to prevent attacks
                    if message_len > READ_BUFFER_SIZE - 4 {
                        println!("===== ERROR: Message too large: {} bytes from {} =====", message_len, addr);
                        error!("Message too large: {} bytes from {}", message_len, addr);
                        continue;
                    }
                    
                    // Check if we have the complete message
                    if n < 4 + message_len {
                        println!("===== ERROR: Incomplete message: got {} bytes, expected {} bytes from {} =====", 
                            n, 4 + message_len, addr);
                        error!("Incomplete message: got {} bytes, expected {} bytes from {}", 
                            n, 4 + message_len, addr);
                        continue;
                    }
                    
                    // Check for protocol magic bytes
                    if message_len >= PROTOCOL_MAGIC.len() && 
                       buffer[4..4 + PROTOCOL_MAGIC.len()] == PROTOCOL_MAGIC {
                        
                        println!("===== PROTOCOL: Valid TagIO message detected from {} =====", addr);
                        debug!("Valid TagIO protocol magic bytes detected from {}", addr);
                        
                        // Extract the actual message data (after magic bytes)
                        let message_data = &buffer[4 + PROTOCOL_MAGIC.len()..4 + message_len];
                        
                        // Try to deserialize the message
                        match bincode::deserialize::<NatMessage>(message_data) {
                            Ok(message) => {
                                // Process the message based on its type
                                match message {
                                    NatMessage::Authenticate { secret, client_id: id } => {
                                        println!("===== AUTH: Attempt from {} with ID {} =====", addr, id);
                                        info!("Authentication attempt from {} with ID {}", addr, id);
                                        
                                        // Even in a cloud environment, verify authentication
                                        if secret == self.auth_secret {
                                            authenticated = true;
                                            client_id = id.clone();
                                            debug!("Client {} authenticated with ID {}", addr, client_id);
                                            
                                            // Register the client in our tracking system
                                            if let Err(e) = self.register_client(client_id.clone(), public_addr, control_tx.clone()).await {
                                                println!("===== ERROR: Failed to register client {} =====", client_id);
                                                error!("Failed to register client {}: {}", client_id, e);
                                                break;
                                            }
                                            
                                            println!("===== CLIENT REGISTERED: {} at {} =====", client_id, public_addr);
                                            
                                            // Send authentication acknowledgment with public address info
                                            println!("===== SENDING AUTH ACK to {} =====", client_id);
                                            if let Err(e) = control_tx.send(NatMessage::AuthAck { 
                                                public_addr,
                                                message: format!("Authenticated as {} from {}", client_id, public_addr) 
                                            }).await {
                                                println!("===== ERROR: Failed to send auth ack to {} =====", client_id);
                                                error!("Failed to send auth ack to {}: {}", client_id, e);
                                                break;
                                            }
                                        } else {
                                            // Track unauthorized attempts
                                            let attempts = self.unauthorized_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                                            println!("===== AUTH FAIL: Invalid authentication from {} (attempt #{}) =====", addr, attempts);
                                            if attempts % MAX_UNAUTHORIZED_ATTEMPTS == 0 {
                                                warn!("AUTH FAIL: Multiple unauthorized authentication attempts: {}", attempts);
                                            } else {
                                                warn!("AUTH FAIL: Invalid authentication from {}", addr);
                                            }
                                            
                                            // Send error
                                            println!("===== SENDING AUTH ERROR to {} =====", addr);
                                            if let Err(e) = control_tx.send(NatMessage::AuthError { 
                                                message: "Invalid authentication secret".to_string() 
                                            }).await {
                                                println!("===== ERROR: Failed to send auth error to {} =====", addr);
                                                error!("Failed to send auth error: {}", e);
                                            }
                                            break;
                                        }
                                    },
                                    
                                    // Check version compatibility
                                    NatMessage::VersionCheck { version } => {
                                        if version != PROTOCOL_VERSION {
                                            warn!("Protocol version mismatch from {}: got {}, expected {}", 
                                                  addr, version, PROTOCOL_VERSION);
                                            if let Err(e) = control_tx.send(NatMessage::Error { 
                                                message: format!("Protocol version mismatch: server={}, client={}", 
                                                                PROTOCOL_VERSION, version)
                                            }).await {
                                                error!("Failed to send version error message: {}", e);
                                            }
                                            break;
                                        }
                                        _version_checked = true;
                                    },
                                    
                                    // STUN-like binding request for NAT detection
                                    NatMessage::StunBindingRequest => {
                                        if authenticated {
                                            debug!("Received STUN binding request from client {}", client_id);
                                            
                                            // Send back the client's public address
                                            if let Err(e) = control_tx.send(NatMessage::StunBindingResponse { 
                                                public_addr 
                                            }).await {
                                                error!("Failed to send STUN binding response: {}", e);
                                            } else {
                                                debug!("Sent STUN binding response to {}: {}", client_id, public_addr);
                                                
                                                // Try to detect the client's NAT type if we have enough information
                                                if !client_id.is_empty() {
                                                    if let Err(e) = self.detect_nat_type(&client_id, public_addr, control_tx.clone()).await {
                                                        debug!("NAT detection error for {}: {}", client_id, e);
                                                    }
                                                }
                                            }
                                        } else {
                                            warn!("Unauthenticated STUN binding request from {}", addr);
                                            if let Err(e) = control_tx.send(NatMessage::Error { 
                                                message: "Authentication required".to_string() 
                                            }).await {
                                                error!("Failed to send auth required error: {}", e);
                                            }
                                        }
                                    },
                                    
                                    // Connect request
                                    NatMessage::ConnectRequest { target_id } => {
                                        if authenticated {
                                            debug!("Connect request from {} to {}", client_id, target_id);
                                            if let Err(e) = self.handle_connect_request(&client_id, &target_id, control_tx.clone()).await {
                                                warn!("Failed to establish connection from {} to {}: {}", client_id, target_id, e);
                                            }
                                        } else {
                                            warn!("Unauthenticated connect request from {}", addr);
                                            if let Err(e) = control_tx.send(NatMessage::Error { 
                                                message: "Authentication required".to_string() 
                                            }).await {
                                                error!("Failed to send auth required error: {}", e);
                                            }
                                            break;
                                        }
                                    },
                                    
                                    // Relay request
                                    NatMessage::RelayRequest { target_id, session_id } => {
                                        if authenticated {
                                            debug!("Relay request from {} to {} with session {}", client_id, target_id, session_id);
                                            if let Err(e) = self.handle_relay_request(&client_id, &target_id, &session_id, control_tx.clone()).await {
                                                warn!("Failed to establish relay from {} to {}: {}", client_id, target_id, e);
                                            }
                                        } else {
                                            warn!("Unauthenticated relay request from {}", addr);
                                            if let Err(e) = control_tx.send(NatMessage::Error { 
                                                message: "Authentication required".to_string() 
                                            }).await {
                                                error!("Failed to send auth required error: {}", e);
                                            }
                                            break;
                                        }
                                    },
                                    
                                    // Relay data
                                    NatMessage::RelayData { session_id, data } => {
                                        if authenticated {
                                            if let Err(e) = self.handle_relay_data(&session_id, data).await {
                                                debug!("Error relaying data for session {}: {}", session_id, e);
                                            }
                                        } else {
                                            warn!("Unauthenticated relay data from {}", addr);
                                            break;
                                        }
                                    },
                                    
                                    // Ping for keep-alive
                                    NatMessage::Ping => {
                                        // Send pong response
                                        if let Err(e) = control_tx.send(NatMessage::Pong).await {
                                            error!("Failed to send pong to {}: {}", addr, e);
                                            break;
                                        }
                                    },
                                    
                                    // Ignore other messages - they are meant for clients
                                    _ => {
                                        debug!("Ignoring client-bound message from {}: {:?}", addr, message);
                                    }
                                }
                            },
                            Err(e) => {
                                println!("===== ERROR: Failed to deserialize message from {} =====", addr);
                                error!("Failed to deserialize message from {}: {}", addr, e);
                                // Don't break here - could be a corrupted message
                            }
                        }
                    } else {
                        // Invalid protocol magic bytes - this could be a client that doesn't use the TagIO protocol
                        println!("===== PROTOCOL ERROR: Missing or invalid magic bytes from {} =====", addr);
                        warn!("Missing or invalid protocol magic bytes from {}", addr);
                        
                        // Try to guess if the client is attempting an older protocol version
                        // This helps with backwards compatibility for older clients
                        if n > PROTOCOL_MAGIC.len() {
                            match bincode::deserialize::<NatMessage>(&buffer[..n]) {
                                Ok(NatMessage::Authenticate { secret, client_id: id }) => {
                                    println!("===== LEGACY PROTOCOL: Detected authentication attempt without magic bytes from {} =====", addr);
                                    info!("Detected legacy protocol with authentication from {} for ID {}", addr, id);
                                    
                                    // Handle legacy client authentication
                                    if secret == self.auth_secret {
                                        authenticated = true;
                                        client_id = id.clone();
                                        
                                        println!("===== AUTH SUCCESS (LEGACY): Client {} authenticated from {} =====", id, addr);
                                        info!("Legacy client {} successfully authenticated from {}", id, addr);
                                        
                                        // Register the client
                                        if let Err(e) = self.register_client(client_id.clone(), public_addr, control_tx.clone()).await {
                                            println!("===== ERROR: Failed to register legacy client {} =====", id);
                                            error!("Failed to register legacy client {}: {}", id, e);
                                            break;
                                        }
                                        
                                        // Send auth ack in legacy format (without length prefix or magic bytes)
                                        let response = NatMessage::AuthAck {
                                            public_addr,
                                            message: format!("Authenticated as {} from {}", id, public_addr)
                                        };
                                        
                                        if let Ok(data) = bincode::serialize(&response) {
                                            // Send without length prefix for legacy clients
                                            write_task.abort();
                                            
                                            // Write directly to the socket
                                            if let Err(e) = http_tx.send(String::from_utf8_lossy(&data).to_string()).await {
                                                error!("Failed to send legacy auth response: {}", e);
                                            }
                                        }
                                    } else {
                                        // Send auth error for legacy client
                                        println!("===== AUTH FAIL (LEGACY): Invalid authentication from {} =====", addr);
                                        warn!("Legacy client from {} failed authentication", addr);
                                        
                                        let auth_error = NatMessage::AuthError {
                                            message: "Invalid authentication secret".to_string()
                                        };
                                        
                                        if let Ok(data) = bincode::serialize(&auth_error) {
                                            if let Err(e) = http_tx.send(String::from_utf8_lossy(&data).to_string()).await {
                                                error!("Failed to send legacy auth error: {}", e);
                                            }
                                        }
                                    }
                                    continue;
                                },
                                _ => {
                                    // Not a legacy auth message - likely just wrong protocol
                                    // Send an HTTP-like error response so client gets feedback
                                    let error_body = "Invalid protocol: TagIO Relay Server requires TagIO protocol with length prefix and magic bytes";
                                    let response = format!("HTTP/1.1 400 Bad Request\r\n\
                                                   Content-Type: text/plain\r\n\
                                                   Content-Length: {}\r\n\
                                                   Connection: close\r\n\
                                                   \r\n\
                                                   {}", error_body.len(), error_body);
                                    
                                    if let Err(e) = http_tx.send(response).await {
                                        error!("Failed to send protocol error response: {}", e);
                                    }
                                    break;
                                }
                            }
                        } else {
                            // Too short to even try to parse - send error and disconnect
                            let error_body = "Invalid protocol: TagIO Relay Server requires TagIO protocol with length prefix and magic bytes";
                            let response = format!("HTTP/1.1 400 Bad Request\r\n\
                                                   Content-Type: text/plain\r\n\
                                                   Content-Length: {}\r\n\
                                                   Connection: close\r\n\
                                                   \r\n\
                                                   {}", error_body.len(), error_body);
                            
                            if let Err(e) = http_tx.send(response).await {
                                error!("Failed to send protocol error response: {}", e);
                            }
                            break;
                        }
                    }
                },
                Ok(Err(e)) => {
                    error!("Error reading from client {}: {}", addr, e);
                    break;
                },
                Err(_) => {
                    // Connection timed out
                    debug!("Connection to {} timed out", addr);
                    break;
                }
            }
        }
        
        // Client disconnected, clean up
        debug!("Client connection from {} ended", addr);
        
        // Unregister client if it was authenticated
        if authenticated && !client_id.is_empty() {
            let mut clients = self.clients.lock().await;
            clients.remove(&client_id);
            info!("Client {} unregistered", client_id);
        }
        
        // Cancel writer task
        write_task.abort();
        
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
                    // Enhance logging with more descriptive information
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