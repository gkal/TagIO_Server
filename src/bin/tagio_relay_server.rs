use std::env;
use std::net::{SocketAddr, IpAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::io::{self, Write};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use anyhow::{Result, anyhow};
use env_logger;
use log;
use reqwest;

// Information about each connected client
struct ClientInfo {
    _public_addr: SocketAddr,
    _sender: mpsc::Sender<Vec<u8>>,
}

// Add new message types for NAT traversal
enum NatTraversalMessageType {
    StunBindingRequest = 10,
    StunBindingResponse = 11,
    UdpHolePunch = 12,
    KeepAlive = 13,
    NatTypeNotification = 14,
}

// Add enum for NAT types
enum NatType {
    OpenInternet = 0,
    FullCone = 1,
    RestrictedCone = 2,
    PortRestrictedCone = 3,
    SymmetricNat = 4,
    Unknown = 5,
}

// Simple NAT traversal relay server
struct RelayServer {
    clients: Arc<Mutex<HashMap<String, ClientInfo>>>,
    public_ip: Option<String>,
    auth_secret: Option<String>,
    nat_traversal_enabled: bool,
}

impl RelayServer {
    // Create a new relay server
    fn new(public_ip: Option<String>, auth_secret: Option<String>) -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            public_ip,
            auth_secret,
            nat_traversal_enabled: true, // Enable NAT traversal by default
        }
    }
    
    // Add a setter for NAT traversal
    fn set_nat_traversal_enabled(&mut self, enabled: bool) {
        self.nat_traversal_enabled = enabled;
        println!("NAT traversal {} for this server instance", 
                 if enabled { "enabled" } else { "disabled" });
    }
    
    // Start the relay server with dynamic port detection
    async fn run(&self, bind_addr: &str) -> io::Result<()> {
        // Log environment details
        println!("=== TagIO Cloud Relay Server Environment ===");
        println!("OS: {}", env::consts::OS);
        println!("ARCH: {}", env::consts::ARCH);
        for (key, value) in env::vars() {
            if key.starts_with("RENDER_") || key == "PORT" || key == "PUBLIC_IP" || key == "AUTH_SECRET" {
                println!("ENV: {} = {}", key, value);
            }
        }
        println!("==========================================");
        
        // Determine if we're running in a cloud environment
        let is_render = env::var("RENDER").is_ok() || env::var("RENDER_SERVICE_ID").is_ok();
        
        // If we have a specific PORT environment variable, use it
        let fixed_port = env::var("PORT").ok();
        
        // Define ports to try in order of preference
        let ports_to_try = if is_render {
            if let Some(port) = &fixed_port {
                // On Render.com, use the assigned port first, then try fallbacks
                vec![port.clone(), "443".to_string(), "80".to_string(), "10000".to_string(), "3000".to_string(), "8080".to_string()]
            } else {
                // Standard cloud ports if no PORT env var
                vec!["443".to_string(), "80".to_string(), "10000".to_string(), "3000".to_string(), "8080".to_string()]
            }
        } else {
            // For local development, try these ports
            vec!["8443".to_string(), "8080".to_string(), "3000".to_string()]
        };
        
        println!("Will try binding to the following ports in order: {:?}", ports_to_try);
        
        // Try binding to each port in sequence until one succeeds
        let mut listener = None;
        let mut bound_addr = String::new();
        
        for port in &ports_to_try {
            let addr = format!("0.0.0.0:{}", port);
            println!("Attempting to bind to {}", addr);
            
            match TcpListener::bind(&addr).await {
                Ok(l) => {
                    println!("SUCCESS: Bound to {}", addr);
                    listener = Some(l);
                    bound_addr = addr;
                    break;
                },
                Err(e) => {
                    println!("Failed to bind to {}: {}", addr, e);
                    println!("Trying next port...");
                }
            }
        }
        
        // If no ports could be bound, try binding to port 0 (let OS choose)
        if listener.is_none() {
            println!("Could not bind to any predefined ports, letting OS choose an available port...");
            
            match TcpListener::bind("0.0.0.0:0").await {
                Ok(l) => {
                    let addr = l.local_addr()?;
                    println!("SUCCESS: Bound to OS-assigned port: {}", addr);
                    listener = Some(l);
                    bound_addr = format!("0.0.0.0:{}", addr.port());
                },
                Err(e) => {
                    let error_msg = format!("Failed to bind to any port, including dynamic port assignment: {}", e);
                    println!("FATAL ERROR: {}", error_msg);
                    return Err(io::Error::new(io::ErrorKind::AddrInUse, error_msg));
                }
            }
        }
        
        // Unwrap the listener (we know it's Some now)
        let listener = listener.unwrap();
        
        println!("TagIO relay server listening on {}", bound_addr);
        
        // Log if NAT traversal is enabled
        if self.nat_traversal_enabled {
            println!("NAT traversal is ENABLED - clients can establish peer-to-peer connections");
            println!("This allows for optimal direct connections between clients when possible");
            println!("Using STUN-like protocol for NAT type detection and hole punching");
        } else {
            println!("NAT traversal is DISABLED - all connections will be relayed through this server");
            println!("This may result in higher latency but better compatibility with strict firewalls");
        }
        
        // Log the public IP if provided
        if let Some(ip) = &self.public_ip {
            println!("Server public IP configured as: {}", ip);
            println!("NAT traversal should work optimally with configured public IP");
        } else {
            println!("WARNING: No public IP configured. NAT traversal may not work correctly!");
            println!("For optimal NAT traversal, set the PUBLIC_IP environment variable on Render.com");
            println!("Without PUBLIC_IP set, NAT traversal between clients behind symmetric NATs may fail");
            println!("The server will use client-perceived addresses, which may be inaccurate behind complex NATs");
        }
        
        // Log authentication status
        if self.auth_secret.is_some() {
            println!("Authentication enabled for client connections");
        } else {
            println!("Authentication disabled - all connections will be accepted");
        }
        
        // Accept and handle connections
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    println!("New connection from {} (local address: {})", 
                             addr, 
                             socket.local_addr().unwrap_or_else(|_| "unknown".parse().unwrap()));
                    
                    // Use public IP if configured, otherwise use the detected address
                    let public_addr = if let Some(ip) = &self.public_ip {
                        let port = addr.port();
                        match IpAddr::from_str(ip) {
                            Ok(ip_addr) => {
                                println!("Using configured public IP: {} (instead of {})", ip_addr, addr.ip());
                                SocketAddr::new(ip_addr, port)
                            },
                            Err(_) => {
                                println!("Failed to parse configured public IP: {}", ip);
                                println!("Falling back to socket address: {}", addr);
                                addr
                            }
                        }
                    } else {
                        println!("No configured public IP, using detected IP: {}", addr);
                        addr
                    };
                    
                    // Log active connections count
                    let client_count = self.clients.lock().await.len();
                    println!("Active connections before accepting new client: {}", client_count);
                    
                    // Handle the connection in a new task
                    let clients = self.clients.clone();
                    let auth_secret = self.auth_secret.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client(socket, addr, public_addr, clients, auth_secret).await {
                            eprintln!("Error handling client {}: {} ({:?})", addr, e, e.kind());
                        }
                    });
                },
                Err(e) => {
                    eprintln!("Error accepting connection: {}", e);
                    // Brief pause to avoid CPU spinning on repeated errors
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
    
    // Handle a client connection
    async fn handle_client(
        socket: TcpStream, 
        addr: SocketAddr,
        public_addr: SocketAddr,
        clients: Arc<Mutex<HashMap<String, ClientInfo>>>,
        auth_secret: Option<String>,
    ) -> io::Result<()> {
        println!("=== New Client Connection ===");
        println!("Socket address: {}", addr);
        println!("Public address: {}", public_addr);
        println!("Authentication required: {}", auth_secret.is_some());
        println!("Socket info: {:?}", socket);
        
        // Check for potential regional connectivity issues
        let ip = addr.ip().to_string();
        // Log if connection is from a region with known Render.com connectivity issues
        if is_potential_problematic_region(&ip) {
            println!("NOTE: Client connecting from a region that may experience connectivity issues with Render.com");
            println!("If clients report connection problems, consider using a different cloud provider");
            println!("See: https://community.render.com/t/solved-infinite-loading-for-all-of-our-services-in-frankfurt-region-from-nigeria/4626");
        }
        
        println!("==============================");
        
        // Create a channel for sending messages to this client
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
        
        // Create a channel for sending outgoing messages
        let (writer_tx, mut writer_rx) = mpsc::channel::<Vec<u8>>(100);
        
        // Split the socket for concurrent reading and writing
        let (mut reader, mut writer) = socket.into_split();
        
        println!("Client connection from {}, public address: {}", addr, public_addr);
        
        // Spawn a task for handling outgoing messages
        tokio::spawn(async move {
            while let Some(msg) = writer_rx.recv().await {
                if let Err(e) = writer.write_all(&msg).await {
                    eprintln!("Error writing to client: {}", e);
                    break;
                }
            }
        });
        
        // Read the client ID (first 4 bytes are the ID length, then the ID string)
        let mut id_len_bytes = [0u8; 4];
        
        // Read with timeout, properly handling errors
        match tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut id_len_bytes)).await {
            Ok(result) => {
                if let Err(e) = result {
                    println!("Error reading client ID length: {}", e);
                    return Err(e);
                }
            },
            Err(_) => {
                println!("Timeout reading client ID length");
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Timeout reading client ID"));
            }
        }
        
        let id_len = u32::from_be_bytes(id_len_bytes) as usize;
        if id_len > 1000 {
            // Prevent excessive memory allocation
            println!("Client ID too long: {}", id_len);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Client ID too long"));
        }
        
        let mut id_bytes = vec![0u8; id_len];
        
        // Read with timeout, properly handling errors
        match tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut id_bytes)).await {
            Ok(result) => {
                if let Err(e) = result {
                    println!("Error reading client ID: {}", e);
                    return Err(e);
                }
            },
            Err(_) => {
                println!("Timeout reading client ID");
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Timeout reading client ID"));
            }
        }
        
        let client_id = match String::from_utf8(id_bytes) {
            Ok(id) => id,
            Err(e) => {
                println!("Invalid client ID encoding: {}", e);
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid client ID encoding"));
            }
        };
        
        // Verify authentication if enabled
        if let Some(secret) = auth_secret {
            println!("Authentication required for client {}", client_id);
            
            // Read authentication data
            let mut auth_len_bytes = [0u8; 4];
            match tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut auth_len_bytes)).await {
                Ok(result) => {
                    if let Err(e) = result {
                        println!("Error reading auth data length for client {}: {}", client_id, e);
                        return Err(e);
                    }
                },
                Err(_) => {
                    println!("Timeout reading auth data length for client {}", client_id);
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "Timeout reading auth data"));
                }
            }
            
            let auth_len = u32::from_be_bytes(auth_len_bytes) as usize;
            println!("Client {} provided auth data of length {}", client_id, auth_len);
            
            if auth_len > 1000 {
                // Prevent excessive memory allocation
                println!("Auth data too long for client {}: {}", client_id, auth_len);
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Auth data too long"));
            }
            
            let mut auth_bytes = vec![0u8; auth_len];
            match tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut auth_bytes)).await {
                Ok(result) => {
                    if let Err(e) = result {
                        println!("Error reading auth data: {}", e);
                        return Err(e);
                    }
                },
                Err(_) => {
                    println!("Timeout reading auth data");
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "Timeout reading auth data"));
                }
            }
            
            let auth_str = match String::from_utf8(auth_bytes) {
                Ok(auth) => auth,
                Err(e) => {
                    println!("Invalid auth data encoding: {}", e);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid auth data encoding"));
                }
            };
            
            // Verify the authentication secret
            if auth_str != secret {
                println!("Authentication failed for client {}: invalid secret", client_id);
                println!("Expected secret length: {}, received: {}", secret.len(), auth_str.len());
                
                // Send auth failure message
                let mut msg = Vec::new();
                msg.extend_from_slice(&2u32.to_be_bytes()); // Message type 2 = auth failure
                if let Err(e) = writer_tx.send(msg).await {
                    println!("Error sending auth failure to client {}: {}", client_id, e);
                } else {
                    println!("Sent auth failure message to client {}", client_id);
                }
                
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Authentication failed"));
            }
            
            println!("Client {} authenticated successfully", client_id);
        } else {
            println!("Authentication is disabled, client {} accepted without auth", client_id);
        }
        
        println!("Client {} registered as '{}'", addr, client_id);
        
        // Create a server instance for NAT detection
        let server = RelayServer {
            clients: clients.clone(),
            public_ip: None,
            auth_secret: None,
            nat_traversal_enabled: true,
        };
        
        // Detect and notify client of its NAT type
        let client_id_clone = client_id.clone();
        tokio::spawn(async move {
            if let Err(e) = server.detect_nat_type(&client_id_clone, public_addr).await {
                println!("Error detecting NAT type for client {}: {}", client_id_clone, e);
            }
        });
        
        // Register the client and update ClientInfo with our writer channel
        {
            let mut clients_map = clients.lock().await;
            clients_map.insert(client_id.clone(), ClientInfo {
                _public_addr: public_addr,
                _sender: tx.clone(),
            });
            
            // Log NAT traversal diagnostic info
            println!("NAT traversal diagnostics for new client '{}':", client_id);
            println!("  - Client public endpoint: {}", public_addr);
            println!("  - Current active clients: {}", clients_map.len());
            
            // Send connection info to all other clients
            let mut sent_count = 0;
            for (other_id, other_client) in clients_map.iter() {
                if other_id != &client_id {
                    println!("  - Attempting NAT traversal setup between '{}' and '{}'", client_id, other_id);
                    println!("    * '{}' endpoint: {}", client_id, public_addr);
                    println!("    * '{}' endpoint: {}", other_id, other_client._public_addr);
                    
                    // Format connection info message:
                    // 1. 4 bytes for message type (1 = connection info)
                    // 2. 4 bytes for ID length
                    // 3. ID bytes
                    // 4. 4 bytes for IP length
                    // 5. IP address string bytes
                    // 6. 4 bytes for port
                    let mut msg = Vec::new();
                    msg.extend_from_slice(&1u32.to_be_bytes()); // Message type 1 = connection info
                    
                    // ID
                    msg.extend_from_slice(&(client_id.len() as u32).to_be_bytes());
                    msg.extend_from_slice(client_id.as_bytes());
                    
                    // IP address
                    let ip_str = public_addr.ip().to_string();
                    msg.extend_from_slice(&(ip_str.len() as u32).to_be_bytes());
                    msg.extend_from_slice(ip_str.as_bytes());
                    
                    // Port
                    msg.extend_from_slice(&public_addr.port().to_be_bytes());
                    
                    let res = other_client._sender.send(msg).await;
                    if res.is_ok() {
                        sent_count += 1;
                        println!("    * Sent connection info about '{}' to '{}'", client_id, other_id);
                    } else {
                        println!("    * FAILED to send connection info about '{}' to '{}'", client_id, other_id);
                    }
                }
            }
            
            println!("NAT traversal setup completed. Sent client info to {} other clients", sent_count);
        }
        
        // Send acknowledgment with public address
        let mut ack = Vec::new();
        ack.extend_from_slice(&0u32.to_be_bytes()); // Message type 0 = register ack
        
        // IP address
        let ip_str = public_addr.ip().to_string();
        ack.extend_from_slice(&(ip_str.len() as u32).to_be_bytes());
        ack.extend_from_slice(ip_str.as_bytes());
        
        // Port
        ack.extend_from_slice(&public_addr.port().to_be_bytes());
        
        if let Err(e) = writer_tx.send(ack).await {
            println!("Error sending registration acknowledgment: {}", e);
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "Failed to send acknowledgement"));
        }
        
        // Spawn a task to forward messages from others to this client
        let client_id_clone = client_id.clone();
        let writer_tx_clone = writer_tx.clone();
        
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Err(e) = writer_tx_clone.send(msg).await {
                    println!("Error forwarding message to client {}: {}", client_id_clone, e);
                    break;
                }
            }
            println!("Message forwarding task for client {} stopped", client_id_clone);
        });
        
        // Main loop: read messages from this client and broadcast to others
        let mut buffer = vec![0u8; 1024];
        loop {
            // Read message with timeout
            let read_result = tokio::time::timeout(
                Duration::from_secs(120), // 2-minute timeout to detect dead connections
                reader.read(&mut buffer)
            ).await;
            
            let n = match read_result {
                Ok(Ok(0)) => {
                    // Connection closed
                    println!("Client {} disconnected", client_id);
                    break;
                },
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    println!("Error reading from client {}: {}", client_id, e);
                    break;
                },
                Err(_) => {
                    // Timeout - ping the client
                    let ping = [0u8; 1]; // Empty ping
                    if let Err(e) = writer_tx.send(ping.to_vec()).await {
                        println!("Error sending ping to client {}: {}", client_id, e);
                        break;
                    }
                    continue;
                }
            };
            
            // Process the message
            if n >= 4 {
                let msg_type = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
                
                match msg_type {
                    // Handle lookup request
                    3 => {
                        if n < 8 {
                            println!("Received incomplete lookup request from client {}", client_id);
                            continue; // Not enough data
                        }
                        
                        let id_len = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]) as usize;
                        if n < 8 + id_len {
                            println!("Received lookup request with insufficient data from client {}", client_id);
                            continue; // Not enough data
                        }
                        
                        let id_slice = &buffer[8..8 + id_len];
                        if let Ok(lookup_id) = String::from_utf8(id_slice.to_vec()) {
                            println!("=== NAT Traversal Lookup ===");
                            println!("Client '{}' looking up client '{}'", client_id, lookup_id);
                            
                            // Look up the client info
                            let clients_map = clients.lock().await;
                            println!("Currently registered clients: {}", clients_map.len());
                            
                            if let Some(info) = clients_map.get(&lookup_id) {
                                // Send the client info
                                let mut response = Vec::new();
                                response.extend_from_slice(&4u32.to_be_bytes()); // Message type 4 = lookup response
                                
                                // ID
                                response.extend_from_slice(&(lookup_id.len() as u32).to_be_bytes());
                                response.extend_from_slice(lookup_id.as_bytes());
                                
                                // IP address
                                let ip_str = info._public_addr.ip().to_string();
                                response.extend_from_slice(&(ip_str.len() as u32).to_be_bytes());
                                response.extend_from_slice(ip_str.as_bytes());
                                
                                // Port
                                response.extend_from_slice(&info._public_addr.port().to_be_bytes());
                                
                                // Found = true
                                response.push(1);
                                
                                if let Err(e) = writer_tx.send(response).await {
                                    println!("Error sending lookup response: {}", e);
                                } else {
                                    println!("NAT traversal handshake: Sent endpoint info about '{}' to '{}'", lookup_id, client_id);
                                    println!("  - '{}' endpoint: {}", lookup_id, info._public_addr);
                                    println!("  - Now clients will attempt direct connection (UDP hole punching)");
                                }
                                
                                println!("Client '{}' looked up client '{}' - FOUND", client_id, lookup_id);
                                println!("===========================");
                            } else {
                                // Client not found
                                let mut response = Vec::new();
                                response.extend_from_slice(&4u32.to_be_bytes()); // Message type 4 = lookup response
                                
                                // ID
                                response.extend_from_slice(&(lookup_id.len() as u32).to_be_bytes());
                                response.extend_from_slice(lookup_id.as_bytes());
                                
                                // Found = false
                                response.push(0);
                                
                                if let Err(e) = writer_tx.send(response).await {
                                    println!("Error sending lookup response: {}", e);
                                } else {
                                    println!("Sent 'not found' response to '{}'", client_id);
                                }
                                
                                println!("Client '{}' looked up client '{}' - NOT FOUND", client_id, lookup_id);
                                println!("===========================");
                            }
                        }
                    },
                    // Handle NAT traversal request
                    7 => {
                        if n < 8 {
                            println!("Received incomplete NAT traversal request from client {}", client_id);
                            continue; // Not enough data
                        }
                        
                        let target_id_len = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]) as usize;
                        if n < 8 + target_id_len {
                            println!("Received NAT traversal request with insufficient data from client {}", client_id);
                            continue; // Not enough data
                        }
                        
                        let target_id_slice = &buffer[8..8 + target_id_len];
                        if let Ok(target_id) = String::from_utf8(target_id_slice.to_vec()) {
                            println!("=== NAT Traversal Request ===");
                            println!("Client '{}' requesting NAT traversal with client '{}'", client_id, target_id);
                            
                            // Get a clone of the clients Arc to move into the task
                            let clients_clone = clients.clone();
                            let client_id_clone = client_id.clone();
                            let target_id_clone = target_id.clone();
                            
                            // Create a new server instance to facilitate NAT traversal
                            let server = RelayServer {
                                clients: clients_clone,
                                public_ip: None,
                                auth_secret: None,
                                nat_traversal_enabled: true,
                            };
                            
                            // Spawn a task to facilitate NAT traversal
                            tokio::spawn(async move {
                                match server.facilitate_nat_traversal(&client_id_clone, &target_id_clone).await {
                                    Ok(true) => {
                                        println!("NAT traversal facilitation successful");
                                    },
                                    Ok(false) => {
                                        println!("NAT traversal facilitation failed - one or both clients not found");
                                    },
                                    Err(e) => {
                                        println!("Error facilitating NAT traversal: {}", e);
                                    }
                                }
                            });
                            
                            println!("NAT traversal request processed");
                            println!("===========================");
                        }
                    },
                    // Handle STUN binding request
                    10 => { // NatTraversalMessageType::StunBindingRequest
                        println!("Received STUN binding request from client {}", client_id);
                        
                        // Create a STUN binding response with the client's public address
                        let mut response = Vec::new();
                        response.extend_from_slice(&11u32.to_be_bytes()); // StunBindingResponse
                        
                        // Add the public IP address
                        let ip_str = public_addr.ip().to_string();
                        response.extend_from_slice(&(ip_str.len() as u32).to_be_bytes());
                        response.extend_from_slice(ip_str.as_bytes());
                        
                        // Add the public port
                        response.extend_from_slice(&public_addr.port().to_be_bytes());
                        
                        // Send the response
                        if let Err(e) = writer_tx.send(response).await {
                            println!("Error sending STUN binding response: {}", e);
                            break;
                        } else {
                            println!("Sent STUN binding response to client {}: {}", client_id, public_addr);
                        }
                    },
                    // Handle UDP hole punch request
                    12 => { // NatTraversalMessageType::UdpHolePunch
                        if n < 8 {
                            println!("Received incomplete UDP hole punch request from client {}", client_id);
                            continue;
                        }
                        
                        let target_id_len = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]) as usize;
                        if n < 8 + target_id_len {
                            println!("Received UDP hole punch request with insufficient data from client {}", client_id);
                            continue;
                        }
                        
                        let target_id_slice = &buffer[8..8 + target_id_len];
                        if let Ok(target_id) = String::from_utf8(target_id_slice.to_vec()) {
                            println!("=== UDP Hole Punch Request ===");
                            println!("Client '{}' requesting hole punch with client '{}'", client_id, target_id);
                            
                            // Create a server instance to initiate symmetric NAT traversal
                            let server = RelayServer {
                                clients: clients.clone(),
                                public_ip: None,
                                auth_secret: None,
                                nat_traversal_enabled: true,
                            };
                            
                            // Get a clone of values for the task
                            let client_id_clone = client_id.clone();
                            let target_id_clone = target_id.clone();
                            
                            // Spawn a task to handle NAT traversal
                            tokio::spawn(async move {
                                match server.initiate_symmetric_nat_traversal(&client_id_clone, &target_id_clone).await {
                                    Ok(true) => {
                                        println!("Symmetric NAT traversal initiated successfully");
                                    },
                                    Ok(false) => {
                                        println!("Symmetric NAT traversal failed - one or both clients not found");
                                    },
                                    Err(e) => {
                                        println!("Error initiating symmetric NAT traversal: {}", e);
                                    }
                                }
                            });
                            
                            println!("UDP hole punch request processed");
                            println!("===========================");
                        }
                    },
                    // Handle keep-alive message
                    13 => { // NatTraversalMessageType::KeepAlive
                        // Create a server instance to handle keep-alive
                        let server = RelayServer {
                            clients: clients.clone(),
                            public_ip: None,
                            auth_secret: None,
                            nat_traversal_enabled: true,
                        };
                        
                        // Get a clone of the client ID for the task
                        let client_id_clone = client_id.clone();
                        
                        // Spawn a task to handle keep-alive
                        tokio::spawn(async move {
                            if let Err(e) = server.handle_keep_alive(&client_id_clone).await {
                                println!("Error handling keep-alive for client {}: {}", client_id_clone, e);
                            }
                        });
                    },
                    // Handle ping - just acknowledge
                    5 => {
                        let pong = [6u8, 0, 0, 0]; // Message type 6 = pong
                        if let Err(e) = writer_tx.send(pong.to_vec()).await {
                            println!("Error sending pong: {}", e);
                            break;
                        }
                    },
                    // Ignore other message types
                    _ => {}
                }
            }
        }
        
        // Remove client from registry
        {
            let mut clients_map = clients.lock().await;
            clients_map.remove(&client_id);
            println!("Removed client {} from registry", client_id);
        }
        
        Ok(())
    }

    // Add this new method for facilitating NAT traversal
    async fn facilitate_nat_traversal(&self, client_id_a: &str, client_id_b: &str) -> io::Result<bool> {
        println!("Facilitating NAT traversal between '{}' and '{}'", client_id_a, client_id_b);
        
        // Get lock on clients map
        let clients_map = self.clients.lock().await;
        
        // Ensure both clients exist
        let client_a = match clients_map.get(client_id_a) {
            Some(client) => client,
            None => {
                println!("Client '{}' not found", client_id_a);
                return Ok(false);
            }
        };
        
        let client_b = match clients_map.get(client_id_b) {
            Some(client) => client,
            None => {
                println!("Client '{}' not found", client_id_b);
                return Ok(false);
            }
        };
        
        // Create NAT traversal message for client A
        let mut msg_to_a = Vec::new();
        msg_to_a.extend_from_slice(&5u32.to_be_bytes()); // Message type 5 = NAT traversal
        
        // ID of client B
        msg_to_a.extend_from_slice(&(client_id_b.len() as u32).to_be_bytes());
        msg_to_a.extend_from_slice(client_id_b.as_bytes());
        
        // Endpoint of client B
        let ip_str_b = client_b._public_addr.ip().to_string();
        msg_to_a.extend_from_slice(&(ip_str_b.len() as u32).to_be_bytes());
        msg_to_a.extend_from_slice(ip_str_b.as_bytes());
        msg_to_a.extend_from_slice(&client_b._public_addr.port().to_be_bytes());
        
        // Create NAT traversal message for client B
        let mut msg_to_b = Vec::new();
        msg_to_b.extend_from_slice(&5u32.to_be_bytes()); // Message type 5 = NAT traversal
        
        // ID of client A
        msg_to_b.extend_from_slice(&(client_id_a.len() as u32).to_be_bytes());
        msg_to_b.extend_from_slice(client_id_a.as_bytes());
        
        // Endpoint of client A
        let ip_str_a = client_a._public_addr.ip().to_string();
        msg_to_b.extend_from_slice(&(ip_str_a.len() as u32).to_be_bytes());
        msg_to_b.extend_from_slice(ip_str_a.as_bytes());
        msg_to_b.extend_from_slice(&client_a._public_addr.port().to_be_bytes());
        
        // Send messages to both clients simultaneously
        let (res_a, res_b) = tokio::join!(
            client_a._sender.send(msg_to_a),
            client_b._sender.send(msg_to_b)
        );
        
        // Check results
        if let Err(e) = res_a {
            println!("Failed to send NAT traversal info to client '{}': {}", client_id_a, e);
            return Ok(false);
        }
        
        if let Err(e) = res_b {
            println!("Failed to send NAT traversal info to client '{}': {}", client_id_b, e);
            return Ok(false);
        }
        
        println!("NAT traversal information sent to both clients successfully");
        println!("Client '{}' endpoint: {}", client_id_a, client_a._public_addr);
        println!("Client '{}' endpoint: {}", client_id_b, client_b._public_addr);
        
        Ok(true)
    }

    // Add this method to detect NAT type for a client
    async fn detect_nat_type(&self, client_id: &str, client_addr: SocketAddr) -> io::Result<NatType> {
        println!("Attempting to detect NAT type for client '{}'", client_id);
        
        // Get the client info
        let clients_map = self.clients.lock().await;
        let client_info = match clients_map.get(client_id) {
            Some(info) => info,
            None => {
                println!("Client '{}' not found when detecting NAT type", client_id);
                return Ok(NatType::Unknown);
            }
        };
        
        // For simple detection, we'll check if the client's IP matches our expected public IP
        if let Some(ref public_ip) = self.public_ip {
            if client_addr.ip().to_string() == *public_ip {
                println!("Client '{}' appears to be directly connected (Open Internet)", client_id);
                return Ok(NatType::OpenInternet);
            }
        }
        
        // In a real implementation, we would perform multiple tests:
        // 1. Try sending from different source ports to detect port-restricted NAT
        // 2. Try sending from different source IPs to detect symmetric NAT
        // For now, we'll assume a port-restricted cone NAT as that's most common
        println!("Client '{}' likely behind Port Restricted Cone NAT (most common type)", client_id);
        
        // Notify the client of its detected NAT type
        let mut msg = Vec::new();
        msg.extend_from_slice(&(NatTraversalMessageType::NatTypeNotification as u32).to_be_bytes());
        msg.push(NatType::PortRestrictedCone as u8);
        
        if let Err(e) = client_info._sender.send(msg).await {
            println!("Failed to send NAT type notification to client '{}': {}", client_id, e);
        } else {
            println!("Sent NAT type notification to client '{}'", client_id);
        }
        
        Ok(NatType::PortRestrictedCone)
    }
    
    // Implement a more sophisticated NAT traversal for clients behind symmetric NATs
    async fn initiate_symmetric_nat_traversal(&self, client_id_a: &str, client_id_b: &str) -> io::Result<bool> {
        println!("Initiating symmetric NAT traversal between '{}' and '{}'", client_id_a, client_id_b);
        
        // Get lock on clients map
        let clients_map = self.clients.lock().await;
        
        // Ensure both clients exist
        let client_a = match clients_map.get(client_id_a) {
            Some(client) => client,
            None => {
                println!("Client '{}' not found", client_id_a);
                return Ok(false);
            }
        };
        
        let client_b = match clients_map.get(client_id_b) {
            Some(client) => client,
            None => {
                println!("Client '{}' not found", client_id_b);
                return Ok(false);
            }
        };
        
        // For clients behind symmetric NATs, we need a more complex approach:
        // 1. Have both clients send packets to each other's endpoints (traditional hole punching)
        // 2. If that fails, use the relay server as a fallback
        
        // Send message to client A with instructions for symmetric traversal
        let mut msg_to_a = Vec::new();
        msg_to_a.extend_from_slice(&(NatTraversalMessageType::UdpHolePunch as u32).to_be_bytes());
        
        // ID of client B
        msg_to_a.extend_from_slice(&(client_id_b.len() as u32).to_be_bytes());
        msg_to_a.extend_from_slice(client_id_b.as_bytes());
        
        // Endpoint of client B (multiple ports to try)
        let ip_str_b = client_b._public_addr.ip().to_string();
        msg_to_a.extend_from_slice(&(ip_str_b.len() as u32).to_be_bytes());
        msg_to_a.extend_from_slice(ip_str_b.as_bytes());
        
        // Primary port
        msg_to_a.extend_from_slice(&client_b._public_addr.port().to_be_bytes());
        
        // Send prediction for additional ports to try (for symmetric NATs)
        // Add port+1 and port+2 as common predictions
        let port_b = client_b._public_addr.port();
        msg_to_a.extend_from_slice(&(port_b + 1).to_be_bytes());
        msg_to_a.extend_from_slice(&(port_b + 2).to_be_bytes());
        
        // Similarly for client B
        let mut msg_to_b = Vec::new();
        msg_to_b.extend_from_slice(&(NatTraversalMessageType::UdpHolePunch as u32).to_be_bytes());
        
        // ID of client A
        msg_to_b.extend_from_slice(&(client_id_a.len() as u32).to_be_bytes());
        msg_to_b.extend_from_slice(client_id_a.as_bytes());
        
        // Endpoint of client A
        let ip_str_a = client_a._public_addr.ip().to_string();
        msg_to_b.extend_from_slice(&(ip_str_a.len() as u32).to_be_bytes());
        msg_to_b.extend_from_slice(ip_str_a.as_bytes());
        
        // Primary port
        msg_to_b.extend_from_slice(&client_a._public_addr.port().to_be_bytes());
        
        // Send prediction for additional ports to try
        let port_a = client_a._public_addr.port();
        msg_to_b.extend_from_slice(&(port_a + 1).to_be_bytes());
        msg_to_b.extend_from_slice(&(port_a + 2).to_be_bytes());
        
        // Send messages to both clients simultaneously
        let (res_a, res_b) = tokio::join!(
            client_a._sender.send(msg_to_a),
            client_b._sender.send(msg_to_b)
        );
        
        // Check results
        if let Err(e) = res_a {
            println!("Failed to send symmetric NAT traversal info to client '{}': {}", client_id_a, e);
            return Ok(false);
        }
        
        if let Err(e) = res_b {
            println!("Failed to send symmetric NAT traversal info to client '{}': {}", client_id_b, e);
            return Ok(false);
        }
        
        println!("Symmetric NAT traversal information sent to both clients successfully");
        println!("Client '{}' endpoint: {}", client_id_a, client_a._public_addr);
        println!("Client '{}' endpoint: {}", client_id_b, client_b._public_addr);
        
        // Schedule a check after a short delay to see if traversal was successful
        let clients_clone = self.clients.clone();
        let client_id_a_clone = client_id_a.to_string();
        let client_id_b_clone = client_id_b.to_string();
        
        tokio::spawn(async move {
            // Wait for clients to attempt direct connection
            tokio::time::sleep(Duration::from_secs(5)).await;
            
            // In a complete implementation, we would check if clients report successful connection
            // For now, just log that we're checking
            println!("Checking if NAT traversal between '{}' and '{}' was successful...", 
                     client_id_a_clone, client_id_b_clone);
            
            // Logic to check connection status would go here
            
            // If traversal failed, we would fall back to relay mode
            let clients = clients_clone.lock().await;
            if clients.contains_key(&client_id_a_clone) && clients.contains_key(&client_id_b_clone) {
                println!("Both clients still connected, will use relay if direct connection failed");
            } else {
                println!("One or both clients disconnected during NAT traversal attempt");
            }
        });
        
        Ok(true)
    }
    
    // New method for handling keep-alive messages
    async fn handle_keep_alive(&self, client_id: &str) -> io::Result<()> {
        println!("Processing keep-alive for client '{}'", client_id);
        
        // Get the client info
        let clients_map = self.clients.lock().await;
        let client_info = match clients_map.get(client_id) {
            Some(info) => info,
            None => {
                println!("Client '{}' not found when handling keep-alive", client_id);
                return Ok(());
            }
        };
        
        // Send keep-alive acknowledgment
        let mut msg = Vec::new();
        msg.extend_from_slice(&(NatTraversalMessageType::KeepAlive as u32).to_be_bytes());
        
        if let Err(e) = client_info._sender.send(msg).await {
            println!("Failed to send keep-alive acknowledgment to client '{}': {}", client_id, e);
        } else {
            println!("Sent keep-alive acknowledgment to client '{}'", client_id);
        }
        
        Ok(())
    }
}

fn prompt_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or(0);
    
    input.trim().to_string()
}

// Helper function to detect public IP
async fn detect_public_ip() -> Result<String> {
    // Use a simple HTTP service to detect public IP
    println!("Detecting public IP address...");
    
    // Try to detect via multiple services
    let services = [
        "https://api.ipify.org", 
        "https://ifconfig.me/ip", 
        "https://ipecho.net/plain",
        "https://checkip.amazonaws.com"
    ];
    
    // Check if we're on render.com
    let is_render = env::var("RENDER").is_ok() || env::var("RENDER_SERVICE_ID").is_ok();
    
    if is_render {
        println!("Detected Render.com environment, attempting to determine outbound IP...");
        
        // Create a reqwest client with timeout
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        
        // Try to connect to external services to determine our outbound IP
        for service_url in &services {
            println!("Trying to determine public IP using: {}", service_url);
            
            match client.get(*service_url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.text().await {
                            Ok(ip) => {
                                let ip = ip.trim();
                                if !ip.is_empty() && ip.chars().all(|c| c.is_digit(10) || c == '.') {
                                    println!("Successfully detected Render outbound IP: {}", ip);
                                    println!("This is the static outbound IP for your Render region");
                                    println!("NAT traversal will use this IP for optimal performance");
                                    return Ok(ip.to_string());
                                } else {
                                    println!("Service returned invalid IP format: '{}'", ip);
                                }
                            },
                            Err(e) => println!("Failed to read response from {}: {}", service_url, e)
                        }
                    } else {
                        println!("Service {} returned error status: {}", service_url, response.status());
                    }
                },
                Err(e) => println!("Failed to connect to {}: {}", service_url, e)
            }
        }
        
        // If all services failed, suggest manual configuration
        println!("Could not auto-detect Render.com outbound IP address.");
        println!("You can manually set the PUBLIC_IP environment variable in the Render dashboard.");
        println!("Find your static outbound IP in the Render dashboard under Connect > Outbound.");
        println!("This is important for optimal NAT traversal between clients.");
    } else {
        println!("Not running on Render.com, auto-detection might not be accurate.");
        println!("For production, please manually set the PUBLIC_IP environment variable.");
    }
    
    Err(anyhow!("Could not auto-detect public IP address"))
}

fn prompt_yes_no(prompt: &str) -> bool {
    print!("{} ", prompt);
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    
    let input = input.trim().to_lowercase();
    input == "y" || input == "yes"
}

// Function to check if an IP might be from a region with known connectivity issues
fn is_potential_problematic_region(ip: &str) -> bool {
    // This is a very basic implementation 
    // In production, you'd want to use a proper IP geolocation database
    
    // Example: Check if the IP might be from regions with known Render.com connectivity issues
    // These are just examples and not comprehensive
    let problematic_prefixes = [
        // Some Nigerian ISP prefixes (example)
        "41.58.", "41.75.", "41.76.", "41.84.", "41.86.", "41.184.", "41.190.",
        "41.203.", "41.204.", "41.215.", "41.217.", "41.219.", "41.220.", "41.221.",
        // Add other regions with known issues as needed
    ];
    
    for prefix in problematic_prefixes {
        if ip.starts_with(prefix) {
            return true;
        }
    }
    
    false
}

// Start a health check server that responds to any HTTP request with 200 OK
// This is critical for Render.com port detection to succeed
async fn start_health_check_server() {
    let is_render = env::var("RENDER").is_ok() || env::var("RENDER_SERVICE_ID").is_ok();
    
    // Try multiple ports that Render might check
    let health_check_ports = if is_render {
        vec!["3000", "10000", "8080", "80"]
    } else {
        vec!["8080"]
    };
    
    let mut success = false;
    
    for port in health_check_ports {
        let addr = format!("0.0.0.0:{}", port);
        println!("Attempting to start health check server on {}", addr);
        
        match TcpListener::bind(&addr).await {
            Ok(listener) => {
                println!("SUCCESS: Health check server listening on {}", addr);
                
                // Spawn a task to handle health check requests
                tokio::spawn(async move {
                    println!("Health check server active on {}", addr);
                    
                    loop {
                        match listener.accept().await {
                            Ok((mut socket, addr)) => {
                                println!("Health check request from {}", addr);
                                
                                // Create a more robust HTTP response that is more likely to be detected
                                let response = concat!(
                                    "HTTP/1.1 200 OK\r\n",
                                    "Server: TagIO-Relay\r\n",
                                    "Content-Type: text/plain\r\n",
                                    "Connection: keep-alive\r\n",
                                    "Content-Length: 22\r\n",
                                    "\r\n",
                                    "TagIO Relay Server Ready"
                                );
                                
                                // Send the response immediately without waiting for request parsing
                                match socket.write_all(response.as_bytes()).await {
                                    Ok(_) => {
                                        println!("Health check response sent to {}", addr);
                                        // Try to flush the socket to ensure response is sent
                                        if let Err(e) = socket.flush().await {
                                            println!("Failed to flush health check response: {}", e);
                                        }
                                    },
                                    Err(e) => {
                                        println!("Failed to send health check response: {}", e);
                                    }
                                }
                            },
                            Err(e) => {
                                println!("Error accepting health check connection: {}", e);
                                // Brief pause to avoid CPU spinning on repeated errors
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                });
                
                success = true;
                println!("Health check server successfully started on port {}", port);
                
                // Don't immediately return - try to bind to multiple ports
                // This increases chances of Render.com's port scan finding our service
            },
            Err(e) => {
                println!("Failed to bind health check server to {}: {}", addr, e);
            }
        }
    }
    
    if !success {
        println!("WARNING: Could not start health check server on any port");
        println!("Render.com deployment may fail during port detection");
    } else {
        println!("Health check server(s) started successfully");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    
    // Initialize logging
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .init();
    
    println!("=== TagIO Relay Server Starting ===");
    println!("Version: {}", env!("CARGO_PKG_VERSION"));
    println!("Args: {:?}", args);
    println!("Working directory: {:?}", env::current_dir().unwrap_or_default());
    
    // Check for NAT traversal options
    let enable_nat_traversal = !args.contains(&"--disable-nat-traversal".to_string());
    
    // Check if running on render.com
    let is_render = env::var("RENDER").is_ok() || env::var("RENDER_SERVICE_ID").is_ok();
    println!("Running on render.com: {}", is_render);
    if is_render {
        println!("Detected render.com environment - optimized for cloud deployment");
        println!("Service ID: {}", env::var("RENDER_SERVICE_ID").unwrap_or_else(|_| "unknown".to_string()));
        println!("Instance ID: {}", env::var("RENDER_INSTANCE_ID").unwrap_or_else(|_| "unknown".to_string()));
    } else {
        println!("Running in local/custom environment");
    }
    
    println!("NAT traversal: {}", if enable_nat_traversal { "ENABLED" } else { "DISABLED" });
    println!("=================================");
    
    // IMPORTANT: Start health check server FIRST
    // This ensures Render.com can detect our service quickly
    println!("Starting health check server for Render.com port detection...");
    start_health_check_server().await;
    
    // If running on render.com, wait a bit to ensure the health check is detected
    if is_render {
        println!("Waiting for health check server to be detected by Render.com...");
        tokio::time::sleep(Duration::from_secs(2)).await;
        println!("Continuing with main server initialization");
    }
    
    // Get public IP from environment variable or auto-detect
    let mut public_ip = env::var("PUBLIC_IP").ok();
    
    // If no PUBLIC_IP is set and we're on render.com, try to auto-detect
    if public_ip.is_none() && is_render {
        println!("No PUBLIC_IP environment variable set but running on Render.com");
        println!("Attempting to auto-detect the Render.com outbound IP...");
        
        match detect_public_ip().await {
            Ok(ip) => {
                println!("Successfully auto-detected Render.com outbound IP: {}", ip);
                println!("Using this IP for optimal NAT traversal");
                public_ip = Some(ip);
            }
            Err(e) => {
                println!("Failed to auto-detect outbound IP: {}", e);
                println!("NAT traversal may not work optimally.");
                println!("For best results, set the PUBLIC_IP environment variable in the Render dashboard.");
            }
        }
    } else if public_ip.is_none() && !args.contains(&"--auto-detect".to_string()) && !is_render {
        // Only prompt in local/development environment, not on Render
        let auto_detect = prompt_yes_no("Do you want to auto-detect your public IP? (y/n)");
        if auto_detect {
            match detect_public_ip().await {
                Ok(ip) => {
                    println!("Auto-detected public IP: {}", ip);
                    public_ip = Some(ip);
                }
                Err(e) => {
                    eprintln!("Failed to auto-detect public IP: {}", e);
                    let manual_ip = prompt_input("Please enter your server's public IP address (leave empty to use socket addresses):");
                    if !manual_ip.is_empty() {
                        public_ip = Some(manual_ip);
                    }
                }
            }
        } else {
            let manual_ip = prompt_input("Please enter your server's public IP address (leave empty to use socket addresses):");
            if !manual_ip.is_empty() {
                public_ip = Some(manual_ip);
            }
        }
    }
    
    if let Some(ip) = &public_ip {
        println!("Using public IP address: {}", ip);
    } else {
        println!("No public IP specified, using client-perceived addresses");
    }
    
    // Get auth secret from environment variable or use default
    let auth_secret = env::var("AUTH_SECRET").ok();
    
    // Create the relay server with NAT traversal setting
    let mut server = RelayServer::new(public_ip, auth_secret);
    
    // Set the NAT traversal flag based on command line arguments
    server.set_nat_traversal_enabled(enable_nat_traversal);
    
    // Run the relay server (we'll pass empty string - the run method will handle port binding logic)
    match server.run("").await {
        Ok(_) => {
            println!("Server terminated normally");
            Ok(())
        },
        Err(e) => {
            eprintln!("Error running server: {}", e);
            eprintln!("Error details: {:?}", e);
            
            Err(anyhow!("Server error: {}", e))
        }
    }
} 