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

// Information about each connected client
struct ClientInfo {
    _public_addr: SocketAddr,
    _sender: mpsc::Sender<Vec<u8>>,
}

// Simple NAT traversal relay server
struct RelayServer {
    clients: Arc<Mutex<HashMap<String, ClientInfo>>>,
    public_ip: Option<String>,
    auth_secret: Option<String>,
}

impl RelayServer {
    // Create a new relay server
    fn new(public_ip: Option<String>, auth_secret: Option<String>) -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            public_ip,
            auth_secret,
        }
    }
    
    // Start the relay server
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
        
        // Start the health check endpoint on port 8080
        let health_check_addr = "0.0.0.0:8080";
        let health_check_server = Self::run_health_check(health_check_addr);
        
        // Bind to the specified address for the main server
        println!("Attempting to bind to {}", bind_addr);
        let listener = match TcpListener::bind(bind_addr).await {
            Ok(l) => {
                println!("SUCCESS: Bound to {}", bind_addr);
                l
            },
            Err(e) => {
                println!("ERROR: Failed to bind to {}: {}", bind_addr, e);
                println!("This error is expected in local environments where port 443 is privileged or in use.");
                println!("On render.com production environment, this should succeed.");
                return Err(e);
            }
        };
        println!("TagIO relay server listening on {}", bind_addr);
        
        // Log the public IP if provided
        if let Some(ip) = &self.public_ip {
            println!("Server public IP configured as: {}", ip);
            println!("NAT traversal should work optimally with configured public IP");
        } else {
            println!("WARNING: No public IP configured. NAT traversal may not work correctly!");
            println!("For optimal NAT traversal, set the PUBLIC_IP environment variable on Render.com");
            println!("Without PUBLIC_IP set, NAT traversal between clients behind symmetric NATs may fail");
            println!("The server will use client-perceived addresses, which may be inaccurate behind complex NATs");
            
            if env::var("RENDER").is_ok() || env::var("RENDER_SERVICE_ID").is_ok() {
                println!("IMPORTANT: You are running on Render.com. Set PUBLIC_IP in the environment variables section");
                println!("You can find your Render service's static outbound IP in the 'Connect' tab");
                println!("See: https://render.com/docs/static-outbound-ip-addresses");
            }
        }
        
        // Log authentication status
        if self.auth_secret.is_some() {
            println!("Authentication enabled for client connections");
        } else {
            println!("Authentication disabled - all connections will be accepted");
        }
        
        // Spawn health check task
        tokio::spawn(health_check_server);
        
        // Accept and handle connections
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    println!("New connection from {} (local address: {})", addr, socket.local_addr().unwrap_or_else(|_| "unknown".parse().unwrap()));
                    
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

    // Add a new static method to run the health check endpoint
    async fn run_health_check(addr: &str) {
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                println!("Health check endpoint successfully bound to {}", addr);
                println!("Health endpoint will respond with HTTP 200 OK to any request");
                
                loop {
                    match listener.accept().await {
                        Ok((mut socket, client_addr)) => {
                            println!("Health check request from {}", client_addr);
                            tokio::spawn(async move {
                                // Simple HTTP response
                                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                                match socket.write_all(response.as_bytes()).await {
                                    Ok(_) => println!("Health check response sent to {}", client_addr),
                                    Err(e) => println!("Failed to send health check response to {}: {}", client_addr, e),
                                }
                            });
                        }
                        Err(e) => {
                            eprintln!("Error accepting health check connection: {}", e);
                        }
                    }
                }
            },
            Err(e) => {
                eprintln!("Failed to start health check endpoint on {}: {}", addr, e);
                eprintln!("Health check will not be available - this may affect container orchestration");
            }
        }
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
        "https://ipecho.net/plain"
    ];
    
    println!("On render.com, please use the PUBLIC_IP environment variable instead");
    println!("Auto-detection may not work in cloud environments");
    
    // We can't use curl directly in Rust, so let's return a manual message
    println!("Automatic IP detection not available in this build.");
    println!("Please manually set the PUBLIC_IP environment variable on Render.");
    
    Err(anyhow!("Automatic IP detection not implemented"))
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
    
    println!("=================================");
    
    // Get binding address from environment variable or use default
    let bind_addr = if is_render {
        // On render.com, we should use the PORT environment variable
        match env::var("PORT") {
            Ok(port) => {
                println!("Using render.com assigned port: {}", port);
                format!("0.0.0.0:{}", port)
            },
            Err(_) => {
                println!("WARNING: Running on render.com but PORT environment variable not found!");
                println!("This is unexpected and may cause binding errors");
                "0.0.0.0:8443".to_string()
            }
        }
    } else {
        // For local development
        env::var("PORT")
            .map(|port| format!("0.0.0.0:{}", port))
            .unwrap_or_else(|_| "0.0.0.0:8443".to_string())
    };
    
    println!("TagIO Relay Server v{}", env!("CARGO_PKG_VERSION"));
    println!("Starting relay server on {}", bind_addr);
    println!("NOTE: On render.com, PORT is set by the platform and will be used automatically");
    
    // Get public IP from environment variable or prompt
    let public_ip = env::var("PUBLIC_IP").ok();
    let public_ip = if public_ip.is_none() && !args.contains(&"--auto-detect".to_string()) {
        let auto_detect = prompt_yes_no("Do you want to auto-detect your public IP? (y/n)");
        if auto_detect {
            match detect_public_ip().await {
                Ok(ip) => {
                    println!("Auto-detected public IP: {}", ip);
                    Some(ip)
                }
                Err(e) => {
                    eprintln!("Failed to auto-detect public IP: {}", e);
                    let manual_ip = prompt_input("Please enter your server's public IP address (leave empty to use socket addresses):");
                    if manual_ip.is_empty() { None } else { Some(manual_ip) }
                }
            }
        } else {
            let manual_ip = prompt_input("Please enter your server's public IP address (leave empty to use socket addresses):");
            if manual_ip.is_empty() { None } else { Some(manual_ip) }
        }
    } else {
        public_ip
    };
    
    if let Some(ip) = &public_ip {
        println!("Using public IP address: {}", ip);
    } else {
        println!("No public IP specified, using client-perceived addresses");
    }
    
    // Get auth secret from environment variable or use default
    let auth_secret = env::var("AUTH_SECRET").ok();
    
    // Run the relay server
    let server = RelayServer::new(public_ip, auth_secret);
    match server.run(&bind_addr).await {
        Ok(_) => {
            println!("Server terminated normally");
            Ok(())
        },
        Err(e) => {
            eprintln!("Error running server: {}", e);
            eprintln!("Error details: {:?}", e);
            
            // Check for specific error conditions
            if e.kind() == io::ErrorKind::AddrInUse {
                eprintln!("Address already in use error - this is common in local development");
                eprintln!("On render.com, the PORT environment variable is managed by the platform");
                eprintln!("and should be available when the container starts");
            }
            if e.kind() == io::ErrorKind::PermissionDenied {
                eprintln!("Permission denied error - cannot bind to privileged port");
                eprintln!("On render.com, this should not happen as the container runs with sufficient privileges");
            }
            
            Err(anyhow!("Server error: {}", e))
        }
    }
} 