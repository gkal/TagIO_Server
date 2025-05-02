use std::net::{SocketAddr, IpAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use anyhow::{Result, anyhow};
use log::{info, warn, error, debug};

use crate::constants::{
    CONNECTION_TIMEOUT_SECS, 
    HEALTH_CHECK_PORT,
    MAX_ID_LENGTH,
    MAX_AUTH_LENGTH,
    PROTOCOL_MAGIC
};
use crate::messages::MessageType;

// Information about each connected client
struct ClientInfo {
    public_addr: SocketAddr,
    sender: mpsc::Sender<Vec<u8>>,
}

/// Main relay server implementation 
pub struct RelayServer {
    clients: Arc<Mutex<HashMap<String, ClientInfo>>>,
    public_ip: Option<String>,
    auth_secret: Option<String>,
}

impl RelayServer {
    /// Create a new relay server
    pub fn new(public_ip: Option<String>, auth_secret: Option<String>) -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            public_ip,
            auth_secret,
        }
    }
    
    /// Start the relay server
    pub async fn run(&self, bind_addr: &str) -> Result<()> {
        // Start the health check endpoint on port 8080
        let health_check_addr = format!("0.0.0.0:{}", HEALTH_CHECK_PORT);
        // Pass the health_check_addr as an owned String to avoid lifetime issues
        let health_check_server = Self::run_health_check(health_check_addr);
        
        // Bind to the specified address for the main server
        let listener = TcpListener::bind(bind_addr).await?;
        info!("TagIO relay server listening on {}", bind_addr);
        
        // Log the public IP if provided
        if let Some(ip) = &self.public_ip {
            info!("Server public IP configured as: {}", ip);
        } else {
            warn!("WARNING: No public IP configured. NAT traversal may not work correctly!");
            warn!("You should specify a public IP in the configuration.");
        }
        
        // Log authentication status
        if self.auth_secret.is_some() {
            info!("Authentication enabled for client connections");
        } else {
            info!("Authentication disabled - all connections will be accepted");
        }
        
        // Spawn health check task
        tokio::spawn(health_check_server);
        
        // Accept and handle connections
        loop {
            let (socket, addr) = listener.accept().await?;
            info!("New connection from {}", addr);
            
            // Use public IP if configured, otherwise use the detected address
            let public_addr = if let Some(ip) = &self.public_ip {
                let port = addr.port();
                match IpAddr::from_str(ip) {
                    Ok(ip_addr) => {
                        info!("Using configured public IP: {}", ip_addr);
                        SocketAddr::new(ip_addr, port)
                    },
                    Err(_) => {
                        warn!("Failed to parse configured public IP: {}", ip);
                        addr
                    }
                }
            } else {
                info!("Using detected IP: {}", addr);
                addr
            };
            
            // Handle the connection in a new task
            let clients = self.clients.clone();
            let auth_secret = self.auth_secret.clone();
            
            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(socket, addr, public_addr, clients, auth_secret).await {
                    error!("Error handling client {}: {}", addr, e);
                }
            });
        }
    }
    
    /// Handle a client connection
    async fn handle_client(
        socket: TcpStream, 
        addr: SocketAddr,
        public_addr: SocketAddr,
        clients: Arc<Mutex<HashMap<String, ClientInfo>>>,
        auth_secret: Option<String>,
    ) -> Result<()> {
        // Create a channel for sending messages to this client
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
        
        // Split the socket for concurrent reading and writing
        let (mut reader, mut writer) = socket.into_split();
        
        info!("Client connection from {}, public address: {}", addr, public_addr);
        
        // Spawn a task for handling outgoing messages
        let writer_handle = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Err(e) = writer.write_all(&msg).await {
                    error!("Error writing to client: {}", e);
                    break;
                }
            }
        });
        
        // Read the client ID (first 4 bytes are the ID length, then the ID string)
        let mut id_len_bytes = [0u8; 4];
        
        // Read with timeout, properly handling errors
        match tokio::time::timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS), reader.read_exact(&mut id_len_bytes)).await {
            Ok(result) => {
                if let Err(e) = result {
                    error!("Error reading client ID length: {}", e);
                    return Err(anyhow::Error::new(e));
                }
            },
            Err(_) => {
                error!("Timeout reading client ID length");
                return Err(anyhow!("Timeout reading client ID"));
            }
        }
        
        let id_len = u32::from_be_bytes(id_len_bytes) as usize;
        if id_len > MAX_ID_LENGTH {
            // Prevent excessive memory allocation
            error!("Client ID too long: {}", id_len);
            return Err(anyhow!("Client ID too long"));
        }
        
        let mut id_bytes = vec![0u8; id_len];
        
        // Read with timeout, properly handling errors
        match tokio::time::timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS), reader.read_exact(&mut id_bytes)).await {
            Ok(result) => {
                if let Err(e) = result {
                    error!("Error reading client ID: {}", e);
                    return Err(anyhow::Error::new(e));
                }
            },
            Err(_) => {
                error!("Timeout reading client ID");
                return Err(anyhow!("Timeout reading client ID"));
            }
        }
        
        let client_id = match String::from_utf8(id_bytes) {
            Ok(id) => id,
            Err(e) => {
                error!("Invalid client ID encoding: {}", e);
                return Err(anyhow!("Invalid client ID encoding"));
            }
        };
        
        // Verify authentication if enabled
        if let Some(secret) = auth_secret {
            // Read authentication data
            let mut auth_len_bytes = [0u8; 4];
            match tokio::time::timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS), reader.read_exact(&mut auth_len_bytes)).await {
                Ok(result) => {
                    if let Err(e) = result {
                        error!("Error reading auth data length: {}", e);
                        return Err(anyhow::Error::new(e));
                    }
                },
                Err(_) => {
                    error!("Timeout reading auth data length");
                    return Err(anyhow!("Timeout reading auth data"));
                }
            }
            
            let auth_len = u32::from_be_bytes(auth_len_bytes) as usize;
            if auth_len > MAX_AUTH_LENGTH {
                // Prevent excessive memory allocation
                error!("Auth data too long: {}", auth_len);
                return Err(anyhow!("Auth data too long"));
            }
            
            let mut auth_bytes = vec![0u8; auth_len];
            match tokio::time::timeout(Duration::from_secs(CONNECTION_TIMEOUT_SECS), reader.read_exact(&mut auth_bytes)).await {
                Ok(result) => {
                    if let Err(e) = result {
                        error!("Error reading auth data: {}", e);
                        return Err(anyhow::Error::new(e));
                    }
                },
                Err(_) => {
                    error!("Timeout reading auth data");
                    return Err(anyhow!("Timeout reading auth data"));
                }
            }
            
            let auth_str = match String::from_utf8(auth_bytes) {
                Ok(auth) => auth,
                Err(e) => {
                    error!("Invalid auth data encoding: {}", e);
                    return Err(anyhow!("Invalid auth data encoding"));
                }
            };
            
            // Verify the authentication secret
            if auth_str != secret {
                error!("Authentication failed for client {}", client_id);
                
                // Send auth failure message
                let mut msg = Vec::new();
                msg.extend_from_slice(&(MessageType::AuthFailure as u32).to_be_bytes());
                if let Err(e) = tx.send(msg).await {
                    error!("Error sending auth failure: {}", e);
                }
                
                return Err(anyhow!("Authentication failed"));
            }
            
            info!("Client {} authenticated successfully", client_id);
        }
        
        info!("Client {} registered as '{}'", addr, client_id);
        
        // Register the client
        {
            let mut clients_map = clients.lock().await;
            clients_map.insert(client_id.clone(), ClientInfo {
                public_addr,
                sender: tx.clone(),
            });
            
            // Send registration acknowledgment to the client
            let mut msg = Vec::new();
            msg.extend_from_slice(&(MessageType::ClientRegistered as u32).to_be_bytes());
            // Send the public IP and port as seen by the server
            msg.extend_from_slice(&public_addr.ip().to_string().len().to_be_bytes());
            msg.extend_from_slice(public_addr.ip().to_string().as_bytes());
            msg.extend_from_slice(&public_addr.port().to_be_bytes());
            
            if let Err(e) = tx.send(msg).await {
                error!("Error sending registration ack: {}", e);
            }
        }
        
        // Process connection requests
        loop {
            // Read message type
            let mut msg_type_bytes = [0u8; 4];
            let read_result = tokio::time::timeout(
                Duration::from_secs(CONNECTION_TIMEOUT_SECS * 6), // Use longer timeout for regular operation
                reader.read_exact(&mut msg_type_bytes)
            ).await;
            
            let msg_type = match read_result {
                Ok(Ok(_)) => u32::from_be_bytes(msg_type_bytes),
                Ok(Err(e)) => {
                    error!("Error reading message type: {}", e);
                    break;
                },
                Err(_) => {
                    // Timeout, client might be disconnected
                    error!("Timeout reading message type, client disconnected");
                    break;
                }
            };
            
            match msg_type {
                // Connection request (type 1)
                1 => {
                    // Read target ID length
                    let mut target_id_len_bytes = [0u8; 4];
                    if let Err(e) = reader.read_exact(&mut target_id_len_bytes).await {
                        error!("Error reading target ID length: {}", e);
                        break;
                    }
                    
                    let target_id_len = u32::from_be_bytes(target_id_len_bytes) as usize;
                    if target_id_len > MAX_ID_LENGTH {
                        error!("Target ID too long: {}", target_id_len);
                        break;
                    }
                    
                    let mut target_id_bytes = vec![0u8; target_id_len];
                    if let Err(e) = reader.read_exact(&mut target_id_bytes).await {
                        error!("Error reading target ID: {}", e);
                        break;
                    }
                    
                    let target_id = match String::from_utf8(target_id_bytes) {
                        Ok(id) => id,
                        Err(e) => {
                            error!("Invalid target ID encoding: {}", e);
                            break;
                        }
                    };
                    
                    info!("Client {} requested connection to {}", client_id, target_id);
                    
                    // Find the target client
                    let clients_map = clients.lock().await;
                    if let Some(target_info) = clients_map.get(&target_id) {
                        // Send connection request to target
                        let mut msg = Vec::new();
                        msg.extend_from_slice(&(MessageType::ConnectionRequest as u32).to_be_bytes());
                        
                        // Add source client ID length and bytes
                        msg.extend_from_slice(&(client_id.len() as u32).to_be_bytes());
                        msg.extend_from_slice(client_id.as_bytes());
                        
                        // Add source client public address
                        msg.extend_from_slice(&public_addr.ip().to_string().len().to_be_bytes());
                        msg.extend_from_slice(public_addr.ip().to_string().as_bytes());
                        msg.extend_from_slice(&public_addr.port().to_be_bytes());
                        
                        if let Err(e) = target_info.sender.send(msg).await {
                            error!("Error sending connection request to target: {}", e);
                        }
                        
                        // Send the target's connection info back to the requester
                        let mut msg = Vec::new();
                        msg.extend_from_slice(&(MessageType::ConnectionInfo as u32).to_be_bytes());
                        
                        // Add target client ID length and bytes
                        msg.extend_from_slice(&(target_id.len() as u32).to_be_bytes());
                        msg.extend_from_slice(target_id.as_bytes());
                        
                        // Add target public address
                        msg.extend_from_slice(&target_info.public_addr.ip().to_string().len().to_be_bytes());
                        msg.extend_from_slice(target_info.public_addr.ip().to_string().as_bytes());
                        msg.extend_from_slice(&target_info.public_addr.port().to_be_bytes());
                        
                        if let Err(e) = tx.send(msg).await {
                            error!("Error sending target info to requester: {}", e);
                        }
                    } else {
                        info!("Target client {} not found", target_id);
                        
                        // Send error response
                        let mut msg = Vec::new();
                        msg.extend_from_slice(&6u32.to_be_bytes()); // Type 6 = client not found
                        msg.extend_from_slice(&(target_id.len() as u32).to_be_bytes());
                        msg.extend_from_slice(target_id.as_bytes());
                        
                        if let Err(e) = tx.send(msg).await {
                            error!("Error sending client not found message: {}", e);
                        }
                    }
                },
                
                // Ping message (type 7)
                7 => {
                    // Respond with pong (type 8)
                    let msg = Vec::from(&8u32.to_be_bytes()[..]);
                    if let Err(e) = tx.send(msg).await {
                        error!("Error sending pong response: {}", e);
                        break;
                    }
                },
                
                // Unknown message type
                _ => {
                    error!("Unknown message type: {}", msg_type);
                    break;
                }
            }
        }
        
        // Client disconnected or error occurred
        info!("Client {} disconnected", client_id);
        
        // Remove client from registry
        {
            let mut clients_map = clients.lock().await;
            clients_map.remove(&client_id);
            info!("Removed client {} from registry", client_id);
        }
        
        // Cancel the writer task
        writer_handle.abort();
        
        Ok(())
    }
    
    /// Run a simple health check HTTP server
    async fn run_health_check(addr: String) -> Result<()> {
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind health check server: {}", e);
                return Err(anyhow!("Failed to bind health check server: {}", e));
            }
        };
        
        info!("Health check server listening on {}", addr);
        
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    error!("Error accepting health check connection: {}", e);
                    continue;
                }
            };
            
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                match socket.read(&mut buf).await {
                    Ok(_) => {
                        // Simple HTTP response
                        let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                        if let Err(e) = socket.write_all(response.as_bytes()).await {
                            error!("Error writing health check response: {}", e);
                        }
                    },
                    Err(e) => {
                        error!("Error reading from health check connection: {}", e);
                    }
                }
            });
        }
    }
} 