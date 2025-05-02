use anyhow::{Result, anyhow};
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use std::{
    net::SocketAddr,
    sync::Arc,
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
};
use log::{debug, error, info, warn, trace};
use crate::relay::messages::NatMessage;
use crate::relay::constants::DEFAULT_AUTH_SECRET;

// Keep alive timeout
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(60);
// Buffer size for reading from clients
const READ_BUFFER_SIZE: usize = 8192;
// Maximum number of unauthorized attempts before logging a warning
const MAX_UNAUTHORIZED_ATTEMPTS: usize = 10;

// Information about a connected client
struct ClientInfo {
    public_addr: SocketAddr,
    control_sender: mpsc::Sender<NatMessage>,
}

// Relay session for direct data forwarding
struct RelaySession {
    client_a: String,
    client_b: String,
    data_sender: mpsc::Sender<Vec<u8>>,
}

// NAT traversal server - runs as a standalone server to facilitate connections
#[derive(Clone)]
pub struct NatTraversalServer {
    clients: Arc<TokioMutex<HashMap<String, ClientInfo>>>,
    relay_sessions: Arc<TokioMutex<HashMap<String, RelaySession>>>,
    public_ip: Option<String>, // Store the server's public IP address
    auth_secret: String, // Authentication secret
    unauthorized_attempts: Arc<AtomicUsize>, // Track unauthorized connection attempts
}

impl NatTraversalServer {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(TokioMutex::new(HashMap::new())),
            relay_sessions: Arc::new(TokioMutex::new(HashMap::new())),
            public_ip: None,
            auth_secret: DEFAULT_AUTH_SECRET.to_string(),
            unauthorized_attempts: Arc::new(AtomicUsize::new(0)),
        }
    }
    
    // Allow setting the public IP explicitly
    pub fn with_public_ip(mut self, ip: &str) -> Self {
        self.public_ip = Some(ip.to_string());
        self
    }
    
    // Set authentication secret
    pub fn with_auth_secret(mut self, secret: &str) -> Self {
        self.auth_secret = secret.to_string();
        self
    }
    
    // Run the server and start accepting connections
    pub async fn run(&self, bind_addr: &str) -> Result<()> {
        info!("Starting NAT traversal relay server on {}", bind_addr);
        
        // Bind the TCP listener to the specified address
        let listener = TcpListener::bind(bind_addr).await?;
        
        if let Some(public_ip) = &self.public_ip {
            info!("Server configured with public IP: {}", public_ip);
        } else {
            warn!("No public IP configured. NAT traversal may be limited.");
            warn!("Server will use client-reported public addresses for NAT traversal.");
        }
        
        // Accept incoming connections
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    debug!("New connection from {}", addr);
                    
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
    
    // Handle a client connection
    async fn handle_client(&self, socket: TcpStream, addr: SocketAddr) -> Result<()> {
        trace!("Handling new client connection from {}", addr);
        
        // Get socket info for later use
        let peer_addr = socket.peer_addr()?;
        
        // Establish the public address to use for NAT traversal
        let public_addr = if let Some(ip_str) = &self.public_ip {
            match ip_str.parse() {
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
        let (mut read, mut write) = tokio::io::split(socket);
        
        // Spawn a task for sending messages to the client
        let write_task = {
            tokio::spawn(async move {
                while let Some(message) = control_rx.recv().await {
                    trace!("Sending message to {}: {:?}", addr, message);
                    match bincode::serialize(&message) {
                        Ok(data) => {
                            if let Err(e) = write.write_all(&data).await {
                                error!("Error writing to client {}: {}", addr, e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Error serializing message for {}: {}", addr, e);
                            break;
                        }
                    }
                }
                debug!("Client sender task for {} terminated", addr);
            })
        };
        
        // Buffer for incoming data
        let mut buffer = vec![0u8; READ_BUFFER_SIZE];
        let mut client_id = String::new();
        let mut authenticated = false;
        
        // Process messages from the client
        loop {
            // Read with timeout to detect dead connections
            match timeout(KEEP_ALIVE_TIMEOUT, read.read(&mut buffer)).await {
                Ok(Ok(0)) => {
                    // Connection closed by client
                    debug!("Client {} disconnected", addr);
                    break;
                }
                Ok(Ok(n)) => {
                    // Deserialize the message
                    match bincode::deserialize::<NatMessage>(&buffer[..n]) {
                        Ok(message) => {
                            trace!("Received message from {}: {:?}", addr, message);
                            
                            // Handle client authentication first
                            if !authenticated {
                                match &message {
                                    NatMessage::Authenticate { secret, client_id: id } => {
                                        if secret == &self.auth_secret {
                                            authenticated = true;
                                            client_id = id.clone();
                                            
                                            // Register the client
                                            self.register_client(id.clone(), public_addr, control_tx.clone()).await?;
                                            
                                            // Send acknowledgment with public address
                                            control_tx.send(NatMessage::AuthAck { 
                                                public_addr, 
                                                message: format!("Authenticated as {}", id) 
                                            }).await?;
                                            
                                            info!("Client {} registered with ID {}", addr, id);
                                        } else {
                                            // Invalid authentication
                                            let attempts = self.unauthorized_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                                            if attempts % MAX_UNAUTHORIZED_ATTEMPTS == 0 {
                                                warn!("Multiple unauthorized connection attempts detected ({})", attempts);
                                            }
                                            
                                            // Send auth failure and close connection
                                            let _ = control_tx.send(NatMessage::AuthError { 
                                                message: "Invalid authentication secret".to_string() 
                                            }).await;
                                            
                                            // Wait a bit before closing to allow the error to be sent
                                            tokio::time::sleep(Duration::from_millis(100)).await;
                                            break;
                                        }
                                    }
                                    _ => {
                                        // Client must authenticate first
                                        let _ = control_tx.send(NatMessage::AuthError { 
                                            message: "Authentication required".to_string() 
                                        }).await;
                                        
                                        // Wait a bit before closing to allow the error to be sent
                                        tokio::time::sleep(Duration::from_millis(100)).await;
                                        break;
                                    }
                                }
                            } else {
                                // Process authenticated client messages
                                match message {
                                    NatMessage::Ping => {
                                        // Respond to ping with pong
                                        if let Err(e) = control_tx.send(NatMessage::Pong).await {
                                            error!("Failed to send pong to {}: {}", addr, e);
                                        }
                                    }
                                    NatMessage::ConnectRequest { target_id } => {
                                        // Handle connection request
                                        self.handle_connect_request(&client_id, &target_id, control_tx.clone()).await?;
                                    }
                                    NatMessage::RelayRequest { target_id, session_id } => {
                                        // Handle relay request
                                        self.handle_relay_request(&client_id, &target_id, &session_id, control_tx.clone()).await?;
                                    }
                                    NatMessage::RelayData { session_id, data } => {
                                        // Forward relay data
                                        self.handle_relay_data(&session_id, data).await?;
                                    }
                                    _ => {
                                        // Other message types can be handled as needed
                                        trace!("Unhandled message type from {}: {:?}", addr, message);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to deserialize message from {}: {}", addr, e);
                            // Continue - the next message might be valid
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("Error reading from client {}: {}", addr, e);
                    break;
                }
                Err(_) => {
                    // Timeout occurred
                    debug!("Read timeout for client {}, sending ping", addr);
                    
                    // Send ping to check if client is still alive
                    if let Err(e) = control_tx.send(NatMessage::Ping).await {
                        error!("Failed to send ping to {}: {}", addr, e);
                        break;
                    }
                }
            }
        }
        
        // Clean up client resources
        if !client_id.is_empty() {
            debug!("Removing client {} ({})", client_id, addr);
            let mut clients = self.clients.lock().await;
            clients.remove(&client_id);
        }
        
        // Abort write task
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
        debug!("Connect request from {} to {}", client_id, target_id);
        
        // Get client info
        let clients = self.clients.lock().await;
        
        // Get target client info
        if let Some(target_client) = clients.get(target_id) {
            // Send connection info to the requestor
            control_sender.send(NatMessage::ConnectionInfo {
                client_id: target_id.to_string(),
                public_addr: target_client.public_addr,
            }).await?;
            
            // Send connect notification to the target
            if let Err(e) = target_client.control_sender.send(NatMessage::ConnectNotification {
                client_id: client_id.to_string(),
                public_addr: clients.get(client_id)
                    .map(|info| info.public_addr)
                    .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0))),
            }).await {
                error!("Failed to send connect notification to {}: {}", target_id, e);
                return Err(anyhow!("Failed to notify target client"));
            }
            
            info!("Connection facilitated between {} and {}", client_id, target_id);
        } else {
            // Target client not found
            warn!("Connect request for unknown client: {}", target_id);
            control_sender.send(NatMessage::Error {
                message: format!("Target client {} not found", target_id),
            }).await?;
        }
        
        Ok(())
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
                    client_a: client_id.to_string(),
                    client_b: target_id.to_string(),
                    data_sender: data_tx.clone(),
                });
            }
            
            // Clone target sender for the relay task
            let target_sender = target_client.control_sender.clone();
            let session_id = session_id.to_string();
            
            // Create task for relay forwarding
            tokio::spawn(async move {
                while let Some(data) = data_rx.recv().await {
                    if let Err(e) = target_sender.send(NatMessage::RelayData {
                        session_id: session_id.clone(),
                        data,
                    }).await {
                        error!("Failed to relay data: {}", e);
                        break;
                    }
                }
                debug!("Relay forwarding task for session {} terminated", session_id);
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
} 