mod screen_capture;
mod streaming;
mod input;
mod network_speed;
mod config;
mod relay;

// Import VERSION from lib.rs instead of defining it here
use tagio::VERSION;
use tagio::gui;
use anyhow::{Result, anyhow};
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use rfd::MessageDialog;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};

const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:443";
const DEFAULT_LOG_LEVEL: log::LevelFilter = log::LevelFilter::Info;

// Client information stored in the server
struct ClientInfo {
    _public_addr: SocketAddr,
    _sender: mpsc::Sender<Vec<u8>>,
}

// Message types for relay protocol
#[derive(Debug, Serialize, Deserialize, Clone)]
enum RelayMessage {
    // Registration messages
    Register { client_id: String },
    RegisterAck { public_addr: SocketAddr },
    
    // Connection establishment
    ConnectRequest { target_id: String },
    ConnectionInfo { 
        client_id: String, 
        public_addr: SocketAddr, 
        private_addrs: Vec<SocketAddr> 
    },
    
    // Relay functionality
    RelayRequest { session_id: String },
    RelayAccept { session_id: String },
    RelayData { session_id: String, data: Vec<u8> },
    
    // Keep-alive
    Ping,
    Pong,
}

// Main relay server implementation
struct RelayServer {
    clients: Arc<Mutex<HashMap<String, ClientInfo>>>,
    public_ip: Option<String>,
}

impl RelayServer {
    // Initialize a new relay server
    fn new(public_ip: Option<String>) -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            public_ip,
        }
    }
    
    // Main server loop
    async fn run(&self, bind_addr: &str) -> io::Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        info!("Relay server listening on {}", bind_addr);
        
        if let Some(public_ip) = &self.public_ip {
            info!("Server configured with public IP: {}", public_ip);
        } else {
            warn!("No public IP configured. NAT traversal may not work optimally.");
            warn!("Server will attempt to auto-detect public IP or use client's perceived address.");
        }
        
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    info!("New connection from {}", addr);
                    
                    // Determine the public address to use for this client
                    let public_addr = if let Some(ip) = &self.public_ip {
                        match ip.parse::<IpAddr>() {
                            Ok(public_ip) => SocketAddr::new(public_ip, addr.port()),
                            Err(_) => {
                                warn!("Failed to parse configured public IP. Using detected IP.");
                                addr
                            }
                        }
                    } else {
                        addr
                    };
                    
                    // Clone shared state for this client's task
                    let clients_clone = self.clients.clone();
                    
                    // Handle each client in a separate task
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client(socket, addr, public_addr, clients_clone).await {
                            error!("Error handling client {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
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
    ) -> Result<()> {
        debug!("Handling new client connection from {}", addr);
        
        // Create channel for sending messages to client
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
        
        // Split the socket for concurrent reading and writing
        let (mut read, mut write) = tokio::io::split(socket);
        
        // Spawn a task to handle messages sent to the client
        let write_task = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let Err(e) = write.write_all(&message).await {
                    error!("Error writing to client {}: {}", addr, e);
                    break;
                }
            }
            debug!("Client sender task for {} terminated", addr);
        });
        
        // Buffer for incoming messages
        let mut buffer = [0u8; 4096];
        let mut client_id = String::new();
        
        // Read and process client messages
        loop {
            // Set a timeout for reading from the client
            match timeout(KEEP_ALIVE_TIMEOUT, read.read(&mut buffer)).await {
                Ok(Ok(0)) => {
                    // Connection closed
                    debug!("Client {} disconnected", addr);
                    break;
                },
                Ok(Ok(n)) => {
                    // Process the message
                    if let Ok(message) = bincode::deserialize::<RelayMessage>(&buffer[..n]) {
                        debug!("Received message from {}: {:?}", addr, message);
                        
                        // Process registration first
                        if let RelayMessage::Register { client_id: id } = &message {
                            client_id = id.clone();
                            
                            // Store client info
                            let mut clients_lock = clients.lock().await;
                            clients_lock.insert(id.clone(), ClientInfo {
                                _public_addr: public_addr,
                                _sender: tx.clone(),
                            });
                            
                            // Send acknowledgment with public address
                            if let Ok(ack) = bincode::serialize(&RelayMessage::RegisterAck { 
                                public_addr 
                            }) {
                                // Check if write task is still running before sending
                                if !write_task.is_finished() {
                                    if let Err(e) = tx.send(ack).await {
                                        error!("Failed to send ack to {}: {}", addr, e);
                                    }
                                }
                            }
                            
                            debug!("Client {} registered with ID {}", addr, id);
                        }
                        
                        // Handle other message types
                        // This is a simplified implementation - you'd handle
                        // connect requests, relay data, etc. here
                    }
                },
                Ok(Err(e)) => {
                    error!("Error reading from client {}: {}", addr, e);
                    break;
                },
                Err(_) => {
                    // Timeout occurred, client might be dead
                    debug!("Timeout reading from client {}, closing connection", addr);
                    break;
                }
            }
        }
        
        // Remove client from active clients
        if !client_id.is_empty() {
            let mut clients_lock = clients.lock().await;
            clients_lock.remove(&client_id);
            debug!("Removed client {} with ID {}", addr, client_id);
        }
        
        // Ensure write task is terminated
        write_task.abort();
        
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging with default level
    env_logger::Builder::new()
        .format_timestamp_millis()
        .filter_level(DEFAULT_LOG_LEVEL)
        .init();
    
    // Print banner
    println!("TagIO NAT Traversal Relay Server v0.2.0");
    println!("----------------------------------------");
    
    // Get the local IP address to display to the user
    let local_ip = match local_ip_address::local_ip() {
        Ok(ip) => ip.to_string(),
        Err(_) => "unknown".to_string(),
    };
    
    println!("Local IP address: {}", local_ip);
    println!("Default binding to: {}", DEFAULT_BIND_ADDRESS);
    println!("");
    println!("Note: For optimal NAT traversal, configure your");
    println!("      public IP in the server settings if needed.");
    
    // Create and run the relay server with no public IP configured by default
    // Users will need to configure this in settings if needed
    let server = RelayServer::new(None);
    
    info!("Starting relay server on {}", DEFAULT_BIND_ADDRESS);
    if let Err(e) = server.run(DEFAULT_BIND_ADDRESS).await {
        error!("Server error: {}", e);
        return Err(anyhow!("Server error: {}", e));
    }
    
    Ok(())
}

#[allow(dead_code)]
async fn relay_mode(mut shutdown_rx: mpsc::Receiver<()>, config: config::Config) -> Result<()> {
    let local_key = config.local_key.clone();
    
    // Show connection dialog
    print!("Enter the remote TagIO ID: ");
    io::stdout().flush()?;
    
    let mut remote_key = String::new();
    io::stdin().read_line(&mut remote_key)?;
    let remote_key = remote_key.trim().to_string();
    
    if remote_key.is_empty() {
        println!("Remote TagIO ID cannot be empty!");
        return Ok(());
    }
    
    // Compare keys to determine role
    if remote_key == local_key {
        println!("Error: Remote TagIO ID cannot be the same as your local TagIO ID!");
        return Ok(());
    }

    // Connect to the relay server and request connection to the remote key
    println!("Connecting to relay server ({}) and looking for {}", config.relay_server, remote_key);
    let mut stream = match relay::connect_via_relay(&local_key, &remote_key, Some(config.relay_server.clone()), true).await {
        Ok(stream) => {
            println!("Connection request sent. Waiting for remote approval...");
            stream
        },
        Err(e) => {
            // Cannot establish relay connection
            println!("Failed to establish connection through relay: {}", e);
            println!("Starting listener mode with local TagIO ID: {}", local_key);
            
            // Start TCP listener and wait for incoming connections
            let listen_port = config.port;
            let listener = TcpListener::bind(format!("0.0.0.0:{}", listen_port)).await?;
            
            println!("Waiting for connection... Share your TagIO ID with the person who needs to connect.");
            
            // Use select to handle either new connection or shutdown signal
            let result = tokio::select! {
                result = listener.accept() => Ok::<(TcpStream, SocketAddr), anyhow::Error>(result?),
                _ = shutdown_rx.recv() => {
                    println!("Shutting down listener...");
                    return Ok(())
                }
            };
            
            if let Ok((socket, addr)) = result {
                println!("Incoming connection from: {}", addr);
                
                // Show approval dialog
                let dialog = MessageDialog::new()
                    .set_title("Connection Request")
                    .set_description(&format!("Allow connection from {}?", addr))
                    .set_buttons(rfd::MessageButtons::YesNo);
                
                if dialog.show() == rfd::MessageDialogResult::Yes {
                    println!("Connection accepted");
                    socket
                } else {
                    println!("Connection rejected");
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        }
    };
    
    // Wait for connection response or request
    let mut buffer = [0u8; 1024];
    let n = stream.read(&mut buffer).await?;
    let response = String::from_utf8_lossy(&buffer[..n]);
    
    if response.starts_with("CONNECTION_REQUEST:") {
        // We received a connection request - show approval dialog
        let requester_id = response.trim_start_matches("CONNECTION_REQUEST:").trim();
        
        let dialog = MessageDialog::new()
            .set_title("Connection Request")
            .set_description(&format!("Allow connection from TagIO ID: {}?", requester_id))
            .set_buttons(rfd::MessageButtons::YesNo);
        
        if dialog.show() == rfd::MessageDialogResult::Yes {
            println!("Connection accepted");
            // Send approval
            stream.write_all(b"APPROVE\n").await?;
        } else {
            println!("Connection rejected");
            stream.write_all(b"REJECT\n").await?;
            return Ok(());
        }
        
        // Wait for established response
        let n = stream.read(&mut buffer).await?;
        let response = String::from_utf8_lossy(&buffer[..n]);
        
        if !response.starts_with("ESTABLISHED") {
            println!("Failed to establish connection: {}", response);
            return Ok(());
        }
    } else if !response.starts_with("ESTABLISHED") {
        // Unexpected response
        println!("Unexpected response from relay server: {}", response);
        return Ok(());
    }
    
    println!("Connection established with remote TagIO ID: {}", remote_key);
    
    // Determine role based on key comparison
    let client_mode = remote_key < local_key;
    
    if client_mode {
        // We become the client (viewer)
        println!("Running as client (remote ID: {} < local ID: {})", remote_key, local_key);
        println!("You are VIEWER - Starting image streaming from {}", remote_key);
        
        // Set up GUI with the new create_gui_with_title function
        let (frame_tx, app) = gui::create_gui_with_title(&format!("TagIO Client - Connected to {}", remote_key));
        
        // Update connection status
        {
            let mut app_lock = app.lock().unwrap();
            app_lock.connection_status = format!("Connected to {}...", remote_key);
        }
        
        println!("Starting remote desktop session as VIEWER - Receiving screen data...");
        
        // Start streaming client
        streaming::run_client(stream, frame_tx).await?;
    } else {
        // We become the server (host)
        println!("Running as server (remote ID: {} > local ID: {})", remote_key, local_key);
        println!("You are HOST - Your screen is being shared with {}", remote_key);
        println!("Remote control session active as HOST - Your screen is being shared");
        
        // Create a null channel (we don't need GUI updates on server)
        let (frame_tx, _) = mpsc::channel::<(Vec<u8>, u32, u32)>(1);
        
        // Start streaming server
        streaming::run_server(stream, frame_tx).await?;
    }
    
    Ok(())
}