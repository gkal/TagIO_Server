use anyhow::{Result, anyhow};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex as TokioMutex},
};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
    collections::HashMap,
};
use log::{debug, info, warn, error, trace};

use crate::relay::NatMessage;

/// Information about a connected client
struct ClientInfo {
    _public_addr: SocketAddr, // Add underscore to mark as intentionally unused
    control_sender: mpsc::Sender<NatMessage>,
}

/// NAT traversal server - runs as a standalone server to facilitate connections
#[derive(Clone)]
pub struct NatTraversalServer {
    clients: Arc<TokioMutex<HashMap<String, ClientInfo>>>,
    relay_sessions: Arc<TokioMutex<HashMap<String, (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>)>>>,
}

impl NatTraversalServer {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(TokioMutex::new(HashMap::new())),
            relay_sessions: Arc::new(TokioMutex::new(HashMap::new())),
        }
    }
    
    /// Run the server on the specified address
    pub async fn run(&self, bind_addr: &str) -> Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        println!("NAT traversal server listening on {}", bind_addr);
        
        loop {
            let (socket, addr) = listener.accept().await?;
            println!("New connection from {}", addr);
            
            // Clone shared state for the client handler
            let clients = self.clients.clone();
            let relay_sessions = self.relay_sessions.clone();
            
            // Handle each client in a separate task
            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(socket, addr, clients, relay_sessions).await {
                    println!("Error handling client {}: {}", addr, e);
                }
            });
        }
    }
    
    /// Handle an individual client connection
    async fn handle_client(
        socket: TcpStream, 
        addr: SocketAddr,
        clients: Arc<TokioMutex<HashMap<String, ClientInfo>>>,
        relay_sessions: Arc<TokioMutex<HashMap<String, (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>)>>>,
    ) -> Result<()> {
        // Create a channel for sending messages to this client
        let (tx, mut rx) = mpsc::channel::<NatMessage>(100);
        
        // Split the socket for concurrent reading and writing
        let (mut reader, mut writer) = tokio::io::split(socket);
        
        // Clone tx for use in the message receiving loop
        let tx_clone = tx.clone();
        
        // Clone shared state for the message receiving loop
        let clients_clone = clients.clone();
        let relay_sessions_clone = relay_sessions.clone();
        let addr_clone = addr;
        
        // Create Arc versions of everything we need to move into tasks
        let tx_for_task = tx_clone.clone();
        
        // READ TASK - handles messages from client
        let read_handle = tokio::spawn(async move {
            loop {
                // Read message length
                let mut len_bytes = [0u8; 4];
                if let Err(e) = reader.read_exact(&mut len_bytes).await {
                    println!("Client disconnected: {}", e);
                    break;
                }
                
                let len = u32::from_be_bytes(len_bytes) as usize;
                let mut buffer = vec![0u8; len];
                
                if let Err(e) = reader.read_exact(&mut buffer).await {
                    println!("Error reading message data: {}", e);
                    break;
                }
                
                match bincode::deserialize::<NatMessage>(&buffer) {
                    Ok(message) => {
                        // Process message without capturing MutexGuard across await points
                        if let Err(e) = Self::process_message_safe(
                            message, 
                            addr_clone, 
                            tx_for_task.clone(), 
                            clients_clone.clone(),
                            relay_sessions_clone.clone(),
                        ).await {
                            println!("Error processing message: {}", e);
                        }
                    }
                    Err(e) => println!("Error deserializing message: {}", e),
                }
            }
            
            // Remove the client when they disconnect - do this in a way that doesn't hold the lock across an await
            let capacity = tx_clone.capacity();
            {
                let mut clients = clients_clone.lock().await;
                clients.retain(|_, info| info.control_sender.capacity() != capacity);
            }
        });
        
        // WRITE TASK - sends messages to the client
        let write_handle = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                let encoded = match bincode::serialize(&message) {
                    Ok(data) => data,
                    Err(e) => {
                        println!("Error serializing message: {}", e);
                        continue;
                    }
                };
                
                let len = encoded.len() as u32;
                if let Err(e) = writer.write_all(&len.to_be_bytes()).await {
                    println!("Error writing message length: {}", e);
                    break;
                }
                
                if let Err(e) = writer.write_all(&encoded).await {
                    println!("Error writing message data: {}", e);
                    break;
                }
            }
        });
        
        // Wait for either task to complete
        tokio::select! {
            _ = read_handle => {},
            _ = write_handle => {},
        }
        
        Ok(())
    }
    
    /// Process a message from a client safely, without holding locks across await points
    async fn process_message_safe(
        message: NatMessage,
        addr: SocketAddr,
        tx: mpsc::Sender<NatMessage>,
        clients: Arc<TokioMutex<HashMap<String, ClientInfo>>>,
        relay_sessions: Arc<TokioMutex<HashMap<String, (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>)>>>,
    ) -> Result<()> {
        match message {
            NatMessage::Register { client_id } => {
                println!("Client {} registered as {}", addr, client_id);
                
                // Register the client - don't hold lock across await points
                {
                    let mut clients_map = clients.lock().await;
                    clients_map.insert(client_id.clone(), ClientInfo {
                        _public_addr: addr,
                        control_sender: tx.clone(),
                    });
                }
                
                // Send acknowledgment with public address
                let ack = NatMessage::RegisterAck {
                    public_addr: addr,
                };
                tx.send(ack).await?;
            }
            
            NatMessage::ConnectRequest { target_id } => {
                println!("Connection request from {} to {}", addr, target_id);
                
                // Find the target client - get data from lock then release it before await
                let target_sender = {
                    let clients_map = clients.lock().await;
                    clients_map.get(&target_id).map(|target| target.control_sender.clone())
                };
                
                // Forward the connection request outside the lock
                if let Some(sender) = target_sender {
                    let req = NatMessage::ConnectRequest {
                        target_id: "".to_string(), // We'll extract the sender ID later
                    };
                    sender.send(req).await?;
                } else {
                    println!("Target client {} not found", target_id);
                }
            }
            
            NatMessage::ConnectionInfo { client_id, public_addr, private_addrs } => {
                // Get clone of all client senders we need to notify
                let client_senders: Vec<(String, mpsc::Sender<NatMessage>)> = {
                    let clients_map = clients.lock().await;
                    clients_map.iter()
                        .filter(|(id, _)| *id != &client_id)
                        .map(|(id, client)| (id.clone(), client.control_sender.clone()))
                        .collect()
                };
                
                // Now send messages outside the lock
                for (id, sender) in client_senders {
                    let info = NatMessage::ConnectionInfo {
                        client_id: client_id.clone(),
                        public_addr,
                        private_addrs: private_addrs.clone(),
                    };
                    if let Err(e) = sender.send(info).await {
                        println!("Failed to send connection info to {}: {}", id, e);
                    }
                }
            }
            
            NatMessage::RelayRequest { session_id } => {
                // Create a new relay session
                let (tx1, _rx1) = mpsc::channel::<Vec<u8>>(100);
                let (_tx2, rx2) = mpsc::channel::<Vec<u8>>(100);
                
                // Insert into sessions map - drop lock before await
                {
                    let mut sessions = relay_sessions.lock().await;
                    sessions.insert(session_id.clone(), (tx1, rx2));
                }
                
                // Get target client info
                let parts: Vec<&str> = session_id.split(':').collect();
                let target_sender = if parts.len() >= 2 {
                    let target_id = parts[1];
                    let clients_map = clients.lock().await;
                    clients_map.get(target_id).map(|target| target.control_sender.clone())
                } else {
                    None
                };
                
                // Send acceptance to the requesting client
                let accept = NatMessage::RelayAccept {
                    session_id: session_id.clone(),
                };
                tx.send(accept.clone()).await?;
                
                // Also notify the target client if found
                if let Some(sender) = target_sender {
                    sender.send(accept).await?;
                }
            }
            
            NatMessage::RelayData { session_id, data } => {
                // Get the sender channel from sessions
                let tx_opt = {
                    let sessions = relay_sessions.lock().await;
                    sessions.get(&session_id).map(|(tx, _)| tx.clone())
                };
                
                // Forward data through the relay if session exists
                if let Some(tx) = tx_opt {
                    tx.send(data).await?;
                }
            }
            
            _ => {
                // Handle other message types as needed
            }
        }
        
        Ok(())
    }
} 