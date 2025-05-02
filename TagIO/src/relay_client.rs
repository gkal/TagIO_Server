// Proper import for the tls module
use crate::tls;

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep, Duration};
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use tokio_rustls::client::TlsStream;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use reqwest;

// Default relay server address - use a public IP if you have a fixed one
// For development, you can use your local public IP
// 2.86.97.232 was the original value
const DEFAULT_RELAY_SERVER: &str = "2.86.97.232:443";

// Define an enum to handle both TLS and plain TCP streams
enum TlsOrPlainStream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

// Implement AsyncRead for our enum
impl AsyncRead for TlsOrPlainStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TlsOrPlainStream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            TlsOrPlainStream::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

// Implement AsyncWrite for our enum
impl AsyncWrite for TlsOrPlainStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            TlsOrPlainStream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            TlsOrPlainStream::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            TlsOrPlainStream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            TlsOrPlainStream::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            TlsOrPlainStream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            TlsOrPlainStream::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Message {
    /// Register with tagio_id
    Register { tagio_id: String },
    
    /// Request IP of a tagio_id
    LookupRequest { target_tagio_id: String },
    
    /// Response with IP for requested tagio_id
    LookupResponse { ip: Option<String> },
    
    /// Connection request from one peer to another
    ConnectionRequest { 
        from_tagio_id: String, 
        to_tagio_id: String,
        from_ip: Option<String> // Include the requester's IP address
    },
    
    /// Confirmation that connection was accepted
    ConnectionAccepted { 
        from_tagio_id: String, 
        to_tagio_id: String,
        to_ip: Option<String> // Include target IP address
    },
    
    /// Notification that a connection was rejected
    ConnectionRejected { 
        from_tagio_id: String, 
        to_tagio_id: String 
    },
}

pub enum RelayCommand {
    LookupPeer { 
        target_id: String, 
        resp: oneshot::Sender<Option<String>> 
    },
    RequestConnection { 
        from_id: String, 
        to_id: String, 
        resp: oneshot::Sender<bool> 
    },
    AcceptConnection { 
        from_id: String, 
        to_id: String 
    },
    RejectConnection { 
        from_id: String, 
        to_id: String 
    },
}

pub enum RelayEvent {
    ConnectionRequest {
        from_id: String,
        from_ip: Option<String>, // Add the requester's IP
    },
    ConnectionAccepted {
        from_id: String,
        remote_ip: Option<String>, // Add the remote peer's IP
    },
    ConnectionRejected {
        from_id: String,
    },
}

pub struct RelayClient {
    cmd_tx: mpsc::Sender<RelayCommand>,
    event_rx: mpsc::Receiver<RelayEvent>,
    my_tagio_id: String,
}

impl RelayClient {
    pub async fn connect(tagio_id: &str, relay_server: Option<&str>) -> Result<Self> {
        println!("Connecting to relay server as {}", tagio_id);
        let relay_addr = relay_server.unwrap_or(DEFAULT_RELAY_SERVER);
        println!("Using relay server address: {}", relay_addr);
        
        // Connect to the relay server with TLS
        let use_tls = true; // By default, use TLS (can add a parameter to disable it)
        let stream = connect_with_tls_option(relay_addr, use_tls).await?;
        
        // Register our TagIO ID
        let register_msg = Message::Register { 
            tagio_id: tagio_id.to_string() 
        };
        
        let register_json = serde_json::to_string(&register_msg)?;
        println!("Sending registration message: {}", register_json);
        stream.write_all(register_json.as_bytes()).await?;
        println!("Registration message sent to relay server");
        
        // Create channels for commands and events
        let (cmd_tx, cmd_rx) = mpsc::channel::<RelayCommand>(100);
        let (event_tx, event_rx) = mpsc::channel::<RelayEvent>(100);
        
        // Spawn background task to handle communication with relay
        let tagio_id_clone = tagio_id.to_string();
        tokio::spawn(async move {
            if let Err(e) = Self::handle_relay_connection(
                stream, 
                cmd_rx, 
                event_tx, 
                tagio_id_clone
            ).await {
                eprintln!("Relay connection error: {}", e);
            }
        });
        
        println!("RelayClient successfully created with ID: {}", tagio_id);
        Ok(Self {
            cmd_tx,
            event_rx,
            my_tagio_id: tagio_id.to_string(),
        })
    }
    
    // Get the next event from the relay
    pub async fn next_event(&mut self) -> Option<RelayEvent> {
        self.event_rx.recv().await
    }
    
    // Look up a peer's IP by their TagIO ID
    pub async fn lookup_peer(&self, target_id: &str) -> Result<Option<String>> {
        let (resp_tx, resp_rx) = oneshot::channel();
        
        self.cmd_tx.send(RelayCommand::LookupPeer {
            target_id: target_id.to_string(),
            resp: resp_tx,
        }).await?;
        
        resp_rx.await.map_err(|_| anyhow!("Relay channel closed"))
    }
    
    // Request a connection to another peer
    pub async fn request_connection(&self, target_id: &str) -> Result<bool> {
        let (resp_tx, resp_rx) = oneshot::channel();
        
        self.cmd_tx.send(RelayCommand::RequestConnection {
            from_id: self.my_tagio_id.clone(),
            to_id: target_id.to_string(),
            resp: resp_tx,
        }).await?;
        
        resp_rx.await.map_err(|_| anyhow!("Relay channel closed"))
    }
    
    // Accept a connection request from another peer
    pub async fn accept_connection(&self, from_id: &str) -> Result<()> {
        self.cmd_tx.send(RelayCommand::AcceptConnection {
            from_id: from_id.to_string(),
            to_id: self.my_tagio_id.clone(),
        }).await?;
        
        Ok(())
    }
    
    // Reject a connection request from another peer
    pub async fn reject_connection(&self, from_id: &str) -> Result<()> {
        self.cmd_tx.send(RelayCommand::RejectConnection {
            from_id: from_id.to_string(),
            to_id: self.my_tagio_id.clone(),
        }).await?;
        
        Ok(())
    }
    
    // Background task handling the relay connection
    async fn handle_relay_connection(
        mut stream: TlsOrPlainStream,
        mut cmd_rx: mpsc::Receiver<RelayCommand>,
        event_tx: mpsc::Sender<RelayEvent>,
        tagio_id: String,
    ) -> Result<()> {
        println!("Starting relay connection handler for TagIO ID: {}", tagio_id);
        // Buffer for reading messages from the relay
        let mut buffer = [0; 4096];
        
        loop {
            tokio::select! {
                // Handle incoming relay messages
                n = stream.read(&mut buffer) => {
                    match n {
                        Ok(0) => {
                            println!("Connection closed by relay server");
                            return Ok(());
                        }
                        Ok(n) => {
                            println!("Received {} bytes from relay server", n);
                            // Try to parse message
                            if let Ok(msg_str) = std::str::from_utf8(&buffer[..n]) {
                                println!("Received message: {}", msg_str);
                                if let Ok(msg) = serde_json::from_str::<Message>(msg_str) {
                                    println!("Parsed message type: {:?}", std::mem::discriminant(&msg));
                                    match msg {
                                        Message::ConnectionRequest { from_tagio_id, to_tagio_id, from_ip } => {
                                            println!("Received connection request from {} to {}", from_tagio_id, to_tagio_id);
                                            if to_tagio_id == tagio_id {
                                                // Connection request for us
                                                println!("Connection request is for us, forwarding to UI");
                                                event_tx.send(RelayEvent::ConnectionRequest {
                                                    from_id: from_tagio_id,
                                                    from_ip: from_ip,
                                                }).await?;
                                            } else {
                                                println!("Connection request is not for us, ignoring");
                                            }
                                        }
                                        Message::ConnectionAccepted { from_tagio_id, to_tagio_id, to_ip } => {
                                            println!("Received connection acceptance from {} to {}", from_tagio_id, to_tagio_id);
                                            if to_tagio_id == tagio_id {
                                                // Our connection request was accepted
                                                println!("Our connection request was accepted, forwarding to UI");
                                                event_tx.send(RelayEvent::ConnectionAccepted {
                                                    from_id: from_tagio_id,
                                                    remote_ip: to_ip,
                                                }).await?;
                                            } else {
                                                println!("Connection acceptance is not for us, ignoring");
                                            }
                                        }
                                        Message::ConnectionRejected { from_tagio_id, to_tagio_id } => {
                                            println!("Received connection rejection from {} to {}", from_tagio_id, to_tagio_id);
                                            if to_tagio_id == tagio_id {
                                                // Our connection request was rejected
                                                println!("Our connection request was rejected, forwarding to UI");
                                                event_tx.send(RelayEvent::ConnectionRejected {
                                                    from_id: from_tagio_id,
                                                }).await?;
                                            } else {
                                                println!("Connection rejection is not for us, ignoring");
                                            }
                                        }
                                        Message::LookupResponse { ip } => {
                                            println!("Received lookup response: {:?}", ip);
                                            // This should be handled by the appropriate oneshot responder
                                            // For our simple implementation, we'll ignore this here
                                            // In a real application, we would store the pending lookup requests
                                        }
                                        _ => {
                                            println!("Received unhandled message type");
                                        }
                                    }
                                } else {
                                    eprintln!("Failed to parse message as JSON: {}", msg_str);
                                }
                            } else {
                                eprintln!("Received non-UTF8 data from relay");
                            }
                        }
                        Err(e) => {
                            eprintln!("Error reading from relay: {}", e);
                            return Err(anyhow!("Relay connection error: {}", e));
                        }
                    }
                }
                
                // Handle commands from the application
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(RelayCommand::LookupPeer { target_id, resp }) => {
                            println!("Looking up peer: {}", target_id);
                            // Send lookup request to relay
                            let lookup_msg = Message::LookupRequest {
                                target_tagio_id: target_id,
                            };
                            let lookup_json = serde_json::to_string(&lookup_msg)?;
                            println!("Sending lookup request: {}", lookup_json);
                            stream.write_all(lookup_json.as_bytes()).await?;
                            
                            // TODO: In a real implementation, we would wait for the response
                            // For now, we'll just simulate a delayed response
                            tokio::spawn(async move {
                                sleep(Duration::from_millis(500)).await;
                                println!("Sending simulated lookup response");
                                let _ = resp.send(Some("192.168.1.100:12345".to_string()));
                            });
                        }
                        
                        Some(RelayCommand::RequestConnection { from_id, to_id, resp }) => {
                            println!("Requesting connection from {} to {}", from_id, to_id);
                            
                            // Try to include our public IP if possible
                            let local_ip_future = tokio::spawn(get_public_ip());
                            let local_ip = match tokio::time::timeout(Duration::from_secs(3), local_ip_future).await {
                                Ok(Ok(Some(ip))) => {
                                    println!("Including our public IP in request: {}", ip);
                                    Some(format!("{}:443", ip)) // Assuming default port
                                },
                                _ => {
                                    println!("Could not detect public IP, letting server determine our IP");
                                    None
                                }
                            };
                            
                            // Send connection request to relay
                            let request_msg = Message::ConnectionRequest {
                                from_tagio_id: from_id,
                                to_tagio_id: to_id,
                                from_ip: local_ip,
                            };
                            let request_json = serde_json::to_string(&request_msg)?;
                            println!("Sending connection request: {}", request_json);
                            stream.write_all(request_json.as_bytes()).await?;
                            
                            // TODO: In a real implementation, we would wait for the response
                            // For now, we'll just simulate a delayed success
                            tokio::spawn(async move {
                                sleep(Duration::from_millis(500)).await;
                                println!("Sending simulated connection response");
                                let _ = resp.send(true);
                            });
                        }
                        
                        Some(RelayCommand::AcceptConnection { from_id, to_id }) => {
                            println!("Accepting connection from {} to {}", from_id, to_id);
                            
                            // Try to include our public IP if possible
                            let local_ip_future = tokio::spawn(get_public_ip());
                            let local_ip = match tokio::time::timeout(Duration::from_secs(3), local_ip_future).await {
                                Ok(Ok(Some(ip))) => {
                                    println!("Including our public IP in acceptance: {}", ip);
                                    Some(format!("{}:443", ip)) // Assuming default port
                                },
                                _ => {
                                    println!("Could not detect public IP, letting server determine our IP");
                                    None
                                }
                            };
                            
                            // Send accept message to relay
                            let accept_msg = Message::ConnectionAccepted {
                                from_tagio_id: to_id,
                                to_tagio_id: from_id,
                                to_ip: local_ip, 
                            };
                            let accept_json = serde_json::to_string(&accept_msg)?;
                            println!("Sending connection acceptance: {}", accept_json);
                            stream.write_all(accept_json.as_bytes()).await?;
                        }
                        
                        Some(RelayCommand::RejectConnection { from_id, to_id }) => {
                            println!("Rejecting connection from {} to {}", from_id, to_id);
                            // Send reject message to relay
                            let reject_msg = Message::ConnectionRejected {
                                from_tagio_id: to_id,
                                to_tagio_id: from_id,
                            };
                            let reject_json = serde_json::to_string(&reject_msg)?;
                            println!("Sending connection rejection: {}", reject_json);
                            stream.write_all(reject_json.as_bytes()).await?;
                        }
                        
                        None => {
                            println!("Command channel closed, exiting relay handler");
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

// Helper function to connect with optional TLS
async fn connect_with_tls_option(server: &str, use_tls: bool) -> Result<TlsOrPlainStream> {
    println!("Attempting to connect to server: {}", server);
    
    // Connect TCP
    match TcpStream::connect(server).await {
        Ok(tcp_stream) => {
            println!("TCP connection established to: {}", server);
            
            if use_tls {
                println!("Attempting TLS handshake with {}", server);
                // Create TLS connector that accepts self-signed certificates in development
                let accept_invalid_certs = true; // In development we accept self-signed certs
                match tls::create_tls_connector(accept_invalid_certs) {
                    Ok(connector) => {
                        // Parse server name for TLS
                        match tls::parse_server_name(server) {
                            Ok(server_name) => {
                                println!("Using server name for TLS: {}", server_name);
                                // Perform TLS handshake
                                match connector.connect(server_name, tcp_stream).await {
                                    Ok(tls_stream) => {
                                        println!("TLS handshake successful with {}", server);
                                        Ok(TlsOrPlainStream::Tls(tls_stream))
                                    },
                                    Err(e) => {
                                        eprintln!("TLS handshake failed with {}: {}", server, e);
                                        eprintln!("Falling back to plain TCP");
                                        // Reconnect with plain TCP as fallback
                                        match TcpStream::connect(server).await {
                                            Ok(fallback_stream) => {
                                                println!("Fallback TCP connection established");
                                                Ok(TlsOrPlainStream::Plain(fallback_stream))
                                            },
                                            Err(e) => {
                                                eprintln!("Failed to establish fallback TCP connection: {}", e);
                                                Err(anyhow!("Failed to connect: {}", e))
                                            }
                                        }
                                    }
                                }
                            },
                            Err(e) => {
                                eprintln!("Failed to parse server name '{}': {}", server, e);
                                eprintln!("Falling back to plain TCP");
                                Ok(TlsOrPlainStream::Plain(tcp_stream))
                            }
                        }
                    },
                    Err(e) => {
                        eprintln!("Failed to create TLS connector: {}", e);
                        eprintln!("Falling back to plain TCP");
                        Ok(TlsOrPlainStream::Plain(tcp_stream))
                    }
                }
            } else {
                // Use plain TCP
                println!("Using plain TCP connection (TLS disabled)");
                Ok(TlsOrPlainStream::Plain(tcp_stream))
            }
        },
        Err(e) => {
            eprintln!("Failed to establish TCP connection to {}: {}", server, e);
            Err(anyhow!("Failed to connect: {}", e))
        }
    }
}

// Add a function to detect public IP address
pub async fn get_public_ip() -> Option<String> {
    println!("Attempting to detect public IP address...");
    
    // Try multiple public IP detection services
    let services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
        "https://checkip.amazonaws.com",
    ];
    
    for service in services {
        match reqwest::get(service).await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.text().await {
                        Ok(ip) => {
                            let ip = ip.trim().to_string();
                            println!("Public IP detected: {}", ip);
                            return Some(ip);
                        },
                        Err(e) => {
                            eprintln!("Failed to read response from {}: {}", service, e);
                        }
                    }
                }
            },
            Err(e) => {
                eprintln!("Failed to connect to {}: {}", service, e);
            }
        }
    }
    
    eprintln!("Failed to detect public IP address");
    None
} 