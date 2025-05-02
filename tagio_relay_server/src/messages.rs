use serde::{Serialize, Deserialize};
use std::net::SocketAddr;

/// Messages used for NAT traversal
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum NatMessage {
    // Authentication messages
    Authenticate { secret: String, client_id: String },
    AuthAck { public_addr: SocketAddr, message: String },
    AuthError { message: String },
    
    // Registration messages
    Register { client_id: String },
    RegisterAck { public_addr: SocketAddr },
    
    // Connection establishment
    ConnectRequest { target_id: String },
    ConnectionInfo { client_id: String, public_addr: SocketAddr, private_addrs: Vec<SocketAddr> },
    ConnectNotification { client_id: String, public_addr: SocketAddr },
    
    // Relay functionality
    RelayRequest { target_id: String, session_id: String },
    RelayEstablished { session_id: String, target_id: String },
    RelayRequested { session_id: String, client_id: String },
    RelayData { session_id: String, data: Vec<u8> },
    
    // Error
    Error { message: String },
    
    // Keep-alive
    Ping,
    Pong,
} 