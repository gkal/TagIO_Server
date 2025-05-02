use serde::{Serialize, Deserialize};
use std::net::SocketAddr;

/// Messages used for NAT traversal and relay functionality
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RelayMessage {
    // Authentication messages
    AuthRequest { client_id: String, auth_token: String },
    AuthSuccess { client_id: String },
    AuthFailure { reason: String },
    
    // Registration messages
    Register { client_id: String },
    RegisterAck { public_addr: SocketAddr },
    
    // Connection establishment
    ConnectRequest { target_id: String },
    ConnectionInfo { client_id: String, public_addr: SocketAddr, private_addrs: Vec<SocketAddr> },
    
    // Relay functionality
    RelayRequest { session_id: String },
    RelayAccept { session_id: String },
    RelayData { session_id: String, data: Vec<u8> },
    
    // Keep-alive
    Ping,
    Pong,
}

/// Simple message types for direct TCP communication
#[derive(Debug)]
pub enum MessageType {
    // Message types as used in tagio_relay_server.rs
    AuthFailure = 2,
    ClientRegistered = 3,
    ConnectionRequest = 4,
    ConnectionInfo = 5,
} 