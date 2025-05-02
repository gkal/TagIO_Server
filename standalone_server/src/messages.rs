use serde::{Serialize, Deserialize};
use std::net::SocketAddr;

/// Protocol version for detecting mismatches
pub const PROTOCOL_VERSION: u32 = 1;

/// NAT traversal technique types
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum NatTraversalType {
    /// Direct hole punching (most common)
    HolePunch,
    /// Use port prediction for symmetric NATs
    PortPrediction,
    /// Relay through server (fallback)
    Relay,
    /// Unknown/auto-detect
    Unknown,
}

/// NAT types for traversal optimization
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
pub enum NatType {
    /// Direct connectivity available
    OpenInternet,
    /// Port restriction, but predictable mapping
    FullCone,
    /// Address restriction, but predictable mapping
    RestrictedCone,
    /// Port and address restrictions
    PortRestrictedCone,
    /// Unpredictable mapping
    SymmetricNat,
    /// Unknown NAT type
    Unknown,
}

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
    
    // Enhanced connection establishment
    ConnectRequest { target_id: String },
    ConnectionRequest { client_id: String, addr: SocketAddr, nat_type: NatTraversalType },
    ConnectionInfo { 
        target_id: String, 
        addr: SocketAddr, 
        nat_type: NatTraversalType,
        predicted_ports: Vec<u16>,
    },
    
    // Legacy connection establishment (kept for backward compatibility)
    ConnectionInfoLegacy { client_id: String, public_addr: SocketAddr, private_addrs: Vec<SocketAddr> },
    ConnectNotification { client_id: String, public_addr: SocketAddr },
    
    // Target client not found
    TargetNotFound { target_id: String },
    
    // NAT type detection
    StunBindingRequest,
    StunBindingResponse { public_addr: SocketAddr },
    NatTypeDetected { nat_type: NatType },
    
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
    
    // Version check - added to help detect protocol mismatches
    VersionCheck { version: u32 },
} 