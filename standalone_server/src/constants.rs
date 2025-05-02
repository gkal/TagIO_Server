//! Constants for the relay module

// Constants shared across server components

// Server bind address
#[allow(dead_code)]
pub const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:10000";

// Main protocol binary message header magic bytes - identifies TagIO protocol
pub const PROTOCOL_MAGIC: [u8; 8] = [0x54, 0x41, 0x47, 0x49, 0x4f, 0x50, 0x52, 0x4f]; // "TAGIOPRO"

// Maximum range of predicted ports for symmetric NAT traversal
pub const MAX_PORT_PREDICTION_RANGE: u16 = 10;

// Fallback port for HTTPS based connections
pub const FALLBACK_PORT: u16 = 443;

// Health check server port
#[allow(dead_code)]
pub const HEALTH_CHECK_PORT: u16 = 8080;

// Ensure we also listen on TCP port 80, standard HTTP port
#[allow(dead_code)]
pub const HTTP_PORT: u16 = 80;

// Cloud server's public IP address - used for NAT traversal
#[allow(dead_code)]
pub const CLOUD_SERVER_IP: &str = "18.156.158.53";

// Authentication constants
pub const DEFAULT_AUTH_SECRET: &str = "tagio_default_secret";

// NAT traversal constants
pub const _HTTP_PORT_PRIORITIES: [u16; 5] = [10000, 8080, 3000, 443, 80];
pub const _PORT_PREDICTION_RANGE: usize = 10;
pub const _KEEP_ALIVE_INTERVAL_SECS: u64 = 30;
pub const _NAT_TRAVERSAL_TIMEOUT_SECS: u64 = 10; 