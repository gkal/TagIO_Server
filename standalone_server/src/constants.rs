//! Constants for the relay module

// Default bind address for server - binds to all interfaces
// Using Render's recommended port 10000 for free tier compatibility
pub const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:10000";

// Cloud server address for clients to connect to
#[allow(dead_code)]
pub const DEFAULT_RELAY_SERVER: &str = "tagio-server.onrender.com:443";

// Cloud server's public IP address - used for NAT traversal
#[allow(dead_code)]
pub const CLOUD_SERVER_IP: &str = "18.156.158.53";

// Authentication constants
pub const DEFAULT_AUTH_SECRET: &str = "tagio_default_secret";

// Protocol magic bytes for identifying valid TagIO traffic
// "TAGIO" in ASCII bytes
pub const PROTOCOL_MAGIC: [u8; 5] = [0x54, 0x41, 0x47, 0x49, 0x4F];

// NAT traversal constants
pub const KEEP_ALIVE_INTERVAL_SECS: u64 = 30;
pub const NAT_TRAVERSAL_TIMEOUT_SECS: u64 = 10;
pub const MAX_PORT_PREDICTION_RANGE: u16 = 10; 