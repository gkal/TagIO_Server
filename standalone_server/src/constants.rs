//! Constants for the relay module

// Default bind address for server - binds to all interfaces
pub const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:443";

// Cloud server address for clients to connect to
#[allow(dead_code)]
pub const DEFAULT_RELAY_SERVER: &str = "tagio-server.onrender.com:443";

// Authentication constants
pub const DEFAULT_AUTH_SECRET: &str = "tagio_default_secret";

// Protocol magic bytes for identifying valid TagIO traffic
// "TAGIO" in ASCII bytes
pub const PROTOCOL_MAGIC: [u8; 5] = [0x54, 0x41, 0x47, 0x49, 0x4F]; 