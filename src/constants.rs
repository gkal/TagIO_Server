//! Constants for the relay server

// Default bind address for the server
pub const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:8443";

// Health check endpoint port
pub const HEALTH_CHECK_PORT: u16 = 8080;

// Alternative port to try if main port is blocked
pub const RELAY_SERVICE_ALT_PORT: u16 = 80;

// Fallback port if both HTTP and HTTPS are blocked
pub const RELAY_SERVICE_FALLBACK_PORT: u16 = 7568;

// Standard timeout (seconds)
pub const CONNECTION_TIMEOUT_SECS: u64 = 10;
pub const HEALTH_CHECK_INTERVAL_SECS: u64 = 30;

// Add constants for authentication
pub const DEFAULT_AUTH_SECRET: &str = "tagio_default_secret";

// Message size limits
pub const MAX_ID_LENGTH: usize = 1000;
pub const MAX_AUTH_LENGTH: usize = 1000;
pub const MAX_MESSAGE_SIZE: usize = 65536; // 64KB

// Cloud server address for clients to connect to
#[allow(dead_code)]
pub const DEFAULT_RELAY_SERVER: &str = "tagio-server.onrender.com:443";

// Protocol magic bytes for identifying valid TagIO traffic
// "TAGIO" in ASCII bytes
pub const PROTOCOL_MAGIC: [u8; 5] = [0x54, 0x41, 0x47, 0x49, 0x4F]; 