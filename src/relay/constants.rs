//! Constants for the relay module

// Default relay server address - prefer connecting via HTTPS port for better firewall traversal
pub const DEFAULT_RELAY_SERVER: &str = "tagio.onrender.com:443";

// Alternative port to try if main port is blocked
pub const RELAY_SERVICE_ALT_PORT: u16 = 80;

// Fallback port if both HTTP and HTTPS are blocked
pub const RELAY_SERVICE_FALLBACK_PORT: u16 = 7568;

// UPnP lease duration in seconds (1 hour)
pub const UPNP_LEASE_DURATION: u32 = 3600;

// Standard timeout (5 seconds)
pub const CONNECTION_TIMEOUT_SECS: u64 = 5;

// Add constants for authentication
pub const AUTH_TOKEN_HEADER: &str = "tagio-auth-token";
pub const DEFAULT_AUTH_SECRET: &str = "tagio_default_secret"; 