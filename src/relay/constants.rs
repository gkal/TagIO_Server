//! Constants for the relay module

// Default relay server address - prefer connecting via non-standard port to avoid HTTP protocol handling
// Changed from port 80 to 7568 to avoid Render's HTTP protocol handling on standard ports
pub const DEFAULT_RELAY_SERVER: &str = "tagio-server.onrender.com:7568";

// Alternative port to try if main port is blocked
pub const RELAY_SERVICE_ALT_PORT: u16 = 443;

// Fallback port if both main and alternative ports are blocked
pub const RELAY_SERVICE_FALLBACK_PORT: u16 = 80;

// UPnP lease duration in seconds (1 hour)
pub const UPNP_LEASE_DURATION: u32 = 3600;

// Standard timeout (5 seconds)
pub const CONNECTION_TIMEOUT_SECS: u64 = 5;

// Add constants for authentication
pub const AUTH_TOKEN_HEADER: &str = "tagio-auth-token";
pub const DEFAULT_AUTH_SECRET: &str = "tagio_default_secret"; 