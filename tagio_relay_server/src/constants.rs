//! Constants for the relay module

// Default bind address for server
pub const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:443";

// Default relay server address for clients to connect to
#[allow(dead_code)]
pub const DEFAULT_RELAY_SERVER: &str = "tagio-server.onrender.com:443";

// Authentication constants
pub const DEFAULT_AUTH_SECRET: &str = "tagio_default_secret"; 