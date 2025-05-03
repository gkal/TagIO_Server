// TagIO Relay Server - Library for the TagIO HTTP Tunnel Server
// Exposes the HTTP tunnel implementation for use by binary targets

// Re-export modules
pub mod constants;
pub mod http_tunnel;
pub mod logging_filter;
pub mod messages;
pub mod protocol_detect;
pub mod server;

// Create a version function that can be used to query the version
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
} 