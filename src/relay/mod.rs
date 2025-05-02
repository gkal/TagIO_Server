#![allow(dead_code)]
// Explicitly allow unused_imports here to silence warnings caused by re-exports in lib.rs
#![allow(unused_imports)]

mod constants;
mod messages;
mod server;
mod client;

// Re-export constants needed by other modules
pub use constants::{DEFAULT_AUTH_SECRET, DEFAULT_RELAY_SERVER};

// Re-export the message types needed by other modules
pub use messages::NatMessage;

// Re-export the server
pub use server::NatTraversalServer;

// Re-export client functions
pub use client::{
    connect_via_relay,
    start_nat_traversal_listener,
    setup_upnp_port_mapping
}; 