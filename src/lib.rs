// Export all the modules so they can be imported from crate root
pub mod config;
pub mod relay;
pub mod nat_traversal;
pub mod p2p_tls;
pub mod cert_utils;
pub mod network_speed;
pub mod input;
pub mod debug_logging;
pub mod streaming;

// Re-export common constants
pub const VERSION: &str = "0.1.9";
pub use relay::constants::*;
pub use nat_traversal::client::NatTraversalClient;
pub use p2p_tls::{P2PTlsClient, TlsStream, TlsServerStream, TlsListener};
pub use relay::NatTraversalServer;

// Client-only modules
#[cfg(feature = "client")]
pub mod gui;
#[cfg(feature = "client")]
pub mod screen_capture; 