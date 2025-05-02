// Export all the modules so they can be imported from crate root
pub mod config;
pub mod relay;
pub mod p2p_tls;
pub mod nat_traversal;
pub mod input;
pub mod screen_capture;
pub mod streaming;
pub mod debug_logging;
pub mod gui;
pub mod network_speed;
pub mod cert_utils;

// Re-export common constants
pub const VERSION: &str = "0.1.9";

// Re-export main modules
pub use config::Config;
pub use relay::{connect_via_relay, setup_upnp_port_mapping, DEFAULT_RELAY_SERVER};
pub use nat_traversal::NatTraversalClient;
pub use p2p_tls::{P2PTlsClient, TlsStream, TlsServerStream, TlsListener};
pub use relay::NatTraversalServer; 