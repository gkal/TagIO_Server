#![allow(dead_code)]

mod client;
mod stream;
mod server;
mod util;

// Export the main client type
pub use client::P2PTlsClient;

// Export stream types
pub use stream::{TlsStream, TlsServerStream};

// Export server types
pub use server::TlsListener;

// Re-export any utility functions
pub use util::*; 