#![allow(dead_code)]

mod communication;
mod client;
mod server;
mod nat_client;

pub use communication::AsyncCommunication;
pub use client::NatTraversalClient;
pub use server::NatTraversalServer;
pub use nat_client::NatClient;

// Set standard timeouts
pub const CONNECTION_TIMEOUT_SECS: u64 = 5;
pub const KEEP_ALIVE_INTERVAL_SECS: u64 = 15;
pub const KEEP_ALIVE_TIMEOUT_SECS: u64 = 30; 