#![allow(dead_code)]

mod client;
mod server;
pub mod protocol;
mod encryption;

// Re-export client functionality
pub use client::run_client;

// Re-export server functionality 
pub use server::run_server; 