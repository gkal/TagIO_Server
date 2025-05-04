use log::{debug, info};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use rand::Rng;

// Client registry to track connected clients
#[derive(Clone)]
pub struct ClientInfo {
    pub tagio_id: u32,
    pub ip_address: String,
    pub last_seen: Instant,
}

// Global client registry
lazy_static::lazy_static! {
    pub static ref CLIENT_REGISTRY: Arc<RwLock<HashMap<u32, ClientInfo>>> = Arc::new(RwLock::new(HashMap::new()));
}

/// Format an IP address string for consistent log display
pub fn format_ip_for_log(ip: &str) -> String {
    // Ensure consistent width for IP addresses in logs
    if ip == "unknown" {
        return "unknown    ".to_string();
    } else if ip == "system" {
        return "system     ".to_string();
    }
    
    // For normal IPs, ensure they're properly padded/truncated for consistent width
    // Target width is 12 characters to accommodate most IPv4 addresses
    let ip_len = ip.len();
    if ip_len <= 12 {
        // Pad shorter IPs with spaces
        format!("{:<12}", ip)
    } else {
        // For longer IPs (like IPv6), truncate with indicator
        format!("{}..{:<5}", &ip[0..4], &ip[ip_len-5..])
    }
}

/// Format a log message with client information
pub fn log_msg(msg_type: &str, client_ip: &str, tagio_id: u32, message: &str) -> String {
    let formatted_ip = format_ip_for_log(client_ip);
    
    // Add direction indicators for clarity
    let direction_prefix = if is_incoming_message(msg_type) {
        "← "
    } else if is_outgoing_message(msg_type) {
        "→ "
    } else {
        "  "
    };
    
    format!("[{:^8}] [ID:{:08X}] [{}] {}{}", 
           msg_type, 
           tagio_id, 
           formatted_ip,
           direction_prefix,
           message)
}

/// Determine if a message type represents incoming traffic
fn is_incoming_message(msg_type: &str) -> bool {
    matches!(msg_type, 
        "WS-RECV" | "MSG-TYPE" | "WS-PING" | "WS-PONG" | "WS-CLOSE" | "WS-TEXT" |
        "PING-IN" | "REGL-IN" | "MSG-IN"  | "TEXT-IN"
    )
}

/// Determine if a message type represents outgoing traffic
fn is_outgoing_message(msg_type: &str) -> bool {
    matches!(msg_type, 
        "WS-SENT" | "WS-ACK" | "PONG-OUT" |
        "ACK-OUT" | "PING-OUT" | "MSG-OUT" | "REGLACK" | 
        "TX-ACK" | "TX-MSG" | "SENDING" | "ACK-SENT"
    )
}

/// Helper function to register a client in the client registry
pub async fn register_client(tagio_id: u32, ip_address: String) {
    info!("{}", log_msg("REGISTER", &ip_address, tagio_id, &format!("New client registration")));
    
    let mut registry = CLIENT_REGISTRY.write().await;
    registry.insert(tagio_id, ClientInfo {
        tagio_id,
        ip_address,
        last_seen: Instant::now(),
    });
    
    info!("{}", log_msg("REGISTRY", "system", 0, &format!("Registry now contains {} clients", registry.len())));
}

/// Helper function to update client's last seen timestamp
pub async fn update_client_timestamp(tagio_id: u32) {
    if let Some(client) = CLIENT_REGISTRY.write().await.get_mut(&tagio_id) {
        client.last_seen = Instant::now();
        debug!("{}", log_msg("ACTIVITY", &client.ip_address, tagio_id, "Updated last seen timestamp"));
    }
}

/// Helper function to get client info by TagIO ID
pub async fn get_client_by_id(tagio_id: u32) -> Option<ClientInfo> {
    CLIENT_REGISTRY.read().await.get(&tagio_id).cloned()
}

/// Generate a unique TagIO ID between 5000-9999 that's not already in use
pub async fn generate_unique_tagio_id() -> u32 {
    // Use a thread-safe random number generator for async contexts
    let tagio_id = {
        // Scope the RNG so it's dropped before the await points
        let mut rng = rand::thread_rng();
        rng.gen_range(5000..10000)
    };
    
    // Check if the ID already exists in the registry
    let registry = CLIENT_REGISTRY.read().await;
    
    // If the randomly generated ID already exists, find the next available one
    let final_id = if registry.contains_key(&tagio_id) {
        // Try sequential IDs until we find an unused one
        let mut available_id = tagio_id;
        for i in 0..5000 { // Maximum 5000 attempts (covers the entire range of 5000-9999)
            let next_id = 5000 + ((tagio_id - 5000 + i) % 5000);
            if !registry.contains_key(&next_id) {
                available_id = next_id;
                break;
            }
        }
        available_id
    } else {
        tagio_id
    };
    
    // Log the generated ID
    info!("Generated unique TagIO ID: {}", final_id);
    final_id
}

/// Task to clean up stale clients from the registry
pub async fn cleanup_stale_clients() {
    let stale_timeout = Duration::from_secs(3600); // 1 hour timeout
    
    loop {
        tokio::time::sleep(Duration::from_secs(300)).await; // Run every 5 minutes
        
        let now = Instant::now();
        let mut to_remove = Vec::new();
        
        // Find stale clients
        {
            let registry = CLIENT_REGISTRY.read().await;
            for (&id, client) in registry.iter() {
                if now.duration_since(client.last_seen) > stale_timeout {
                    to_remove.push(id);
                }
            }
        }
        
        // Remove stale clients
        if !to_remove.is_empty() {
            let mut registry = CLIENT_REGISTRY.write().await;
            for id in to_remove.iter() {
                if let Some(client) = registry.remove(id) {
                    info!("Removed stale client {} from IP {} (last seen {} minutes ago)",
                          id, client.ip_address, 
                          now.duration_since(client.last_seen).as_secs() / 60);
                }
            }
            info!("Cleaned up {} stale clients, {} active clients remaining", 
                  to_remove.len(), registry.len());
        }
    }
} 