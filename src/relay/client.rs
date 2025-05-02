use anyhow::{Result, anyhow};
use tokio::{
    net::TcpStream,
    time::timeout,
};
use std::{
    net::IpAddr,
    time::Duration,
};
use log::info;
use local_ip_address::local_ip;
use uuid::Uuid;
use std::io::{BufReader, Write};

use crate::relay::constants::{
    DEFAULT_RELAY_SERVER, 
    CONNECTION_TIMEOUT_SECS
};

// Attempts to configure UPnP port mapping using IGD
pub fn setup_upnp_port_mapping(_port: u16) -> Result<()> {
    println!("Attempting to set up UPnP port mapping...");
    
    // Implementation will be provided later
    Err(anyhow!("Not implemented yet"))
}

// Get the machine's local IP address
pub fn get_local_address() -> Result<IpAddr> {
    match local_ip() {
        Ok(ip) => Ok(ip),
        Err(e) => Err(anyhow!("Failed to get local IP address: {}", e))
    }
}

// Check if the relay server is reachable
pub async fn verify_relay_connectivity(relay_server: &str) -> Result<bool> {
    // Try to connect to the relay server
    match timeout(
        Duration::from_secs(CONNECTION_TIMEOUT_SECS),
        TcpStream::connect(relay_server)
    ).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(e)) => {
            println!("Failed to connect to relay server: {}", e);
            Ok(false)
        },
        Err(_) => {
            println!("Connection to relay server timed out");
            Ok(false)
        }
    }
}

// Connect to the remote key via the relay server
pub async fn connect_via_relay(_local_key: &str, remote_key: &str, relay_server: Option<String>, secure_mode: bool) -> Result<TcpStream> {
    // Use the provided relay server or fall back to default
    let relay_addr = relay_server.unwrap_or_else(|| DEFAULT_RELAY_SERVER.to_string());
    
    info!("Connecting to relay server ({}) and looking for {} {}",
        relay_addr, remote_key, 
        if secure_mode { "with secure TLS" } else { "" });
    
    // Implementation will be provided later
    Err(anyhow!("Not implemented yet"))
}

// Function to start a NAT traversal listener (for sharing your screen)
pub async fn start_nat_traversal_listener(local_key: &str, _secure_mode: bool) -> Result<TcpStream> {
    // Create a unique client ID if none provided
    let _client_id = if local_key.is_empty() {
        format!("tagio-{}", Uuid::new_v4().simple())
    } else {
        local_key.to_string()
    };
    
    // Implementation will be provided later
    Err(anyhow!("Not implemented yet"))
}

// When connecting to the relay server, start with an HTTP-like request header
// that our server can detect as TagIO protocol
pub async fn connect_to_relay(&mut self) -> Result<(), Error> {
    // Attempt to connect to the server
    info!("Connecting to relay server on {} through Render's load balancer (port 80)", self.server);
    info!("Attempting to connect to relay server at {}", self.server);
    
    let addr = match self.server.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                debug!("DNS resolution successful for {}", self.server);
                addr
            } else {
                return Err(Error::NetworkError("DNS resolution failed: no addresses returned".to_string()));
            }
        },
        Err(e) => {
            return Err(Error::NetworkError(format!("DNS resolution failed: {}", e)));
        }
    };
    
    debug!("Resolved server address: {}", addr);
    
    // Connect to the server
    let stream = match TcpStream::connect(addr).await {
        Ok(stream) => {
            debug!("Connected to relay server at {} with TCP", self.server);
            stream
        },
        Err(e) => {
            return Err(Error::NetworkError(format!("Failed to connect to relay server: {}", e)));
        }
    };
    
    // Configure the stream
    stream.set_nodelay(true).map_err(|e| Error::NetworkError(format!("Failed to set TCP_NODELAY: {}", e)))?;
    
    // Store the stream
    let (reader, writer) = tokio::io::split(stream);
    self.reader = Some(Box::new(BufReader::new(reader)));
    self.writer = Some(Box::new(writer));
    
    info!("Successfully connected to relay server at {}", self.server);
    info!("Connected to relay server at {}", self.server);
    
    // Check if the writer is ready
    if let Some(writer) = &self.writer {
        if writer.is_write_vectored() {
            debug!("Connection to relay server is writable");
        }
    } else {
        return Err(Error::NetworkError("Writer not available".to_string()));
    }
    
    // Send a special HTTP-like request that our server will recognize as TagIO protocol
    // This bypasses Render.com's HTTP proxy behavior
    let tagio_protocol_header = format!(
        "POST /tagio HTTP/1.1\r\n\
         Host: {}\r\n\
         X-TagIO-Protocol: 1\r\n\
         Content-Type: application/tagio\r\n\
         Connection: Upgrade\r\n\
         Upgrade: TagIO\r\n\
         Content-Length: 44\r\n\
         \r\n", 
         self.server
    );
    
    // Send the header
    if let Some(writer) = &mut self.writer {
        if let Err(e) = writer.write_all(tagio_protocol_header.as_bytes()).await {
            return Err(Error::NetworkError(format!("Failed to send protocol header: {}", e)));
        }
        debug!("Sent TagIO protocol header to bypass HTTP filtering");
    }
    
    // Now authenticate
    self.authenticate().await
} 