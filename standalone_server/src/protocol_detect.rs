use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use log::{debug, error, info, warn};
use tokio::net::TcpStream;
use std::net::SocketAddr;
use crate::constants::PROTOCOL_MAGIC;

/// Determines if the data in the buffer appears to be an HTTP request
pub fn is_http_request(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    
    data.starts_with(b"GET ") || 
    data.starts_with(b"POST ") || 
    data.starts_with(b"PUT ") || 
    data.starts_with(b"HEAD ") || 
    data.starts_with(b"DELETE ") || 
    data.starts_with(b"OPTIONS ") ||
    data.starts_with(b"CONNECT ") ||
    data.starts_with(b"TRACE ") ||
    data.starts_with(b"HTTP/")
}

/// Handles an incoming connection with protocol detection
pub async fn handle_connection_with_protocol_detection<R, W>(
    mut reader: R, 
    mut writer: W,
    client_addr: SocketAddr,
    health_check_path: &str
) -> anyhow::Result<(bool, Vec<u8>)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Create a buffer for reading initial bytes
    let mut initial_buffer = [0u8; 16]; // 16 bytes should be enough for protocol detection
    
    // Read the initial bytes from the connection
    let bytes_read = match reader.read(&mut initial_buffer).await {
        Ok(n) if n > 0 => n,
        Ok(_) => return Err(anyhow::anyhow!("Connection closed before any data was received")),
        Err(e) => return Err(anyhow::anyhow!("Error reading from socket: {}", e)),
    };
    
    let initial_data = &initial_buffer[..bytes_read];
    
    // Check if it's an HTTP request
    if is_http_request(initial_data) {
        info!("Detected HTTP request from {}", client_addr);
        
        // Create a simple HTTP response
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html; charset=UTF-8\r\n\
             Connection: close\r\n\
             \r\n\
             <!DOCTYPE html>\
             <html>\
             <head><title>TagIO Relay Server</title></head>\
             <body>\
             <h1>TagIO Relay Server</h1>\
             <p>This is a TagIO relay server for NAT traversal. It's working correctly!</p>\
             <p>For more information, visit the TagIO documentation.</p>\
             </body>\
             </html>"
        );
        
        // Send the HTTP response
        if let Err(e) = writer.write_all(response.as_bytes()).await {
            error!("Failed to send HTTP response to {}: {}", client_addr, e);
        }
        
        // Return false indicating this is not a TagIO protocol connection
        return Ok((false, Vec::new()));
    }
    
    // If it's not HTTP, treat it as TagIO protocol
    info!("Detected non-HTTP traffic from {}, assuming TagIO protocol", client_addr);
    
    // Return true and the initial data for further processing
    Ok((true, initial_buffer[..bytes_read].to_vec()))
}

/// Handles an incoming HTTP request for the health check
pub async fn handle_health_check(
    stream: &mut TcpStream, 
    addr: SocketAddr
) -> anyhow::Result<()> {
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).await?;
    
    if n > 0 && is_http_request(&buffer[..n]) {
        // Generate a simple HTML response indicating the server is healthy
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html; charset=UTF-8\r\n\
             Connection: close\r\n\
             \r\n\
             <!DOCTYPE html>\
             <html>\
             <head><title>TagIO Relay Server - Health Check</title></head>\
             <body>\
             <h1>TagIO Relay Server</h1>\
             <p>Status: <strong style=\"color:green\">Healthy</strong></p>\
             <p>Server is running and accepting connections.</p>\
             </body>\
             </html>"
        );
        
        debug!("Sending health check response to {}", addr);
        stream.write_all(response.as_bytes()).await?;
    }
    
    Ok(())
} 