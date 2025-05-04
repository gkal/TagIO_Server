use log::{debug, info, error};
use hyper::{Body, Response, StatusCode};

use crate::client::{register_client, generate_unique_tagio_id, CLIENT_REGISTRY};
use crate::protocol::{PROTOCOL_MAGIC, hex_dump};

/// Extract TagIO protocol data from HTTP headers and body
pub fn extract_tagio_from_http(headers: &hyper::HeaderMap, body: &[u8]) -> bool {
    // Check for TagIO protocol indicators in headers
    let has_tagio_header = headers.get("X-TagIO-Protocol").is_some();
    let has_tagio_upgrade = headers.get("Upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("TagIO"))
        .unwrap_or(false);
    let has_tagio_content = headers.get("Content-Type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/tagio"))
        .unwrap_or(false);
    
    // Check for TagIO magic in body
    let has_tagio_magic = body.len() >= PROTOCOL_MAGIC.len() && 
                       &body[0..PROTOCOL_MAGIC.len()] == PROTOCOL_MAGIC;
    
    // Return true if any of the TagIO indicators are present
    has_tagio_header || has_tagio_upgrade || has_tagio_content || has_tagio_magic
}

/// Serves an HTML status page with TagIO connection instructions
pub async fn serve_status_page() -> Result<Response<Body>, hyper::http::Error> {
    // Get current count of connected clients
    let client_count = CLIENT_REGISTRY.read().await.len();
    
    // Simple HTML template that can be expanded if needed
    let html = format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TagIO HTTP Tunnel Server</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; line-height: 1.6; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .status {{ background-color: #e8f5e9; border-left: 5px solid #4caf50; padding: 15px; margin: 20px 0; }}
        .clients {{ background-color: #e3f2fd; border-left: 5px solid #2196f3; padding: 15px; margin: 20px 0; }}
        pre {{ background-color: #f5f5f5; padding: 15px; border-radius: 4px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>TagIO HTTP Tunnel Server</h1>
    
    <div class="status">
        <h2>Server Status: Online</h2>
        <p>The TagIO server is running and ready to accept connections through either HTTP tunneling or WebSocket.</p>
    </div>
    
    <div class="clients">
        <h2>Connected Clients: {}</h2>
        <p>Number of TagIO clients currently registered with the server.</p>
    </div>
    
    <h2>Connection Methods</h2>
    <p>To connect to TagIO, use either:</p>
    <ul>
        <li>HTTP Tunnel: Send TagIO protocol messages in HTTP POST requests</li>
        <li>WebSocket: Connect to /ws endpoint for real-time communication (recommended)</li>
    </ul>
    
    <p>For detailed documentation, please refer to the <a href="https://github.com/YourOrg/TagIO/docs">TagIO documentation</a>.</p>
</body>
</html>
    "#, client_count);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(Body::from(html))
        .unwrap())
}

/// Handles HTTP POST requests containing TagIO protocol messages
pub async fn handle_tagio_over_http(body_bytes: Vec<u8>, headers: Option<&hyper::HeaderMap>) -> Result<Response<Body>, hyper::http::Error> {
    if body_bytes.is_empty() {
        error!("Received empty request body");
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Empty request body"))
            .unwrap());
    }

    debug!("Processing TagIO over HTTP with {} bytes", body_bytes.len());
    debug!("Message hex dump: {}", hex_dump(&body_bytes, 64));

    // Extract client's IP address from headers
    let client_ip = if let Some(headers) = headers {
        headers.get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string()
    } else {
        "unknown".to_string()
    };

    // Perform TagIO message handling (simplified version)
    if body_bytes.len() >= PROTOCOL_MAGIC.len() {
        let magic_slice = &body_bytes[0..PROTOCOL_MAGIC.len()];
        if magic_slice == PROTOCOL_MAGIC {
            info!("Valid TagIO protocol message received from IP: {}", client_ip);
            
            // Check for specific message types after the TAGIO magic and protocol version
            if body_bytes.len() >= PROTOCOL_MAGIC.len() + 4 {
                let msg_type_offset = PROTOCOL_MAGIC.len() + 4;
                let msg_type_bytes = &body_bytes[msg_type_offset..];
                
                // Try to decode the message type as ASCII
                let msg_type = String::from_utf8_lossy(&msg_type_bytes[..std::cmp::min(msg_type_bytes.len(), 10)]);
                info!("TagIO message type: {}", msg_type);
                
                // If client sent PING message, send ACK with a unique ID
                if msg_type.contains("PING") {
                    let tagio_id = generate_unique_tagio_id().await;
                    register_client(tagio_id, client_ip).await;
                    
                    // Create ACK response
                    let mut response = Vec::with_capacity(16);
                    response.extend_from_slice(PROTOCOL_MAGIC);
                    response.extend_from_slice(&[0, 0, 0, 1]);
                    response.extend_from_slice(b"ACK");
                    response.extend_from_slice(&tagio_id.to_be_bytes());
                    
                    debug!("Sending ACK response with TagIO ID {}", tagio_id);
                    
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/octet-stream")
                        .header("X-TagIO-Raw-Protocol", "true")
                        .body(Body::from(response))
                        .unwrap());
                }
                
                // For REGL message, respond with REGLACK (no ID)
                // This implements the REGLACK fix for HTTP tunnel mode
                if msg_type.contains("REGL") {
                    let mut response = Vec::with_capacity(16);
                    response.extend_from_slice(PROTOCOL_MAGIC);
                    response.extend_from_slice(&[0, 0, 0, 1]);
                    response.extend_from_slice(b"REGLACK");
                    
                    debug!("Sending REGLACK response for REGL message");
                    
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/octet-stream")
                        .header("X-TagIO-Raw-Protocol", "true")
                        .body(Body::from(response))
                        .unwrap());
                }
            }
        }
    }

    // For unrecognized TagIO messages, echo back the original
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .header("X-TagIO-Raw-Protocol", "true")
        .body(Body::from(body_bytes))
        .unwrap())
} 