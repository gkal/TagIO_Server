use log::{debug, info, error};
use hyper::upgrade::Upgraded;
use futures::{SinkExt, StreamExt};
use hyper_tungstenite::tungstenite::Message as WsMessage;
use hyper_tungstenite::WebSocketStream;
use std::net::SocketAddr;

use crate::client::{register_client, update_client_timestamp, log_msg};
use crate::protocol::{create_tagio_ack_response, create_tagio_reglack_response, hex_dump, PROTOCOL_MAGIC};

/// Handle WebSocket client registration and message exchange with immediate ACK
pub async fn handle_websocket_with_immediate_ack(
    ws_stream: WebSocketStream<Upgraded>, 
    peer_addr: Option<SocketAddr>, 
    tagio_id: u32, 
    ack_message: Vec<u8>
) -> Result<(), anyhow::Error> {
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    
    // Get a client IP string that we can use throughout the function
    let client_ip = peer_addr
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    
    info!("{}", log_msg("WS-INIT", &client_ip, tagio_id, "Handling WebSocket connection with immediate ACK"));
    
    // Register this client
    register_client(tagio_id, client_ip.clone()).await;
    
    info!("{}", log_msg("WS-REG", &client_ip, tagio_id, "Registered WebSocket client"));
    
    // Flag to track if initial ACK was sent
    let mut _initial_ack_sent = false;

    // Send an initial ACK response immediately upon connection to reduce latency
    info!("{}", log_msg("ACK-INIT", &client_ip, tagio_id, "Sending immediate ACK"));
    debug!("{}", log_msg("ACK-HEX", &client_ip, tagio_id, &format!("ACK hex dump: {}", hex_dump(&ack_message, ack_message.len()))));
    
    // Log each byte for debugging
    let bytes_str: Vec<String> = ack_message.iter().map(|b| format!("{:02X}", b)).collect();
    debug!("{}", log_msg("ACK-BYTES", &client_ip, tagio_id, &format!("[{}]", bytes_str.join(", "))));
    
    // Send the response via WebSocket, wrapped in a binary frame
    if let Err(e) = ws_sender.send(WsMessage::Binary(ack_message.clone())).await {
        error!("{}", log_msg("WS-ERROR", &client_ip, tagio_id, &format!("Error sending initial ACK: {}", e)));
        return Ok(());
    } else {
        info!("{}", log_msg("ACK-SENT", &client_ip, tagio_id, "Successfully sent initial ACK"));
        _initial_ack_sent = true;
    }
    
    // Flag to track if client has registered
    let mut client_registered = false;
    
    // Wait for client messages
    while let Some(msg_result) = ws_receiver.next().await {
        let msg = match msg_result {
            Ok(msg) => msg,
            Err(e) => {
                error!("{}", log_msg("WS-ERROR", &client_ip, tagio_id, &format!("WebSocket error: {}", e)));
                break;
            }
        };
        
        // Check for REGL to optimize handling
        if let WsMessage::Binary(ref data) = msg {
            // Check for REGL message format
            if data.len() > PROTOCOL_MAGIC.len() + 8 {  // TAGIO + version + REGL
                let header_offset = PROTOCOL_MAGIC.len() + 4;
                if data.len() > header_offset + 4 && 
                   &data[header_offset..header_offset+4] == b"REGL" {
                    info!("{}", log_msg("REGL-DET", &client_ip, tagio_id, "Detected REGL message - client registering"));
                    // Mark client as registered
                    client_registered = true;
                }
            }
        }
        
        // Handle different types of WebSocket messages
        let continue_loop = match msg {
            WsMessage::Binary(data) => {
                if let Err(e) = handle_ws_binary_message(data, tagio_id, &client_ip, &mut ws_sender).await {
                    error!("{}", log_msg("MSG-ERROR", &client_ip, tagio_id, &format!("Error handling message: {}", e)));
                    false
                } else {
                    let _ = ws_sender.flush().await;
                    true
                }
            },
            WsMessage::Text(text) => {
                if client_registered {
                    info!("{}", log_msg("TEXT-SKIP", &client_ip, tagio_id, "Client already registered, ignoring text message"));
                    true
                } else if let Err(e) = handle_ws_text_message(text, tagio_id, &client_ip, &mut ws_sender).await {
                    error!("{}", log_msg("TEXT-ERR", &client_ip, tagio_id, &format!("Error handling text: {}", e)));
                    false
                } else {
                    true
                }
            },
            WsMessage::Ping(data) => {
                info!("{}", log_msg("WS-PING", &client_ip, tagio_id, "Received ping, sending pong"));
                if let Err(e) = ws_sender.send(WsMessage::Pong(data)).await {
                    error!("{}", log_msg("PONG-ERR", &client_ip, tagio_id, &format!("Error sending pong: {}", e)));
                    false
                } else {
                    let _ = ws_sender.flush().await;
                    true
                }
            },
            WsMessage::Pong(_) => {
                debug!("{}", log_msg("WS-PONG", &client_ip, tagio_id, "Received pong"));
                true
            },
            WsMessage::Close(_) => {
                info!("{}", log_msg("WS-CLOSE", &client_ip, tagio_id, "Received close frame"));
                false
            },
            _ => {
                debug!("{}", log_msg("WS-OTHER", &client_ip, tagio_id, "Unknown WebSocket message type"));
                true
            }
        };
        
        if !continue_loop {
            break;
        }
        
        // Update client's last seen timestamp after each message
        update_client_timestamp(tagio_id).await;
    }
    
    info!("{}", log_msg("WS-END", &client_ip, tagio_id, "WebSocket connection closed"));
    Ok(())
}

/// Handle WebSocket client registration and message exchange without immediate ACK
/// 
/// Note: Clients should implement a keepalive mechanism by sending a PING message
/// every 10-15 minutes to prevent connection timeouts. The server will respond with
/// an ACK message, which maintains the connection.
pub async fn handle_websocket_without_immediate_ack(
    ws_stream: WebSocketStream<Upgraded>, 
    peer_addr: Option<SocketAddr>, 
    tagio_id: u32
) -> Result<(), anyhow::Error> {
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    
    // Get a client IP string that we can use throughout the function
    let client_ip = peer_addr
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    
    info!("{}", log_msg("WS-INIT", &client_ip, tagio_id, "Handling WebSocket connection without immediate ACK"));
    
    // Register this client
    register_client(tagio_id, client_ip.clone()).await;
    
    info!("{}", log_msg("WS-REG", &client_ip, tagio_id, "Registered WebSocket client"));
    
    // Wait for client messages - NO IMMEDIATE ACK
    while let Some(msg_result) = ws_receiver.next().await {
        let msg = match msg_result {
            Ok(msg) => msg,
            Err(e) => {
                error!("{}", log_msg("WS-ERROR", &client_ip, tagio_id, &format!("WebSocket error: {}", e)));
                break;
            }
        };
        
        // Check for REGL to optimize handling
        if let WsMessage::Binary(ref data) = msg {
            // Check for REGL message format
            if data.len() > PROTOCOL_MAGIC.len() + 8 {  // TAGIO + version + REGL
                let header_offset = PROTOCOL_MAGIC.len() + 4;
                if data.len() > header_offset + 4 && 
                   &data[header_offset..header_offset+4] == b"REGL" {
                    info!("{}", log_msg("REGL-DET", &client_ip, tagio_id, "Detected REGL message - client registering"));
                    // Mark client as registered
                }
            }
        }
        
        // Handle different types of WebSocket messages
        let continue_loop = match msg {
            WsMessage::Binary(data) => {
                if let Err(e) = handle_ws_binary_message(data, tagio_id, &client_ip, &mut ws_sender).await {
                    error!("{}", log_msg("MSG-ERROR", &client_ip, tagio_id, &format!("Error handling message: {}", e)));
                    false
                } else {
                    let _ = ws_sender.flush().await;
                    true
                }
            },
            WsMessage::Text(text) => {
                if let Err(e) = handle_ws_text_message(text, tagio_id, &client_ip, &mut ws_sender).await {
                    error!("{}", log_msg("TEXT-ERR", &client_ip, tagio_id, &format!("Error handling text: {}", e)));
                    false
                } else {
                    true
                }
            },
            WsMessage::Ping(data) => {
                info!("{}", log_msg("WS-PING", &client_ip, tagio_id, "Received ping, sending pong"));
                if let Err(e) = ws_sender.send(WsMessage::Pong(data)).await {
                    error!("{}", log_msg("PONG-ERR", &client_ip, tagio_id, &format!("Error sending pong: {}", e)));
                    false
                } else {
                    let _ = ws_sender.flush().await;
                    true
                }
            },
            WsMessage::Pong(_) => {
                debug!("{}", log_msg("WS-PONG", &client_ip, tagio_id, "Received pong"));
                true
            },
            WsMessage::Close(_) => {
                info!("{}", log_msg("WS-CLOSE", &client_ip, tagio_id, "Received close frame"));
                false
            },
            _ => {
                debug!("{}", log_msg("WS-OTHER", &client_ip, tagio_id, "Unknown WebSocket message type"));
                true
            }
        };
        
        if !continue_loop {
            break;
        }
        
        // Update client's last seen timestamp after each message
        update_client_timestamp(tagio_id).await;
    }
    
    info!("{}", log_msg("WS-END", &client_ip, tagio_id, "WebSocket connection closed"));
    Ok(())
}

/// Handle binary WebSocket messages
pub async fn handle_ws_binary_message(
    data: Vec<u8>, 
    tagio_id: u32, 
    client_ip: &str, 
    ws_sender: &mut futures::stream::SplitSink<WebSocketStream<Upgraded>, WsMessage>
) -> Result<(), anyhow::Error> {
    // Log last activity time for idle connection monitoring
    update_client_timestamp(tagio_id).await;
    
    info!("{}", log_msg("WS-RECV", client_ip, tagio_id, &format!("Binary message: {} bytes", data.len())));
    debug!("{}", log_msg("WS-DUMP", client_ip, tagio_id, &format!("Hex dump: {}", hex_dump(&data, data.len().min(100)))));
    
    // Check for TAGIO protocol
    if data.len() < PROTOCOL_MAGIC.len() {
        info!("{}", log_msg("INVALID", client_ip, tagio_id, "Message too short for TagIO protocol"));
        return Ok(());
    }
    
    if &data[0..PROTOCOL_MAGIC.len()] != PROTOCOL_MAGIC {
        info!("{}", log_msg("INVALID", client_ip, tagio_id, "Invalid protocol magic"));
        return Ok(());
    }
    
    // Extract protocol version
    let version_offset = PROTOCOL_MAGIC.len();
    if data.len() < version_offset + 4 {
        info!("{}", log_msg("INVALID", client_ip, tagio_id, "Message too short for protocol version"));
        return Ok(());
    }
    
    let version_bytes = &data[version_offset..version_offset + 4];
    let version = u32::from_be_bytes([
        version_bytes[0], version_bytes[1],
        version_bytes[2], version_bytes[3]
    ]);
    
    debug!("{}", log_msg("PROTOCOL", client_ip, tagio_id, &format!("TagIO protocol version: {}", version)));
    
    // Extract message type
    let msg_type_offset = version_offset + 4;
    if data.len() <= msg_type_offset {
        info!("{}", log_msg("INVALID", client_ip, tagio_id, "Message too short for message type"));
        return Ok(());
    }
    
    // Get message data after header
    let message_data = &data[msg_type_offset..];
    
    // Check for common message types
    let is_regl = message_data.len() >= 4 && &message_data[0..4] == b"REGL";
    let is_ping = message_data.len() >= 4 && &message_data[0..4] == b"PING";
    
    // Extract text representation for logging
    let msg_type_end = message_data.iter()
        .take(10)
        .position(|&b| !b.is_ascii_uppercase() && !b.is_ascii_digit())
        .unwrap_or(4.min(message_data.len()));
    
    let msg_type = String::from_utf8_lossy(&message_data[..msg_type_end]).to_string();
    
    info!("{}", log_msg("MSG-TYPE", client_ip, tagio_id, &format!("Message type: {}", msg_type)));
    
    // Handle REGL message - THIS IS THE CRITICAL FIX FOR THE REGLACK ISSUE
    if is_regl {
        info!("{}", log_msg("REGL-IN", client_ip, tagio_id, "Processing registration message"));
        
        // REGL message validation omitted for brevity - would check for valid ID format
        let _id_valid = true; // Simplified for example
        
        // Create REGLACK response
        let response = create_tagio_reglack_response();
        
        info!("{}", log_msg("REGLACK", client_ip, tagio_id, "Sending REGLACK response"));
        debug!("{}", log_msg("MSG-OUT", client_ip, tagio_id, &format!("Response hex: {}", hex_dump(&response, response.len()))));
        
        // Log the exact bytes for debugging
        let bytes_str: Vec<String> = response.iter().map(|b| format!("{:02X}", b)).collect();
        debug!("{}", log_msg("MSG-OUT", client_ip, tagio_id, &format!("[{}]", bytes_str.join(", "))));
        
        // Ensure clean send
        ws_sender.flush().await?;
        ws_sender.send(WsMessage::Binary(response)).await?;
        ws_sender.flush().await?;
        
        info!("{}", log_msg("WS-SENT", client_ip, tagio_id, "Successfully sent registration response"));
        
        // CRITICAL: Return immediately without sending any ACK
        return Ok(());
    } else if is_ping {
        info!("{}", log_msg("PING-IN", client_ip, tagio_id, "Handling PING message"));
    } else {
        info!("{}", log_msg("MSG-IN", client_ip, tagio_id, &format!("Handling message type: {}", msg_type)));
    }
    
    // Standard ACK response for non-REGL messages
    let response = create_tagio_ack_response(tagio_id);
    
    info!("{}", log_msg("ACK-OUT", client_ip, tagio_id, &format!("Sending ACK response with ID {}", tagio_id)));
    debug!("{}", log_msg("MSG-OUT", client_ip, tagio_id, &format!("ACK hex: {}", hex_dump(&response, response.len()))));
    
    ws_sender.send(WsMessage::Binary(response)).await?;
    ws_sender.flush().await?;
    
    info!("{}", log_msg("WS-SENT", client_ip, tagio_id, "Successfully sent ACK response"));
    info!("{}", log_msg("COMPLETE", client_ip, tagio_id, &format!("Processed {} byte TagIO message", data.len())));
    
    Ok(())
}

/// Handle text WebSocket messages
pub async fn handle_ws_text_message(
    text: String, 
    tagio_id: u32, 
    client_ip: &str, 
    ws_sender: &mut futures::stream::SplitSink<WebSocketStream<Upgraded>, WsMessage>
) -> Result<(), anyhow::Error> {
    info!("{}", log_msg("TEXT-IN", client_ip, tagio_id, &format!("Text message: {}", text)));
    
    // Check for registration in text message
    if text.contains("REGL") || text.contains("REGISTER") {
        info!("{}", log_msg("REGL-IN", client_ip, tagio_id, "Detected registration in text message"));
        
        // Create REGLACK response
        let response = create_tagio_reglack_response();
        
        info!("{}", log_msg("REGLACK", client_ip, tagio_id, "Sending REGLACK for text registration"));
        
        ws_sender.send(WsMessage::Binary(response)).await?;
        ws_sender.flush().await?;
        
        info!("{}", log_msg("WS-SENT", client_ip, tagio_id, "Successfully sent REGLACK"));
        return Ok(());
    }
    
    // For regular text messages, send ACK
    let response = create_tagio_ack_response(tagio_id);
    
    info!("{}", log_msg("ACK-OUT", client_ip, tagio_id, &format!("Sending ACK with ID: {}", tagio_id)));
    
    ws_sender.send(WsMessage::Binary(response)).await?;
    ws_sender.flush().await?;
    
    info!("{}", log_msg("WS-SENT", client_ip, tagio_id, "Successfully sent ACK response"));
    
    Ok(())
} 