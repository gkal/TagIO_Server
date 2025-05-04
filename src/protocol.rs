use log::debug;
use std::fmt;

// Constants for protocol magic
pub const PROTOCOL_MAGIC: &[u8] = b"TAGIO";

pub enum MessageType {
    Ping,
    Ack,
    Regl,
    ReglAck,
    ReglErr,
    Msg,
    Conn,
    Unknown
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MessageType::Ping => write!(f, "PING"),
            MessageType::Ack => write!(f, "ACK"),
            MessageType::Regl => write!(f, "REGL"),
            MessageType::ReglAck => write!(f, "REGLACK"),
            MessageType::ReglErr => write!(f, "REGLERR"),
            MessageType::Msg => write!(f, "MSG"),
            MessageType::Conn => write!(f, "CONN"),
            MessageType::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Create a TagIO ACK response message
pub fn create_tagio_ack_response(tagio_id: u32) -> Vec<u8> {
    // Create response with exact allocation for: TAGIO(5) + version(4) + ACK(3) + ID(4)
    let mut response = Vec::with_capacity(16);
    
    // Add TAGIO magic bytes
    response.extend_from_slice(PROTOCOL_MAGIC); // 5 bytes: "TAGIO"
    
    // Use protocol version 1
    response.extend_from_slice(&[0, 0, 0, 1]); // 4 bytes: version
    
    // Add ACK message - EXACTLY 3 bytes, no null terminator or extra bytes
    response.extend_from_slice(b"ACK"); // 3 bytes: "ACK"
    
    // Add TagIO ID in big-endian format
    response.extend_from_slice(&tagio_id.to_be_bytes()); // 4 bytes: ID
    
    // Verify length is exactly 16 bytes
    debug_assert_eq!(response.len(), 16, "ACK response must be exactly 16 bytes");
    
    // Log response bytes for debugging
    debug!("Created ACK message - 16 bytes: TAGIO + version + ACK + ID({})", tagio_id);
    
    response
}

/// Create a TagIO REGLACK response message
pub fn create_tagio_reglack_response() -> Vec<u8> {
    let mut response = Vec::with_capacity(16);
    
    // Add TAGIO magic bytes
    response.extend_from_slice(PROTOCOL_MAGIC); // 5 bytes: "TAGIO"
    
    // Use protocol version 1
    response.extend_from_slice(&[0, 0, 0, 1]); // 4 bytes: version
    
    // Add REGLACK message - EXACTLY 7 bytes
    response.extend_from_slice(b"REGLACK"); // 7 bytes: "REGLACK"
    
    debug!("Created REGLACK message - 16 bytes: TAGIO + version + REGLACK");
    
    response
}

/// Create a TagIO REGLERR response message
pub fn create_tagio_reglerr_response(error_msg: &str) -> Vec<u8> {
    let mut response = Vec::with_capacity(32);
    
    // Add TAGIO magic bytes
    response.extend_from_slice(PROTOCOL_MAGIC); // 5 bytes: "TAGIO"
    
    // Use protocol version 1
    response.extend_from_slice(&[0, 0, 0, 1]); // 4 bytes: version
    
    // Add REGLERR message
    response.extend_from_slice(b"REGLERR"); // 7 bytes: "REGLERR"
    
    // Add error message
    response.extend_from_slice(error_msg.as_bytes());
    
    debug!("Created REGLERR message: TAGIO + version + REGLERR + {}", error_msg);
    
    response
}

/// Create a TagIO CONN response message containing the IP address of the target client
pub fn create_tagio_conn_response(target_ip: &str) -> Vec<u8> {
    // Create response with: TAGIO(5) + version(4) + "CONN"(4) + IP length(2) + IP address
    let mut response = Vec::with_capacity(32);
    
    // Add TAGIO magic bytes
    response.extend_from_slice(PROTOCOL_MAGIC); // 5 bytes: "TAGIO"
    
    // Use protocol version 1
    response.extend_from_slice(&[0, 0, 0, 1]); // 4 bytes: version
    
    // Add CONN message
    response.extend_from_slice(b"CONN"); // 4 bytes: "CONN"
    
    // Add IP address length as 2 bytes (big-endian u16)
    let ip_len = target_ip.len() as u16;
    response.extend_from_slice(&ip_len.to_be_bytes()); // 2 bytes: length
    
    // Add the IP address as a string
    response.extend_from_slice(target_ip.as_bytes());
    
    debug!("Created CONN response with target IP: {}, length: {}", target_ip, ip_len);
    
    response
}

/// Parse a connection request message to extract the target TagIO ID
pub fn parse_conn_request(data: &[u8]) -> Option<u32> {
    // Check if this is a valid TagIO message
    if data.len() < PROTOCOL_MAGIC.len() + 4 + 4 + 4 {
        return None; // Too short for CONN request
    }
    
    // Check for TagIO magic bytes
    if &data[0..PROTOCOL_MAGIC.len()] != PROTOCOL_MAGIC {
        return None;
    }
    
    // Message type starts after TAGIO(5) + version(4)
    let msg_type_offset = PROTOCOL_MAGIC.len() + 4;
    let msg_type_data = &data[msg_type_offset..];
    
    // Check if this is a CONN message
    if msg_type_data.len() < 4 || &msg_type_data[0..4] != b"CONN" {
        return None;
    }
    
    // Extract the target ID - it should be 4 bytes after "CONN"
    if msg_type_data.len() < 8 {
        return None; // Not enough data for the ID
    }
    
    // The target ID is 4 bytes starting after "CONN"
    let id_bytes = &msg_type_data[4..8];
    
    // Convert the 4 bytes to a u32
    Some(u32::from_be_bytes([id_bytes[0], id_bytes[1], id_bytes[2], id_bytes[3]]))
}

/// Parse a TagIO message to identify its type
pub fn parse_message_type(data: &[u8]) -> MessageType {
    // Ensure we have enough data to identify message type
    if data.len() < PROTOCOL_MAGIC.len() + 4 {
        return MessageType::Unknown;
    }
    
    // Check for TagIO magic bytes
    if &data[0..PROTOCOL_MAGIC.len()] != PROTOCOL_MAGIC {
        return MessageType::Unknown;
    }
    
    // Message type starts after TAGIO(5) + version(4)
    let msg_type_offset = PROTOCOL_MAGIC.len() + 4;
    let msg_type_data = &data[msg_type_offset..];
    
    // Identify message type based on prefix
    if msg_type_data.len() >= 4 && &msg_type_data[0..4] == b"PING" {
        MessageType::Ping
    } else if msg_type_data.len() >= 3 && &msg_type_data[0..3] == b"ACK" {
        MessageType::Ack
    } else if msg_type_data.len() >= 4 && &msg_type_data[0..4] == b"REGL" {
        MessageType::Regl
    } else if msg_type_data.len() >= 7 && &msg_type_data[0..7] == b"REGLACK" {
        MessageType::ReglAck
    } else if msg_type_data.len() >= 7 && &msg_type_data[0..7] == b"REGLERR" {
        MessageType::ReglErr
    } else if msg_type_data.len() >= 3 && &msg_type_data[0..3] == b"MSG" {
        MessageType::Msg
    } else if msg_type_data.len() >= 4 && &msg_type_data[0..4] == b"CONN" {
        MessageType::Conn
    } else {
        MessageType::Unknown
    }
}

/// Print out the TagIO protocol specification for debugging
/// This function is no longer used in production but kept for reference
#[allow(dead_code)]
pub fn print_protocol_spec() {
    println!("[T] ===== TAGIO WEBSOCKET PROTOCOL SPECIFICATION =====");
    println!("[T] WebSocket clients must follow this binary protocol:");
    println!("[T]");
    println!("[T] 1. Message Format:");
    println!("[T]    All messages start with: TAGIO + Version(4 bytes) + Message Type + [Payload]");
    println!("[T]");
    println!("[T] 2. To register with server:");
    println!("[T]    a. Connect to WebSocket endpoint");
    println!("[T]    b. Send any message to receive TagIO ID");
    println!("[T]    c. Server will respond with ACK containing your TagIO ID");
    println!("[T]    d. Client should confirm by sending REGL with REGISTER:<assigned_id>");
    println!("[T]    e. Server will respond with REGLACK message");
    println!("[T]");
    println!("[T] 3. Keepalive:");
    println!("[T]    a. Send PING message every 10-15 minutes to keep connection alive");
    println!("[T]    b. Server will respond with ACK");
    println!("[T]    c. Long idle periods without communication may cause connection closure");
    println!("[T]");
    println!("[T] 4. PING message format (client to server):");
    println!("[T]    TAGIO + Version(00 00 00 01) + \"PING\"");
    println!("[T]    Binary: 54 41 47 49 4F 00 00 00 01 50 49 4E 47");
    println!("[T]");
    println!("[T] 5. ACK message format (server to client):");
    println!("[T]    TAGIO + Version(00 00 00 01) + \"ACK\" + TagIO ID (4 bytes, big-endian)");
    println!("[T]    Example: 54 41 47 49 4F 00 00 00 01 41 43 4B XX XX XX XX");
    println!("[T]");
    println!("[T] 6. REGL message format (client to server):");
    println!("[T]    TAGIO + Version(00 00 00 01) + \"REGL\" + \"REGISTER:<assigned_id>\"");
    println!("[T]    Example: 54 41 47 49 4F 00 00 00 01 52 45 47 4C 52 45 47 49 53 54 45 52 3A 37 38 39 30");
    println!("[T]");
    println!("[T] 7. REGLACK message format (server to client):");
    println!("[T]    TAGIO + Version(00 00 00 01) + \"REGLACK\"");
    println!("[T]    Example: 54 41 47 49 4F 00 00 00 01 52 45 47 4C 41 43 4B");
    println!("[T]");
    println!("[T] 8. REGLERR message format (server to client on error):");
    println!("[T]    TAGIO + Version(00 00 00 01) + \"REGLERR\" + [Error message]");
    println!("[T]    Error types: ID_MISMATCH, INVALID_ID, MISSING_ID, MISSING_REGISTER, INVALID_FORMAT");
    println!("[T]    Example: 54 41 47 49 4F 00 00 00 01 52 45 47 4C 45 52 52 49 44 5F 4D 49 53 4D 41 54 43 48");
    println!("[T]");
    println!("[T] 9. MSG message format (bidirectional):");
    println!("[T]    TAGIO + Version(00 00 00 01) + \"MSG\" + Target ID (4 bytes) + [Payload]");
    println!("[T]    Example: 54 41 47 49 4F 00 00 00 01 4D 53 47 XX XX XX XX [payload data]");
    println!("[T]");
    println!("[T] 10. CONN message format (client to server):");
    println!("[T]    TAGIO + Version(00 00 00 01) + \"CONN\" + Target ID (4 bytes)");
    println!("[T]    Example: 54 41 47 49 4F 00 00 00 01 43 4F 4E 4E XX XX XX XX");
    println!("[T]");
    println!("[T] 11. CONN response format (server to client):");
    println!("[T]    TAGIO + Version(00 00 00 01) + \"CONN\" + IP Length (2 bytes) + [IP Address]");
    println!("[T]    Example: 54 41 47 49 4F 00 00 00 01 43 4F 4E 4E 00 0B 31 39 32 2E 31 36 38 2E 31 2E 31");
    println!("[T]    In the example, 00 0B indicates the IP address is 11 bytes long (\"192.168.1.1\")");
    println!("[T]");
    println!("[T] Note: All messages must be sent as BINARY WebSocket frames, not text frames");
    println!("[T] ===================================================");
}

/// Helper function to format bytes as a hex dump for logging
pub fn hex_dump(bytes: &[u8], max_len: usize) -> String {
    let preview_len = std::cmp::min(bytes.len(), max_len);
    let preview: Vec<String> = bytes.iter()
        .take(preview_len)
        .map(|b| format!("{:02X}", b))
        .collect();
    
    let preview_str = preview.join(" ");
    if bytes.len() > max_len {
        format!("{} ... ({} more bytes)", preview_str, bytes.len() - max_len)
    } else {
        preview_str
    }
}

/// Helper function to find a subsequence in a byte array
pub fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    
    'outer: for i in 0..=haystack.len() - needle.len() {
        for (j, &b) in needle.iter().enumerate() {
            if haystack[i + j] != b {
                continue 'outer;
            }
        }
        return Some(i);
    }
    
    None
}

/// Find TagIO magic bytes in a byte array, searching the entire array if needed
pub fn find_tagio_magic(data: &[u8]) -> Option<usize> {
    if data.len() < PROTOCOL_MAGIC.len() {
        return None;
    }
    
    // Check if TAGIO is at the beginning
    if data.starts_with(PROTOCOL_MAGIC) {
        return Some(0);
    }
    
    // Otherwise search through the whole buffer
    find_subsequence(data, PROTOCOL_MAGIC)
} 