// TagIO Protocol Test Tool
// Compile with: rustc test_tagio_protocol.rs
// Run with: ./test_tagio_protocol

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use std::env;

// Magic bytes for the TagIO protocol ("TAGIOPRO")
const PROTOCOL_MAGIC: [u8; 8] = [0x54, 0x41, 0x47, 0x49, 0x4f, 0x50, 0x52, 0x4f];

fn main() {
    // Parse command line args
    let args: Vec<String> = env::args().collect();
    let mut server = "tagio.onrender.com".to_string();
    let mut port = 443;
    
    if args.len() > 1 {
        server = args[1].clone();
    }
    
    if args.len() > 2 {
        port = args[2].parse().unwrap_or(443);
    }
    
    println!("TagIO Protocol Test Tool");
    println!("=======================");
    println!("Testing connection to: {}:{}", server, port);
    
    // Try to connect
    println!("\nAttempting connection...");
    let start = Instant::now();
    
    match TcpStream::connect(format!("{}:{}", server, port)) {
        Ok(mut stream) => {
            let elapsed = start.elapsed();
            println!("✅ Connected in {:.2} seconds", elapsed.as_secs_f32());
            
            // Set read timeout
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            
            // Test 1: Send TagIO protocol message
            println!("\nTest 1: Sending TagIO protocol message");
            
            // Create message: length prefix + magic bytes + auth request
            let message = create_tagio_message();
            
            match stream.write_all(&message) {
                Ok(_) => {
                    println!("✅ Message sent successfully ({} bytes)", message.len());
                    
                    // Try to read response
                    println!("\nReading response...");
                    let mut response = [0u8; 1024];
                    
                    match stream.read(&mut response) {
                        Ok(bytes) => {
                            if bytes > 0 {
                                println!("Received {} bytes", bytes);
                                
                                // Check if response looks like HTTP
                                if check_if_http(&response[..bytes]) {
                                    println!("❌ ERROR: Received HTTP response instead of TagIO protocol");
                                    println!("This likely means Render.com is treating port {} as HTTP", port);
                                    print_first_bytes(&response[..bytes]);
                                } else if check_if_tagio(&response[..bytes]) {
                                    println!("✅ Success! Received TagIO protocol response");
                                    print_first_bytes(&response[..bytes]);
                                } else {
                                    println!("⚠️ WARNING: Unknown protocol response");
                                    print_first_bytes(&response[..bytes]);
                                }
                            } else {
                                println!("❌ No response received (0 bytes)");
                            }
                        },
                        Err(e) => {
                            println!("❌ Error reading response: {}", e);
                        }
                    }
                },
                Err(e) => {
                    println!("❌ Failed to send message: {}", e);
                }
            }
        },
        Err(e) => {
            let elapsed = start.elapsed();
            println!("❌ Failed to connect after {:.2} seconds: {}", elapsed.as_secs_f32(), e);
        }
    }
    
    println!("\n=======================");
    println!("RECOMMENDATION:");
    println!("1. If you see 'Received HTTP response', try using port 80 or 7568 instead");
    println!("2. Make sure you're using the correct server address (tagio.onrender.com)");
    println!("3. If all ports fail, check your firewall settings");
    println!("=======================");
}

// Create a TagIO protocol message (auth request with client ID)
fn create_tagio_message() -> Vec<u8> {
    // Client ID and auth token
    let client_id = "test_client";
    let auth_token = "tagio_default_secret";
    
    // Create auth request message: type (1) + client_id + auth_token
    let mut message = Vec::new();
    
    // Message type 1 (auth request)
    message.push(1);
    
    // Client ID (with 1-byte length prefix)
    message.push(client_id.len() as u8);
    message.extend_from_slice(client_id.as_bytes());
    
    // Auth token (with 1-byte length prefix)
    message.push(auth_token.len() as u8);
    message.extend_from_slice(auth_token.as_bytes());
    
    // Add protocol magic bytes at the start
    let mut full_message = Vec::new();
    full_message.extend_from_slice(&PROTOCOL_MAGIC);
    
    // Add 4-byte length prefix (big-endian u32)
    let len = message.len() as u32;
    full_message.push((len >> 24) as u8);
    full_message.push((len >> 16) as u8);
    full_message.push((len >> 8) as u8);
    full_message.push(len as u8);
    
    // Add the actual message
    full_message.extend(message);
    
    full_message
}

// Check if response is HTTP
fn check_if_http(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    
    // Convert first 4 bytes to string if possible
    let http_check = match std::str::from_utf8(&data[0..4]) {
        Ok(s) => s.to_uppercase(),
        Err(_) => return false,
    };
    
    http_check == "HTTP" || 
        data.starts_with(b"HTTP/") || 
        data.starts_with(b"GET ") || 
        data.starts_with(b"POST")
}

// Check if response includes TagIO protocol magic bytes
fn check_if_tagio(data: &[u8]) -> bool {
    if data.len() < PROTOCOL_MAGIC.len() {
        return false;
    }
    
    for (i, &byte) in PROTOCOL_MAGIC.iter().enumerate() {
        if data.len() <= i || data[i] != byte {
            return false;
        }
    }
    
    true
}

// Print the first bytes of response (up to 32)
fn print_first_bytes(data: &[u8]) {
    let max = std::cmp::min(32, data.len());
    
    print!("First {} bytes: ", max);
    
    for i in 0..max {
        print!("{:02X} ", data[i]);
    }
    println!();
    
    // Try to print as string if it looks like ASCII
    let printable = data.iter().take(max)
        .filter(|&&b| b >= 32 && b <= 126)
        .count() >= max / 2;
    
    if printable {
        print!("As text: \"");
        for &byte in data.iter().take(max) {
            if byte >= 32 && byte <= 126 {
                print!("{}", byte as char);
            } else {
                print!(".");
            }
        }
        println!("\"");
    }
} 