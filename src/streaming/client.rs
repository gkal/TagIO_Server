use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
    time::{self, Duration},
};
use aes_gcm::Nonce;
use rand::Rng;
use std::sync::Arc;
use log::{debug, info, error};

use crate::network_speed::SharedNetworkSpeed;
use crate::streaming::protocol::{ClientMessage, ServerMessage};
use crate::streaming::encryption::{create_cipher, encrypt, decrypt, get_encryption_key_id};

/// Run the client side (viewer)
pub async fn run_client(
    stream: TcpStream, 
    frame_tx: mpsc::Sender<(Vec<u8>, u32, u32)>
) -> Result<()> {
    info!("Starting screen sharing client (viewer)...");
    info!("Encryption key ID: {}", get_encryption_key_id());
    
    // Set up buffers and channels
    let peer_addr = stream.peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    info!("Connected to remote host: {}", peer_addr);
    
    // Set up encryption
    let cipher = Arc::new(create_cipher()?);
    debug!("AES-256 encryption initialized");
    
    // Set up network speed tracking
    let network_speed = SharedNetworkSpeed::new();
    let _network_speed_clone = network_speed.clone_tracker();
    
    // Split the TCP stream
    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    
    // Channel for mouse/keyboard events
    let (input_tx, mut input_rx) = mpsc::channel::<ClientMessage>(100);
    
    // Handle incoming screen frames
    let cipher_clone = cipher.clone();
    let network_speed_for_reader = network_speed.clone_tracker();
    let frame_tx_clone = frame_tx.clone();
    
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1024 * 1024]; // 1MB buffer for screen frames
        
        loop {
            // Read the nonce (12 bytes) and encrypted length (4 bytes) first
            let mut header = [0u8; 16];
            match reader.read_exact(&mut header).await {
                Ok(_) => {
                    // Extract the nonce (first 12 bytes)
                    let nonce = Nonce::from_slice(&header[..12]);
                    
                    // Extract the data length (next 4 bytes)
                    let mut length_bytes = [0u8; 4];
                    length_bytes.copy_from_slice(&header[12..16]);
                    let data_length = u32::from_be_bytes(length_bytes) as usize;
                    
                    // Ensure buffer is large enough
                    if data_length > buf.len() {
                        // Resize if needed
                        buf.resize(data_length, 0);
                    }
                    
                    // Read the encrypted data
                    match reader.read_exact(&mut buf[..data_length]).await {
                        Ok(_) => {
                            // Record received packet for speed monitoring
                            if let Ok(mut speed_tracker) = network_speed_for_reader.lock() {
                                speed_tracker.record_packet(data_length as u64);
                            }
                            
                            // Decrypt message
                            match decrypt(&cipher_clone, nonce, &buf[..data_length]) {
                                Ok(decrypted) => {
                                    match bincode::deserialize::<ServerMessage>(&decrypted) {
                                        Ok(message) => {
                                            match message {
                                                ServerMessage::ScreenFrame { 
                                                    data, 
                                                    width, 
                                                    height, 
                                                    timestamp: _ 
                                                } => {
                                                    let _ = frame_tx_clone.send((data, width, height)).await;
                                                },
                                                ServerMessage::NetworkStats { 
                                                    speed, 
                                                    quality_level 
                                                } => {
                                                    debug!("Network stats: {} bytes/s, quality: {}", 
                                                           speed, quality_level);
                                                },
                                                ServerMessage::Heartbeat { timestamp: _ } => {
                                                    // Just acknowledge heartbeat
                                                },
                                                ServerMessage::PingResponse { request_timestamp } => {
                                                    let now = std::time::SystemTime::now()
                                                        .duration_since(std::time::UNIX_EPOCH)
                                                        .unwrap()
                                                        .as_millis() as u64;
                                                    let rtt = now - request_timestamp;
                                                    debug!("Ping RTT: {}ms", rtt);
                                                }
                                            }
                                        },
                                        Err(e) => {
                                            error!("Failed to deserialize message: {}", e);
                                        }
                                    }
                                },
                                Err(e) => {
                                    error!("Decryption error: {}", e);
                                }
                            }
                        },
                        Err(e) => {
                            error!("Error reading frame data: {}", e);
                            break;
                        }
                    }
                },
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        info!("Server disconnected");
                    } else {
                        error!("Read error: {}", e);
                    }
                    break;
                }
            }
        }
    });
    
    // Set up periodic ping
    let ping_interval = time::interval(Duration::from_secs(5));
    let writer_for_ping = writer.clone();
    let cipher_for_ping = cipher.clone();
    
    tokio::spawn(async move {
        let mut ping_interval = ping_interval;
        
        loop {
            ping_interval.tick().await;
            
            // Send ping request
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            
            let ping = ClientMessage::PingRequest { timestamp: now };
            
            if let Ok(serialized) = bincode::serialize(&ping) {
                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);
                
                match encrypt(&cipher_for_ping, nonce, &serialized) {
                    Ok(encrypted) => {
                        // Construct message with nonce and length
                        let mut msg = Vec::with_capacity(16 + encrypted.len());
                        msg.extend_from_slice(nonce.as_slice());
                        
                        let data_len = (encrypted.len() as u32).to_be_bytes();
                        msg.extend_from_slice(&data_len);
                        msg.extend_from_slice(&encrypted);
                        
                        // Send ping
                        let mut writer_guard = writer_for_ping.lock().await;
                        if let Err(e) = writer_guard.write_all(&msg).await {
                            error!("Failed to send ping: {}", e);
                            break;
                        }
                    },
                    Err(e) => {
                        error!("Failed to encrypt ping: {}", e);
                    }
                }
            }
        }
    });
    
    // Wait for input events and send them to the server
    let writer_clone = writer.clone();
    let cipher_clone = cipher.clone();
    
    tokio::spawn(async move {
        while let Some(message) = input_rx.recv().await {
            // Serialize and encrypt the input event
            if let Ok(serialized) = bincode::serialize(&message) {
                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);
                
                match encrypt(&cipher_clone, nonce, &serialized) {
                    Ok(encrypted) => {
                        // Construct message with nonce and length
                        let mut msg = Vec::with_capacity(16 + encrypted.len());
                        msg.extend_from_slice(nonce.as_slice());
                        
                        let data_len = (encrypted.len() as u32).to_be_bytes();
                        msg.extend_from_slice(&data_len);
                        msg.extend_from_slice(&encrypted);
                        
                        // Send the message
                        let mut writer_guard = writer_clone.lock().await;
                        if let Err(e) = writer_guard.write_all(&msg).await {
                            error!("Failed to send input event: {}", e);
                            break;
                        }
                    },
                    Err(e) => {
                        error!("Failed to encrypt input event: {}", e);
                    }
                }
            }
        }
    });
    
    // Main loop - handle GUI events (mouse/keyboard) and forward them
    let _input_tx_clone = input_tx.clone();
    
    tokio::spawn(async move {
        // This would be integrated with the GUI framework
        // For now, just keep the connection alive
        tokio::time::sleep(Duration::from_secs(3600)).await;
    });
    
    Ok(())
} 