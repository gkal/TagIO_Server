#[cfg(feature = "client")]
use anyhow::{Result, Context};
#[cfg(not(feature = "client"))]
use anyhow::Result;

#[cfg(feature = "client")]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, Mutex},
    time::{self, Duration},
};
#[cfg(not(feature = "client"))]
use tokio::{net::TcpStream, sync::mpsc};

#[cfg(feature = "client")]
use aes_gcm::Nonce;
#[cfg(feature = "client")]
use rand::Rng;
#[cfg(feature = "client")]
use std::sync::Arc;
#[cfg(feature = "client")]
use log::{debug, info, error};

#[cfg(feature = "client")]
use crate::screen_capture::{self, ScreenCapture};
#[cfg(feature = "client")]
use crate::input;
#[cfg(feature = "client")]
use crate::network_speed::{SharedNetworkSpeed, QualityLevel};
#[cfg(feature = "client")]
use crate::streaming::protocol::{ClientMessage, ServerMessage};
#[cfg(feature = "client")]
use crate::streaming::encryption::{create_cipher, encrypt, decrypt, get_encryption_key_id};

/// Run the server side (screen sharing)
#[cfg(feature = "client")]
pub async fn run_server(
    stream: TcpStream, 
    _frame_tx: mpsc::Sender<(Vec<u8>, u32, u32)>
) -> Result<()> {
    info!("Starting screen sharing server (v{})...", crate::VERSION);
    info!("Encryption key ID: {}", get_encryption_key_id());
    
    let peer_addr = stream.peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    info!("Client connected from: {}", peer_addr);
    info!("SCREEN SHARING ACTIVE: Your screen is now being transmitted to the remote user");
    
    // Set up encryption
    let cipher = Arc::new(create_cipher()?);
    debug!("AES-256 encryption initialized");
    
    // Set up network speed tracking
    let network_speed = SharedNetworkSpeed::new();
    let _network_speed_clone = network_speed.clone_tracker();
    
    // Set up screen capture
    let screen_capture = ScreenCapture::new()
        .context("Failed to initialize screen capture")?;
    
    // Set up input handler
    let input_handler = Arc::new(Mutex::new(input::InputHandler::new()));
    
    // Split TCP stream
    let (mut reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));
    
    // Channel for input events
    let (input_tx, mut input_rx) = mpsc::channel::<ClientMessage>(100);
    
    // Handle incoming messages from client
    let input_handler_clone = input_handler.clone();
    let cipher_clone = cipher.clone();
    let network_speed_for_reader = network_speed.clone_tracker();
    let writer_for_ping = writer.clone();
    let cipher_for_ping = cipher.clone();
    
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1024];
        
        loop {
            // Read the nonce (12 bytes) and encrypted length (4 bytes) first
            let mut header = [0u8; 16];
            match reader.read_exact(&mut header).await {
                Ok(_n) => {
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
                    if let Err(e) = reader.read_exact(&mut buf[..data_length]).await {
                        error!("Failed to read encrypted data: {}", e);
                        break;
                    }
                    
                    // Record received packet for speed monitoring
                    if let Ok(mut speed_tracker) = network_speed_for_reader.lock() {
                        speed_tracker.record_packet(data_length as u64);
                    }
                    
                    // Decrypt message
                    match decrypt(&cipher_clone, nonce, &buf[..data_length]) {
                        Ok(decrypted) => {
                            match bincode::deserialize::<ClientMessage>(&decrypted) {
                                Ok(message) => {
                                    match message {
                                        ClientMessage::PingRequest { timestamp } => {
                                            // Respond to ping request immediately
                                            let response = ServerMessage::PingResponse { 
                                                request_timestamp: timestamp 
                                            };
                                            
                                            // Serialize and encrypt response
                                            if let Ok(serialized) = bincode::serialize(&response) {
                                                let mut resp_nonce_bytes = [0u8; 12];
                                                rand::thread_rng().fill(&mut resp_nonce_bytes);
                                                let resp_nonce = Nonce::from_slice(&resp_nonce_bytes);
                                                
                                                if let Ok(encrypted) = encrypt(&cipher_for_ping, resp_nonce, &serialized) {
                                                    // Construct message with nonce and length
                                                    let mut msg = Vec::with_capacity(16 + encrypted.len());
                                                    msg.extend_from_slice(resp_nonce.as_slice());
                                                    
                                                    let data_len = (encrypted.len() as u32).to_be_bytes();
                                                    msg.extend_from_slice(&data_len);
                                                    msg.extend_from_slice(&encrypted);
                                                    
                                                    // Send ping response
                                                    let mut writer = writer_for_ping.lock().await;
                                                    let _ = writer.write_all(&msg).await;
                                                }
                                            }
                                        },
                                        _ => {
                                            // Send other message types to input channel
                                            let _ = input_tx.send(message).await;
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to deserialize message: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Decryption error: {}", e);
                        }
                    }
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        info!("Client disconnected");
                    } else {
                        error!("Read error: {}", e);
                    }
                    break;
                }
            }
        }
    });
    
    // Process input events
    tokio::spawn(async move {
        while let Some(message) = input_rx.recv().await {
            let mut handler = input_handler_clone.lock().await;
            
            match message {
                ClientMessage::MouseMove { x, y } => {
                    handler.move_mouse(x, y);
                }
                ClientMessage::MouseClick { x, y, button, down } => {
                    if down {
                        handler.mouse_down(x, y, button);
                    } else {
                        handler.mouse_up(x, y, button);
                    }
                }
                ClientMessage::KeyEvent { key_code, down } => {
                    if down {
                        handler.key_down(key_code);
                    } else {
                        handler.key_up(key_code);
                    }
                }
                ClientMessage::Heartbeat => {
                    // Just acknowledge heartbeat
                }
                ClientMessage::PingRequest { .. } => {
                    // Should be handled elsewhere, but don't panic
                }
            }
        }
    });
    
    // Set up network stats reporting interval
    let mut stats_interval = time::interval(Duration::from_secs(1));
    let writer_for_stats = writer.clone();
    let cipher_for_stats = cipher.clone();
    let network_speed_for_stats = network_speed.clone_tracker();
    
    tokio::spawn(async move {
        loop {
            stats_interval.tick().await;
            
            // Get speed stats
            let (bytes_per_sec, quality_level_str) = if let Ok(network_stats) = network_speed_for_stats.lock() {
                let bytes = network_stats.average_speed();
                let quality = match network_stats.get_quality() {
                    QualityLevel::High => "High",
                    QualityLevel::Medium => "Medium",
                    QualityLevel::Low => "Low",
                    QualityLevel::VeryLow => "VeryLow",
                }.to_string();
                // Drop the lock by returning the values we need
                (bytes, quality)
            } else {
                (0, "Medium".to_string())
            };
            
            // Send network stats to client
            let stats = ServerMessage::NetworkStats {
                speed: bytes_per_sec,
                quality_level: quality_level_str,
            };
            
            if let Ok(serialized) = bincode::serialize(&stats) {
                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);
                
                if let Ok(encrypted) = encrypt(&cipher_for_stats, nonce, &serialized) {
                    // Construct message with nonce and length
                    let mut msg = Vec::with_capacity(16 + encrypted.len());
                    msg.extend_from_slice(nonce.as_slice());
                    
                    let data_len = (encrypted.len() as u32).to_be_bytes();
                    msg.extend_from_slice(&data_len);
                    msg.extend_from_slice(&encrypted);
                    
                    // Send stats
                    let mut writer = writer_for_stats.lock().await;
                    if let Err(e) = writer.write_all(&msg).await {
                        error!("Failed to send network stats: {}", e);
                        break;
                    }
                }
            }
        }
    });
    
    // Set up screen capture and send frames
    let screen_capture = Arc::new(screen_capture);
    let writer_for_frames = writer.clone();
    let cipher_for_frames = cipher.clone();
    let network_speed_for_frames = network_speed.clone_tracker();
    
    tokio::spawn(async move {
        let mut frame_interval = tokio::time::interval(tokio::time::Duration::from_millis(33)); // ~30 FPS
        
        loop {
            frame_interval.tick().await;
            
            // Capture screen
            let screen_capture_clone = screen_capture.clone();
            let capture_result = tokio::task::spawn_blocking(move || {
                screen_capture_clone.capture()
            }).await;
            
            match capture_result {
                Ok(Ok(image_buffer)) => {
                    // Get image dimensions
                    let width = image_buffer.width();
                    let height = image_buffer.height();

                    // Get current quality level
                    let quality_level = if let Ok(speed_tracker) = network_speed_for_frames.lock() {
                        let ql = match speed_tracker.get_quality() {
                            QualityLevel::High => QualityLevel::High,
                            QualityLevel::Medium => QualityLevel::Medium, 
                            QualityLevel::Low => QualityLevel::Low,
                            QualityLevel::VeryLow => QualityLevel::VeryLow,
                        };
                        drop(speed_tracker);
                        ql
                    } else {
                        QualityLevel::Medium
                    };
                    
                    // Compress the frame with quality based on network speed
                    let compression_quality = match quality_level {
                        QualityLevel::Low => 30,
                        QualityLevel::Medium => 50,
                        QualityLevel::High => 70,
                        QualityLevel::VeryLow => 15,
                    };
                    
                    // Compress frame in a blocking task
                    let image_buffer_clone = image_buffer.clone();
                    let compression_result = tokio::task::spawn_blocking(move || {
                        screen_capture::compress_image(&image_buffer_clone, compression_quality)
                    }).await;
                    
                    if let Ok(Ok(compressed)) = compression_result {
                        // Create screen frame message
                        let frame = ServerMessage::ScreenFrame {
                            data: compressed,
                            width,
                            height,
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64,
                        };
                        
                        // Serialize with bincode
                        if let Ok(serialized) = bincode::serialize(&frame) {
                            // Encrypt the frame
                            let mut nonce_bytes = [0u8; 12];
                            rand::thread_rng().fill(&mut nonce_bytes);
                            let nonce = Nonce::from_slice(&nonce_bytes);
                            
                            if let Ok(encrypted) = encrypt(&cipher_for_frames, nonce, &serialized) {
                                // Track outgoing bytes
                                {
                                    if let Ok(mut speed_tracker) = network_speed_for_frames.lock() {
                                        speed_tracker.record_packet(encrypted.len() as u64);
                                    }
                                }
                                
                                // Construct message with nonce and length
                                let mut msg = Vec::with_capacity(16 + encrypted.len());
                                msg.extend_from_slice(nonce.as_slice());
                                
                                let data_len = (encrypted.len() as u32).to_be_bytes();
                                msg.extend_from_slice(&data_len);
                                msg.extend_from_slice(&encrypted);
                                
                                // Send frame
                                let mut writer = writer_for_frames.lock().await;
                                if let Err(e) = writer.write_all(&msg).await {
                                    error!("Failed to send frame: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Error in screen capture task: {}", e);
                }
                Ok(Err(e)) => {
                    error!("Screen capture error: {}", e);
                }
            }
        }
    });
    
    // Keep running until stopped
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(3600), // 1 hour timeout
        tokio::time::sleep(tokio::time::Duration::from_secs(3600))
    ).await {
        Ok(_) => {
            info!("Screen sharing session timeout reached");
        },
        Err(_) => {
            info!("Screen sharing interrupted");
        }
    }
    
    info!("Shutting down screen sharing server");
    
    Ok(())
}

// Empty implementation for server-only builds
#[cfg(not(feature = "client"))]
pub async fn run_server(
    _stream: TcpStream, 
    _frame_tx: mpsc::Sender<(Vec<u8>, u32, u32)>
) -> Result<()> {
    log::warn!("Screen capture not available in server-only build");
    Ok(())
} 