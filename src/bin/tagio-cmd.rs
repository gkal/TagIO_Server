use anyhow::Result;
use tagio::VERSION;
use tagio::nat_traversal::NatTraversalClient;
use std::env;
use std::io::Write;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rand::random;

#[tokio::main]
async fn main() -> Result<()> {
    // Print version and basic information
    println!("TagIO P2P Command-Line Client v{}", VERSION);
    println!("No port forwarding required!");
    println!("---------------------------------------");

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: tagio-cmd [server|client] [options]");
        println!("  server            - Run in server mode, waiting for connections");
        println!("  client <id>       - Connect to a remote peer with the given ID");
        println!("  --no-relay        - Skip connecting to the relay server (for testing)");
        return Ok(());
    }

    // Check for --no-relay flag
    let skip_relay = args.iter().any(|arg| arg == "--no-relay");

    let mode = &args[1];
    let client_id = format!("tagio-{}", random::<u16>()); // Generate a random client ID

    println!("Your client ID: {}", client_id);
    
    // Use local address for testing
    let relay_server = "127.0.0.1:443";
    
    // Create NAT traversal client
    let mut nat_client = NatTraversalClient::new(
        client_id.clone(),
        relay_server.to_string(),
    ).await?;
    
    // Connect to the relay server if not skipped
    if !skip_relay {
        println!("Connecting to relay server at {}...", relay_server);
        match nat_client.connect_to_relay().await {
            Ok(_) => println!("Connected to relay server successfully"),
            Err(e) => {
                println!("Failed to connect to relay server: {}", e);
                println!("Note: Make sure the relay server is running on localhost port 443");
                println!("You can start it with: cargo run --bin tagio-relay -- --port 443");
                println!("Or use --no-relay to test without a relay server");
                return Err(e);
            }
        }
    } else {
        println!("Skipping relay server connection (--no-relay flag)");
    }

    match mode.as_str() {
        "server" => {
            println!("Running in server mode");
            println!("Waiting for incoming connections...");
            println!("Tell clients to connect using ID: {}", client_id);
            
            // Wait for incoming connections - use default port 7588
            nat_client.accept_connections(7588).await?;
            
            // Accept a connection
            match nat_client.accept().await {
                Ok(mut stream) => {
                    println!("Accepted connection from a client!");
                    
                    // Simple echo server for testing
                    println!("Type messages and press Enter (Ctrl+C to exit):");
                    
                    // Read buffer for received data
                    let mut recv_buffer = [0u8; 1024];
                    
                    loop {
                        // Only handle incoming data in this simple version
                        match stream.read(&mut recv_buffer).await {
                            Ok(0) => {
                                println!("Connection closed by client");
                                break;
                            }
                            Ok(n) => {
                                println!("Received: {}", String::from_utf8_lossy(&recv_buffer[0..n]));
                                
                                // Echo back
                                if let Err(e) = stream.write_all(&recv_buffer[0..n]).await {
                                    println!("Error sending response: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                println!("Error reading from client: {}", e);
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("Error accepting connection: {}", e);
                }
            }
        }
        "client" => {
            if args.len() < 3 {
                println!("Error: Missing target ID");
                println!("Usage: tagio-cmd client <target_id>");
                return Ok(());
            }
            
            let target_id = &args[2];
            println!("Connecting to remote peer: {}", target_id);
            
            // Connect to the specified peer
            match nat_client.connect_to_peer(target_id).await {
                Ok(mut stream) => {
                    println!("Connected to {}!", target_id);
                    
                    // Simple echo client for testing
                    println!("Type messages and press Enter (Ctrl+C to exit):");
                    
                    // Buffer for messages and responses
                    let mut buffer = String::new();
                    let mut response = [0u8; 1024];
                    
                    loop {
                        print!("> ");
                        std::io::stdout().flush()?;
                        
                        // Read input using standard blocking IO
                        buffer.clear();
                        if std::io::stdin().read_line(&mut buffer)? == 0 {
                            break;
                        }
                        
                        // Send the message
                        stream.write_all(buffer.as_bytes()).await?;
                        
                        // Wait for response
                        let n = stream.read(&mut response).await?;
                        if n == 0 {
                            println!("Connection closed by peer");
                            break;
                        }
                        
                        println!("Received: {}", String::from_utf8_lossy(&response[0..n]));
                    }
                }
                Err(e) => {
                    println!("Failed to connect: {}", e);
                }
            }
        }
        _ => {
            println!("Unknown mode: {}", mode);
            println!("Usage: tagio-cmd [server|client] [options]");
        }
    }

    Ok(())
} 