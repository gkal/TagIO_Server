use anyhow;
use clap::Parser;
use hyper::{Body, Request, Response, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use log::{debug, info, error, warn, LevelFilter};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

// Constants for protocol magic
const PROTOCOL_MAGIC: &[u8] = b"TAGIO";

#[derive(Parser)]
#[clap(author = "TagIO Team", version, about = "TagIO HTTP Tunnel Server")]
struct Args {
    /// Port to bind to
    #[clap(short, long, default_value_t = 10000)]
    port: u16,
    
    /// Log level
    #[clap(short, long, default_value = "info")]
    log_level: String,
    
    /// Log to file
    #[clap(long)]
    log_file: Option<PathBuf>,
}

/// Initialize the logger
fn setup_logger(level: LevelFilter, log_file: Option<PathBuf>) -> Result<(), fern::InitError> {
    let mut builder = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [T] {} [{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.target(),
                message
            ))
        })
        .level(level);
    
    // Log to stdout
    builder = builder.chain(std::io::stdout());
    
    // Log to file if specified
    if let Some(log_file) = log_file {
        builder = builder.chain(fern::log_file(log_file)?);
    }
    
    // Apply configuration
    builder.apply()?;
    
    Ok(())
}

/// Helper function to format bytes as a hex dump for logging
fn hex_dump(bytes: &[u8], max_len: usize) -> String {
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

/// Extract TagIO protocol data from HTTP headers and body
fn extract_tagio_from_http(headers: &hyper::HeaderMap, body: &[u8]) -> bool {
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

/// Handles HTTP POST requests containing TagIO protocol messages
async fn handle_tagio_over_http(body_bytes: Vec<u8>) -> Result<Response<Body>, hyper::http::Error> {
    if body_bytes.is_empty() {
        error!("Received empty request body");
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Empty request body"))
            .unwrap());
    }

    debug!("Processing TagIO over HTTP with {} bytes", body_bytes.len());
    debug!("Message hex dump: {}", hex_dump(&body_bytes, 64));

    // Log if we have the magic bytes
    if body_bytes.len() >= PROTOCOL_MAGIC.len() {
        let magic_slice = &body_bytes[0..PROTOCOL_MAGIC.len()];
        if magic_slice == PROTOCOL_MAGIC {
            info!("Valid TagIO protocol message received (magic: {})", 
                 String::from_utf8_lossy(magic_slice));
        } else {
            warn!("Invalid protocol magic: {}", hex_dump(magic_slice, magic_slice.len()));
            warn!("Expected magic: {}", hex_dump(PROTOCOL_MAGIC, PROTOCOL_MAGIC.len()));
        }
    } else {
        warn!("Message too short ({} bytes) to contain TagIO protocol magic", body_bytes.len());
    }

    // For TagIO protocol, the content type must be application/octet-stream
    // and we must return the raw bytes WITHOUT any HTTP headers in the response body
    debug!("Sending TagIO response with {} bytes", body_bytes.len());
    debug!("Response hex dump: {}", hex_dump(&body_bytes, 64));

    // IMPORTANT: Return raw bytes for TagIO protocol without HTTP wrapping
    // This allows clients expecting raw TagIO protocol to work correctly
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .header("X-TagIO-Raw-Protocol", "true")
        .body(Body::from(body_bytes))
        .unwrap())
}

/// Serves an HTML status page with TagIO connection instructions
async fn serve_status_page() -> Result<Response<Body>, hyper::http::Error> {
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TagIO HTTP Tunnel Server</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .status {
            background-color: #e8f5e9;
            border-left: 5px solid #4caf50;
            padding: 15px;
            margin: 20px 0;
        }
        pre {
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
        }
        .note {
            background-color: #fff8e1;
            border-left: 5px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <h1>TagIO HTTP Tunnel Server</h1>
    
    <div class="status">
        <h2>Server Status: Online</h2>
        <p>The TagIO HTTP tunnel server is running and ready to accept connections.</p>
    </div>
    
    <h2>Connection Information</h2>
    <p>To connect to this TagIO HTTP tunnel server, use the following information:</p>
    
    <pre>
Server: This domain (same as in your browser address bar)
Port: 443 (HTTPS)
Protocol: TagIO over HTTP tunneling
</pre>
    
    <div class="note">
        <h3>Important Note for Client Applications</h3>
        <p>This server implements TagIO protocol tunneling over HTTPS. Client applications must wrap TagIO protocol messages 
        in HTTP POST requests to any endpoint. The server is accessible only via HTTPS on the standard port 443.</p>
        <p>You do NOT need to specify any special port in your client configuration.</p>
    </div>
    
    <h2>For Developers</h2>
    <p>TagIO clients should:</p>
    <ol>
        <li>Connect to this server via HTTPS (port 443)</li>
        <li>Send TagIO protocol messages in the body of POST requests</li>
        <li>Read responses from the HTTP response body</li>
        <li>Do not attempt to connect directly to internal port 10000</li>
    </ol>
    
    <p>For more information, please refer to the TagIO documentation.</p>
</body>
</html>
    "#;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(Body::from(html))
        .unwrap())
}

// Helper function to find a subsequence in a byte array
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args = Args::parse();
    
    // Set up the logger
    let log_level = match args.log_level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };
    
    setup_logger(log_level, args.log_file.clone())?;
    
    // Print banner
    println!("[T] ===== STARTING TAGIO HTTP TUNNEL SERVER =====");
    info!("TagIO HTTP Tunnel Server starting up with log level: {}", args.log_level);
    
    // Check for PORT environment variable (for cloud platforms like Render)
    let port = match std::env::var("PORT") {
        Ok(val) => match val.parse::<u16>() {
            Ok(port) => {
                info!("Using PORT environment variable: {}", port);
                port
            },
            Err(_) => {
                warn!("Invalid PORT environment variable: {}, using command line port: {}", val, args.port);
                args.port
            }
        },
        Err(_) => args.port,
    };
    
    // Determine the bind address
    let bind_addr = SocketAddr::new(
        std::net::IpAddr::from_str("0.0.0.0").unwrap(),
        port
    );
    
    // Use a boolean flag for debug mode to avoid lifetime issues
    let debug_enabled = log_level == LevelFilter::Debug || log_level == LevelFilter::Trace;
    
    // Create the HTTP service
    let make_svc = make_service_fn(move |_conn| {
        // Create a clone for moving into the service_fn closure
        let debug_mode = debug_enabled;
        
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                // Clone for the async block
                let debug_mode = debug_mode;
                
                async move {
                    // Log all incoming requests with detailed information
                    info!("Received HTTP request: {} {} from {:?}", 
                          req.method(), 
                          req.uri().path(),
                          req.headers().get("host").map(|h| h.to_str().unwrap_or("unknown")).unwrap_or("unknown"));
                    
                    if debug_mode {
                        debug!("Request headers: {:?}", req.headers());
                    }
                    
                    // Check for TagIO protocol indicators in headers
                    let headers = req.headers().clone();
                    let is_http_upgrade_to_tagio = extract_tagio_from_http(&headers, &[]);
                    
                    // Special case for GET requests to root or status
                    if req.method() == hyper::Method::GET && 
                       (req.uri().path() == "/" || req.uri().path() == "/status") && 
                       !is_http_upgrade_to_tagio {
                        debug!("Serving status page");
                        match serve_status_page().await {
                            Ok(response) => return Ok::<_, hyper::http::Error>(response),
                            Err(e) => {
                                error!("Error serving status page: {}", e);
                                return Ok::<_, hyper::http::Error>(Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Body::from("Internal server error"))
                                    .unwrap());
                            }
                        }
                    }

                    // Get the request body directly
                    let body_bytes = match hyper::body::to_bytes(req.into_body()).await {
                        Ok(bytes) => bytes.to_vec(),
                        Err(e) => {
                            error!("Failed to read request body: {}", e);
                            return Ok::<_, hyper::http::Error>(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Failed to read request body: {}", e)))
                                .unwrap());
                        }
                    };
                    
                    debug!("Received request body of {} bytes", body_bytes.len());
                    
                    // Look for TagIO protocol markers in headers or body
                    let is_tagio_magic = body_bytes.len() >= PROTOCOL_MAGIC.len() && 
                                   body_bytes.starts_with(PROTOCOL_MAGIC);
                    
                    let is_tagio = is_tagio_magic || is_http_upgrade_to_tagio || 
                                   extract_tagio_from_http(&headers, &body_bytes);
                    
                    if is_tagio {
                        debug!("Found TagIO protocol data in request of {} bytes", body_bytes.len());
                        info!("Processing TagIO protocol message");
                        
                        // Skip HTTP headers if they exist, find the TagIO protocol data
                        let actual_body = if !is_tagio_magic && body_bytes.len() > 5 {
                            // Try to find TAGIO marker in the body
                            if let Some(pos) = find_subsequence(&body_bytes, PROTOCOL_MAGIC) {
                                debug!("Found TagIO magic at position {}", pos);
                                &body_bytes[pos..]
                            } else {
                                &body_bytes
                            }
                        } else {
                            &body_bytes
                        };
                        
                        // Convert back to owned Vec<u8>
                        let actual_body = actual_body.to_vec();
                        
                        match handle_tagio_over_http(actual_body).await {
                            Ok(response) => Ok::<_, hyper::http::Error>(response),
                            Err(e) => {
                                error!("Error handling TagIO request: {}", e);
                                Ok::<_, hyper::http::Error>(Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Body::from("Internal server error"))
                                    .unwrap())
                            }
                        }
                    } else {
                        // If not TagIO data, log the first few bytes for debugging
                        if !body_bytes.is_empty() {
                            debug!("Request body bytes: {}", hex_dump(&body_bytes, 64));
                        }
                        
                        // Accept any HTTP request for troubleshooting
                        info!("Non-TagIO request received, responding with echo");
                        Ok::<_, hyper::http::Error>(Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", "application/octet-stream")
                            .body(Body::from(body_bytes))
                            .unwrap())
                    }
                }
            }))
        }
    });
    
    // Create the HTTP server
    let server = hyper::Server::bind(&bind_addr)
        .serve(make_svc);
    
    info!("HTTP tunneling server listening on {}", bind_addr);
    println!("[T] HTTP tunneling server listening on {}", bind_addr);
    println!("[T] Clients should POST TagIO protocol messages to any endpoint");
    
    // Run the server
    if let Err(e) = server.await {
        error!("HTTP server error: {}", e);
        return Err(anyhow::anyhow!("HTTP server error: {}", e));
    }
    
    Ok(())
}