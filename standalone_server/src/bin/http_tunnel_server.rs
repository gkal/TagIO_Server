use anyhow;
use clap::Parser;
use hyper::{Body, Request, Response, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use log::{debug, info, error, LevelFilter};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

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
                "{} {} [{}] {}",
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

/// Handles HTTP POST requests containing TagIO protocol messages
async fn handle_tagio_over_http(req: Request<Body>) -> Result<Response<Body>, hyper::http::Error> {
    // Only accept POST requests for TagIO tunneling
    if req.method() != hyper::Method::POST {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from("Only POST method is allowed for TagIO protocol tunneling"))
            .unwrap());
    }

    // Get the request body
    let body_bytes = match hyper::body::to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to read request body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(format!("Failed to read request body: {}", e)))
                .unwrap());
        }
    };
    
    if body_bytes.is_empty() {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Empty request body"))
            .unwrap());
    }

    debug!("Received TagIO over HTTP request with {} bytes", body_bytes.len());

    // Examine the request body for TagIO protocol
    if body_bytes.len() < PROTOCOL_MAGIC.len() || !body_bytes.starts_with(PROTOCOL_MAGIC) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Invalid TagIO protocol data"))
            .unwrap());
    }

    // For now, just echo back the request with an acknowledgment
    let mut response_bytes = Vec::with_capacity(body_bytes.len() + 32);
    response_bytes.extend_from_slice(PROTOCOL_MAGIC);
    response_bytes.extend_from_slice(b"ACKNOWLEDGED");
    response_bytes.extend_from_slice(&body_bytes);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .body(Body::from(response_bytes))
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
Port: 80 (HTTP) or 443 (HTTPS)
Protocol: TagIO over HTTP tunneling
    </pre>
    
    <div class="note">
        <h3>Important Note for Client Applications</h3>
        <p>This server implements TagIO protocol tunneling over HTTP. Client applications must wrap TagIO protocol messages 
        in HTTP POST requests to the /tagio endpoint.</p>
    </div>
    
    <h2>For Developers</h2>
    <p>TagIO clients should:</p>
    <ol>
        <li>Connect to this server via HTTP or HTTPS</li>
        <li>Send TagIO protocol messages in the body of POST requests to /tagio</li>
        <li>Read responses from the HTTP response body</li>
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
    println!("===== STARTING TAGIO HTTP TUNNEL SERVER =====");
    info!("TagIO HTTP Tunnel Server starting up");
    
    // Determine the bind address
    let bind_addr = SocketAddr::new(
        std::net::IpAddr::from_str("0.0.0.0").unwrap(),
        args.port
    );
    
    // Create the HTTP service
    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(move |req: Request<Body>| async move {
            // Route the request based on the path
            match (req.method(), req.uri().path()) {
                (&hyper::Method::GET, "/") | (&hyper::Method::GET, "/status") => {
                    match serve_status_page().await {
                        Ok(response) => Ok::<_, hyper::http::Error>(response),
                        Err(e) => {
                            error!("Error serving status page: {}", e);
                            Ok::<_, hyper::http::Error>(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from("Internal server error"))
                                .unwrap())
                        }
                    }
                }
                (_, "/tagio") => {
                    match handle_tagio_over_http(req).await {
                        Ok(response) => Ok::<_, hyper::http::Error>(response),
                        Err(e) => {
                            error!("Error handling TagIO request: {}", e);
                            Ok::<_, hyper::http::Error>(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from("Internal server error"))
                                .unwrap())
                        }
                    }
                }
                _ => {
                    // Return 404 for any other path
                    Ok::<_, hyper::http::Error>(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Body::from("Not Found"))
                        .unwrap())
                }
            }
        }))
    });
    
    // Create the HTTP server
    let server = hyper::Server::bind(&bind_addr)
        .serve(make_svc);
    
    info!("HTTP tunneling server listening on {}", bind_addr);
    println!("HTTP tunneling server listening on {}", bind_addr);
    println!("Clients should POST TagIO protocol messages to /tagio endpoint");
    
    // Run the server
    if let Err(e) = server.await {
        error!("HTTP server error: {}", e);
        return Err(anyhow::anyhow!("HTTP server error: {}", e));
    }
    
    Ok(())
} 