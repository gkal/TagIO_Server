use anyhow::Result;
use hyper::{Body, Request, Response, StatusCode};
use log::debug;
use std::net::SocketAddr;
use crate::constants::PROTOCOL_MAGIC;

/// Handles HTTP POST requests containing TagIO protocol messages
pub async fn handle_tagio_over_http(req: Request<Body>) -> Result<Response<Body>> {
    // Only accept POST requests for TagIO tunneling
    if req.method() != hyper::Method::POST {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from("Only POST method is allowed for TagIO protocol tunneling"))
            .unwrap());
    }

    // Get the request body
    let body_bytes = hyper::body::to_bytes(req.into_body()).await?;
    
    if body_bytes.is_empty() {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Empty request body"))
            .unwrap());
    }

    debug!("Received TagIO over HTTP request with {} bytes", body_bytes.len());

    // Examine the request body for TagIO protocol
    if body_bytes.len() < PROTOCOL_MAGIC.len() || !body_bytes.starts_with(&PROTOCOL_MAGIC) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Invalid TagIO protocol data"))
            .unwrap());
    }

    // For now, just echo back the request with an acknowledgment
    let mut response_bytes = Vec::with_capacity(body_bytes.len() + 32);
    response_bytes.extend_from_slice(&PROTOCOL_MAGIC);
    response_bytes.extend_from_slice(b"ACKNOWLEDGED");
    response_bytes.extend_from_slice(&body_bytes);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .body(Body::from(response_bytes))
        .unwrap())
}

/// Serves an HTML status page with TagIO connection instructions
pub async fn serve_status_page() -> Result<Response<Body>> {
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TagIO Relay Server</title>
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
    <h1>TagIO Relay Server</h1>
    
    <div class="status">
        <h2>Server Status: Online</h2>
        <p>The TagIO relay server is running and ready to accept connections.</p>
    </div>
    
    <h2>Connection Information</h2>
    <p>To connect to this TagIO relay server, use the following information:</p>
    
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

/// Start an HTTP server that can accept TagIO protocol messages over HTTP
pub async fn start_http_tunnel_server(bind_addr: SocketAddr) -> Result<()> {
    // Create the HTTP service
    let make_svc = hyper::service::make_service_fn(|_conn| async {
        Ok::<_, std::convert::Infallible>(hyper::service::service_fn(move |req: Request<Body>| async move {
            // Route the request based on the path
            let response = match (req.method(), req.uri().path()) {
                (&hyper::Method::GET, "/") | (&hyper::Method::GET, "/status") => {
                    serve_status_page().await
                }
                (_, "/tagio") => {
                    handle_tagio_over_http(req).await
                }
                _ => {
                    // Return 404 for any other path
                    Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Body::from("Not Found"))
                        .unwrap())
                }
            };
            
            match response {
                Ok(resp) => Ok::<Response<Body>, hyper::http::Error>(resp),
                Err(e) => {
                    eprintln!("Error handling HTTP request: {}", e);
                    // Create a simple error response
                    let error_response = Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from(format!("Internal Server Error: {}", e)))
                        .unwrap();
                    Ok::<Response<Body>, hyper::http::Error>(error_response)
                }
            }
        }))
    });
    
    // Create and run the server
    let server = hyper::Server::bind(&bind_addr)
        .serve(make_svc);
    
    println!("HTTP tunneling server listening on {}", bind_addr);
    
    // Run the server
    server.await?;
    
    Ok(())
} 