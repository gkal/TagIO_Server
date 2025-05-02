use anyhow::{Result, anyhow};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use log::{debug, error};

use crate::p2p_tls::TlsServerStream;

/// TLS listener for accepting secure connections
pub struct TlsListener {
    pub(crate) listener: TcpListener,
    pub(crate) acceptor: TlsAcceptor,
}

impl TlsListener {
    /// Accept a new TLS connection
    pub async fn accept(&self) -> Result<(TlsServerStream, String)> {
        debug!("Waiting for incoming TLS connection");
        
        // Accept the TCP connection first
        let (tcp_stream, peer_addr) = match self.listener.accept().await {
            Ok((stream, addr)) => {
                debug!("Accepted TCP connection from {}", addr);
                (stream, addr.to_string())
            },
            Err(e) => {
                error!("Failed to accept TCP connection: {}", e);
                return Err(anyhow!("Failed to accept TCP connection: {}", e));
            }
        };
        
        // Perform TLS handshake
        match self.acceptor.accept(tcp_stream).await {
            Ok(tls_stream) => {
                debug!("TLS handshake completed successfully with {}", peer_addr);
                
                Ok((
                    TlsServerStream { stream: tls_stream },
                    peer_addr,
                ))
            },
            Err(e) => {
                error!("TLS handshake failed with {}: {}", peer_addr, e);
                Err(anyhow!("TLS handshake failed: {}", e))
            }
        }
    }
} 