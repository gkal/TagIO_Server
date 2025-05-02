use anyhow::{anyhow, Result};
use rustls::{client::ServerCertVerifier, Certificate, ClientConfig, ServerName};
use std::sync::Arc;
use tokio_rustls::TlsConnector;

/// A custom certificate verifier that accepts self-signed certificates
struct AcceptSelfSigned;

impl ServerCertVerifier for AcceptSelfSigned {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        // Accept any certificate - this is for development only and should be replaced
        // with proper verification in production
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

/// Create a TLS connector with options to accept self-signed certificates
pub fn create_tls_connector(accept_invalid_certs: bool) -> Result<TlsConnector> {
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(rustls::RootCertStore::empty());
    
    if accept_invalid_certs {
        // For development: Accept self-signed certificates
        let verifier = Arc::new(AcceptSelfSigned {});
        config.dangerous().set_certificate_verifier(verifier);
    } else {
        // For production: Use standard web PKI with Mozilla roots
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store);
    }
    
    Ok(Arc::new(config).into())
}

/// Parse a server name for TLS SNI
pub fn parse_server_name(server: &str) -> Result<ServerName> {
    // Extract hostname without port
    let host = if let Some(colon_pos) = server.rfind(':') {
        &server[..colon_pos]
    } else {
        server
    };
    
    // Convert to DNS name for TLS
    ServerName::try_from(host)
        .map_err(|e| anyhow!("Invalid server name '{}': {}", host, e))
} 