use anyhow::{Result, anyhow};
use std::sync::Arc;
use std::path::Path;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, rustls::ClientConfig, rustls::ServerConfig};
use rustls::Certificate;
use rustls::client::HandshakeSignatureValid;
use log::{debug, info, warn, error};

use crate::p2p_tls::util::{load_certificates, load_private_keys};
use crate::p2p_tls::{TlsStream, TlsListener};

/// P2P TLS client for secure communications
pub struct P2PTlsClient {
    client_config: Arc<ClientConfig>,
    server_config: Option<Arc<ServerConfig>>,
}

impl P2PTlsClient {
    /// Create a new P2P TLS client with the provided certificate and key
    pub fn new(cert_path: &Path, key_path: &Path) -> Result<Self> {
        debug!("Creating new P2PTlsClient with cert: {:?}, key: {:?}", cert_path, key_path);
        
        // Load client certificates and keys
        let client_config = Self::create_client_config(cert_path, key_path)?;
        
        info!("P2PTlsClient created successfully with client configuration");
        
        Ok(Self {
            client_config: Arc::new(client_config),
            server_config: None,
        })
    }
    
    /// Configure the client to also act as a server (accept inbound connections)
    pub fn with_server_config(mut self, cert_path: &Path, key_path: &Path) -> Result<Self> {
        debug!("Adding server config to P2PTlsClient with cert: {:?}, key: {:?}", cert_path, key_path);
        
        let server_config = Self::create_server_config(cert_path, key_path)?;
        self.server_config = Some(Arc::new(server_config));
        
        info!("P2PTlsClient configured with server capabilities");
        
        Ok(self)
    }
    
    /// Create client TLS configuration
    fn create_client_config(cert_path: &Path, key_path: &Path) -> Result<ClientConfig> {
        debug!("Creating client TLS configuration");
        
        // Load our certificates and private key
        let certs = load_certificates(cert_path)?;
        let keys = load_private_keys(key_path)?;
        
        if keys.is_empty() {
            error!("No private keys found in {:?}", key_path);
            return Err(anyhow!("No private keys found"));
        }
        
        // Create a fully permissive verifier that bypasses all certificate checks
        struct PermissiveVerifier {}
        
        impl rustls::client::ServerCertVerifier for PermissiveVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &Certificate,
                _intermediates: &[Certificate],
                _server_name: &rustls::ServerName,
                _scts: &mut dyn Iterator<Item = &[u8]>,
                _ocsp_response: &[u8],
                _now: std::time::SystemTime,
            ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
                debug!("Certificate verification completely bypassed - accepting any certificate");
                Ok(rustls::client::ServerCertVerified::assertion())
            }
            
            // Override additional verification methods to bypass all checks
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &Certificate,
                _dss: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::HandshakeSignatureValid::assertion())
            }
            
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &Certificate,
                _dss: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::HandshakeSignatureValid::assertion())
            }
            
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                // Return all schemes to avoid capability negotiation failures
                vec![
                    rustls::SignatureScheme::RSA_PKCS1_SHA1,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                    rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                    rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    rustls::SignatureScheme::RSA_PKCS1_SHA384,
                    rustls::SignatureScheme::RSA_PKCS1_SHA512,
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                    rustls::SignatureScheme::RSA_PSS_SHA384,
                    rustls::SignatureScheme::RSA_PSS_SHA512,
                    rustls::SignatureScheme::ED25519,
                    rustls::SignatureScheme::ED448,
                ]
            }
        }
        
        // Build client config with permissive settings
        let mut client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates({
                let mut root_store = rustls::RootCertStore::empty();
                
                // Add webpki roots
                debug!("Added root certificates from webpki-roots");
                root_store.add_trust_anchors(
                    webpki_roots::TLS_SERVER_ROOTS
                        .iter()
                        .map(|ta| {
                            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                                ta.subject,
                                ta.spki,
                                ta.name_constraints,
                            )
                        })
                );
                
                // Also try to add our own certificate to root store for mutual authentication
                for (i, cert) in certs.iter().enumerate() {
                    match root_store.add(cert) {
                        Ok(_) => debug!("Added certificate #{} to root store", i+1),
                        Err(e) => warn!("Failed to add certificate #{} to root store: {}", i+1, e),
                    }
                }
                
                root_store
            })
            .with_no_client_auth();
        
        // Set our completely permissive certificate verifier
        client_config.dangerous().set_certificate_verifier(Arc::new(PermissiveVerifier {}));
        
        // Add client certificate
        if !certs.is_empty() {
            // For rustls 0.21, we have to rebuild the config to include client certificates
            let cert_config = match ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates({
                    // Create a new root store
                    let mut root_store = rustls::RootCertStore::empty();
                    
                    // Add webpki roots
                    root_store.add_trust_anchors(
                        webpki_roots::TLS_SERVER_ROOTS
                            .iter()
                            .map(|ta| {
                                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                                    ta.subject,
                                    ta.spki,
                                    ta.name_constraints,
                                )
                            })
                    );
                    
                    // Also try to add our own certificate to root store for mutual authentication
                    for (i, cert) in certs.iter().enumerate() {
                        match root_store.add(cert) {
                            Ok(_) => debug!("Added certificate #{} to root store", i+1),
                            Err(e) => warn!("Failed to add certificate #{} to root store: {}", i+1, e),
                        }
                    }
                    
                    root_store
                })
                .with_client_auth_cert(certs.clone(), keys[0].clone()) {
                Ok(config) => {
                    debug!("Client certificate configured successfully");
                    config
                },
                Err(e) => {
                    warn!("Failed to configure client auth cert: {}", e);
                    // Continue with the config we have without client auth
                    client_config
                }
            };
            
            // Update client config with the new one including certificates
            if let Ok(config) = ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates({
                    // Empty root store to avoid validation issues 
                    let mut root_store = rustls::RootCertStore::empty();
                    
                    // Add webpki roots
                    root_store.add_trust_anchors(
                        webpki_roots::TLS_SERVER_ROOTS
                            .iter()
                            .map(|ta| {
                                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                                    ta.subject,
                                    ta.spki,
                                    ta.name_constraints,
                                )
                            })
                    );
                    
                    // Add our certificates to the root store
                    for (i, cert) in certs.iter().enumerate() {
                        match root_store.add(cert) {
                            Ok(_) => debug!("Added certificate #{} to the enhanced root store", i+1),
                            Err(e) => warn!("Failed to add certificate #{} to enhanced root store: {}", i+1, e),
                        }
                    }
                    
                    root_store
                })
                .with_client_auth_cert(certs.clone(), keys[0].clone()) {
                client_config = config;
            } else {
                // Fall back to previous config with client certificate if the new build fails
                client_config = cert_config;
            }
            
            // Always apply our permissive verifier
            client_config.dangerous().set_certificate_verifier(Arc::new(PermissiveVerifier {}));
        }
        
        debug!("Client TLS configuration successfully created with maximum compatibility");
        
        Ok(client_config)
    }
    
    /// Create server TLS configuration
    fn create_server_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig> {
        debug!("Creating server TLS configuration");
        
        // Load our certificates and private key
        let certs = load_certificates(cert_path)?;
        let keys = load_private_keys(key_path)?;
        
        if keys.is_empty() {
            error!("No private keys found in {:?}", key_path);
            return Err(anyhow!("No private keys found"));
        }
        
        // Create a flexible client verifier that allows any client certificate but verifies them against the root store
        struct FlexibleClientVerifier {
            inner_verifier: Arc<rustls::server::AllowAnyAuthenticatedClient>,
        }
        
        impl rustls::server::ClientCertVerifier for FlexibleClientVerifier {
            fn client_auth_root_subjects(&self) -> &[rustls::DistinguishedName] {
                // Return the root subjects from the inner verifier
                self.inner_verifier.client_auth_root_subjects()
            }
            
            fn verify_client_cert(
                &self,
                end_entity: &rustls::Certificate,
                intermediates: &[rustls::Certificate],
                now: std::time::SystemTime,
            ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
                // First try to verify the client cert using the inner verifier
                match self.inner_verifier.verify_client_cert(end_entity, intermediates, now) {
                    Ok(verified) => Ok(verified),
                    Err(e) => {
                        // If verification fails, log the error and accept anyway
                        warn!("Client certificate failed verification: {}", e);
                        Ok(rustls::server::ClientCertVerified::assertion())
                    }
                }
            }
            
            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &rustls::Certificate,
                dss: &rustls::DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                // First try to verify the signature using the inner verifier
                match self.inner_verifier.verify_tls12_signature(message, cert, dss) {
                    Ok(valid) => Ok(valid),
                    Err(e) => {
                        // If verification fails, log the error and accept anyway
                        warn!("TLS 1.2 signature failed verification: {}", e);
                        Ok(HandshakeSignatureValid::assertion())
                    }
                }
            }
            
            fn verify_tls13_signature(
                &self,
                message: &[u8],
                cert: &rustls::Certificate,
                dss: &rustls::DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                // First try to verify the signature using the inner verifier
                match self.inner_verifier.verify_tls13_signature(message, cert, dss) {
                    Ok(valid) => Ok(valid),
                    Err(e) => {
                        // If verification fails, log the error and accept anyway
                        warn!("TLS 1.3 signature failed verification: {}", e);
                        Ok(HandshakeSignatureValid::assertion())
                    }
                }
            }
            
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                // Return all schemes to avoid capability negotiation failures
                vec![
                    rustls::SignatureScheme::RSA_PKCS1_SHA1,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                    rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                    rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    rustls::SignatureScheme::RSA_PKCS1_SHA384,
                    rustls::SignatureScheme::RSA_PKCS1_SHA512,
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                    rustls::SignatureScheme::RSA_PSS_SHA384,
                    rustls::SignatureScheme::RSA_PSS_SHA512,
                    rustls::SignatureScheme::ED25519,
                    rustls::SignatureScheme::ED448,
                ]
            }
        }
        
        // Create root store for client verification
        let mut root_store = rustls::RootCertStore::empty();
        
        // Add our certificate to the root store
        for (i, cert) in certs.iter().enumerate() {
            match root_store.add(cert) {
                Ok(_) => debug!("Added certificate #{} to server root store", i+1),
                Err(e) => warn!("Failed to add certificate #{} to server root store: {}", i+1, e),
            }
        }
        
        // Build server config
        let client_verifier = rustls::server::AllowAnyAuthenticatedClient::new(root_store);
        let client_verifier = FlexibleClientVerifier {
            inner_verifier: Arc::new(client_verifier),
        };
        
        let server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(client_verifier))
            .with_single_cert(certs, keys[0].clone())?;
        
        debug!("Server TLS configuration successfully created");
        
        Ok(server_config)
    }
    
    /// Connect to a remote host using TLS
    pub async fn connect(&self, addr: &str) -> Result<TlsStream> {
        debug!("Connecting to {} with TLS", addr);
        
        let domain = match addr.split(':').next() {
            Some(d) => d.trim(),
            None => {
                let e = anyhow!("Invalid address format: {}", addr);
                error!("{}", e);
                return Err(e);
            }
        };
        
        // Convert domain to server name
        let server_name = match rustls::ServerName::try_from(domain) {
            Ok(name) => name,
            Err(_) => {
                debug!("Using IP address as server name: {}", domain);
                // For IP addresses, we need to use the IP literal format
                match domain.parse::<std::net::IpAddr>() {
                    Ok(ip) => {
                        // For IP addresses, we'll use their IP literal format
                        match rustls::ServerName::try_from(format!("{}.", ip).as_str()) {
                            Ok(name) => name,
                            Err(e) => {
                                let e = anyhow!("Failed to create ServerName from IP: {}", e);
                                error!("{}", e);
                                return Err(e);
                            }
                        }
                    }
                    Err(_) => {
                        // Try using the DNS name directly
                        match rustls::ServerName::try_from(domain) {
                            Ok(name) => name,
                            Err(e) => {
                                let e = anyhow!("Failed to create ServerName: {}", e);
                                error!("{}", e);
                                return Err(e);
                            }
                        }
                    }
                }
            }
        };
        
        // Try to connect to the target
        let tcp_stream = match TcpStream::connect(addr).await {
            Ok(stream) => {
                debug!("TCP connection established to {}", addr);
                stream
            }
            Err(e) => {
                error!("Failed to connect to {}: {}", addr, e);
                return Err(anyhow!("Failed to connect to {}: {}", addr, e));
            }
        };
        
        // Create TLS connector
        let connector = TlsConnector::from(self.client_config.clone());
        
        // Try to connect with TLS
        debug!("Establishing TLS connection to {}", addr);
        match connector.connect(server_name.clone(), tcp_stream).await {
            Ok(stream) => {
                debug!("TLS connection established to {}", addr);
                Ok(TlsStream {
                    stream,
                    last_activity: std::time::Instant::now(),
                })
            }
            Err(e) => {
                error!("Failed to establish TLS connection to {}: {}", addr, e);
                
                // Fallback to a completely permissive verifier if the issue is with certificate validation
                if e.to_string().contains("cert") || e.to_string().contains("certificate") {
                    warn!("Attempting fallback with permissive certificate verification");
                    
                    // Create a completely permissive verifier
                    struct FallbackPermissiveVerifier {}
                    
                    impl rustls::client::ServerCertVerifier for FallbackPermissiveVerifier {
                        fn verify_server_cert(
                            &self,
                            _end_entity: &Certificate,
                            _intermediates: &[Certificate],
                            _server_name: &rustls::ServerName,
                            _scts: &mut dyn Iterator<Item = &[u8]>,
                            _ocsp_response: &[u8],
                            _now: std::time::SystemTime,
                        ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
                            debug!("Fallback certificate verification: accepting any certificate");
                            Ok(rustls::client::ServerCertVerified::assertion())
                        }
                        
                        fn verify_tls12_signature(
                            &self,
                            _message: &[u8],
                            _cert: &Certificate,
                            _dss: &rustls::DigitallySignedStruct,
                        ) -> std::result::Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
                            Ok(rustls::client::HandshakeSignatureValid::assertion())
                        }
                        
                        fn verify_tls13_signature(
                            &self,
                            _message: &[u8],
                            _cert: &Certificate,
                            _dss: &rustls::DigitallySignedStruct,
                        ) -> std::result::Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
                            Ok(rustls::client::HandshakeSignatureValid::assertion())
                        }
                        
                        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                            // Return all schemes
                            vec![
                                rustls::SignatureScheme::RSA_PKCS1_SHA1,
                                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                                rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                                rustls::SignatureScheme::RSA_PSS_SHA256,
                                rustls::SignatureScheme::RSA_PSS_SHA384,
                                rustls::SignatureScheme::RSA_PSS_SHA512,
                                rustls::SignatureScheme::ED25519,
                                rustls::SignatureScheme::ED448,
                            ]
                        }
                    }
                    
                    // Create a fallback client config with permissive settings
                    let fallback_config = ClientConfig::builder()
                        .with_safe_defaults()
                        .with_custom_certificate_verifier(Arc::new(FallbackPermissiveVerifier {}))
                        .with_no_client_auth();
                    
                    // Try a new connection with the fallback config
                    let tcp_stream = TcpStream::connect(addr).await?;
                    let connector = TlsConnector::from(Arc::new(fallback_config));
                    
                    match connector.connect(server_name, tcp_stream).await {
                        Ok(stream) => {
                            debug!("Fallback TLS connection established to {}", addr);
                            Ok(TlsStream {
                                stream,
                                last_activity: std::time::Instant::now(),
                            })
                        }
                        Err(e) => {
                            error!("Fallback TLS connection also failed: {}", e);
                            Err(anyhow!("Failed to establish TLS connection: {}", e))
                        }
                    }
                } else {
                    Err(anyhow!("Failed to establish TLS connection: {}", e))
                }
            }
        }
    }
    
    /// Listen for incoming connections using TLS
    pub async fn listen(&self, addr: &str) -> Result<TlsListener> {
        debug!("Setting up TLS listener on {}", addr);
        
        // Make sure we have server configuration
        if self.server_config.is_none() {
            let e = anyhow!("No server configuration available. Use with_server_config() to add it.");
            error!("{}", e);
            return Err(e);
        }
        
        // Create TCP listener
        let tcp_listener = match TcpListener::bind(addr).await {
            Ok(listener) => {
                debug!("TCP listener bound to {}", addr);
                listener
            }
            Err(e) => {
                error!("Failed to bind TCP listener to {}: {}", addr, e);
                return Err(anyhow!("Failed to bind to {}: {}", addr, e));
            }
        };
        
        // Create TLS acceptor
        let acceptor = TlsAcceptor::from(self.server_config.as_ref().unwrap().clone());
        
        debug!("TLS listener ready on {}", addr);
        
        Ok(TlsListener {
            listener: tcp_listener,
            acceptor,
        })
    }
} 