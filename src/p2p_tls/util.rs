use anyhow::{Result, anyhow};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys};
use log::{debug, warn, error};

/// Load certificates from a file
pub fn load_certificates(cert_path: &Path) -> Result<Vec<Certificate>> {
    let cert_file = match File::open(cert_path) {
        Ok(file) => file,
        Err(e) => {
            error!("Failed to open certificate file {:?}: {}", cert_path, e);
            return Err(anyhow!("Failed to open certificate file: {}", e));
        }
    };
    
    let mut reader = BufReader::new(cert_file);
    let certs = certs(&mut reader)?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<Certificate>>();
    
    if certs.is_empty() {
        let e = anyhow!("No certificates found in {:?}", cert_path);
        error!("{}", e);
        Err(e)
    } else {
        debug!("Loaded {} certificates from {:?}", certs.len(), cert_path);
        Ok(certs)
    }
}

/// Load private keys from a file
pub fn load_private_keys(key_path: &Path) -> Result<Vec<PrivateKey>> {
    let key_file = match File::open(key_path) {
        Ok(file) => file,
        Err(e) => {
            error!("Failed to open key file {:?}: {}", key_path, e);
            return Err(anyhow!("Failed to open key file: {}", e));
        }
    };
    
    let mut reader = BufReader::new(key_file);
    let keys = pkcs8_private_keys(&mut reader)?
        .into_iter()
        .map(PrivateKey)
        .collect::<Vec<PrivateKey>>();
    
    if keys.is_empty() {
        // Warn but don't fail - some configurations might not need a private key
        warn!("No private keys found in {:?}", key_path);
    } else {
        debug!("Loaded {} private keys from {:?}", keys.len(), key_path);
    }
    
    Ok(keys)
} 