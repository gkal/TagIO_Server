use anyhow::Result;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Generate a self-signed certificate for TLS connections
pub fn generate_self_signed_cert(common_name: &str) -> Result<(Certificate, String)> {
    let mut params = CertificateParams::new(vec![common_name.to_string()]);
    
    // Add additional Subject Alternative Names (SANs)
    params.subject_alt_names = vec![
        SanType::DnsName(common_name.to_string()),
        SanType::DnsName("localhost".to_string()),
    ];
    
    // Set distinguished name fields
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, common_name);
    distinguished_name.push(DnType::OrganizationName, "TagIO");
    distinguished_name.push(DnType::CountryName, "US");
    params.distinguished_name = distinguished_name;
    
    // Set validity period (1 year)
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + Duration::from_secs(365 * 24 * 60 * 60);
    
    // Generate certificate
    let cert = Certificate::from_params(params)?;
    let key_pem = cert.serialize_private_key_pem();
    
    Ok((cert, key_pem))
}

/// Save certificate and private key to disk
pub fn save_cert_and_key(cert: &Certificate, key_pem: &str, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    fs::create_dir_all(output_dir)?;
    
    let cert_path = output_dir.join("cert.pem");
    let key_path = output_dir.join("key.pem");
    
    let cert_pem = cert.serialize_pem()?;
    
    // Write certificate to file
    let mut cert_file = File::create(&cert_path)?;
    cert_file.write_all(cert_pem.as_bytes())?;
    
    // Write private key to file
    let mut key_file = File::create(&key_path)?;
    key_file.write_all(key_pem.as_bytes())?;
    
    Ok((cert_path, key_path))
}

/// Load certificate and private key from disk
pub fn load_cert_and_key(cert_path: &Path, key_path: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut cert_file = File::open(cert_path)?;
    let mut cert_pem = Vec::new();
    cert_file.read_to_end(&mut cert_pem)?;
    
    let mut key_file = File::open(key_path)?;
    let mut key_pem = Vec::new();
    key_file.read_to_end(&mut key_pem)?;
    
    Ok((cert_pem, key_pem))
}

/// Check if certificate and key files exist
pub fn cert_files_exist(output_dir: &Path) -> bool {
    let cert_path = output_dir.join("cert.pem");
    let key_path = output_dir.join("key.pem");
    
    cert_path.exists() && key_path.exists()
}

/// Get or create certificate paths
pub fn get_or_create_cert(common_name: &str, output_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    if cert_files_exist(output_dir) {
        return Ok((output_dir.join("cert.pem"), output_dir.join("key.pem")));
    }
    
    let (cert, key_pem) = generate_self_signed_cert(common_name)?;
    save_cert_and_key(&cert, &key_pem, output_dir)
} 