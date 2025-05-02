use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use aes_gcm::aead::generic_array::typenum::U12;
use anyhow::{Result, anyhow};

// Encryption constants
// 32 bytes key - count each character: "TAGIO1234ENCRYPTKEY5678VERSION90"
const AES_KEY: &[u8; 32] = b"TAGIO1234ENCRYPTKEY5678VERSION90";

/// Function to get a unique identifier for the encryption key
/// This allows checking that both client and server are using the same key
/// without revealing the actual key
pub fn get_encryption_key_id() -> String {
    // Simple hash of the key - just for identification purposes
    let mut hash: u64 = 0;
    for (i, &byte) in AES_KEY.iter().enumerate() {
        hash = hash.wrapping_add((byte as u64).wrapping_mul(i as u64 + 1));
    }
    format!("{:016x}", hash)
}

/// Create a new encryption cipher
pub fn create_cipher() -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(AES_KEY)
        .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))
}

/// Encrypt data with AES-GCM
pub fn encrypt(cipher: &Aes256Gcm, nonce: &Nonce<U12>, data: &[u8]) -> Result<Vec<u8>> {
    cipher.encrypt(nonce, data)
        .map_err(|e| anyhow!("Encryption failed: {}", e))
}

/// Decrypt data with AES-GCM
pub fn decrypt(cipher: &Aes256Gcm, nonce: &Nonce<U12>, data: &[u8]) -> Result<Vec<u8>> {
    cipher.decrypt(nonce, data)
        .map_err(|e| anyhow!("Decryption failed: {}", e))
} 