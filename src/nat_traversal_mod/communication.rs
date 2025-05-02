use tokio::{
    io::{AsyncWriteExt, AsyncReadExt},
    net::TcpStream,
};
use std::io;
use crate::p2p_tls::TlsStream;

// Define a trait for async read/write operations that can be used with both TcpStream and TlsStream
#[async_trait::async_trait]
pub trait AsyncCommunication: Send + Sync {
    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()>;
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;
}

// Implement AsyncCommunication for TcpStream
#[async_trait::async_trait]
impl AsyncCommunication for TcpStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let _ = tokio::io::AsyncReadExt::read_exact(self, buf).await?;
        Ok(())
    }
    
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        tokio::io::AsyncWriteExt::write_all(self, buf).await
    }
}

// Implement AsyncCommunication for our TLS stream
#[async_trait::async_trait]
impl AsyncCommunication for TlsStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let _ = tokio::io::AsyncReadExt::read_exact(self, buf).await?;
        Ok(())
    }
    
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        tokio::io::AsyncWriteExt::write_all(self, buf).await
    }
} 