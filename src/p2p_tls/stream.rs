use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use log::{debug, trace};

/// TLS stream wrapper for client-side connections
pub struct TlsStream {
    pub(crate) stream: ClientTlsStream<TcpStream>,
    pub(crate) last_activity: Instant,
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let stream = Pin::new(&mut this.stream);
        let result = stream.poll_read(cx, buf);
        
        if let Poll::Ready(Ok(())) = &result {
            this.last_activity = Instant::now();
        }
        
        result
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let stream = Pin::new(&mut this.stream);
        let result = stream.poll_write(cx, buf);
        
        if let Poll::Ready(Ok(_)) = &result {
            this.last_activity = Instant::now();
        }
        
        result
    }
    
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_flush(cx)
    }
    
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl TlsStream {
    /// Read from the TLS stream
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = tokio::io::AsyncReadExt::read(&mut self.stream, buf).await;
        
        if let Ok(size) = result {
            if size > 0 {
                self.last_activity = Instant::now();
                trace!("Read {} bytes from TLS stream", size);
            } else if size == 0 {
                debug!("Read EOF from TLS stream");
            }
        }
        
        result
    }
    
    /// Write to the TLS stream
    pub async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let result = tokio::io::AsyncWriteExt::write(&mut self.stream, buf).await;
        
        if let Ok(size) = result {
            if size > 0 {
                self.last_activity = Instant::now();
                trace!("Wrote {} bytes to TLS stream", size);
            }
        }
        
        result
    }
    
    /// Flush the TLS stream
    pub async fn flush(&mut self) -> io::Result<()> {
        tokio::io::AsyncWriteExt::flush(&mut self.stream).await
    }
    
    /// Send a keepalive if necessary
    pub async fn send_keepalive_if_needed(&mut self) -> io::Result<()> {
        const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
        
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_activity);
        
        if elapsed > KEEPALIVE_INTERVAL {
            debug!("Sending TLS keepalive after {} seconds of inactivity", 
                elapsed.as_secs());
            
            // TLS KeepAlive is just a zero-length record, but we'll use a 1-byte message
            let result = self.write(&[0]).await;
            match result {
                Ok(_) => {
                    // Flush to ensure the keepalive is sent immediately
                    self.flush().await?;
                    debug!("TLS keepalive sent successfully");
                },
                Err(e) => {
                    debug!("Failed to send TLS keepalive: {}", e);
                    return Err(e);
                }
            }
        }
        
        Ok(())
    }
}

/// TLS server stream
pub struct TlsServerStream {
    pub(crate) stream: ServerTlsStream<TcpStream>,
}

impl AsyncRead for TlsServerStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsServerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_write(cx, buf)
    }
    
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_flush(cx)
    }
    
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl TlsServerStream {
    /// Read from the TLS stream
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        tokio::io::AsyncReadExt::read(&mut self.stream, buf).await
    }
    
    /// Write to the TLS stream
    pub async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        tokio::io::AsyncWriteExt::write(&mut self.stream, buf).await
    }
    
    /// Flush the TLS stream
    pub async fn flush(&mut self) -> io::Result<()> {
        tokio::io::AsyncWriteExt::flush(&mut self.stream).await
    }
} 