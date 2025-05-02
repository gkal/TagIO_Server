use log::{Record, Metadata, LevelFilter};
use std::net::IpAddr;
use std::str::FromStr;

// Function to check if a log message contains a localhost IP
pub fn contains_localhost(message: &str) -> bool {
    message.contains("127.0.0.1") || 
    message.contains("localhost") ||
    // Also check for IPv6 localhost
    message.contains("::1")
}

// Check if an IP address string represents localhost
pub fn is_localhost_ip(ip_str: &str) -> bool {
    if let Ok(ip) = IpAddr::from_str(ip_str) {
        ip.is_loopback()
    } else {
        // Check for common localhost strings
        ip_str == "localhost" || ip_str.starts_with("127.")
    }
}

// Extract any IP address from a log message
pub fn extract_ip(message: &str) -> Option<String> {
    // Common IP address patterns
    let patterns = [
        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", // IPv4
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", // IPv6
        r"\blocalhost\b" // Literal localhost
    ];
    
    for pattern in patterns {
        if let Some(captures) = regex::Regex::new(pattern)
            .ok()
            .and_then(|re| re.captures(message)) {
            if let Some(m) = captures.get(0) {
                return Some(m.as_str().to_string());
            }
        }
    }
    None
}

// Custom logger that filters out localhost messages
pub struct LocalhostFilter {
    inner: env_logger::Logger,
}

impl log::Log for LocalhostFilter {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.inner.enabled(metadata)
    }
    
    fn log(&self, record: &Record) {
        // Skip any logs containing localhost references
        let message = format!("{}", record.args());
        
        // Check for localhost in the message
        if contains_localhost(&message) {
            return;
        }
        
        // Extract IP and check if it's localhost
        if let Some(ip) = extract_ip(&message) {
            if is_localhost_ip(&ip) {
                return;
            }
        }
        
        // Forward to inner logger
        self.inner.log(record);
    }
    
    fn flush(&self) {
        self.inner.flush();
    }
}

// Initialize with our filter
pub fn init(log_level: Option<LevelFilter>) -> Result<(), log::SetLoggerError> {
    let level = log_level.unwrap_or(LevelFilter::Info);
    
    let env_logger = env_logger::Builder::new()
        .format(|buf, record| {
            use std::io::Write;
            writeln!(buf, "[ T ] {} | {}", record.level(), record.args())
        })
        .filter(None, level)
        .build();
    
    let logger = LocalhostFilter { inner: env_logger };
    
    log::set_boxed_logger(Box::new(logger))?;
    log::set_max_level(level);
    
    Ok(())
} 