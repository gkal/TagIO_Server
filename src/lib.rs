// This is just a placeholder library to satisfy Cargo workspace requirements
// The actual HTTP tunnel server implementation is in standalone_server/src/bin/http_tunnel_server.rs

/// A dummy function to satisfy the compiler
pub fn placeholder() -> &'static str {
    "This is a placeholder library for the TagIO workspace"
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
} 