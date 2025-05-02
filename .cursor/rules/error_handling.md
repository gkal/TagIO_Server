# TagIO Relay Server - Error Handling and Code Patterns

This file documents error handling patterns and code conventions for the TagIO Relay Server.

## Error Handling Patterns

### Network Operation Timeouts

All network operations must have timeouts:

```rust
// Correct - with timeout
match tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut buf)).await {
    Ok(result) => {
        if let Err(e) = result {
            println!("Error reading data: {}", e);
            return Err(e);
        }
    },
    Err(_) => {
        println!("Timeout reading data");
        return Err(io::Error::new(io::ErrorKind::TimedOut, "Read timeout"));
    }
}

// Incorrect - no timeout
let result = reader.read_exact(&mut buf).await; // Don't do this
```

### Proper Error Context

Use `anyhow` for error context:

```rust
// Correct - with context
let listener = TcpListener::bind(&addr).await
    .map_err(|e| anyhow!("Failed to bind to {}: {}", addr, e))?;

// Incorrect - no context
let listener = TcpListener::bind(&addr).await?; // Don't do this
```

### Connection Handling

```rust
// Correct pattern for client handling
tokio::spawn(async move {
    if let Err(e) = handle_client(socket, addr, clients.clone()).await {
        eprintln!("Error handling client {}: {}", addr, e);
    }
});
```

## Code Conventions

### Consistent Naming

- Use `snake_case` for variables and functions
- Prefix private methods with `_`
- Use descriptive names for public functions

### Structured Messages

Protocol message construction:

```rust
// Message format example
let mut msg = Vec::new();
msg.extend_from_slice(&msg_type.to_be_bytes()); // Message type (u32)
msg.extend_from_slice(&(id_str.len() as u32).to_be_bytes()); // Length
msg.extend_from_slice(id_str.as_bytes()); // Payload
```

### Resource Management

```rust
// Proper client cleanup
let mut clients_map = clients.lock().await;
clients_map.remove(&client_id);
```

## Testing Patterns

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_connection_handling() {
        // Test setup
        // ...
        
        // Assertions
        assert!(result.is_ok());
    }
}
``` 