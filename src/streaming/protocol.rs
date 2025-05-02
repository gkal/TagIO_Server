use serde::{Serialize, Deserialize};

// Protocol message types
#[derive(Serialize, Deserialize, Debug)]
pub enum ServerMessage {
    ScreenFrame {
        data: Vec<u8>,
        width: u32,
        height: u32,
        timestamp: u64,
    },
    NetworkStats {
        speed: u64,
        quality_level: String,
    },
    Heartbeat {
        timestamp: u64,
    },
    PingResponse {
        request_timestamp: u64,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientMessage {
    MouseMove { x: i32, y: i32 },
    MouseClick { x: i32, y: i32, button: MouseButton, down: bool },
    KeyEvent { key_code: u32, down: bool },
    Heartbeat,
    PingRequest {
        timestamp: u64,
    },
}

// Re-export for use in input and other modules
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
} 