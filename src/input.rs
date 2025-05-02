#![allow(dead_code)]
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_KEYUP,
    MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE,
    MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEINPUT, VIRTUAL_KEY,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN,
};
use tokio::sync::mpsc;

use crate::streaming::protocol::MouseButton;

/// Handles injecting input events into the system
pub struct InputHandler {
    screen_width: i32,
    screen_height: i32,
}

impl InputHandler {
    pub fn new() -> Self {
        let screen_width = unsafe { GetSystemMetrics(SM_CXSCREEN) };
        let screen_height = unsafe { GetSystemMetrics(SM_CYSCREEN) };
        
        Self {
            screen_width,
            screen_height,
        }
    }
    
    pub fn move_mouse(&mut self, x: i32, y: i32) {
        // Convert coordinates to the 0..65535 range expected by SendInput
        let normalized_x = (x * 65535) / self.screen_width;
        let normalized_y = (y * 65535) / self.screen_height;
        
        let input = INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_0 {
                mi: MOUSEINPUT {
                    dx: normalized_x,
                    dy: normalized_y,
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        
        unsafe {
            SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
        }
    }
    
    pub fn mouse_down(&mut self, x: i32, y: i32, button: MouseButton) {
        // First move to position
        self.move_mouse(x, y);
        
        // Then send button down event
        let flags = match button {
            MouseButton::Left => MOUSEEVENTF_LEFTDOWN,
            MouseButton::Right => MOUSEEVENTF_RIGHTDOWN,
            MouseButton::Middle => MOUSEEVENTF_MIDDLEDOWN,
        };
        
        let input = INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_0 {
                mi: MOUSEINPUT {
                    dx: 0,
                    dy: 0,
                    mouseData: 0,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        
        unsafe {
            SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
        }
    }
    
    pub fn mouse_up(&mut self, x: i32, y: i32, button: MouseButton) {
        // First move to position
        self.move_mouse(x, y);
        
        // Then send button up event
        let flags = match button {
            MouseButton::Left => MOUSEEVENTF_LEFTUP,
            MouseButton::Right => MOUSEEVENTF_RIGHTUP,
            MouseButton::Middle => MOUSEEVENTF_MIDDLEUP,
        };
        
        let input = INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_0 {
                mi: MOUSEINPUT {
                    dx: 0,
                    dy: 0,
                    mouseData: 0,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        
        unsafe {
            SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
        }
    }
    
    pub fn key_down(&mut self, key_code: u32) {
        let input = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(key_code as u16),
                    wScan: 0,
                    dwFlags: windows::Win32::UI::Input::KeyboardAndMouse::KEYBD_EVENT_FLAGS(0),
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        
        unsafe {
            SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
        }
    }
    
    pub fn key_up(&mut self, key_code: u32) {
        let input = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(key_code as u16),
                    wScan: 0,
                    dwFlags: KEYEVENTF_KEYUP,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        
        unsafe {
            SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
        }
    }
}

/// Captures input events from client side to send to server
pub struct InputCapture {
    // Will be expanded in future versions with actual hooks
}

impl InputCapture {
    pub fn new() -> Self {
        Self {}
    }
    
    /// Start listening for input events
    pub fn start(&mut self, _tx: mpsc::Sender<crate::streaming::protocol::ClientMessage>) {
        // Not needed for now - implemented differently in the actual app
    }
} 