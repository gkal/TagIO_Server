// This is a wrapper for the eframe UI implementation

// Import our implementation
mod main_gui_eframe;

use std::env;

fn main() {
    // Check for command line arguments (kept for future UI style support)
    let args: Vec<String> = env::args().collect();
    
    // Process args (reserved for future UI style options)
    for arg in &args {
        if arg == "--windows-ui" || arg == "-w" {
            println!("Note: Windows UI mode is not yet implemented. Using default UI.");
        }
    }
    
    // Start with eframe UI
    println!("Starting TagIO with eframe UI");
    if let Err(e) = main_gui_eframe::main() {
        eprintln!("Error: {}", e);
    }
} 