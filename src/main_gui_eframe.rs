// This file is now a simple entry point that delegates to the modular components
use anyhow::Result;
use tagio::gui;
use tagio::debug_logging;

pub fn main() -> Result<()> {
    // Initialize logging
    debug_logging::init()?;
    
    // Run the GUI
    gui::run_gui()
} 