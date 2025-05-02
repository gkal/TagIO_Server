// Sub-modules
mod eframe_app;
mod eframe_ui;
mod eframe_connection;

// Re-exports
pub use eframe_app::TagIOApp;

// GUI functionality
use eframe::egui;
use anyhow::Result;
use tokio::sync::mpsc;
use tokio::task;
use log;
use std::sync::{Arc, Mutex};
use log::debug;

/// Main entry point for the TagIO GUI
pub fn run_gui() -> Result<()> {
    // Initialize the eframe native options with current field names
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([500.0, 400.0])
            .with_resizable(true)
            .with_position([0.0, 0.0]), // Center position will be handled by app
        ..Default::default()
    };

    // Start the GUI application
    eframe::run_native(
        &format!("TagIO v{}", crate::VERSION),
        native_options,
        Box::new(|_cc| Box::new(TagIOApp::default())),
    ).map_err(|e| anyhow::anyhow!("Failed to start GUI: {}", e))?;
    
    Ok(())
}

/// Create a GUI with custom title and return frame_tx and app handle
pub fn create_gui_with_title(title: &str) -> (mpsc::Sender<(Vec<u8>, u32, u32)>, Arc<Mutex<TagIOApp>>) {
    // Create channel for streaming frames
    let (frame_tx, _frame_rx) = mpsc::channel::<(Vec<u8>, u32, u32)>(10);
    
    // Create and initialize the app
    let app = Arc::new(Mutex::new(TagIOApp::default()));
    
    // Configure the app as needed
    {
        let _app_lock = app.lock().unwrap();
        // Set any initial configuration
    }
    
    // Clone app reference for the GUI thread
    let _app_clone = app.clone();
    
    // Make a copy of the title string to avoid lifetime issues
    let title_owned = title.to_string();
    
    // Spawn a thread to run the GUI
    std::thread::spawn(move || {
        let native_options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([500.0, 400.0])
                .with_resizable(true)
                .with_position([0.0, 0.0]), // Center position will be handled by app
            ..Default::default()
        };
        
        // Start the GUI application
        eframe::run_native(
            &format!("TagIO v{} - {}", crate::VERSION, title_owned),
            native_options,
            Box::new(|_cc| Box::new(TagIOApp::default())),
        ).unwrap();
    });
    
    (frame_tx, app)
}

/// Initialize a native window for viewing remote screen
pub async fn init_native_window(
    mut frame_rx: mpsc::Receiver<(Vec<u8>, u32, u32)>
) -> Result<()> {
    log::info!("Initializing native window viewer");
    
    // Spawn a blocking task to handle the GUI
    // This is necessary because GUI code is not async-compatible
    task::spawn_blocking(move || {
        log::info!("Starting native window viewer thread");
        
        // Initialize the viewer window
        let result = create_native_viewer(&mut frame_rx);
        
        if let Err(e) = result {
            log::error!("Error in native viewer: {}", e);
        }
        
        log::info!("Native viewer thread terminated");
    }).await?;
    
    Ok(())
}

// Create a native window for viewing the remote screen
fn create_native_viewer(
    frame_rx: &mut mpsc::Receiver<(Vec<u8>, u32, u32)>
) -> Result<()> {
    // This implementation depends on the platform
    // For Windows, we'd use winit or similar
    // For simplicity, we'll just receive frames and print stats
    log::info!("Native viewer window created (placeholder)");
    
    let mut frame_count = 0;
    let start_time = std::time::Instant::now();
    
    // Process incoming frames
    while let Some((_data, width, height)) = frame_rx.blocking_recv() {
        frame_count += 1;
        
        // Print stats every 100 frames
        if frame_count % 100 == 0 {
            let elapsed = start_time.elapsed().as_secs_f32();
            let fps = frame_count as f32 / elapsed;
            log::info!("Received {} frames ({}x{}) at {:.2} FPS", 
                      frame_count, width, height, fps);
        }
    }
    
    log::info!("Frame stream ended");
    Ok(())
}

// Process frame data - mark data as unused with underscore
#[allow(dead_code)]
async fn process_frame(_data: Vec<u8>, width: u32, height: u32) {
    // TODO: Process the frame data
    debug!("Received frame: {}x{}", width, height);
} 