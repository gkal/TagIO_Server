mod app;
mod relay_client;
mod ui;
mod tls;

use iced::{Application, Settings};
use crate::app::App;
use crate::ui::TagioUI;

fn main() -> iced::Result {
    // Initialize the runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime");
    
    // Create the application
    let (app, _ui_tx) = App::new();
    
    // Initialize UI
    TagioUI::new(app).run(Settings::default())
} 