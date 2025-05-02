use iced::{
    alignment, widget::button, widget::column, widget::container, widget::row, widget::text_input, Alignment, widget::Button, widget::Column,
    widget::Container, Element, Length, Application, Subscription, widget::Text, widget::TextInput,
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use crate::app::{App, ConnectionState};
use crate::relay_client::RelayMessage;

pub struct TagioUI {
    app: App,
    
    // UI state
    connect_button: button::State,
    disconnect_button: button::State,
    accept_button: button::State,
    reject_button: button::State,
    remote_id_input: text_input::State,
    remote_id_value: String,
}

#[derive(Debug, Clone)]
pub enum Message {
    Connect,
    Disconnect,
    AcceptConnection,
    RejectConnection,
    RemoteIdChanged(String),
    Tick,
}

impl TagioUI {
    pub fn new(app: App) -> Self {
        Self {
            app,
            connect_button: button::State::new(),
            disconnect_button: button::State::new(),
            accept_button: button::State::new(),
            reject_button: button::State::new(),
            remote_id_input: text_input::State::new(),
            remote_id_value: String::new(),
        }
    }
    
    pub fn update(&mut self, message: Message) {
        match message {
            Message::Connect => {
                let remote_id = self.remote_id_value.clone();
                if !remote_id.is_empty() {
                    tokio::spawn(async move {
                        if let Err(e) = self.app.connect_to_peer(&remote_id).await {
                            eprintln!("Failed to connect: {}", e);
                        }
                    });
                }
            }
            
            Message::Disconnect => {
                tokio::spawn(async move {
                    if let Err(e) = self.app.disconnect().await {
                        eprintln!("Failed to disconnect: {}", e);
                    }
                });
            }
            
            Message::AcceptConnection => {
                let state = self.app.state();
                let pending_request = {
                    let state = state.lock().unwrap();
                    state.pending_request.clone()
                };
                
                if let Some(from_id) = pending_request {
                    tokio::spawn(async move {
                        if let Err(e) = self.app.accept_connection(&from_id).await {
                            eprintln!("Failed to accept connection: {}", e);
                        }
                    });
                }
            }
            
            Message::RejectConnection => {
                let state = self.app.state();
                let pending_request = {
                    let state = state.lock().unwrap();
                    state.pending_request.clone()
                };
                
                if let Some(from_id) = pending_request {
                    tokio::spawn(async move {
                        if let Err(e) = self.app.reject_connection(&from_id).await {
                            eprintln!("Failed to reject connection: {}", e);
                        }
                    });
                }
            }
            
            Message::RemoteIdChanged(value) => {
                self.remote_id_value = value;
            }
            
            Message::Tick => {
                // Process UI events from the app
                self.app.process_ui_events();
            }
        }
    }
    
    pub fn view(&mut self) -> Element<Message> {
        let state = self.app.state();
        let state_guard = state.lock().unwrap();
        
        // Display the TagIO ID
        let tagio_id = Text::new(format!("Your TagIO ID: {}", state_guard.tagio_id))
            .size(20)
            .width(Length::Fill)
            .horizontal_alignment(alignment::Horizontal::Center);
        
        // Connection status
        let status_text = match &state_guard.connection_state {
            ConnectionState::Disconnected => "Disconnected",
            ConnectionState::Connecting => "Connecting...",
            ConnectionState::Connected => {
                if let Some(ip) = &state_guard.remote_ip {
                    format!("Connected to {} ({})", 
                        state_guard.remote_id.as_deref().unwrap_or("unknown"), ip)
                } else {
                    format!("Connected to {}", 
                        state_guard.remote_id.as_deref().unwrap_or("unknown"))
                }
            },
            ConnectionState::Listening => "Listening for connections",
            ConnectionState::Failed(err) => err,
        };
        
        let status = Text::new(format!("Status: {}", status_text))
            .size(16)
            .width(Length::Fill)
            .horizontal_alignment(alignment::Horizontal::Center);
        
        // Remote ID input field
        let remote_id_input = TextInput::new(
            &mut self.remote_id_input,
            "Enter remote TagIO ID",
            &self.remote_id_value,
            Message::RemoteIdChanged,
        )
        .padding(10)
        .size(16);
        
        // Connect button
        let connect_button = Button::new(
            &mut self.connect_button,
            Text::new("Connect")
                .horizontal_alignment(alignment::Horizontal::Center)
                .size(16),
        )
        .width(Length::Fill)
        .padding(10)
        .on_press(Message::Connect);
        
        // Disconnect button
        let disconnect_button = Button::new(
            &mut self.disconnect_button,
            Text::new("Disconnect")
                .horizontal_alignment(alignment::Horizontal::Center)
                .size(16),
        )
        .width(Length::Fill)
        .padding(10)
        .on_press(Message::Disconnect);
        
        // Control buttons based on connection state
        let control_buttons = match &state_guard.connection_state {
            ConnectionState::Connected => row![disconnect_button].spacing(10),
            _ => row![connect_button].spacing(10),
        };
        
        // Connection request dialog
        let connection_dialog = if self.app.show_connection_dialog {
            let buttons = row![
                button("Accept")
                    .on_press(Message::AcceptConnection)
                    .style(theme::Button::Positive),
                button("Reject")
                    .on_press(Message::RejectConnection)
                    .style(theme::Button::Destructive),
            ]
            .spacing(10);
            
            let request_text = text(format!("Connection request from: {}", self.app.connection_from.unwrap_or_default()));
            
            container(
                column(vec![
                    request_text.into(),
                    buttons.into(),
                ])
                .spacing(10)
                .padding(20)
            )
            .style(theme::Container::Box)
            .into()
        } else {
            container(text(""))
                .width(Length::Fill)
                .height(Length::Shrink)
                .into()
        };
        
        // Main content
        let content = column(vec![
            tagio_id.into(),
            status.into(),
            remote_id_input.into(),
            control_buttons.into(),
            connection_dialog,
        ])
        .spacing(20)
        .padding(20)
        .max_width(800);
        
        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }
    
    pub fn subscription(&self) -> Subscription<Message> {
        // Poll for UI events periodically
        iced::time::every(std::time::Duration::from_millis(100))
            .map(|_| Message::Tick)
    }
} 