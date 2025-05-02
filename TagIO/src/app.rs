use tokio::sync::mpsc;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::time::Duration;

// Import our relay client module
use crate::relay_client::{RelayClient, RelayEvent};

// Current state of connection
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Listening,
    Failed(String),
}

// Application state shared between UI thread and connection thread
pub struct AppState {
    pub connection_state: ConnectionState,
    pub tagio_id: String,
    pub remote_id: Option<String>,
    pub remote_ip: Option<String>,
    pub pending_request: Option<String>,
    pub pending_request_ip: Option<String>,
    pub error_message: Option<String>,
}

// Messages sent to the app UI from the connection thread
pub enum AppMessage {
    ConnectionStateChanged(ConnectionState),
    IncomingConnectionRequest { 
        from_id: String,
        from_ip: Option<String>,
    },
    ConnectionAccepted { 
        remote_id: String,
        remote_ip: Option<String>,
    },
    ConnectionRejected { remote_id: String },
    ErrorOccurred { message: String },
}

pub struct App {
    state: Arc<Mutex<AppState>>,
    relay_cmd_tx: mpsc::Sender<RelayCommand>,
    ui_rx: mpsc::Receiver<AppMessage>,
}

enum RelayCommand {
    Connect { target_id: String },
    AcceptConnection { from_id: String },
    RejectConnection { from_id: String },
    Disconnect,
}

impl App {
    pub fn new() -> (Self, mpsc::Sender<AppMessage>) {
        // Generate a unique TagIO ID for this instance
        let tagio_id = format!("tagio-{}", Uuid::new_v4().to_string().split('-').next().unwrap());
        
        // Create initial app state
        let state = Arc::new(Mutex::new(AppState {
            connection_state: ConnectionState::Disconnected,
            tagio_id,
            remote_id: None,
            remote_ip: None,
            pending_request: None,
            pending_request_ip: None,
            error_message: None,
        }));
        
        // Create channels for communication
        let (ui_tx, ui_rx) = mpsc::channel::<AppMessage>(100);
        let (relay_cmd_tx, relay_cmd_rx) = mpsc::channel::<RelayCommand>(100);
        
        // Spawn background task to handle relay connection
        let state_clone = state.clone();
        let ui_tx_clone = ui_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_relay_connection(
                state_clone, 
                relay_cmd_rx, 
                ui_tx_clone
            ).await {
                eprintln!("Relay connection error: {}", e);
            }
        });
        
        (Self {
            state,
            relay_cmd_tx,
            ui_rx,
        }, ui_tx)
    }
    
    // Get the current app state
    pub fn state(&self) -> Arc<Mutex<AppState>> {
        self.state.clone()
    }
    
    // Process UI events
    pub fn process_ui_events(&mut self) {
        // Process any pending UI events
        while let Ok(message) = self.ui_rx.try_recv() {
            match message {
                AppMessage::ConnectionStateChanged(state) => {
                    self.state.lock().unwrap().connection_state = state;
                }
                AppMessage::IncomingConnectionRequest { from_id, from_ip } => {
                    let mut state = self.state.lock().unwrap();
                    state.pending_request = Some(from_id);
                    state.pending_request_ip = from_ip;
                    // Show connection request dialog here
                }
                AppMessage::ConnectionAccepted { remote_id, remote_ip } => {
                    let mut state = self.state.lock().unwrap();
                    state.remote_id = Some(remote_id);
                    state.remote_ip = remote_ip;
                    state.connection_state = ConnectionState::Connected;
                    // Start streaming here using remote_ip if available
                }
                AppMessage::ConnectionRejected { remote_id } => {
                    let mut state = self.state.lock().unwrap();
                    state.connection_state = ConnectionState::Disconnected;
                    state.error_message = Some(format!("Connection rejected by {}", remote_id));
                }
                AppMessage::ErrorOccurred { message } => {
                    let mut state = self.state.lock().unwrap();
                    state.error_message = Some(message.clone());
                    state.connection_state = ConnectionState::Failed(message);
                }
            }
        }
    }
    
    // Connect to remote peer
    pub async fn connect_to_peer(&self, remote_id: &str) -> anyhow::Result<()> {
        self.relay_cmd_tx.send(RelayCommand::Connect {
            target_id: remote_id.to_string(),
        }).await?;
        Ok(())
    }
    
    // Accept incoming connection
    pub async fn accept_connection(&self, from_id: &str) -> anyhow::Result<()> {
        self.relay_cmd_tx.send(RelayCommand::AcceptConnection {
            from_id: from_id.to_string(),
        }).await?;
        Ok(())
    }
    
    // Reject incoming connection
    pub async fn reject_connection(&self, from_id: &str) -> anyhow::Result<()> {
        self.relay_cmd_tx.send(RelayCommand::RejectConnection {
            from_id: from_id.to_string(),
        }).await?;
        Ok(())
    }
    
    // Disconnect from current session
    pub async fn disconnect(&self) -> anyhow::Result<()> {
        self.relay_cmd_tx.send(RelayCommand::Disconnect).await?;
        Ok(())
    }
}

// Background task handling relay connection and events
async fn handle_relay_connection(
    state: Arc<Mutex<AppState>>,
    mut cmd_rx: mpsc::Receiver<RelayCommand>,
    ui_tx: mpsc::Sender<AppMessage>,
) -> anyhow::Result<()> {
    // Get TagIO ID from state
    let tagio_id = {
        let state = state.lock().unwrap();
        state.tagio_id.clone()
    };
    
    // Connect to relay server
    let mut relay_client = match RelayClient::connect(&tagio_id, None).await {
        Ok(client) => client,
        Err(e) => {
            let error_msg = format!("Failed to connect to relay server: {}", e);
            ui_tx.send(AppMessage::ErrorOccurred { message: error_msg }).await?;
            return Err(e);
        }
    };
    
    // Update UI state to listening
    ui_tx.send(AppMessage::ConnectionStateChanged(ConnectionState::Listening)).await?;
    
    // Spawn task to handle relay events
    let ui_tx_clone = ui_tx.clone();
    let mut relay_event_task = tokio::spawn(async move {
        while let Some(event) = relay_client.next_event().await {
            match event {
                RelayEvent::ConnectionRequest { from_id, from_ip } => {
                    ui_tx_clone.send(AppMessage::IncomingConnectionRequest { 
                        from_id, 
                        from_ip 
                    }).await.ok();
                }
                RelayEvent::ConnectionAccepted { from_id, remote_ip } => {
                    ui_tx_clone.send(AppMessage::ConnectionAccepted { 
                        remote_id: from_id,
                        remote_ip: remote_ip,
                    }).await.ok();
                }
                RelayEvent::ConnectionRejected { from_id } => {
                    ui_tx_clone.send(AppMessage::ConnectionRejected { 
                        remote_id: from_id 
                    }).await.ok();
                }
            }
        }
    });
    
    // Handle commands from the UI
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            RelayCommand::Connect { target_id } => {
                // Update UI to connecting state
                ui_tx.send(AppMessage::ConnectionStateChanged(ConnectionState::Connecting)).await?;
                
                // Request connection through relay
                match relay_client.request_connection(&target_id).await {
                    Ok(true) => {
                        // Connection request sent, wait for acceptance
                        // The relay event task will handle the response
                    }
                    Ok(false) => {
                        // Connection request failed
                        ui_tx.send(AppMessage::ErrorOccurred { 
                            message: format!("Failed to connect to {}", target_id) 
                        }).await?;
                    }
                    Err(e) => {
                        // Error occurred
                        ui_tx.send(AppMessage::ErrorOccurred { 
                            message: format!("Connection error: {}", e) 
                        }).await?;
                    }
                }
            }
            
            RelayCommand::AcceptConnection { from_id } => {
                // Accept the connection
                if let Err(e) = relay_client.accept_connection(&from_id).await {
                    ui_tx.send(AppMessage::ErrorOccurred { 
                        message: format!("Failed to accept connection: {}", e) 
                    }).await?;
                } else {
                    // Update state
                    ui_tx.send(AppMessage::ConnectionAccepted { 
                        remote_id: from_id,
                        remote_ip: None
                    }).await?;
                }
            }
            
            RelayCommand::RejectConnection { from_id } => {
                // Reject the connection
                if let Err(e) = relay_client.reject_connection(&from_id).await {
                    ui_tx.send(AppMessage::ErrorOccurred { 
                        message: format!("Failed to reject connection: {}", e) 
                    }).await?;
                }
            }
            
            RelayCommand::Disconnect => {
                // Just update the UI state - the connection will be dropped
                // when this function returns
                ui_tx.send(AppMessage::ConnectionStateChanged(ConnectionState::Disconnected)).await?;
                break;
            }
        }
    }
    
    // Cancel the relay event task
    relay_event_task.abort();
    
    Ok(())
} 