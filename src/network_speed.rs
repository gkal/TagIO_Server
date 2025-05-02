#![allow(dead_code)]
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};

// Number of samples to keep for calculating average
const SPEED_SAMPLE_COUNT: usize = 10;

// Speed thresholds in bytes per second
pub const HIGH_SPEED_THRESHOLD: u64 = 1_000_000;    // 1 MB/s
pub const MEDIUM_SPEED_THRESHOLD: u64 = 300_000;    // 300 KB/s
pub const LOW_SPEED_THRESHOLD: u64 = 100_000;       // 100 KB/s

// Quality levels for image compression
pub enum QualityLevel {
    High,    // 90% quality, full resolution
    Medium,  // 80% quality, 80% resolution
    Low,     // 70% quality, 60% resolution
    VeryLow, // 60% quality, 40% resolution
}

impl QualityLevel {
    pub fn jpeg_quality(&self) -> u8 {
        match self {
            QualityLevel::High => 90,
            QualityLevel::Medium => 80,
            QualityLevel::Low => 70,
            QualityLevel::VeryLow => 60,
        }
    }
    
    pub fn scale_factor(&self) -> f32 {
        match self {
            QualityLevel::High => 1.0,
            QualityLevel::Medium => 0.8,
            QualityLevel::Low => 0.6,
            QualityLevel::VeryLow => 0.4,
        }
    }
}

// Structure to track network speeds
pub struct NetworkSpeedTracker {
    // Circular buffer of speed samples in bytes per second
    samples: Vec<u64>,
    sample_index: usize,
    last_packet_time: Instant,
    bytes_since_last_sample: u64,
    sample_interval: Duration,
    current_quality: QualityLevel,
}

impl NetworkSpeedTracker {
    pub fn new() -> Self {
        Self {
            samples: vec![0; SPEED_SAMPLE_COUNT],
            sample_index: 0,
            last_packet_time: Instant::now(),
            bytes_since_last_sample: 0,
            sample_interval: Duration::from_secs(1),
            current_quality: QualityLevel::Medium, // Start with medium quality
        }
    }
    
    // Record a packet transfer
    pub fn record_packet(&mut self, bytes: u64) {
        self.bytes_since_last_sample += bytes;
        
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_packet_time);
        
        // If enough time has passed, add a new sample
        if elapsed >= self.sample_interval {
            // Calculate bytes per second
            let speed = self.bytes_since_last_sample * 1000 / 
                elapsed.as_millis().max(1) as u64;
            
            // Add to circular buffer
            self.samples[self.sample_index] = speed;
            self.sample_index = (self.sample_index + 1) % SPEED_SAMPLE_COUNT;
            
            // Reset counters
            self.bytes_since_last_sample = 0;
            self.last_packet_time = now;
            
            // Update quality based on new average
            self.update_quality();
        }
    }
    
    // Calculate average speed in bytes per second
    pub fn average_speed(&self) -> u64 {
        let mut sum = 0;
        let mut count = 0;
        
        for &speed in &self.samples {
            if speed > 0 {
                sum += speed;
                count += 1;
            }
        }
        
        if count > 0 {
            sum / count
        } else {
            0
        }
    }
    
    // Get the current quality level
    pub fn get_quality(&self) -> &QualityLevel {
        &self.current_quality
    }
    
    // Update quality level based on network speed
    fn update_quality(&mut self) {
        let avg_speed = self.average_speed();
        
        self.current_quality = if avg_speed >= HIGH_SPEED_THRESHOLD {
            QualityLevel::High
        } else if avg_speed >= MEDIUM_SPEED_THRESHOLD {
            QualityLevel::Medium
        } else if avg_speed >= LOW_SPEED_THRESHOLD {
            QualityLevel::Low
        } else {
            QualityLevel::VeryLow
        };
    }
}

// Thread-safe wrapper for the network speed tracker
pub struct SharedNetworkSpeed {
    tracker: Arc<Mutex<NetworkSpeedTracker>>,
}

impl SharedNetworkSpeed {
    pub fn new() -> Self {
        Self {
            tracker: Arc::new(Mutex::new(NetworkSpeedTracker::new())),
        }
    }
    
    pub fn clone_tracker(&self) -> Arc<Mutex<NetworkSpeedTracker>> {
        self.tracker.clone()
    }
    
    pub fn record_packet(&self, bytes: u64) {
        if let Ok(mut tracker) = self.tracker.lock() {
            tracker.record_packet(bytes);
        }
    }
    
    pub fn get_quality(&self) -> QualityLevel {
        if let Ok(tracker) = self.tracker.lock() {
            match tracker.get_quality() {
                QualityLevel::High => QualityLevel::High,
                QualityLevel::Medium => QualityLevel::Medium,
                QualityLevel::Low => QualityLevel::Low,
                QualityLevel::VeryLow => QualityLevel::VeryLow,
            }
        } else {
            // Default if mutex is poisoned
            QualityLevel::Medium
        }
    }
    
    pub fn average_speed(&self) -> u64 {
        if let Ok(tracker) = self.tracker.lock() {
            tracker.average_speed()
        } else {
            0
        }
    }
} 