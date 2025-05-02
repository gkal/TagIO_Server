#![allow(dead_code)]
use anyhow::{Context, Result};
use std::mem::zeroed;
use windows::Win32::Graphics::Gdi::{
    CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, BitBlt, 
    GetDIBits, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
    SRCCOPY, HDC, HBITMAP,
};
use windows::Win32::UI::WindowsAndMessaging::GetDesktopWindow;
use windows::Win32::Graphics::Gdi::{GetWindowDC, ReleaseDC};
use image::{ImageBuffer, Rgba, DynamicImage};

use crate::network_speed::QualityLevel;

pub struct ScreenCapture {
    desktop_dc: HDC,
    memory_dc: HDC,
    bitmap: HBITMAP,
    width: i32,
    height: i32,
}

impl ScreenCapture {
    pub fn new() -> Result<Self> {
        unsafe {
            // Get desktop window and its device context
            let desktop_window = GetDesktopWindow();
            let desktop_dc = GetWindowDC(desktop_window);
            
            // Get screen dimensions
            let width = windows::Win32::UI::WindowsAndMessaging::GetSystemMetrics(
                windows::Win32::UI::WindowsAndMessaging::SM_CXSCREEN
            );
            let height = windows::Win32::UI::WindowsAndMessaging::GetSystemMetrics(
                windows::Win32::UI::WindowsAndMessaging::SM_CYSCREEN
            );
            
            // Create compatible memory DC and bitmap
            let memory_dc = CreateCompatibleDC(desktop_dc);
            let bitmap = CreateCompatibleBitmap(desktop_dc, width, height);
            SelectObject(memory_dc, bitmap);
            
            Ok(Self {
                desktop_dc,
                memory_dc,
                bitmap,
                width,
                height,
            })
        }
    }
    
    pub fn capture(&self) -> Result<ImageBuffer<Rgba<u8>, Vec<u8>>> {
        unsafe {
            // Copy screen to memory bitmap
            let _ = BitBlt(
                self.memory_dc,
                0, 0,
                self.width, self.height,
                self.desktop_dc,
                0, 0,
                SRCCOPY,
            );
            
            // Set up bitmap info
            let mut bitmap_info: BITMAPINFO = zeroed();
            bitmap_info.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
            bitmap_info.bmiHeader.biWidth = self.width;
            bitmap_info.bmiHeader.biHeight = -self.height; // Negative height for top-down
            bitmap_info.bmiHeader.biPlanes = 1;
            bitmap_info.bmiHeader.biBitCount = 32;
            bitmap_info.bmiHeader.biCompression = BI_RGB.0;
            
            // Allocate buffer for pixel data
            let size = (self.width * self.height * 4) as usize;
            let mut buffer = vec![0u8; size];
            
            // Get bitmap bits
            let result = GetDIBits(
                self.memory_dc,
                self.bitmap,
                0,
                self.height as u32,
                Some(buffer.as_mut_ptr() as _),
                &mut bitmap_info,
                DIB_RGB_COLORS,
            );
            
            if result == 0 {
                return Err(anyhow::anyhow!("GetDIBits failed"));
            }
            
            // Create ImageBuffer (note: Windows uses BGRA, we need to convert to RGBA)
            let mut image_buffer = ImageBuffer::new(self.width as u32, self.height as u32);
            for y in 0..self.height as u32 {
                for x in 0..self.width as u32 {
                    let i = ((y * self.width as u32) + x) as usize * 4;
                    let b = buffer[i];
                    let g = buffer[i + 1];
                    let r = buffer[i + 2];
                    let a = buffer[i + 3];
                    image_buffer.put_pixel(x, y, Rgba([r, g, b, a]));
                }
            }
            
            Ok(image_buffer)
        }
    }
}

impl Drop for ScreenCapture {
    fn drop(&mut self) {
        unsafe {
            DeleteObject(self.bitmap);
            DeleteDC(self.memory_dc);
            ReleaseDC(GetDesktopWindow(), self.desktop_dc);
        }
    }
}

// Function to compress an image using JPEG compression
pub fn compress_image(
    image: &ImageBuffer<Rgba<u8>, Vec<u8>>, 
    quality: u8
) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buffer, quality);
    encoder.encode(
        image.as_raw(),
        image.width(),
        image.height(),
        image::ColorType::Rgba8.into(),
    ).context("Failed to encode image as JPEG")?;
    
    Ok(buffer)
}

// New function to resize and compress an image based on quality level
pub fn process_image_with_quality(
    image: &ImageBuffer<Rgba<u8>, Vec<u8>>,
    quality_level: &QualityLevel
) -> Result<(Vec<u8>, u32, u32)> {
    // Get scale factor and JPEG quality from quality level
    let scale = quality_level.scale_factor();
    let jpeg_quality = quality_level.jpeg_quality();
    
    // Calculate new dimensions
    let new_width = (image.width() as f32 * scale) as u32;
    let new_height = (image.height() as f32 * scale) as u32;
    
    // If scale is 1.0, don't resize
    if scale >= 0.99 {
        let compressed = compress_image(image, jpeg_quality)?;
        return Ok((compressed, image.width(), image.height()));
    }
    
    // Convert to DynamicImage and resize
    let dynamic_image = DynamicImage::ImageRgba8(image.clone());
    let resized = dynamic_image.resize(
        new_width, 
        new_height, 
        image::imageops::FilterType::Triangle
    );
    
    // Convert back to RGBA8
    let resized_rgba8 = resized.to_rgba8();
    
    // Compress the resized image
    let compressed = compress_image(&resized_rgba8, jpeg_quality)?;
    
    Ok((compressed, new_width, new_height))
} 