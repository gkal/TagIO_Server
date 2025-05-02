// Dummy implementation of cairo-sys-rs
// This is used to avoid requiring GUI dependencies for the server build

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

// Export dummy types to provide the expected interface
pub type cairo_bool_t = i32;
pub type cairo_status_t = i32;
pub type cairo_content_t = i32;
pub type cairo_format_t = i32;

// Define essential structs
#[derive(Debug, Copy, Clone)]
pub struct cairo_t(pub *mut std::ffi::c_void);

#[derive(Debug, Copy, Clone)]
pub struct cairo_surface_t(pub *mut std::ffi::c_void);

// Safe dummy implementation
unsafe impl Send for cairo_t {}
unsafe impl Sync for cairo_t {} 