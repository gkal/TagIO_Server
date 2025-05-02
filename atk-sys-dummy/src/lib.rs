// Dummy implementation of atk-sys
// This is used to avoid requiring GUI dependencies for the server build

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

// Export dummy types to provide the expected interface
pub type gint = i32;
pub type guint = u32;
pub type gfloat = f32;
pub type gdouble = f64;
pub type gchar = i8;
pub type guchar = u8;
pub type gboolean = i32;
pub type gpointer = *mut std::ffi::c_void;

// Define essential enums and structs
#[derive(Debug, Copy, Clone)]
pub struct AtkObject(pub *mut std::ffi::c_void);

#[derive(Debug, Copy, Clone)]
pub struct AtkStateSet(pub *mut std::ffi::c_void);

// Safe dummy implementation
unsafe impl Send for AtkObject {}
unsafe impl Sync for AtkObject {} 