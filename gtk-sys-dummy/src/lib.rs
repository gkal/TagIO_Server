// Dummy implementation of gtk-sys
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

// Define essential structs
#[derive(Debug, Copy, Clone)]
pub struct GtkWidget(pub *mut std::ffi::c_void);

#[derive(Debug, Copy, Clone)]
pub struct GtkWindow(pub *mut std::ffi::c_void);

// Dummy constants for v3_24 feature
pub const GTK_MAJOR_VERSION: u32 = 3;
pub const GTK_MINOR_VERSION: u32 = 24;
pub const GTK_MICRO_VERSION: u32 = 0;

// Safe dummy implementation
unsafe impl Send for GtkWidget {}
unsafe impl Sync for GtkWidget {} 