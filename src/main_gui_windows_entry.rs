// This is the main entry point for the Windows-styled GUI version
mod main_gui_windows;

fn main() -> anyhow::Result<()> {
    // Call the main function from the Windows GUI version
    main_gui_windows::main()
} 