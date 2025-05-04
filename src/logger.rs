use log::LevelFilter;
use std::path::PathBuf;

/// Initialize the logger
pub fn setup_logger(level: LevelFilter, log_file: Option<PathBuf>) -> Result<(), fern::InitError> {
    let mut builder = fern::Dispatch::new()
        .format(|out, message, record| {
            // Format level - trim ERROR to ERRO
            let level_str = match record.level() {
                log::Level::Error => "ERRO".to_string(),
                _ => record.level().to_string()
            };
            
            out.finish(format_args!(
                "[T] {} {} {}",
                chrono::Local::now().format("%a %d/%m/%Y %H:%M:%S"),
                level_str,
                message
            ))
        })
        .level(level);
    
    // Log to stdout
    builder = builder.chain(std::io::stdout());
    
    // Log to file if specified
    if let Some(log_file) = log_file {
        builder = builder.chain(fern::log_file(log_file)?);
    }
    
    // Apply configuration
    builder.apply()?;
    
    Ok(())
} 