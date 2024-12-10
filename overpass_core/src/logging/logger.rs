// ./src/logging/logger.rs

use log::{Level, LevelFilter, Metadata, SetLoggerError};

pub trait Logger {
    fn log(&self, level: &str, message: &str);
}

/// Custom Logger implementation that integrates with the `log` crate.
pub struct CustomLogger;

impl log::Log for CustomLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            println!(
                "[{}] {}: {}",
                record.level(),
                record.target(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

impl Logger for CustomLogger {
    fn log(&self, level: &str, message: &str) {
        let log_level = match level.to_lowercase().as_str() {
            "error" => Level::Error,
            "warn" => Level::Warn,
            "info" => Level::Info,
            "debug" => Level::Debug,
            "trace" => Level::Trace,
            _ => Level::Info,
        };

        log::logger().log(
            &log::Record::builder()
                .level(log_level)
                .target("ovp-client")
                .args(format_args!("{}", message))
                .build(),
        );
    }
}

/// Initializes the custom logger with the given level filter.
pub fn init_logger(level_filter: LevelFilter) -> Result<(), SetLoggerError> {
    static INIT: std::sync::Once = std::sync::Once::new();
    let mut result = Ok(());
    INIT.call_once(|| {
        result = log::set_logger(&CustomLogger).map(|()| log::set_max_level(level_filter));
    });
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::LevelFilter;
    use std::sync::Once;

    static TEST_INIT: Once = Once::new();

    fn setup_test_logger() {
        TEST_INIT.call_once(|| {
            init_logger(LevelFilter::Debug).expect("Failed to initialize logger");
        });
    }

    #[test]
    fn test_logger_log() {
        setup_test_logger();
        let logger = CustomLogger;
        logger.log("info", "This is an info-level log");
        logger.log("debug", "This is a debug-level log");
        logger.log("warn", "This is a warn-level log");
        logger.log("error", "This is an error-level log");
        logger.log("trace", "This is a trace-level log");
    }

    #[test]
    fn test_custom_logger_integration() {
        setup_test_logger();
        log::info!("Testing info log through `log` crate");
        log::debug!("This debug log should not appear");
        log::warn!("Testing warn log through `log` crate");
    }

    #[test]
    fn test_logger_initialization() {
        assert!(init_logger(LevelFilter::Debug).is_ok());
    }
}

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use chrono::Local;

pub trait LogConfig {
    fn log_file(&self) -> &str;
}

pub struct FileLogger {
    config: Arc<Mutex<Box<dyn LogConfig>>>,
}

impl FileLogger {
    pub fn new(config: impl LogConfig + 'static) -> Self {
        Self {
            config: Arc::new(Mutex::new(Box::new(config))),
        }
    }

    /// Logs a message with a specified log level.
    pub fn log(&self, level: &str, message: &str) -> io::Result<()> {
        let config = self.config.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Failed to acquire lock")
        })?;
        let log_file = Path::new(config.log_file());
        if let Some(parent) = log_file.parent() {
            fs::create_dir_all(parent)?; // Ensure directory exists.
        }

        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        let log_entry = format!("[{}][{}] {}\n", timestamp, level.to_uppercase(), message);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)?;
        file.write_all(log_entry.as_bytes())
    }

    /// Convenience methods for different log levels
    pub fn info(&self, message: &str) {
        if let Err(e) = self.log("info", message) {
            eprintln!("Failed to log info message: {}", e);
        }
    }

    pub fn warn(&self, message: &str) {
        if let Err(e) = self.log("warn", message) {
            eprintln!("Failed to log warn message: {}", e);
        }
    }

    pub fn error(&self, message: &str) {
        if let Err(e) = self.log("error", message) {
            eprintln!("Failed to log error message: {}", e);
        }
    }
}
