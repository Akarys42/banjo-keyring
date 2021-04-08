use simplelog::{TermLogger, LevelFilter, ConfigBuilder, TerminalMode, ColorChoice};
use log::SetLoggerError;

/// Initialize the logger for the CLI app
pub fn init_cli_logging(level: LevelFilter) -> Result<(), SetLoggerError> {
    TermLogger::init(
        level,
        ConfigBuilder::new()
            .set_time_level(LevelFilter::Off)
            .set_location_level(LevelFilter::Off)
            .set_target_level(LevelFilter::Off)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto
    )
}