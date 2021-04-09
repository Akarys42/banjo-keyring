mod logging;
mod keyblock;
mod utils;
mod debug;

#[macro_use]
extern crate clap;

use clap::{App, SubCommand};
use crate::logging::init_cli_logging;
use log::{debug, warn, LevelFilter};

fn main() {
    let cli_yaml = load_yaml!("cli-definition.yaml");
    let app = App::from_yaml(cli_yaml);


    // Add debug command if required.
    #[cfg(feature = "enable_debug")]
    let debug_cli_yaml = load_yaml!("cli-debug-subcommand.yaml");
    #[cfg(feature = "enable_debug")]
    let app = app.subcommand(SubCommand::from_yaml(debug_cli_yaml));

    let matches = app.get_matches();

    init_cli_logging(
        if matches.is_present("verbose") {LevelFilter::Debug} else {LevelFilter::Info}
    ).expect("Failed to initialize logging.");

    debug!("Logging successfully initialized.");
    #[cfg(feature = "enable_debug")]
    warn!("Debug mode is enabled! NOT SUITABLE FOR PRODUCTION.");
}
