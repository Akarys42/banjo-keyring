#[macro_use]
extern crate clap;

use clap::{App, SubCommand};

fn main() {
    let cli_yaml = load_yaml!("cli-definition.yaml");
    let app = App::from_yaml(cli_yaml);


    // Add debug command if required.
    #[cfg(feature = "enable_debug")]
    let debug_cli_yaml = load_yaml!("cli-debug-subcommand.yaml");
    #[cfg(feature = "enable_debug")]
    let app = app.subcommand(SubCommand::from_yaml(debug_cli_yaml));

    app.get_matches();
}
