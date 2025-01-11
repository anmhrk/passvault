mod cli;
mod crypto;
mod db;
mod errors;
mod utils;

use clap::Parser;
use cli::{Cli, CliHandler};

fn main() {
    let cli = Cli::parse();
    let handler = CliHandler::new("passman.db").expect("Failed to initialize CLI handler");

    if let Err(e) = handler.handle_command(cli) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
