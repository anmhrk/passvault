mod cli;
mod crypto;
mod db;
mod errors;
mod utils;

use clap::Parser;
use cli::{Cli, CliHandler};

fn main() {
    let cli = Cli::parse();
    let db_path = utils::get_db_path().expect("Failed to get database path");
    let handler = CliHandler::new(&db_path).expect("Failed to initialize CLI handler");

    if let Err(e) = handler.handle_command(cli) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
