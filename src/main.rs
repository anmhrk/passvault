mod cli;
mod errors;
mod crypto;
mod db;

use clap::Parser;
use cli::Cli;
use cli::CliHandler;

fn main() {
    let cli = Cli::parse();
    let handler = CliHandler::new("passman.db").expect("Failed to initialize CLI handler"); 

    if let Err(e) = handler.handle_command(cli) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
