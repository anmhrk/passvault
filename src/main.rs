mod cli;
mod errors;
mod crypto;
mod db;

use clap::Parser;
use cli::Cli;

fn main() {
    let cli = Cli::parse();
}
