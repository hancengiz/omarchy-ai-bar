use clap::{Parser, Subcommand};
use serde_json::json;

#[derive(Debug, Parser)]
#[command(name = "omarchy-ai-bar")]
#[command(about = "Omarchy-native AI provider usage monitoring")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print application version information.
    Version {
        /// Emit a machine-readable JSON object.
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    if let Some(Command::Version { json: as_json }) = cli.command {
        if as_json {
            println!(
                "{}",
                json!({
                    "name": env!("CARGO_PKG_NAME"),
                    "version": env!("CARGO_PKG_VERSION"),
                })
            );
        } else {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        }
    }
}
