//! `keychainbreaker` command-line tool.

#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a CLI binary legitimately writes to stdout/stderr"
)]

mod cli;
mod commands;
mod logger;
mod output;

use clap::Parser;

fn main() -> anyhow::Result<()> {
    let parsed = cli::Cli::parse();
    match parsed.command {
        cli::Command::Dump => commands::dump::run(&parsed.global),
        cli::Command::Hash => commands::hash::run(&parsed.global),
        cli::Command::Version => commands::version::run(),
    }
}
