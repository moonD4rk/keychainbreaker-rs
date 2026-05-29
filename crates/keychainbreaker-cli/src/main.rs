//! `keychainbreaker` command-line tool.

// CLI tools legitimately write to stdout/stderr. The library crate keeps
// `print_*` denied; this crate explicitly opts back in for the whole
// binary so individual subcommand files don't each carry the allow.
#![allow(clippy::print_stdout, clippy::print_stderr)]

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
