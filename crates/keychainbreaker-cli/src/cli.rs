//! `clap` derive structs for the `keychainbreaker` binary.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "keychainbreaker",
    version,
    about = "Extract credentials from macOS Keychain files",
    long_about = "keychainbreaker extracts credentials, keys, and certificates from \
                  macOS Keychain files (login.keychain-db)."
)]
pub(crate) struct Cli {
    #[command(flatten)]
    pub(crate) global: GlobalArgs,

    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Args, Clone, Debug)]
pub(crate) struct GlobalArgs {
    /// Keychain file path (default: ~/Library/Keychains/login.keychain-db)
    #[arg(short = 'f', long, global = true)]
    pub(crate) file: Option<PathBuf>,

    /// Keychain password (omit to be prompted; `-p ""` is a valid empty password)
    #[arg(short = 'p', long, global = true)]
    pub(crate) password: Option<String>,

    /// Hex-encoded 24-byte master key (with or without `0x` prefix)
    #[arg(short = 'k', long, global = true)]
    pub(crate) key: Option<String>,

    /// Output file path (default: ./keychain_dump.json)
    #[arg(short = 'o', long, global = true)]
    pub(crate) output: Option<PathBuf>,

    /// Print verbose diagnostic output to stderr
    #[arg(short = 'v', long, global = true)]
    pub(crate) verbose: bool,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Export all keychain data to a JSON file
    Dump,
    /// Print password hash for offline cracking (no unlock needed)
    Hash,
    /// Print version information
    Version,
}
