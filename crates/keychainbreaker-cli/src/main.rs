//! `keychainbreaker` command-line tool.
//!
//! See `rfcs/003-cli-design.md` for the CLI design. This file is currently a
//! skeleton; subcommands will be wired in milestone M4.

// CLI tools legitimately write to stdout/stderr. The library crate keeps
// `print_*` denied; this crate explicitly opts back in.
#![allow(clippy::print_stdout, clippy::print_stderr)]

fn main() -> std::process::ExitCode {
    eprintln!("keychainbreaker: implementation pending (see rfcs/003-cli-design.md)");
    std::process::ExitCode::from(1)
}
