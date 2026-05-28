//! Parse and decrypt macOS Keychain files (`login.keychain-db`).
//!
//! This crate is a Rust port of the Go library at
//! <https://github.com/moond4rk/keychainbreaker>. See the design RFCs in
//! `rfcs/` at the repository root for motivation, API design, CLI design,
//! testing strategy, and the encryption algorithm spec.
//!
//! ## Current state — milestone M2
//!
//! M2 ships the internal parsing layer on top of the M1 primitives: binary
//! readers for the keychain file format, the schema-driven `Record`
//! abstraction, and dynamic schema discovery. None of this is exposed
//! publicly — the high-level `Keychain` open / unlock / extraction surface
//! is added in M3.

mod crypto;
mod error;
mod logger;
mod parse;
mod record;
mod schema;
mod tables;
mod types;

pub use crate::error::{Error, Result};
pub use crate::logger::{Logger, NopLogger};
pub use crate::types::{Certificate, GenericPassword, InternetPassword, PrivateKey};
