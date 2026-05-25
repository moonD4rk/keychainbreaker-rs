//! Parse and decrypt macOS Keychain files (`login.keychain-db`).
//!
//! This crate is a Rust port of the Go library at
//! <https://github.com/moond4rk/keychainbreaker>. See the design RFCs in
//! `rfcs/` at the repository root for motivation, API design, CLI design,
//! testing strategy, and the encryption algorithm spec.
//!
//! ## Current state — milestone M1
//!
//! M1 ships the foundational pieces: typed errors, the logger trait, the
//! public record types, and the cryptographic primitives. The high-level
//! `Keychain` open / unlock / extraction surface is added in M3.

mod crypto;
mod error;
mod logger;
mod types;

pub use crate::error::{Error, Result};
pub use crate::logger::{Logger, NopLogger};
pub use crate::types::{Certificate, GenericPassword, InternetPassword, PrivateKey};
