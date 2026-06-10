//! Parse and decrypt macOS Keychain files (`login.keychain-db`).
//!
//! This crate is a Rust port of the Go library at
//! <https://github.com/moond4rk/keychainbreaker>.
//!
//! ## Quick start
//!
//! ```no_run
//! use keychainbreaker::{Credential, Keychain};
//!
//! # fn main() -> keychainbreaker::Result<()> {
//! let mut kc = Keychain::open_file("/path/to/login.keychain-db")?;
//! kc.unlock(Credential::password("hunter2"))?;
//! for entry in kc.generic_passwords()? {
//!     if let Some(pw) = &entry.password {
//!         println!(
//!             "{}@{}: {}",
//!             entry.account,
//!             entry.service,
//!             String::from_utf8_lossy(pw)
//!         );
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! [`Keychain::password_hash`] can be called without unlock to export a
//! hashcat-mode-23100 / John-the-Ripper hash for offline cracking.

mod crypto;
mod error;
mod keychain;
mod logger;
mod open;
mod parse;
mod record;
mod schema;
mod tables;
mod types;
mod unlock;

pub use crate::error::{Error, Result};
pub use crate::keychain::Keychain;
pub use crate::logger::{Logger, NopLogger};
pub use crate::open::KeychainBuilder;
pub use crate::types::{Certificate, GenericPassword, InternetPassword, PrivateKey};
pub use crate::unlock::Credential;
