//! Error types for the keychain parser and decryptor.

use thiserror::Error;

/// Convenience alias for [`core::result::Result`] with this crate's [`enum@Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// All errors produced by the `keychainbreaker` crate.
#[derive(Debug, Error)]
pub enum Error {
    /// The file header did not start with the expected `kych` magic bytes.
    #[error("invalid keychain signature")]
    InvalidSignature,

    /// A parsing step failed. The message carries a position-tagged reason.
    #[error("parse failed: {0}")]
    ParseFailed(String),

    /// Unlock failed: the supplied password or hex key did not decrypt the
    /// database key. PKCS#7 padding errors during DB-key unwrap are mapped
    /// to this variant rather than [`Error::Cipher`].
    #[error("wrong key or password")]
    WrongKey,

    /// A record extraction method was called before a successful unlock.
    #[error("keychain is locked")]
    Locked,

    /// `Keychain::unlock` was called without a password or hex key.
    #[error("no unlock credential provided")]
    NoCredential,

    /// I/O error from reading the keychain file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Hex decoding failed (e.g. malformed `UnlockOptions::with_key` input).
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),

    /// Low-level cipher or padding failure. Most callers should never see
    /// this directly; see [`Error::WrongKey`] for the unlock-time mapping.
    #[error("cipher: {0}")]
    Cipher(&'static str),
}
