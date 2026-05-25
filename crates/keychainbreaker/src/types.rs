//! Public record types extracted from a keychain.
//!
//! All four types mirror the Go library's `types.go` field for field. Each
//! `Password` / `Data` / `Subject` / etc. is exposed both as raw bytes (for
//! programmatic use) and as multiple encoded representations (for the JSON
//! dump shipped by the CLI). The encoded fields are populated by the
//! extraction methods on `Keychain`; on a locked or partially-unlocked
//! keychain they remain empty.

#[cfg(feature = "serde")]
use serde::Serialize;
use time::OffsetDateTime;

#[cfg(feature = "serde")]
const fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

/// A generic password record (services, applications, custom items).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct GenericPassword {
    /// Service identifier (FourCC attribute `svce`).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub service: String,

    /// Account identifier (FourCC attribute `acct`).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub account: String,

    /// Raw decrypted password bytes. `None` when locked or when `try_unlock`
    /// could not produce a key for this record.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub password: Option<Vec<u8>>,

    /// Decrypted password interpreted as UTF-8. Empty when not decrypted or
    /// when the bytes are not valid UTF-8.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "password", skip_serializing_if = "String::is_empty")
    )]
    pub plain_password: String,

    /// Decrypted password as lowercase hex.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub hex_password: String,

    /// Decrypted password as standard base64.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub base64_password: String,

    /// Free-form description.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub description: String,

    /// Free-form comment.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub comment: String,

    /// Creator FourCC (e.g. `mD4k`).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub creator: String,

    /// Type FourCC (e.g. `note`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", skip_serializing_if = "String::is_empty")
    )]
    pub type_: String,

    /// Display name shown in Keychain Access.app.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub print_name: String,

    /// Alternate name (uncommon).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub alias: String,

    /// Creation timestamp.
    #[cfg_attr(
        feature = "serde",
        serde(
            with = "time::serde::rfc3339::option",
            skip_serializing_if = "Option::is_none"
        )
    )]
    pub created: Option<OffsetDateTime>,

    /// Last-modified timestamp.
    #[cfg_attr(
        feature = "serde",
        serde(
            with = "time::serde::rfc3339::option",
            skip_serializing_if = "Option::is_none"
        )
    )]
    pub modified: Option<OffsetDateTime>,
}

/// An internet password record (web sites, mail servers, file shares).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct InternetPassword {
    /// Server hostname or IP.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub server: String,

    /// Account / username.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub account: String,

    /// Raw decrypted password bytes. `None` when locked or undecryptable.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub password: Option<Vec<u8>>,

    /// Decrypted password interpreted as UTF-8.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "password", skip_serializing_if = "String::is_empty")
    )]
    pub plain_password: String,

    /// Decrypted password as lowercase hex.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub hex_password: String,

    /// Decrypted password as standard base64.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub base64_password: String,

    /// Optional authentication realm.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub security_domain: String,

    /// Protocol FourCC (e.g. `htps`, `smb `).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub protocol: String,

    /// Authentication type FourCC.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub auth_type: String,

    /// Port number (0 when not specified).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_zero_u32"))]
    pub port: u32,

    /// URL path component.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub path: String,

    /// Free-form description.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub description: String,

    /// Free-form comment.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub comment: String,

    /// Creator FourCC.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub creator: String,

    /// Type FourCC.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", skip_serializing_if = "String::is_empty")
    )]
    pub type_: String,

    /// Display name.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub print_name: String,

    /// Alternate name.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub alias: String,

    /// Creation timestamp.
    #[cfg_attr(
        feature = "serde",
        serde(
            with = "time::serde::rfc3339::option",
            skip_serializing_if = "Option::is_none"
        )
    )]
    pub created: Option<OffsetDateTime>,

    /// Last-modified timestamp.
    #[cfg_attr(
        feature = "serde",
        serde(
            with = "time::serde::rfc3339::option",
            skip_serializing_if = "Option::is_none"
        )
    )]
    pub modified: Option<OffsetDateTime>,
}

/// A private-key record. `data` is the decrypted PKCS#8 key material.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct PrivateKey {
    /// Name extracted from the first 12 bytes of decrypted key material.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub name: String,

    /// Raw decrypted key bytes (PKCS#8). Empty when locked or undecryptable.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub data: Vec<u8>,

    /// Decrypted key bytes as lowercase hex.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub data_hex: String,

    /// Decrypted key bytes as standard base64.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub data_base64: String,

    /// Display name.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub print_name: String,

    /// Apple key label.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub label: String,

    /// CSSM key class (private/public/symmetric).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_zero_u32"))]
    pub key_class: u32,

    /// CSSM key type (RSA, ECC, etc.).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_zero_u32"))]
    pub key_type: u32,

    /// Key size in bits.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_zero_u32"))]
    pub key_size: u32,
}

/// An X.509 certificate record. Certificates are not encrypted at rest;
/// `data` is always populated when the keychain is opened successfully.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct Certificate {
    /// Raw DER-encoded certificate bytes.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub data: Vec<u8>,

    /// Certificate bytes as lowercase hex.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub data_hex: String,

    /// Certificate bytes as standard base64.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub data_base64: String,

    /// Certificate type code.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "type", skip_serializing_if = "is_zero_u32")
    )]
    pub type_: u32,

    /// Certificate encoding code.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_zero_u32"))]
    pub encoding: u32,

    /// Display name (typically the subject CN).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub print_name: String,

    /// Raw DER-encoded subject DN.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub subject: Vec<u8>,

    /// Subject DN as lowercase hex.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub subject_hex: String,

    /// Raw DER-encoded issuer DN.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub issuer: Vec<u8>,

    /// Issuer DN as lowercase hex.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub issuer_hex: String,

    /// Raw serial number bytes.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub serial: Vec<u8>,

    /// Serial number as lowercase hex.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "String::is_empty"))]
    pub serial_hex: String,
}
