//! Public record types extracted from a keychain.
//!
//! Each record stores its decrypted secret / binary payload exactly once, as
//! raw bytes. Textual and encoded views (UTF-8, hex, base64) are a presentation
//! concern, not model state: callers read the raw bytes and encode as needed.
//! Under the `serde` feature each type serializes through a private projection
//! that computes those encodings on the fly, so the JSON dump keeps the
//! historical `password`/`hex_password`/`base64_password` shape without the
//! struct carrying redundant copies.

#[cfg(feature = "serde")]
use serde::Serialize;
use time::OffsetDateTime;

/// A generic password record (services, applications, custom items).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(into = "json::GenericPasswordJson"))]
pub struct GenericPassword {
    /// Service identifier (FourCC attribute `svce`).
    pub service: String,
    /// Account identifier (FourCC attribute `acct`).
    pub account: String,
    /// Raw decrypted password bytes. `None` when locked or when the record
    /// could not be decrypted.
    pub password: Option<Vec<u8>>,
    /// Free-form description.
    pub description: String,
    /// Free-form comment.
    pub comment: String,
    /// Creator FourCC (e.g. `mD4k`).
    pub creator: String,
    /// Type FourCC (e.g. `note`).
    pub type_: String,
    /// Display name shown in Keychain Access.app.
    pub print_name: String,
    /// Alternate name (uncommon).
    pub alias: String,
    /// Creation timestamp.
    pub created: Option<OffsetDateTime>,
    /// Last-modified timestamp.
    pub modified: Option<OffsetDateTime>,
}

/// An internet password record (web sites, mail servers, file shares).
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(into = "json::InternetPasswordJson"))]
pub struct InternetPassword {
    /// Server hostname or IP.
    pub server: String,
    /// Account / username.
    pub account: String,
    /// Raw decrypted password bytes. `None` when locked or undecryptable.
    pub password: Option<Vec<u8>>,
    /// Optional authentication realm.
    pub security_domain: String,
    /// Protocol FourCC (e.g. `htps`, `smb `).
    pub protocol: String,
    /// Authentication type FourCC.
    pub auth_type: String,
    /// Port number (0 when not specified).
    pub port: u32,
    /// URL path component.
    pub path: String,
    /// Free-form description.
    pub description: String,
    /// Free-form comment.
    pub comment: String,
    /// Creator FourCC.
    pub creator: String,
    /// Type FourCC.
    pub type_: String,
    /// Display name.
    pub print_name: String,
    /// Alternate name.
    pub alias: String,
    /// Creation timestamp.
    pub created: Option<OffsetDateTime>,
    /// Last-modified timestamp.
    pub modified: Option<OffsetDateTime>,
}

/// A private-key record. `data` is the decrypted PKCS#8 key material.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(into = "json::PrivateKeyJson"))]
pub struct PrivateKey {
    /// Name extracted from the first 12 bytes of decrypted key material.
    pub name: String,
    /// Raw decrypted key bytes (PKCS#8). Empty when locked or undecryptable.
    pub data: Vec<u8>,
    /// Display name.
    pub print_name: String,
    /// Apple key label.
    pub label: String,
    /// CSSM key class (private/public/symmetric).
    pub key_class: u32,
    /// CSSM key type (RSA, ECC, etc.).
    pub key_type: u32,
    /// Key size in bits.
    pub key_size: u32,
}

/// An X.509 certificate record. Certificates are not encrypted at rest;
/// `data` is always populated when the keychain is opened successfully.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(into = "json::CertificateJson"))]
pub struct Certificate {
    /// Raw DER-encoded certificate bytes.
    pub data: Vec<u8>,
    /// Certificate type code.
    pub type_: u32,
    /// Certificate encoding code.
    pub encoding: u32,
    /// Display name (typically the subject CN).
    pub print_name: String,
    /// Raw DER-encoded subject DN.
    pub subject: Vec<u8>,
    /// Raw DER-encoded issuer DN.
    pub issuer: Vec<u8>,
    /// Raw serial number bytes.
    pub serial: Vec<u8>,
}

#[cfg(feature = "serde")]
mod json {
    //! Serialization projections. These mirror the Go CLI's JSON layout:
    //! secrets/blobs are emitted as `*_hex` / `*_base64` (and the UTF-8
    //! `password`) computed from the raw bytes at serialize time, so the public
    //! record types stay free of redundant stored encodings.

    use base64::Engine as _;
    use serde::Serialize;
    use time::OffsetDateTime;

    use super::{Certificate, GenericPassword, InternetPassword, PrivateKey};

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn is_default<T: Default + PartialEq>(v: &T) -> bool {
        *v == T::default()
    }

    /// Expand raw secret bytes into the `(utf8, hex, base64)` triplet the JSON
    /// dump exposes. Absent / empty bytes collapse to three empty strings,
    /// which the `skip_serializing_if` attributes then omit.
    fn encode_secret(bytes: Option<&[u8]>) -> (String, String, String) {
        match bytes {
            Some(b) if !b.is_empty() => (
                String::from_utf8_lossy(b).into_owned(),
                hex::encode(b),
                b64(b),
            ),
            _ => (String::new(), String::new(), String::new()),
        }
    }

    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    pub(super) struct GenericPasswordJson {
        #[serde(skip_serializing_if = "String::is_empty")]
        service: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        account: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        password: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        hex_password: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        base64_password: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        description: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        comment: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        creator: String,
        #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
        type_: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        print_name: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        alias: String,
        #[serde(
            with = "time::serde::rfc3339::option",
            skip_serializing_if = "Option::is_none"
        )]
        created: Option<OffsetDateTime>,
        #[serde(
            with = "time::serde::rfc3339::option",
            skip_serializing_if = "Option::is_none"
        )]
        modified: Option<OffsetDateTime>,
    }

    impl From<GenericPassword> for GenericPasswordJson {
        fn from(g: GenericPassword) -> Self {
            let (password, hex_password, base64_password) = encode_secret(g.password.as_deref());
            Self {
                service: g.service,
                account: g.account,
                password,
                hex_password,
                base64_password,
                description: g.description,
                comment: g.comment,
                creator: g.creator,
                type_: g.type_,
                print_name: g.print_name,
                alias: g.alias,
                created: g.created,
                modified: g.modified,
            }
        }
    }

    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    pub(super) struct InternetPasswordJson {
        #[serde(skip_serializing_if = "String::is_empty")]
        server: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        account: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        password: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        hex_password: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        base64_password: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        security_domain: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        protocol: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        auth_type: String,
        #[serde(skip_serializing_if = "is_default")]
        port: u32,
        #[serde(skip_serializing_if = "String::is_empty")]
        path: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        description: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        comment: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        creator: String,
        #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
        type_: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        print_name: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        alias: String,
        #[serde(
            with = "time::serde::rfc3339::option",
            skip_serializing_if = "Option::is_none"
        )]
        created: Option<OffsetDateTime>,
        #[serde(
            with = "time::serde::rfc3339::option",
            skip_serializing_if = "Option::is_none"
        )]
        modified: Option<OffsetDateTime>,
    }

    impl From<InternetPassword> for InternetPasswordJson {
        fn from(i: InternetPassword) -> Self {
            let (password, hex_password, base64_password) = encode_secret(i.password.as_deref());
            Self {
                server: i.server,
                account: i.account,
                password,
                hex_password,
                base64_password,
                security_domain: i.security_domain,
                protocol: i.protocol,
                auth_type: i.auth_type,
                port: i.port,
                path: i.path,
                description: i.description,
                comment: i.comment,
                creator: i.creator,
                type_: i.type_,
                print_name: i.print_name,
                alias: i.alias,
                created: i.created,
                modified: i.modified,
            }
        }
    }

    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    pub(super) struct PrivateKeyJson {
        #[serde(skip_serializing_if = "String::is_empty")]
        name: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        data_hex: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        data_base64: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        print_name: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        label: String,
        #[serde(skip_serializing_if = "is_default")]
        key_class: u32,
        #[serde(skip_serializing_if = "is_default")]
        key_type: u32,
        #[serde(skip_serializing_if = "is_default")]
        key_size: u32,
    }

    impl From<PrivateKey> for PrivateKeyJson {
        fn from(p: PrivateKey) -> Self {
            let (data_hex, data_base64) = if p.data.is_empty() {
                (String::new(), String::new())
            } else {
                (hex::encode(&p.data), b64(&p.data))
            };
            Self {
                name: p.name,
                data_hex,
                data_base64,
                print_name: p.print_name,
                label: p.label,
                key_class: p.key_class,
                key_type: p.key_type,
                key_size: p.key_size,
            }
        }
    }

    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    pub(super) struct CertificateJson {
        #[serde(skip_serializing_if = "String::is_empty")]
        data_hex: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        data_base64: String,
        #[serde(rename = "type", skip_serializing_if = "is_default")]
        type_: u32,
        #[serde(skip_serializing_if = "is_default")]
        encoding: u32,
        #[serde(skip_serializing_if = "String::is_empty")]
        print_name: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        subject_hex: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        issuer_hex: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        serial_hex: String,
    }

    impl From<Certificate> for CertificateJson {
        fn from(c: Certificate) -> Self {
            let hex_or_empty = |b: &[u8]| {
                if b.is_empty() {
                    String::new()
                } else {
                    hex::encode(b)
                }
            };
            let (data_hex, data_base64) = if c.data.is_empty() {
                (String::new(), String::new())
            } else {
                (hex::encode(&c.data), b64(&c.data))
            };
            Self {
                data_hex,
                data_base64,
                type_: c.type_,
                encoding: c.encoding,
                print_name: c.print_name,
                subject_hex: hex_or_empty(&c.subject),
                issuer_hex: hex_or_empty(&c.issuer),
                serial_hex: hex_or_empty(&c.serial),
            }
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "test code uses direct unwrap and index assertions"
    )]

    use super::{Certificate, GenericPassword};

    #[test]
    fn generic_password_json_is_go_compatible() {
        let gp = GenericPassword {
            account: "admin".to_owned(),
            password: Some(b"password#123".to_vec()),
            ..Default::default()
        };
        let v = serde_json::to_value(gp).unwrap();
        assert_eq!(v["account"], "admin");
        assert_eq!(v["password"], "password#123");
        assert_eq!(v["hex_password"], "70617373776f726423313233");
        assert_eq!(v["base64_password"], "cGFzc3dvcmQjMTIz");
    }

    #[test]
    fn empty_password_omits_encoding_fields() {
        let gp = GenericPassword {
            account: "a".to_owned(),
            ..Default::default()
        };
        let v = serde_json::to_value(gp).unwrap();
        assert!(v.get("password").is_none());
        assert!(v.get("hex_password").is_none());
        assert!(v.get("base64_password").is_none());
    }

    #[test]
    fn certificate_json_uses_hex_blobs() {
        let c = Certificate {
            data: vec![0x30, 0x82],
            subject: vec![0xAB],
            ..Default::default()
        };
        let v = serde_json::to_value(c).unwrap();
        assert_eq!(v["data_hex"], "3082");
        assert_eq!(v["subject_hex"], "ab");
    }
}
