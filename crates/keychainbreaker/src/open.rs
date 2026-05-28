//! Constructors and the [`KeychainBuilder`] for opening keychain files.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::keychain::Keychain;
use crate::logger::{Logger, NopLogger};
use crate::parse::{
    parse_db_blob, parse_header, parse_schema, parse_table, DB_BLOB_SIZE, HEADER_SIZE,
    KEYCHAIN_SIGNATURE, METADATA_OFFSET_ADJUSTMENT,
};
use crate::schema::build_schema;
use crate::tables;

enum Source {
    File(PathBuf),
    Bytes(Vec<u8>),
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(p) => f.debug_tuple("File").field(p).finish(),
            Self::Bytes(b) => f
                .debug_tuple("Bytes")
                .field(&format_args!("[{} bytes]", b.len()))
                .finish(),
        }
    }
}

/// Builder for [`Keychain`] when a custom [`Logger`] is needed. For the
/// common cases without a logger, prefer [`Keychain::open_default`],
/// [`Keychain::open_file`], or [`Keychain::open_bytes`] directly.
#[derive(Default)]
pub struct KeychainBuilder {
    source: Option<Source>,
    logger: Option<Box<dyn Logger>>,
}

impl std::fmt::Debug for KeychainBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeychainBuilder")
            .field("source", &self.source)
            .field("has_logger", &self.logger.is_some())
            .finish()
    }
}

impl KeychainBuilder {
    /// Open a keychain from a specific file path.
    #[must_use]
    pub fn file<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.source = Some(Source::File(path.as_ref().to_path_buf()));
        self
    }

    /// Open a keychain from an in-memory buffer. Wins over [`Self::file`]
    /// if both are set (matches the Go `resolveInput` precedence).
    #[must_use]
    pub fn bytes<B: Into<Vec<u8>>>(mut self, buf: B) -> Self {
        self.source = Some(Source::Bytes(buf.into()));
        self
    }

    /// Install a logger. Every diagnostic the parser and unlock pipeline
    /// emits will route through it.
    #[must_use]
    pub fn logger<L: Logger + 'static>(mut self, logger: L) -> Self {
        self.logger = Some(Box::new(logger));
        self
    }

    /// Resolve the source, read bytes (if a path), and parse into a
    /// locked [`Keychain`]. Falls back to the default macOS login
    /// keychain path when neither [`Self::file`] nor [`Self::bytes`]
    /// was called.
    pub fn open(self) -> Result<Keychain> {
        let logger: Box<dyn Logger> = self.logger.unwrap_or_else(|| Box::new(NopLogger));
        let buf = match self.source {
            Some(Source::Bytes(b)) => b,
            Some(Source::File(p)) => std::fs::read(p)?,
            None => std::fs::read(default_keychain_path()?)?,
        };
        parse_into_keychain(buf, logger)
    }
}

impl Keychain {
    /// Open the default macOS login keychain at
    /// `$HOME/Library/Keychains/login.keychain-db`.
    ///
    /// Returns [`Error::Io`] on hosts where `$HOME` is unset or the file
    /// is absent (every non-macOS target).
    pub fn open_default() -> Result<Self> {
        let path = default_keychain_path()?;
        let buf = std::fs::read(path)?;
        parse_into_keychain(buf, Box::new(NopLogger))
    }

    /// Open a keychain from a specific path.
    pub fn open_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let buf = std::fs::read(path.as_ref())?;
        parse_into_keychain(buf, Box::new(NopLogger))
    }

    /// Open a keychain from an in-memory buffer.
    pub fn open_bytes<B: Into<Vec<u8>>>(buf: B) -> Result<Self> {
        parse_into_keychain(buf.into(), Box::new(NopLogger))
    }

    /// Construct a [`KeychainBuilder`] for the case that needs a custom
    /// logger or wants to defer source selection.
    #[must_use]
    pub fn builder() -> KeychainBuilder {
        KeychainBuilder::default()
    }
}

fn default_keychain_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "HOME environment variable is not set",
        ))
    })?;
    Ok(PathBuf::from(home).join("Library/Keychains/login.keychain-db"))
}

fn parse_into_keychain(buf: Vec<u8>, logger: Box<dyn Logger>) -> Result<Keychain> {
    let header = parse_header(&buf)?;
    if &header.signature != KEYCHAIN_SIGNATURE {
        return Err(Error::InvalidSignature);
    }
    let signature = format_args!(
        "{}{}{}{}",
        header.signature[0] as char,
        header.signature[1] as char,
        header.signature[2] as char,
        header.signature[3] as char,
    );
    logger.info(
        "parsed header",
        &[("signature", &signature), ("version", &header.version)],
    );

    let schema_index = parse_schema(&buf, header.schema_off)?;
    let table_count = schema_index.table_offsets.len();
    logger.debug("parsed schema", &[("tableCount", &table_count)]);

    let mut tables_map: HashMap<u32, _> = HashMap::new();
    for off in &schema_index.table_offsets {
        if *off == 0 {
            continue;
        }
        let abs = HEADER_SIZE.saturating_add(*off as usize);
        let Ok(table) = parse_table(&buf, abs) else {
            continue;
        };
        let _previous = tables_map.entry(table.table_id).or_insert(table);
    }

    let schema = build_schema(&buf, &tables_map)?;

    let meta_table = tables_map
        .get(&tables::TABLE_METADATA)
        .ok_or_else(|| Error::ParseFailed("metadata table not found".into()))?;
    let blob_base_addr = meta_table
        .base_offset
        .saturating_add(METADATA_OFFSET_ADJUSTMENT);
    if blob_base_addr.saturating_add(DB_BLOB_SIZE) > buf.len() {
        return Err(Error::ParseFailed("db blob exceeds file size".into()));
    }
    let db_blob = parse_db_blob(
        buf.get(blob_base_addr..blob_base_addr.saturating_add(DB_BLOB_SIZE))
            .ok_or_else(|| Error::ParseFailed("db blob slice out of bounds".into()))?,
    )?;
    let magic = format_args!("0x{:08X}", db_blob.magic);
    let blob_version = format_args!("0x{:08X}", db_blob.blob_version);
    logger.info(
        "parsed DBBlob",
        &[
            ("magic", &magic),
            ("blobVersion", &blob_version),
            ("startCryptoBlob", &db_blob.start_crypto_blob),
            ("totalLength", &db_blob.total_length),
        ],
    );

    Ok(Keychain::new_locked(
        buf,
        schema,
        tables_map,
        db_blob,
        blob_base_addr,
        logger,
    ))
}
