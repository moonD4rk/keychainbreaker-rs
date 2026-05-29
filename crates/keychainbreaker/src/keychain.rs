//! The public [`Keychain`] type and the record-extraction methods.
//!
//! Construct a `Keychain` via [`Keychain::open_default`],
//! [`Keychain::open_file`], [`Keychain::open_bytes`], or
//! [`Keychain::builder`] (all live in `open.rs`). Unlock it with
//! [`Keychain::unlock`] / [`Keychain::try_unlock`] (`unlock.rs`), then
//! call the extraction methods here to walk records.

use std::collections::HashMap;
use std::fmt;

use crate::crypto::{kc_decrypt, private_key_decrypt};
use crate::error::{Error, Result};
use crate::logger::Logger;
use crate::parse::{
    parse_key_blob, parse_ssgp, DbBlob, TableHeader, KEY_BLOB_LEN, KEY_BLOB_MAGIC,
    SECURE_STORAGE_GROUP,
};
use crate::record::{parse_record, Record};
use crate::schema::DbSchema;
use crate::tables;
use crate::types::{Certificate, GenericPassword, InternetPassword, PrivateKey};

/// First 12 bytes of a decrypted private-key payload hold its name.
pub(crate) const PRIVATE_KEY_NAME_LEN: usize = 12;

/// Index entry size in the key list: 4-byte SSGP magic + 16-byte label.
pub(crate) const KEY_LIST_INDEX_LEN: usize = 20;

/// Per-record decryption keys, indexed by SSGP magic + label.
pub(crate) type KeyList = HashMap<Vec<u8>, Vec<u8>>;

/// Unlock state of a [`Keychain`].
pub(crate) enum State {
    /// No unlock attempted, or a strict [`Keychain::unlock`] failed.
    Locked,
    /// Metadata-only extraction is permitted; no database key is available.
    Partial,
    /// Fully unlocked: the database key and per-record key list are resident.
    Unlocked { db_key: Vec<u8>, key_list: KeyList },
}

/// A parsed (and possibly unlocked) macOS keychain database.
///
/// `Keychain` owns the file bytes, the parsed table catalogue, the discovered
/// schema, and its unlock [`State`]. Extraction methods take `&self` because
/// every state mutation happens during [`Keychain::unlock`] /
/// [`Keychain::try_unlock`].
pub struct Keychain {
    pub(crate) buf: Vec<u8>,
    pub(crate) schema: DbSchema,
    pub(crate) tables_map: HashMap<u32, TableHeader>,
    pub(crate) db_blob: DbBlob,
    pub(crate) blob_base_addr: usize,
    pub(crate) state: State,
    pub(crate) logger: Box<dyn Logger>,
}

impl fmt::Debug for Keychain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keychain")
            .field("unlocked", &self.unlocked())
            .field("partial", &matches!(self.state, State::Partial))
            .field("tables", &self.tables_map.len())
            .field("buf_len", &self.buf.len())
            .finish_non_exhaustive()
    }
}

impl Keychain {
    pub(crate) fn new_locked(
        buf: Vec<u8>,
        schema: DbSchema,
        tables_map: HashMap<u32, TableHeader>,
        db_blob: DbBlob,
        blob_base_addr: usize,
        logger: Box<dyn Logger>,
    ) -> Self {
        Self {
            buf,
            schema,
            tables_map,
            db_blob,
            blob_base_addr,
            state: State::Locked,
            logger,
        }
    }

    /// Return all generic-password records.
    ///
    /// Returns [`Error::Locked`] if the keychain has not been unlocked
    /// (or partially unlocked via [`Keychain::try_unlock`]). When
    /// `try_unlock` was used and per-record decryption fails, metadata
    /// fields are still populated and `password` is `None`.
    pub fn generic_passwords(&self) -> Result<Vec<GenericPassword>> {
        let records = self.iterate_records(tables::TABLE_GENERIC_PASSWORD)?;
        let mut out = Vec::with_capacity(records.len());
        for rec in &records {
            out.push(GenericPassword {
                service: rec.read_string_attr(tables::ATTR_SERVICE_NAME),
                account: rec.read_string_attr(tables::ATTR_ACCOUNT_NAME),
                password: self.decrypt_blob(rec).ok(),
                description: rec.read_string_attr(tables::ATTR_DESCRIPTION),
                comment: rec.read_string_attr(tables::ATTR_COMMENT),
                creator: rec.read_fourcc_attr(tables::ATTR_CREATOR),
                type_: rec.read_fourcc_attr(tables::ATTR_TYPE),
                print_name: rec.read_string_attr(tables::ATTR_PRINT_NAME),
                alias: rec.read_string_attr(tables::ATTR_ALIAS),
                created: rec.read_time_attr(tables::ATTR_CREATED),
                modified: rec.read_time_attr(tables::ATTR_MODIFIED),
            });
        }
        Ok(out)
    }

    /// Return all internet-password records. Semantics match
    /// [`Keychain::generic_passwords`].
    pub fn internet_passwords(&self) -> Result<Vec<InternetPassword>> {
        let records = self.iterate_records(tables::TABLE_INTERNET_PASSWORD)?;
        let mut out = Vec::with_capacity(records.len());
        for rec in &records {
            out.push(InternetPassword {
                server: rec.read_string_attr(tables::ATTR_SERVER),
                account: rec.read_string_attr(tables::ATTR_ACCOUNT_NAME),
                password: self.decrypt_blob(rec).ok(),
                security_domain: rec.read_string_attr(tables::ATTR_SECURITY_DOMAIN),
                protocol: rec.read_fourcc_attr(tables::ATTR_PROTOCOL),
                auth_type: rec.read_fourcc_attr(tables::ATTR_AUTH_TYPE),
                port: rec.read_u32_attr(tables::ATTR_PORT),
                path: rec.read_string_attr(tables::ATTR_PATH),
                description: rec.read_string_attr(tables::ATTR_DESCRIPTION),
                comment: rec.read_string_attr(tables::ATTR_COMMENT),
                creator: rec.read_fourcc_attr(tables::ATTR_CREATOR),
                type_: rec.read_fourcc_attr(tables::ATTR_TYPE),
                print_name: rec.read_string_attr(tables::ATTR_PRINT_NAME),
                alias: rec.read_string_attr(tables::ATTR_ALIAS),
                created: rec.read_time_attr(tables::ATTR_CREATED),
                modified: rec.read_time_attr(tables::ATTR_MODIFIED),
            });
        }
        Ok(out)
    }

    /// Return all private-key records.
    ///
    /// Under `try_unlock`, records whose payload fails to decrypt are
    /// still returned with metadata populated but `name` empty and
    /// `data` empty.
    pub fn private_keys(&self) -> Result<Vec<PrivateKey>> {
        let records = self.iterate_records(tables::TABLE_PRIVATE_KEY)?;
        let mut out = Vec::new();
        for rec in &records {
            match self.decrypt_private_key(rec) {
                Ok(pk) => out.push(pk),
                Err(_) if matches!(self.state, State::Partial) => out.push(PrivateKey {
                    print_name: rec.read_string_attr(tables::ATTR_PRINT_NAME),
                    label: rec.read_string_attr(tables::ATTR_LABEL),
                    key_class: rec.read_u32_attr(tables::ATTR_KEY_CLASS),
                    key_type: rec.read_u32_attr(tables::ATTR_KEY_TYPE),
                    key_size: rec.read_u32_attr(tables::ATTR_KEY_SIZE_IN_BITS),
                    ..PrivateKey::default()
                }),
                Err(_) => {}
            }
        }
        Ok(out)
    }

    /// Return all X.509 certificate records. Certificates are not
    /// encrypted at rest, so they are fully populated regardless of
    /// unlock state (subject to the `Locked` guard).
    pub fn certificates(&self) -> Result<Vec<Certificate>> {
        let records = self.iterate_records(tables::TABLE_X509_CERTIFICATE)?;
        let mut out = Vec::with_capacity(records.len());
        for rec in &records {
            out.push(Certificate {
                data: rec.blob_data.to_vec(),
                type_: rec.read_u32_attr(tables::ATTR_CERT_TYPE),
                encoding: rec.read_u32_attr(tables::ATTR_CERT_ENCODING),
                print_name: rec.read_string_attr(tables::ATTR_CERT_LABEL),
                subject: rec.read_blob_attr(tables::ATTR_SUBJECT),
                issuer: rec.read_blob_attr(tables::ATTR_ISSUER),
                serial: rec.read_blob_attr(tables::ATTR_SERIAL),
            });
        }
        Ok(out)
    }

    /// Export the keychain password hash in
    /// `$keychain$*<salt_hex>*<iv_hex>*<ciphertext_hex>` format
    /// (compatible with hashcat mode 23100 and John the Ripper).
    /// Does not require unlock.
    pub fn password_hash(&self) -> Result<String> {
        let start = self
            .blob_base_addr
            .saturating_add(self.db_blob.start_crypto_blob as usize);
        let end = self
            .blob_base_addr
            .saturating_add(self.db_blob.total_length as usize);
        if start >= end || end > self.buf.len() {
            return Err(Error::ParseFailed("encrypted db key bounds invalid".into()));
        }
        let cipher = self
            .buf
            .get(start..end)
            .ok_or_else(|| Error::ParseFailed("encrypted db key slice out of bounds".into()))?;
        Ok(format!(
            "$keychain$*{}*{}*{}",
            hex::encode(self.db_blob.salt),
            hex::encode(self.db_blob.iv),
            hex::encode(cipher),
        ))
    }

    fn iterate_records(&self, table_id: u32) -> Result<Vec<Record<'_>>> {
        if matches!(self.state, State::Locked) {
            return Err(Error::Locked);
        }
        let Some(table) = self.tables_map.get(&table_id) else {
            return Ok(Vec::new());
        };
        let Some(schema) = self.schema.for_table(table_id) else {
            return Err(Error::ParseFailed(format!(
                "no schema for table 0x{table_id:08X}"
            )));
        };

        let mut records = Vec::with_capacity(table.record_offsets.len());
        let mut skipped = 0_usize;
        for rec_offset in &table.record_offsets {
            let abs_offset = table.base_offset.saturating_add(*rec_offset as usize);
            match parse_record(&self.buf, abs_offset, schema) {
                Ok(rec) => records.push(rec),
                Err(_) => skipped += 1,
            }
        }
        if skipped > 0 {
            let table_tag = format!("0x{table_id:08X}");
            let total = table.record_offsets.len();
            self.logger.warn(
                "records skipped during parse",
                &[
                    ("table", &table_tag),
                    ("skipped", &skipped),
                    ("total", &total),
                ],
            );
        }
        Ok(records)
    }

    fn decrypt_blob(&self, rec: &Record<'_>) -> Result<Vec<u8>> {
        let State::Unlocked { key_list, .. } = &self.state else {
            return Err(Error::Locked);
        };
        let block = parse_ssgp(rec.blob_data)?;
        if &block.magic != SECURE_STORAGE_GROUP {
            return Err(Error::ParseFailed(format!(
                "invalid SSGP magic: {:?}",
                block.magic
            )));
        }
        if block.encrypted_password.is_empty() {
            return Ok(Vec::new());
        }
        let mut index = Vec::with_capacity(block.magic.len() + block.label.len());
        index.extend_from_slice(&block.magic);
        index.extend_from_slice(&block.label);
        let key = key_list
            .get(&index)
            .ok_or_else(|| Error::ParseFailed("no matching key for SSGP label".into()))?;
        kc_decrypt(key, &block.iv, block.encrypted_password)
    }

    fn decrypt_private_key(&self, rec: &Record<'_>) -> Result<PrivateKey> {
        let State::Unlocked { db_key, .. } = &self.state else {
            return Err(Error::Locked);
        };
        let data = rec.raw_payload;
        if data.len() < KEY_BLOB_LEN {
            return Err(Error::ParseFailed("private key blob too small".into()));
        }
        let blob = parse_key_blob(
            data.get(..KEY_BLOB_LEN)
                .ok_or_else(|| Error::ParseFailed("key blob slice out of bounds".into()))?,
        )?;
        if blob.magic != KEY_BLOB_MAGIC {
            return Err(Error::ParseFailed(format!(
                "unexpected keyblob magic: 0x{:08x}",
                blob.magic
            )));
        }
        let cipher_start = blob.start_crypto_blob as usize;
        let cipher_end = blob.total_length as usize;
        if cipher_end > data.len() || cipher_start >= cipher_end {
            return Err(Error::ParseFailed("invalid cipher bounds".into()));
        }
        let ciphertext = data
            .get(cipher_start..cipher_end)
            .ok_or_else(|| Error::ParseFailed("cipher slice out of bounds".into()))?;
        let plain = private_key_decrypt(ciphertext, &blob.iv, db_key)?;
        let (name, key_data) = if plain.len() > PRIVATE_KEY_NAME_LEN {
            let (head, tail) = plain.split_at(PRIVATE_KEY_NAME_LEN);
            (String::from_utf8_lossy(head).into_owned(), tail.to_vec())
        } else {
            (String::new(), plain)
        };
        Ok(PrivateKey {
            name,
            data: key_data,
            print_name: rec.read_string_attr(tables::ATTR_PRINT_NAME),
            label: rec.read_string_attr(tables::ATTR_LABEL),
            key_class: rec.read_u32_attr(tables::ATTR_KEY_CLASS),
            key_type: rec.read_u32_attr(tables::ATTR_KEY_TYPE),
            key_size: rec.read_u32_attr(tables::ATTR_KEY_SIZE_IN_BITS),
        })
    }
}
