//! Unlock options and master-key derivation for [`Keychain`].

use std::collections::HashMap;

use crate::crypto::{generate_master_key, kc_decrypt, keyblob_decrypt, KEY_LENGTH};
use crate::error::{Error, Result};
use crate::keychain::{Keychain, KEY_LIST_INDEX_LEN};
use crate::parse::{parse_key_blob, KEY_BLOB_LEN, KEY_BLOB_MAGIC, SECURE_STORAGE_GROUP};
use crate::record::parse_record;
use crate::tables;

/// Credentials passed to [`Keychain::unlock`] / [`Keychain::try_unlock`].
///
/// Construct via [`UnlockOptions::with_password`] or
/// [`UnlockOptions::with_key`]. [`UnlockOptions::default`] carries no
/// credential and is only useful with [`Keychain::try_unlock`] (where it
/// flips the keychain into partial-extraction mode).
///
/// An empty-string password is distinct from "no password": the empty
/// string is a legitimate unlock attempt that still goes through PBKDF2.
#[derive(Debug, Clone, Default)]
pub struct UnlockOptions {
    password: Option<String>,
    hex_key: Option<String>,
}

impl UnlockOptions {
    /// Use a keychain password (will be run through PBKDF2-HMAC-SHA1
    /// with the per-file salt). The empty string is a valid attempt.
    #[must_use]
    pub fn with_password<S: Into<String>>(password: S) -> Self {
        Self {
            password: Some(password.into()),
            hex_key: None,
        }
    }

    /// Use a hex-encoded 24-byte master key (the one
    /// [`Keychain::password_hash`] is derived from). Whitespace and a
    /// leading `0x` are stripped.
    #[must_use]
    pub fn with_key<S: Into<String>>(hex_key: S) -> Self {
        Self {
            password: None,
            hex_key: Some(hex_key.into()),
        }
    }
}

impl Keychain {
    /// Decrypt the keychain using the provided credential. Leaves the
    /// keychain locked on failure (so extraction methods return
    /// [`Error::Locked`]).
    ///
    /// Takes `UnlockOptions` by value to match the Go API and to make
    /// the consumed credential explicit at the call site.
    #[allow(clippy::needless_pass_by_value)]
    pub fn unlock(&mut self, opts: UnlockOptions) -> Result<()> {
        self.allow_partial = false;
        self.do_unlock(&opts)
    }

    /// Attempt to decrypt; on failure, allow metadata-only extraction.
    /// Calling with [`UnlockOptions::default()`] sets
    /// `allow_partial = true` without attempting decryption (matches the
    /// Go `kc.TryUnlock()` no-arg behaviour).
    #[allow(clippy::needless_pass_by_value)]
    pub fn try_unlock(&mut self, opts: UnlockOptions) -> Result<()> {
        self.allow_partial = true;
        if opts.password.is_none() && opts.hex_key.is_none() {
            return Ok(());
        }
        self.do_unlock(&opts)
    }

    /// `true` once a successful [`Self::unlock`] or [`Self::try_unlock`]
    /// has run. Independent of `allow_partial`.
    #[must_use]
    pub const fn unlocked(&self) -> bool {
        self.db_key.is_some()
    }

    fn do_unlock(&mut self, opts: &UnlockOptions) -> Result<()> {
        let master_key = derive_master_key(opts, &self.db_blob.salt)?;
        let method = derive_method(opts);
        let master_len = master_key.len();
        self.logger.info(
            "master key derived",
            &[("method", &method), ("keyLen", &master_len)],
        );

        let db_key = find_wrapping_key(self, &master_key)?;
        let db_key_len = db_key.len();
        self.logger
            .info("DB key decrypted", &[("keyLen", &db_key_len)]);

        self.db_key = Some(db_key);
        if let Err(e) = generate_key_list(self) {
            self.db_key = None;
            self.key_list.clear();
            let err_msg = format!("{e}");
            self.logger
                .error("generate key list failed", &[("error", &err_msg)]);
            return Err(e);
        }
        let key_count = self.key_list.len();
        self.logger
            .info("key list generated", &[("keyCount", &key_count)]);
        Ok(())
    }
}

const fn derive_method(opts: &UnlockOptions) -> &'static str {
    if opts.hex_key.is_some() {
        "hex-key"
    } else if opts.password.is_some() {
        "PBKDF2-SHA1"
    } else {
        "none"
    }
}

fn derive_master_key(opts: &UnlockOptions, salt: &[u8]) -> Result<Vec<u8>> {
    if let Some(hex_key) = opts.hex_key.as_deref() {
        return decode_hex_key(hex_key);
    }
    if let Some(password) = opts.password.as_deref() {
        return Ok(generate_master_key(password, salt).to_vec());
    }
    Err(Error::NoCredential)
}

fn decode_hex_key(hex_key: &str) -> Result<Vec<u8>> {
    let cleaned = hex_key.trim();
    let cleaned = cleaned.strip_prefix("0x").unwrap_or(cleaned);
    let bytes = hex::decode(cleaned)?;
    if bytes.len() != KEY_LENGTH {
        return Err(Error::ParseFailed(format!(
            "unlock key must be {KEY_LENGTH} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn find_wrapping_key(kc: &Keychain, master: &[u8]) -> Result<Vec<u8>> {
    let start = kc
        .blob_base_addr
        .saturating_add(kc.db_blob.start_crypto_blob as usize);
    let end = kc
        .blob_base_addr
        .saturating_add(kc.db_blob.total_length as usize);
    if start >= end || end > kc.buf.len() {
        return Err(Error::ParseFailed("db blob cipher bounds invalid".into()));
    }
    let cipher = kc
        .buf
        .get(start..end)
        .ok_or_else(|| Error::ParseFailed("db cipher slice out of bounds".into()))?;
    kc.logger
        .debug("decrypting DB key", &[("ciphertextLen", &cipher.len())]);

    let plain = kc_decrypt(master, &kc.db_blob.iv, cipher).map_err(|_| Error::WrongKey)?;
    if plain.len() < KEY_LENGTH {
        return Err(Error::WrongKey);
    }
    Ok(plain.get(..KEY_LENGTH).ok_or(Error::WrongKey)?.to_vec())
}

fn generate_key_list(kc: &mut Keychain) -> Result<()> {
    let sym_table = kc
        .tables_map
        .get(&tables::TABLE_SYMMETRIC_KEY)
        .ok_or_else(|| Error::ParseFailed("no symmetric key table".into()))?;
    let schema = kc
        .schema
        .for_table(tables::TABLE_SYMMETRIC_KEY)
        .ok_or_else(|| Error::ParseFailed("no schema for SymmetricKey table".into()))?;

    let db_key = kc.db_key.as_deref().ok_or(Error::Locked)?;

    let mut key_list: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut skipped = 0_usize;
    for rec_offset in &sym_table.record_offsets {
        let abs_offset = sym_table.base_offset.saturating_add(*rec_offset as usize);
        let Ok(rec) = parse_record(&kc.buf, abs_offset, schema) else {
            skipped += 1;
            continue;
        };
        let Ok((index, ciphertext, iv)) = extract_key_blob(&rec) else {
            skipped += 1;
            continue;
        };
        match keyblob_decrypt(ciphertext, &iv, db_key) {
            Ok(key) if !key.is_empty() => {
                let _previous = key_list.insert(index, key);
            }
            _ => skipped += 1,
        }
    }
    if skipped > 0 {
        let total = sym_table.record_offsets.len();
        kc.logger.warn(
            "symmetric key records skipped",
            &[("skipped", &skipped), ("total", &total)],
        );
    }

    if key_list.is_empty() {
        return Err(Error::WrongKey);
    }
    kc.key_list = key_list;
    Ok(())
}

fn extract_key_blob<'a>(rec: &crate::record::Record<'a>) -> Result<(Vec<u8>, &'a [u8], [u8; 8])> {
    let data = rec.raw_payload;
    if data.len() < KEY_BLOB_LEN {
        return Err(Error::ParseFailed("keyblob structure incomplete".into()));
    }
    let blob = parse_key_blob(
        data.get(..KEY_BLOB_LEN)
            .ok_or_else(|| Error::ParseFailed("keyblob slice out of bounds".into()))?,
    )?;
    if blob.magic != KEY_BLOB_MAGIC {
        return Err(Error::ParseFailed(format!(
            "unexpected keyblob magic: 0x{:08x}",
            blob.magic
        )));
    }

    // SSGP_MAGIC_OFFSET (8) past totalLength puts us at the "ssgp" tag
    // that precedes the per-record key index (Apple's Secure Storage
    // Group label).
    let ssgp_offset = (blob.total_length as usize).saturating_add(8);
    let magic_end = ssgp_offset.saturating_add(4);
    let ssgp_tag = data
        .get(ssgp_offset..magic_end)
        .ok_or_else(|| Error::ParseFailed("ssgp check exceeds record".into()))?;
    if ssgp_tag != SECURE_STORAGE_GROUP {
        return Err(Error::ParseFailed(
            "keyblob not part of secure storage group".into(),
        ));
    }

    let cipher_start = blob.start_crypto_blob as usize;
    let cipher_end = blob.total_length as usize;
    if cipher_end > data.len() || cipher_start >= cipher_end {
        return Err(Error::ParseFailed("invalid cipher bounds".into()));
    }
    let ciphertext = data
        .get(cipher_start..cipher_end)
        .ok_or_else(|| Error::ParseFailed("cipher slice out of bounds".into()))?;

    let index_end = ssgp_offset.saturating_add(KEY_LIST_INDEX_LEN);
    let index = data
        .get(ssgp_offset..index_end)
        .ok_or_else(|| Error::ParseFailed("key index exceeds record length".into()))?
        .to_vec();
    Ok((index, ciphertext, blob.iv))
}
