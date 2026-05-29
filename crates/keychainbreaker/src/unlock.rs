//! Unlock credentials and master-key derivation for [`Keychain`].

use std::collections::HashMap;

use crate::crypto::{generate_master_key, kc_decrypt, keyblob_decrypt, KEY_LENGTH};
use crate::error::{Error, Result};
use crate::keychain::{KeyList, Keychain, State, KEY_LIST_INDEX_LEN};
use crate::parse::{parse_key_blob, KEY_BLOB_LEN, KEY_BLOB_MAGIC, SECURE_STORAGE_GROUP};
use crate::record::parse_record;
use crate::tables;

/// A credential for [`Keychain::unlock`] / [`Keychain::try_unlock`].
///
/// Exactly one of the two unlock paths is representable — there is no "empty"
/// or "both" state to guard against. Hex-string parsing of a recovered key is
/// the caller's job; the library takes the raw 24-byte 3DES master key.
#[derive(Clone)]
pub enum Credential {
    /// A keychain password, run through PBKDF2-HMAC-SHA1 with the per-file salt.
    /// The empty string is a valid attempt.
    Password(String),

    /// A recovered 24-byte master key (the one [`Keychain::password_hash`] is
    /// derived from).
    Key([u8; KEY_LENGTH]),
}

impl Credential {
    /// Convenience constructor for a password credential from any string-like.
    #[must_use]
    pub fn password(password: impl Into<String>) -> Self {
        Self::Password(password.into())
    }
}

impl core::fmt::Debug for Credential {
    /// Never prints the secret material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Password(_) => f.write_str("Credential::Password(..)"),
            Self::Key(_) => f.write_str("Credential::Key(..)"),
        }
    }
}

impl Keychain {
    /// Decrypt the keychain using `cred`. On failure the keychain is left
    /// locked, so extraction methods return [`Error::Locked`].
    ///
    /// Takes the credential by value so it is consumed (and dropped) by the
    /// unlock attempt rather than lingering at the call site.
    #[allow(clippy::needless_pass_by_value)]
    pub fn unlock(&mut self, cred: Credential) -> Result<()> {
        match self.compute_keys(&cred) {
            Ok((db_key, key_list)) => {
                self.state = State::Unlocked { db_key, key_list };
                Ok(())
            }
            Err(e) => {
                self.state = State::Locked;
                Err(e)
            }
        }
    }

    /// Attempt to decrypt, but fall back to metadata-only extraction instead of
    /// failing on a wrong credential.
    ///
    /// - `None` enables partial mode without attempting decryption.
    /// - `Some(cred)` attempts a full unlock; a wrong password / key leaves the
    ///   keychain in partial mode and returns `Ok(())` (check
    ///   [`Self::unlocked`] to tell full from partial). Only a structural
    ///   problem (e.g. a corrupt table) returns `Err`.
    pub fn try_unlock(&mut self, cred: Option<Credential>) -> Result<()> {
        let Some(cred) = cred else {
            self.state = State::Partial;
            return Ok(());
        };
        match self.compute_keys(&cred) {
            Ok((db_key, key_list)) => {
                self.state = State::Unlocked { db_key, key_list };
                Ok(())
            }
            Err(Error::WrongKey) => {
                self.state = State::Partial;
                Ok(())
            }
            Err(e) => {
                self.state = State::Partial;
                Err(e)
            }
        }
    }

    /// `true` once a [`Self::unlock`] / [`Self::try_unlock`] has fully decrypted
    /// the database key. `false` in locked and partial states.
    #[must_use]
    pub const fn unlocked(&self) -> bool {
        matches!(self.state, State::Unlocked { .. })
    }

    /// Derive the master key, unwrap the database key, and build the per-record
    /// key list. Pure with respect to `self` — the caller installs the result
    /// into the unlocked state.
    fn compute_keys(&self, cred: &Credential) -> Result<(Vec<u8>, KeyList)> {
        let master_key = derive_master_key(cred, &self.db_blob.salt);
        let method = derive_method(cred);
        let key_len = master_key.len();
        match cred {
            Credential::Password(_) => {
                let iterations = crate::crypto::PBKDF2_ITER;
                self.logger.info(
                    "master key derived",
                    &[
                        ("method", &method),
                        ("iterations", &iterations),
                        ("keyLen", &key_len),
                    ],
                );
            }
            Credential::Key(_) => self.logger.info(
                "master key derived",
                &[("method", &method), ("keyLen", &key_len)],
            ),
        }

        let db_key = match find_wrapping_key(self, &master_key) {
            Ok(db_key) => db_key,
            Err(e) => {
                self.logger.error("decrypt DB key failed", &[("error", &e)]);
                return Err(e);
            }
        };
        self.logger
            .info("DB key decrypted", &[("keyLen", &db_key.len())]);

        let key_list = match generate_key_list(self, &db_key) {
            Ok(key_list) => key_list,
            Err(e) => {
                self.logger
                    .error("generate key list failed", &[("error", &e)]);
                return Err(e);
            }
        };
        self.logger
            .info("key list generated", &[("keyCount", &key_list.len())]);
        Ok((db_key, key_list))
    }
}

const fn derive_method(cred: &Credential) -> &'static str {
    match cred {
        Credential::Key(_) => "hex-key",
        Credential::Password(_) => "PBKDF2-SHA1",
    }
}

fn derive_master_key(cred: &Credential, salt: &[u8]) -> [u8; KEY_LENGTH] {
    match cred {
        Credential::Key(key) => *key,
        Credential::Password(password) => generate_master_key(password, salt),
    }
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

fn generate_key_list(kc: &Keychain, db_key: &[u8]) -> Result<KeyList> {
    let sym_table = kc
        .tables_map
        .get(&tables::TABLE_SYMMETRIC_KEY)
        .ok_or_else(|| Error::ParseFailed("no symmetric key table".into()))?;
    let schema = kc
        .schema
        .for_table(tables::TABLE_SYMMETRIC_KEY)
        .ok_or_else(|| Error::ParseFailed("no schema for SymmetricKey table".into()))?;

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
    Ok(key_list)
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

    // SSGP_MAGIC_OFFSET (8) past totalLength puts us at the "ssgp" tag that
    // precedes the per-record key index (Apple's Secure Storage Group label).
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
