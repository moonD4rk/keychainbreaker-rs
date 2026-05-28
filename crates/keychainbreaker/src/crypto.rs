//! Cryptographic primitives for keychain decryption.
//!
//! All primitives are crate-private and exposed only through the public
//! `Keychain` unlock and extraction methods (added in later milestones).
//!
//! See `rfcs/005-keychain-encryption.md` for the algorithm details.

// The reverse-buffer loop in `keyblob_decrypt` indexes into bounds-checked
// fixed-size arrays where the bounds are obvious by inspection; the lint
// can't see that, so allow it here only.
#![allow(clippy::indexing_slicing)]

use cbc::cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit};
use cbc::Decryptor;
use des::TdesEde3;
use sha1::Sha1;

use crate::error::{Error, Result};

/// 3DES block size in bytes.
pub(crate) const BLOCK_SIZE: usize = 8;

/// 3DES three-key EDE key length in bytes.
pub(crate) const KEY_LENGTH: usize = 24;

/// PBKDF2 iteration count Apple uses for keychain master-key derivation.
pub(crate) const PBKDF2_ITER: u32 = 1000;

/// Magic IV used by Apple as the outer wrap IV in the RFC 3217 two-stage
/// key unwrap. See `rfcs/005-keychain-encryption.md` § "Key Wrap Algorithm".
pub(crate) const MAGIC_CMS_IV: [u8; 8] = [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05];

type TripleDesCbcDec = Decryptor<TdesEde3>;

/// Decrypt a 3DES-CBC ciphertext with PKCS#7 padding.
///
/// Length and alignment checks are performed up front; the caller does not
/// need to validate inputs.
pub(crate) fn kc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(Error::Cipher("ciphertext is empty"));
    }
    if data.len() % BLOCK_SIZE != 0 {
        return Err(Error::Cipher("ciphertext not aligned to 8-byte block"));
    }
    if key.len() != KEY_LENGTH {
        return Err(Error::Cipher("invalid 3DES key length"));
    }
    if iv.len() != BLOCK_SIZE {
        return Err(Error::Cipher("invalid IV length"));
    }
    let mut buf = data.to_vec();
    let plain = TripleDesCbcDec::new_from_slices(key, iv)
        .map_err(|_| Error::Cipher("invalid key or IV length"))?
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|_| Error::Cipher("padding verification failed"))?;
    Ok(plain.to_vec())
}

/// Apple's two-stage RFC 3217 key unwrap, symmetric-key variant.
///
/// Stage 1 decrypts with the magic IV. The first 32 bytes of plaintext are
/// reversed in place. Stage 2 decrypts the reversed buffer with the
/// caller-supplied IV. The 24-byte wrapped key sits at `plaintext[4..28]`.
pub(crate) fn keyblob_decrypt(blob: &[u8], iv: &[u8], db_key: &[u8]) -> Result<Vec<u8>> {
    let plain = kc_decrypt(db_key, &MAGIC_CMS_IV, blob)
        .map_err(|e| Error::ParseFailed(format!("key unwrap stage 1: {e}")))?;
    if plain.len() < 32 {
        return Err(Error::ParseFailed(
            "unwrapped blob too short for symmetric stage 2".into(),
        ));
    }
    let mut rev = [0_u8; 32];
    for (i, dst) in rev.iter_mut().enumerate() {
        *dst = plain[31 - i];
    }
    let final_plain = kc_decrypt(db_key, iv, &rev)
        .map_err(|e| Error::ParseFailed(format!("key unwrap stage 2: {e}")))?;
    if final_plain.len() != 28 {
        return Err(Error::ParseFailed(format!(
            "invalid unwrapped key length: got {}, want 28",
            final_plain.len()
        )));
    }
    Ok(final_plain[4..28].to_vec())
}

/// Apple's two-stage RFC 3217 key unwrap, private-key variant.
///
/// Differs from [`keyblob_decrypt`] in that **all** stage-1 plaintext bytes
/// are reversed (not just the first 32) and the full stage-2 plaintext is
/// returned (no `[4..28]` slice).
pub(crate) fn private_key_decrypt(blob: &[u8], iv: &[u8], db_key: &[u8]) -> Result<Vec<u8>> {
    let plain = kc_decrypt(db_key, &MAGIC_CMS_IV, blob)
        .map_err(|e| Error::ParseFailed(format!("private key unwrap stage 1: {e}")))?;
    let rev: Vec<u8> = plain.iter().rev().copied().collect();
    let final_plain = kc_decrypt(db_key, iv, &rev)
        .map_err(|e| Error::ParseFailed(format!("private key unwrap stage 2: {e}")))?;
    Ok(final_plain)
}

/// Derive the keychain master key from a password via PBKDF2-HMAC-SHA1
/// with Apple's fixed iteration count of 1000 and a 24-byte output.
pub(crate) fn generate_master_key(password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
    let mut out = [0_u8; KEY_LENGTH];
    pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), salt, PBKDF2_ITER, &mut out);
    out
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::missing_panics_doc
    )]

    use super::*;
    use cbc::cipher::{block_padding::Pkcs7 as Pkcs7Pad, BlockModeEncrypt};
    use cbc::Encryptor;

    type TripleDesCbcEnc = Encryptor<TdesEde3>;

    /// RFC 6070 PBKDF2-HMAC-SHA1 test vector #1 — sanity check on the
    /// `pbkdf2 + sha1` crate combination underlying [`generate_master_key`].
    #[test]
    fn pbkdf2_hmac_sha1_rfc6070_vector_1() {
        let mut out = [0_u8; 20];
        pbkdf2::pbkdf2_hmac::<Sha1>(b"password", b"salt", 1, &mut out);
        assert_eq!(hex::encode(out), "0c60c80f961f0e71f3a9b524af6012062fe037a6");
    }

    /// RFC 6070 PBKDF2-HMAC-SHA1 test vector #2.
    #[test]
    fn pbkdf2_hmac_sha1_rfc6070_vector_2() {
        let mut out = [0_u8; 20];
        pbkdf2::pbkdf2_hmac::<Sha1>(b"password", b"salt", 2, &mut out);
        assert_eq!(hex::encode(out), "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
    }

    /// End-to-end known vector for [`generate_master_key`] extracted from
    /// `tests/data/test.keychain-db`. If this passes, the entire crypto
    /// chain is wired correctly and matches the Go reference implementation
    /// bit-for-bit.
    #[test]
    fn generate_master_key_keychainbreaker_test_vector() {
        let salt = hex::decode("fc143c45cce245f3e54fbb39141a894e2870dd85").unwrap();
        let key = generate_master_key("keychainbreaker-test", &salt);
        assert_eq!(
            hex::encode(key),
            "4557eb716bbf20200945109cf3b884af9aca72e890e47c07"
        );
    }

    /// 3DES-CBC encrypt-then-decrypt round-trip with hand-crafted inputs.
    #[test]
    fn kc_decrypt_round_trip() {
        let key = [0xAB_u8; KEY_LENGTH];
        let iv = [0x12_u8; BLOCK_SIZE];
        let plaintext: &[u8] = b"keychainbreaker test plaintext";

        // Encrypt with the same crate pair, padding to next block boundary.
        let mut buf = vec![0_u8; plaintext.len() + BLOCK_SIZE];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ct = TripleDesCbcEnc::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded::<Pkcs7Pad>(&mut buf, plaintext.len())
            .unwrap();
        let ciphertext = ct.to_vec();

        let recovered = kc_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn kc_decrypt_rejects_short_inputs() {
        let key = [0_u8; KEY_LENGTH];
        let iv = [0_u8; BLOCK_SIZE];
        assert!(kc_decrypt(&key, &iv, &[]).is_err());
        assert!(kc_decrypt(&key, &iv, &[0_u8; 7]).is_err());
        assert!(kc_decrypt(&[0_u8; 16], &iv, &[0_u8; 8]).is_err());
        assert!(kc_decrypt(&key, &[0_u8; 4], &[0_u8; 8]).is_err());
    }

    #[test]
    fn kc_decrypt_rejects_bad_padding() {
        // Ciphertext of valid length but containing random bytes won't
        // decrypt to a valid PKCS#7 trailer.
        let key = [0_u8; KEY_LENGTH];
        let iv = [0_u8; BLOCK_SIZE];
        let bogus = [0xFF_u8; 16];
        assert!(matches!(
            kc_decrypt(&key, &iv, &bogus),
            Err(Error::Cipher(_))
        ));
    }

    #[test]
    fn magic_cms_iv_is_constant() {
        // Sanity check the constant matches Apple's published value.
        assert_eq!(MAGIC_CMS_IV.len(), BLOCK_SIZE);
        assert_eq!(MAGIC_CMS_IV[0], 0x4a);
        assert_eq!(MAGIC_CMS_IV[7], 0x05);
    }

    /// Stage 2 of [`keyblob_decrypt`] must yield exactly 28 bytes (4-byte
    /// header + 24-byte key). This crafts a blob whose stage-2 plaintext is
    /// 24 bytes and asserts the strict length check rejects it.
    #[test]
    fn keyblob_decrypt_rejects_unwrapped_key_with_wrong_length() {
        let db_key = [0xAB_u8; KEY_LENGTH];
        let iv = [0x12_u8; BLOCK_SIZE];

        let stage2_plain = [0x55_u8; 24];
        let mut s2_buf = [0_u8; 32];
        s2_buf[..24].copy_from_slice(&stage2_plain);
        let stage2_ct = TripleDesCbcEnc::new_from_slices(&db_key, &iv)
            .unwrap()
            .encrypt_padded::<Pkcs7Pad>(&mut s2_buf, 24)
            .unwrap()
            .to_vec();
        assert_eq!(stage2_ct.len(), 32);

        let mut stage1_plain = [0_u8; 32];
        for (i, byte) in stage2_ct.iter().enumerate() {
            stage1_plain[31 - i] = *byte;
        }
        let mut s1_buf = [0_u8; 40];
        s1_buf[..32].copy_from_slice(&stage1_plain);
        let blob = TripleDesCbcEnc::new_from_slices(&db_key, &MAGIC_CMS_IV)
            .unwrap()
            .encrypt_padded::<Pkcs7Pad>(&mut s1_buf, 32)
            .unwrap()
            .to_vec();

        let err = keyblob_decrypt(&blob, &iv, &db_key).unwrap_err();
        match err {
            Error::ParseFailed(msg) => {
                assert!(
                    msg.contains("invalid unwrapped key length"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected ParseFailed, got {other:?}"),
        }
    }
}
