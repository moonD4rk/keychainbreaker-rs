//! End-to-end tests against `tests/data/test.keychain-db`, mirroring the
//! Go reference's `keychainbreaker_test.go`. Expected plaintext values
//! come from the fixture's known content.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test code uses direct unwrap, expect, and index assertions"
)]

use keychainbreaker::{Credential, Error, Keychain};

const FIXTURE_PATH: &str = "tests/data/test.keychain-db";
const TEST_PASSWORD: &str = "keychainbreaker-test";
/// The 24-byte master key for the fixture (hex
/// `4557eb716bbf20200945109cf3b884af9aca72e890e47c07`).
const TEST_MASTER_KEY: [u8; 24] = [
    0x45, 0x57, 0xeb, 0x71, 0x6b, 0xbf, 0x20, 0x20, 0x09, 0x45, 0x10, 0x9c, 0xf3, 0xb8, 0x84, 0xaf,
    0x9a, 0xca, 0x72, 0xe8, 0x90, 0xe4, 0x7c, 0x07,
];
const EXPECTED_PLAINTEXT: &[u8] = b"password#123";

fn open_fixture() -> Keychain {
    Keychain::open_file(FIXTURE_PATH).expect("opening fixture must succeed")
}

#[test]
fn open_invalid_signature() {
    let err = Keychain::open_bytes(vec![0_u8; 64]).unwrap_err();
    assert!(
        matches!(err, Error::InvalidSignature),
        "expected InvalidSignature, got {err:?}"
    );
}

#[test]
fn open_truncated_file() {
    let err = Keychain::open_bytes(b"kych".to_vec()).unwrap_err();
    assert!(
        matches!(err, Error::ParseFailed(_)),
        "expected ParseFailed, got {err:?}"
    );
}

#[test]
fn open_succeeds_initially_locked() {
    let kc = open_fixture();
    assert!(!kc.unlocked());
}

#[test]
fn password_hash_matches_known_value() {
    let kc = open_fixture();
    let hash = kc.password_hash().unwrap();
    assert_eq!(
        hash,
        "$keychain$*fc143c45cce245f3e54fbb39141a894e2870dd85*26bca3823a0555be*07821bf723083271da09a3147cb6d73e415d7707099efc3273b36b01c975162bd388f4c5229979e556b74ec1ee3c7cdf"
    );
}

#[test]
fn extract_before_unlock_returns_locked() {
    let kc = open_fixture();
    let err = kc.generic_passwords().unwrap_err();
    assert!(matches!(err, Error::Locked));
}

#[test]
fn unlock_with_wrong_key_returns_wrong_key() {
    let mut kc = open_fixture();
    let err = kc.unlock(Credential::Key([0_u8; 24])).unwrap_err();
    assert!(matches!(err, Error::WrongKey));
    assert!(!kc.unlocked());
}

#[test]
fn unlock_with_wrong_password_returns_wrong_key() {
    let mut kc = open_fixture();
    let err = kc
        .unlock(Credential::password("wrong-password"))
        .unwrap_err();
    assert!(matches!(err, Error::WrongKey));
    assert!(!kc.unlocked());
}

#[test]
fn unlock_with_key_succeeds() {
    let mut kc = open_fixture();
    kc.unlock(Credential::Key(TEST_MASTER_KEY)).unwrap();
    assert!(kc.unlocked());
    assert_generic_passwords_full(&kc);
}

#[test]
fn unlock_with_password_succeeds() {
    let mut kc = open_fixture();
    kc.unlock(Credential::password(TEST_PASSWORD)).unwrap();
    assert!(kc.unlocked());
    assert_generic_passwords_full(&kc);
}

fn assert_generic_passwords_full(kc: &Keychain) {
    let entries = kc.generic_passwords().unwrap();
    assert_eq!(entries.len(), 2);
    let by_service: std::collections::HashMap<_, _> = entries
        .iter()
        .map(|e| (e.service.clone(), e.clone()))
        .collect();

    let moond4rk = &by_service["moond4rk.com"];
    assert_eq!(moond4rk.account, "admin");
    assert_eq!(moond4rk.password.as_deref(), Some(EXPECTED_PLAINTEXT));
    assert_eq!(moond4rk.description, "application password");
    assert_eq!(moond4rk.comment, "test generic password");
    assert_eq!(moond4rk.creator, "mD4k");
    assert_eq!(moond4rk.type_, "note");
    assert_eq!(moond4rk.print_name, "moond4rk.com");
    assert!(moond4rk.created.is_some());
    assert!(moond4rk.modified.is_some());

    let hbd = &by_service["HackBrowserData"];
    assert_eq!(hbd.account, "admin");
    assert_eq!(hbd.password.as_deref(), Some(EXPECTED_PLAINTEXT));
    assert_eq!(hbd.print_name, "HackBrowserData");
}

#[test]
fn internet_passwords_decrypt_correctly() {
    let mut kc = open_fixture();
    kc.unlock(Credential::password(TEST_PASSWORD)).unwrap();

    let entries = kc.internet_passwords().unwrap();
    assert_eq!(entries.len(), 2);
    let by_key: std::collections::HashMap<_, _> = entries
        .iter()
        .map(|e| (format!("{}:{}:{}", e.server, e.protocol, e.port), e.clone()))
        .collect();

    let https = &by_key["moond4rk.com:htps:443"];
    assert_eq!(https.account, "admin");
    assert_eq!(https.password.as_deref(), Some(EXPECTED_PLAINTEXT));
    assert_eq!(https.security_domain, "moond4rk.com");
    assert_eq!(https.path, "/login");
    assert_eq!(https.protocol, "htps");

    let smb = &by_key["moond4rk.com:smb :445"];
    assert_eq!(smb.account, "admin");
    assert_eq!(smb.password.as_deref(), Some(EXPECTED_PLAINTEXT));
    assert_eq!(smb.port, 445);
}

#[test]
fn private_keys_decrypt_and_parse_as_rsa_2048() {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;

    let mut kc = open_fixture();
    kc.unlock(Credential::password(TEST_PASSWORD)).unwrap();

    let keys = kc.private_keys().unwrap();
    assert_eq!(keys.len(), 1);
    let pk = &keys[0];
    assert_eq!(pk.print_name, "93B7C5C0");
    assert_eq!(pk.key_size, 2048);
    assert!(!pk.data.is_empty());

    let parsed = rsa::RsaPrivateKey::from_pkcs8_der(&pk.data)
        .expect("decrypted data must be a valid PKCS#8 RSA key");
    assert_eq!(parsed.n().bits(), 2048);
    parsed.validate().expect("RSA key must self-validate");
}

#[test]
fn certificates_parse_as_self_signed_x509() {
    use x509_parser::prelude::*;

    let mut kc = open_fixture();
    kc.unlock(Credential::password(TEST_PASSWORD)).unwrap();

    let certs = kc.certificates().unwrap();
    assert_eq!(certs.len(), 1);
    let c = &certs[0];
    assert_eq!(c.print_name, "keychainbreaker-test");
    assert!(!c.subject.is_empty());
    assert!(!c.issuer.is_empty());
    assert!(!c.serial.is_empty());

    let (_, cert) = X509Certificate::from_der(&c.data).expect("valid DER certificate");
    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .expect("subject CN present");
    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .expect("issuer CN present");
    assert_eq!(subject_cn, "keychainbreaker-test");
    assert_eq!(issuer_cn, "keychainbreaker-test"); // self-signed
}

#[test]
fn try_unlock_partial_mode_yields_metadata_without_decryption() {
    let mut kc = open_fixture();
    kc.try_unlock(None).unwrap();
    assert!(!kc.unlocked());

    let entries = kc.generic_passwords().unwrap();
    assert_eq!(entries.len(), 2);
    for entry in &entries {
        assert!(entry.password.is_none(), "encrypted bytes leaked");
        assert!(!entry.account.is_empty(), "metadata should still be there");
    }

    let certs = kc.certificates().unwrap();
    assert_eq!(certs.len(), 1);
    assert!(!certs[0].data.is_empty(), "certs are never encrypted");

    let keys = kc.private_keys().unwrap();
    assert_eq!(keys.len(), 1);
    assert!(
        keys[0].data.is_empty(),
        "private-key data should not leak in partial mode"
    );
}

#[test]
fn try_unlock_with_wrong_password_still_returns_metadata() {
    let mut kc = open_fixture();
    kc.try_unlock(Some(Credential::password("wrong-password")))
        .unwrap();
    assert!(!kc.unlocked());

    let entries = kc.generic_passwords().unwrap();
    assert_eq!(entries.len(), 2);
    for entry in &entries {
        assert!(entry.password.is_none());
    }
}

#[test]
fn try_unlock_then_unlock_restores_full_access() {
    let mut kc = open_fixture();
    kc.try_unlock(Some(Credential::password("wrong"))).unwrap();
    assert!(!kc.unlocked());

    kc.unlock(Credential::password(TEST_PASSWORD)).unwrap();
    assert!(kc.unlocked());

    let entries = kc.generic_passwords().unwrap();
    for entry in &entries {
        assert_eq!(entry.password.as_deref(), Some(EXPECTED_PLAINTEXT));
    }
}

#[test]
fn unlock_failure_resets_partial_state() {
    let mut kc = open_fixture();
    kc.try_unlock(None).unwrap();
    assert!(kc.generic_passwords().is_ok()); // partial mode active

    let err = kc.unlock(Credential::password("wrong")).unwrap_err();
    assert!(matches!(err, Error::WrongKey));
    assert!(!kc.unlocked());

    let err = kc.generic_passwords().unwrap_err();
    assert!(
        matches!(err, Error::Locked),
        "strict mode must be restored, got {err:?}"
    );
}

#[test]
fn builder_with_bytes_overrides_file() {
    let bytes = std::fs::read(FIXTURE_PATH).unwrap();
    let kc = Keychain::builder().bytes(bytes).open().unwrap();
    assert!(!kc.unlocked());
    assert!(kc.password_hash().is_ok());
}
