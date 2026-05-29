//! Integration tests for the `keychainbreaker` binary.
//!
//! Scope: only the contracts that are CLI-specific. The library's own
//! end-to-end suite in `crates/keychainbreaker/tests/end_to_end.rs`
//! already exercises every unlock method, all four extractors, and the
//! `password_hash` computation against the same fixture — we do **not**
//! re-verify those through subprocess calls.
//!
//! What stays here:
//!
//! 1. `hash` byte-for-byte parity with the Go reference. The library tests
//!    confirm `password_hash()` is correct; this one confirms the CLI pipes
//!    that string to stdout unchanged.
//! 2. `dump` swallowing `WrongKey` into a `(metadata only)` warning and
//!    still exiting `0`. CLI-only logic — the library's `try_unlock`
//!    surfaces the error as `Err(WrongKey)`.
//! 3. `version` smoke test — proves the binary launches and clap is
//!    wired correctly.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unused_results
)]

use std::path::PathBuf;

use assert_cmd::Command;
use predicates::str as pstr;
use tempfile::tempdir;

const EXPECTED_HASH: &str = "$keychain$*fc143c45cce245f3e54fbb39141a894e2870dd85*26bca3823a0555be*07821bf723083271da09a3147cb6d73e415d7707099efc3273b36b01c975162bd388f4c5229979e556b74ec1ee3c7cdf";

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../keychainbreaker/tests/data/test.keychain-db")
}

fn bin() -> Command {
    Command::cargo_bin("keychainbreaker").expect("binary built")
}

#[test]
fn version_prints_cargo_package_version() {
    bin()
        .arg("version")
        .assert()
        .success()
        .stdout(format!("keychainbreaker {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn hash_matches_go_reference_byte_for_byte() {
    bin()
        .arg("-f")
        .arg(fixture_path())
        .arg("hash")
        .assert()
        .success()
        .stdout(format!("{EXPECTED_HASH}\n"));
}

#[test]
fn dump_with_hex_key_and_0x_prefix_decrypts() {
    let tmp = tempdir().unwrap();
    let out = tmp.path().join("dump.json");
    bin()
        .arg("-f")
        .arg(fixture_path())
        .arg("-k")
        .arg("0x4557eb716bbf20200945109cf3b884af9aca72e890e47c07")
        .arg("-o")
        .arg(&out)
        .arg("dump")
        .assert()
        .success();

    let contents = std::fs::read_to_string(&out).unwrap();
    assert!(
        contents.contains("password#123"),
        "hex-key unlock (with 0x prefix) must decrypt the fixture"
    );
}

#[test]
fn dump_with_wrong_password_warns_and_exits_zero() {
    let tmp = tempdir().unwrap();
    let out = tmp.path().join("dump.json");
    bin()
        .arg("-f")
        .arg(fixture_path())
        .arg("-p")
        .arg("wrong-password")
        .arg("-o")
        .arg(&out)
        .arg("dump")
        .assert()
        .success()
        .stderr(pstr::contains("Warning: wrong key or password"))
        .stderr(pstr::contains("(metadata only)"));

    let contents = std::fs::read_to_string(&out).unwrap();
    assert!(
        !contents.contains("password#123"),
        "plaintext must not leak on wrong-password dump"
    );
}
