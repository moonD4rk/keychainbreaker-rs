# keychainbreaker-rs

Rust library and CLI for parsing and decrypting macOS Keychain files (`login.keychain-db`).

**Status: early development (v0.1.0 pre-release).** The API is still being refined for idiomatic Rust ahead of the first release.

This is a Rust port of the Go library at <https://github.com/moond4rk/keychainbreaker>. The encryption mechanics are identical; this repository tracks Go upstream for crypto correctness and re-defines the surface for idiomatic Rust ergonomics.

## What It Does

- Reads `.keychain-db` files with a pure binary parser — no macOS APIs, so it also runs on Linux and Windows.
- Decrypts stored credentials from the keychain password (PBKDF2-HMAC-SHA1) or a recovered 24-byte master key.
- Extracts generic passwords, internet passwords, PKCS#8 private keys, and X.509 certificates.
- Exports a `hashcat` mode 23100 / John the Ripper hash for offline cracking — no password required.

## Crates

| Crate | Purpose |
|---|---|
| [`keychainbreaker`](crates/keychainbreaker/) | The library. Pure Rust, no `unsafe`, no platform-specific code. MSRV 1.74. |
| [`keychainbreaker-cli`](crates/keychainbreaker-cli/) | The `keychainbreaker` binary with `dump`, `hash`, and `version` subcommands. MSRV 1.78. |

## Quick Start

### Library

```rust
use keychainbreaker::{Credential, Keychain};

let mut kc = Keychain::open_file("/Users/me/Library/Keychains/login.keychain-db")?;
kc.unlock(Credential::password("hunter2"))?;

for entry in kc.generic_passwords()? {
    if let Some(pw) = &entry.password {
        println!("{}: {}", entry.service, String::from_utf8_lossy(pw));
    }
}
```

Record types are serializable through the default-on `serde` feature. Turn it off if you only need decryption:

```toml
keychainbreaker = { version = "0.1", default-features = false }
```

### CLI

```bash
# Extract everything to JSON (prompts for the password when -p is omitted)
keychainbreaker dump -p hunter2 -o dump.json

# Same, with full diagnostics on stderr
keychainbreaker dump -p hunter2 -v

# Export a crackable hash — no unlock needed
keychainbreaker hash > keychain.hash
hashcat -m 23100 keychain.hash wordlist.txt
```

A wrong or missing password still yields a metadata-only dump (record names and timestamps, no secrets) rather than an error. To decrypt with a recovered 24-byte master key instead of a password, pass `-k <hex>`.

## Compatibility

- **Any host OS.** The parser is pure Rust and never calls macOS APIs, so a `.keychain-db` copied to Linux or Windows decrypts exactly as it does on macOS.
- **macOS 26.4+ (v2 keychains).** A fresh 26.4 install — or an upgrade to it — re-encrypts the login keychain to `blobVersion=2`, binding decryption to the device's Secure Enclave. Such keychains **cannot be decrypted offline** from the file and password alone; decryption needs a 24-byte master key recovered on the originating machine, supplied via `-k` / `Credential::Key`. Older `blobVersion=1` keychains are unaffected.
- **JSON output vs. Go.** Byte-identical, except that missing/zero timestamps are omitted here instead of emitted as `"0001-01-01T00:00:00Z"`.

## Building from Source

```bash
git clone https://github.com/moonD4rk/keychainbreaker-rs
cd keychainbreaker-rs

cargo build --workspace                            # build library + CLI
cargo test  --workspace --all-features             # run the test suite
cargo install --path crates/keychainbreaker-cli    # install the `keychainbreaker` binary
```

## Ethics and Authorization

This tool is for authorized security testing, digital forensics, and credential recovery on systems you own or have explicit permission to access. Using it against systems you do not own is illegal in most jurisdictions and is not what this project is for.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Same as the upstream Go project.
