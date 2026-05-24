# keychainbreaker-rs

Rust library and CLI for parsing and decrypting macOS Keychain files (`login.keychain-db`).

**Status: early development (v0.1.0 pre-release).** The design is locked in via the RFC set under [`rfcs/`](rfcs/); the implementation is being delivered in milestones (see [RFC 001 § 10](rfcs/001-rust-port-overview.md)).

This is a Rust port of the Go library at <https://github.com/moond4rk/keychainbreaker>. The encryption mechanics are identical; this repository tracks Go upstream for crypto correctness and re-defines the surface for idiomatic Rust ergonomics.

## What It Does

- Reads `.keychain-db` files (binary parser, no macOS API calls — works on Linux and Windows too).
- Decrypts stored credentials using the keychain password (PBKDF2-HMAC-SHA1) or a recovered 24-byte master key.
- Extracts: generic passwords, internet passwords, PKCS#8 private keys, X.509 certificates.
- Exports `hashcat` mode 23100 / John the Ripper hash format for offline cracking.

## Crates

| Crate | Purpose |
|---|---|
| [`keychainbreaker`](crates/keychainbreaker/) | The library. Pure Rust, no `unsafe`, no platform-specific code. MSRV 1.74. |
| [`keychainbreaker-cli`](crates/keychainbreaker-cli/) | The `keychainbreaker` binary with `dump`, `hash`, `version` subcommands. MSRV 1.78. |

## Quick Start (planned API)

Library:

```rust
use keychainbreaker::{Keychain, UnlockOptions};

let mut kc = Keychain::open_file("/Users/me/Library/Keychains/login.keychain-db")?;
kc.unlock(UnlockOptions::with_password("hunter2"))?;

for entry in kc.generic_passwords()? {
    println!("{}: {}", entry.service, entry.plain_password);
}
```

CLI:

```bash
# Extract everything to JSON
keychainbreaker dump -p hunter2 -o dump.json

# Export hash for offline cracking
keychainbreaker hash > keychain.hash
hashcat -m 23100 keychain.hash wordlist.txt
```

## Building from Source

```bash
git clone https://github.com/moonD4rk/keychainbreaker-rs
cd keychainbreaker-rs

# Build everything
cargo build --workspace

# Run tests
cargo test --workspace --all-features

# Install the CLI
cargo install --path crates/keychainbreaker-cli
```

## Documentation

| Where | What |
|---|---|
| [`rfcs/001-rust-port-overview.md`](rfcs/001-rust-port-overview.md) | Migration motivation, scope, workspace layout, MSRV |
| [`rfcs/002-library-api.md`](rfcs/002-library-api.md) | Library public surface, error model, ownership |
| [`rfcs/003-cli-design.md`](rfcs/003-cli-design.md) | CLI subcommands, flags, output format |
| [`rfcs/004-testing-and-verification.md`](rfcs/004-testing-and-verification.md) | Test fixtures, integration tests, Go-parity verification |
| [`rfcs/005-keychain-encryption.md`](rfcs/005-keychain-encryption.md) | Encryption algorithm spec (copied from Go RFC 001) |
| [`rfcs/006-macos-26-keychain-change.md`](rfcs/006-macos-26-keychain-change.md) | macOS 26.4 v2 keychain background |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to propose changes |
| [`CLAUDE.md`](CLAUDE.md) | Project-specific Claude instructions (also useful as a quick reference for humans) |

## Ethics and Authorization

This tool is for authorized security testing, digital forensics, and credential recovery on systems you own or have explicit permission to access. Use against systems you do not own is illegal in most jurisdictions and is not what this project is for.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Same as the upstream Go project.
