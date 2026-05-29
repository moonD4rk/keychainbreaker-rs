# CLAUDE.md

Project-specific instructions for Claude. Global rules in `~/.claude/CLAUDE.md` still apply.

## Architecture

Rust port of the Go library `github.com/moond4rk/keychainbreaker`. Cargo workspace with two member crates:

- `crates/keychainbreaker/` — library, MSRV 1.74. No CLI dependencies.
- `crates/keychainbreaker-cli/` — `keychainbreaker` binary, MSRV 1.78.

## Development Workflow

```bash
cargo fmt --all                                                       # format
cargo clippy --workspace --all-targets --all-features -- -D warnings  # lint
cargo test  --workspace --all-features                                # test
cargo build -p keychainbreaker --no-default-features                  # verify serde gate
cargo deny check                                                      # supply-chain
```

CI runs all of these on Linux / macOS / Windows. A PR must pass them. When adding tests, put `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` at the top of integration test files — workspace lints are strict by default and tests routinely use these.

## Core Rules

- No `unsafe` (`unsafe_code = forbid`).
- Library code uses `Result`, not `panic!`/`unwrap`/`expect`.
- Library does not depend on `clap` / `rpassword` / `serde_json` / `anyhow`.
- New root-level files must be added to `.gitignore` (whitelist mode — root is ignored by default).

## Where to Read

The Go reference implementation (same algorithm, behavior to match) lives at
`/Users/moond4rk/Developer/golang/mygo/keychainbreaker/`.
