# CLAUDE.md

Project-specific instructions for Claude. Global rules in `~/.claude/CLAUDE.md` still apply.

## Architecture

Rust port of the Go library `github.com/moond4rk/keychainbreaker`. Cargo workspace with two member crates:

- `crates/keychainbreaker/` — library. No CLI dependencies.
- `crates/keychainbreaker-cli/` — `keychainbreaker` binary.

Both crates are edition 2024, MSRV 1.88 (the floor `time` imposes today).

## Development Workflow

```bash
cargo +nightly fmt --all                                             # format (nightly-only rustfmt options)
cargo clippy --workspace --all-targets --all-features -- -D warnings  # lint
cargo test  --workspace --all-features                                # test
cargo build -p keychainbreaker --no-default-features                  # verify serde gate
cargo deny check                                                      # supply-chain
```

Formatting requires nightly rustfmt — `rustfmt.toml` uses `group_imports` / `imports_granularity`, which are nightly-only. Only formatting needs nightly; everything else (build, test, MSRV) stays on stable.

CI runs all of these on Linux / macOS / Windows. A PR must pass them. Workspace lints deny bare `#[allow]`: every suppression must be `#[expect(<lints>, reason = "...")]`, listing only the lints that actually fire (an unfulfilled `expect` is itself an error). In tests that means a module-level `#![expect(clippy::unwrap_used, clippy::expect_used, reason = "...")]` with whatever the test code triggers.

## Core Rules

- No `unsafe` (`unsafe_code = forbid`).
- Library code uses `Result`, not `panic!`/`unwrap`/`expect`.
- Library does not depend on `clap` / `rpassword` / `serde_json` / `anyhow`.
- New root-level files must be added to `.gitignore` (whitelist mode — root is ignored by default).
