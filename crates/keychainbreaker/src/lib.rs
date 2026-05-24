//! Parse and decrypt macOS Keychain files (`login.keychain-db`).
//!
//! This crate is a Rust port of the Go library at
//! <https://github.com/moond4rk/keychainbreaker>. See the design RFCs in
//! `rfcs/` at the repository root:
//!
//! - `rfcs/001-rust-port-overview.md` — motivation, scope, crate layout.
//! - `rfcs/002-library-api.md` — public surface (this crate).
//! - `rfcs/003-cli-design.md` — CLI behavior (`keychainbreaker-cli`).
//! - `rfcs/004-testing-and-verification.md` — test strategy.
//! - `rfcs/005-keychain-encryption.md` — algorithm spec (copied from Go).
//! - `rfcs/006-macos-26-keychain-change.md` — macOS 26 background.
//!
//! The implementation lands in phased milestones. This file is currently a
//! skeleton; see RFC 001 § 10 for the rollout plan.
