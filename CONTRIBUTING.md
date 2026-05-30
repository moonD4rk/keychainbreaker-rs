# Contributing

Thanks for considering a contribution. This project is a Rust port of <https://github.com/moond4rk/keychainbreaker>.

## Before You Start

1. **For non-trivial changes, open an issue first.** Anything that adds, removes, or reshapes the public API, changes a default, or alters CLI output should be discussed in an issue before the PR.

2. **Trivial changes are fine to PR directly** — typos, doc fixes, dependency bumps, small refactors.

## Development Workflow

```bash
# Format
cargo fmt --all

# Lint (CI uses -D warnings; match this locally)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Test
cargo test --workspace --all-features

# Build the library without default features (verifies the `serde` feature gate)
cargo build -p keychainbreaker --no-default-features

# Supply-chain check (requires cargo-deny; install via `cargo install cargo-deny`)
cargo deny check
```

CI runs the same gates on Ubuntu, macOS, and Windows.

## Coding Conventions

- **No `unsafe` code.** The workspace forbids it via the lint set.
- **No `.unwrap()` / `.expect()` / `panic!()` in library code.** Bubble errors via `Result<T, Error>`. Tests are allowed to unwrap.
- **Match the Go library's behavior.** When in doubt, look at <https://github.com/moond4rk/keychainbreaker>. Same input → same output.
- **Library does not depend on `clap`, `rpassword`, `serde_json`, or `anyhow`.** Those are CLI-only.
- **Default to no comments.** Use self-documenting names. Add a comment only when the *why* is non-obvious.

## Commit Messages

- Imperative present tense, ≤ 72 characters in the subject.
- Body explains *why*, not *what* — the diff already shows what.

## License

By contributing, you agree your contribution is licensed under the [Apache License, Version 2.0](LICENSE), same as the project.
