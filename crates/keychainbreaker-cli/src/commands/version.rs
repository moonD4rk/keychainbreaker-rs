//! `keychainbreaker version`: print the Cargo package version.

#[expect(
    clippy::unnecessary_wraps,
    reason = "returns Result for symmetry with the other subcommand entry points"
)]
pub(crate) fn run() -> anyhow::Result<()> {
    println!("keychainbreaker {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
