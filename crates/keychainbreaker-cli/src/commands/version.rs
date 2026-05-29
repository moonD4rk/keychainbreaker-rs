//! `keychainbreaker version`: print the Cargo package version.

// Returns `anyhow::Result` for symmetry with the other subcommand entry
// points, even though this command cannot fail today.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn run() -> anyhow::Result<()> {
    println!("keychainbreaker {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
