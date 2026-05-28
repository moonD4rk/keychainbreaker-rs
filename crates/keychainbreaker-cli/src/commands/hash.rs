//! `keychainbreaker hash`: print the offline-cracking hash to stdout.

use crate::cli::GlobalArgs;

pub(crate) fn run(global: &GlobalArgs) -> anyhow::Result<()> {
    let (kc, _path) = super::open_keychain(global)?;
    let hash = kc.password_hash()?;
    println!("{hash}");
    Ok(())
}
