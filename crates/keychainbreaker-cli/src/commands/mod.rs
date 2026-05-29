//! Subcommand entry points + shared open-and-unlock helper.

pub(crate) mod dump;
pub(crate) mod hash;
pub(crate) mod version;

use std::path::PathBuf;

use anyhow::Context;
use keychainbreaker::{Credential, Keychain};

use crate::cli::GlobalArgs;
use crate::logger::CliLogger;

/// Open the keychain at `global.file` (or the default macOS login path),
/// optionally installing the verbose [`CliLogger`]. Prints the
/// `Keychain: PATH` banner to stderr to match the Go CLI.
pub(crate) fn open_keychain(global: &GlobalArgs) -> anyhow::Result<(Keychain, PathBuf)> {
    let path = match &global.file {
        Some(p) => p.clone(),
        None => default_keychain_path()?,
    };
    eprintln!("Keychain: {}", path.display());

    let kc = if global.verbose {
        Keychain::builder().file(&path).logger(CliLogger).open()?
    } else {
        Keychain::open_file(&path)?
    };
    Ok((kc, path))
}

/// Resolve the unlock credential from `-k` > `-p` > interactive prompt and call
/// [`Keychain::try_unlock`]. A wrong key / password is not an error here: the
/// keychain stays in partial-extraction mode and a warning is printed (matches
/// Go's `openAndTryUnlock` semantics).
pub(crate) fn try_unlock_with_credential(
    kc: &mut Keychain,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    let cred = if let Some(key) = global.key.as_deref() {
        Credential::Key(parse_master_key(key)?)
    } else if let Some(password) = global.password.as_deref() {
        Credential::password(password)
    } else {
        Credential::password(read_password().context("failed to read password from terminal")?)
    };

    kc.try_unlock(Some(cred))?;
    if !kc.unlocked() {
        eprintln!("Warning: wrong key or password, exporting metadata only");
    }
    Ok(())
}

/// Decode a hex-encoded 24-byte master key, tolerating surrounding whitespace
/// and a leading `0x`.
fn parse_master_key(hex_key: &str) -> anyhow::Result<[u8; 24]> {
    let cleaned = hex_key.trim();
    let cleaned = cleaned.strip_prefix("0x").unwrap_or(cleaned);
    let bytes = hex::decode(cleaned).context("master key is not valid hex")?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| anyhow::anyhow!("master key must be 24 bytes, got {}", b.len()))
}

fn default_keychain_path() -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().context("failed to determine user home directory")?;
    Ok(home.join("Library/Keychains/login.keychain-db"))
}

fn read_password() -> anyhow::Result<String> {
    rpassword::prompt_password("Enter keychain password: ")
        .context("interactive password prompt failed")
}
