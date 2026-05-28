//! Subcommand entry points + shared open-and-unlock helper.

pub(crate) mod dump;
pub(crate) mod hash;
pub(crate) mod version;

use std::path::PathBuf;

use anyhow::Context;
use keychainbreaker::{Error, Keychain, UnlockOptions};

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

/// Resolve the unlock credential from `-k` > `-p` > interactive prompt
/// and call [`Keychain::try_unlock`]. A `WrongKey` error is logged as a
/// warning and swallowed, leaving the keychain in partial-extraction
/// mode (matches Go's `openAndTryUnlock` semantics).
pub(crate) fn try_unlock_with_credential(
    kc: &mut Keychain,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    let opts = if let Some(key) = global.key.as_deref() {
        UnlockOptions::with_key(key)
    } else if let Some(password) = global.password.as_deref() {
        UnlockOptions::with_password(password)
    } else {
        let pw = read_password().context("failed to read password from terminal")?;
        UnlockOptions::with_password(pw)
    };

    match kc.try_unlock(opts) {
        Ok(()) => Ok(()),
        Err(e) if matches!(e, Error::WrongKey) => {
            eprintln!("Warning: {e}, exporting metadata only");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn default_keychain_path() -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().context("failed to determine user home directory")?;
    Ok(home.join("Library/Keychains/login.keychain-db"))
}

fn read_password() -> anyhow::Result<String> {
    rpassword::prompt_password("Enter keychain password: ")
        .context("interactive password prompt failed")
}
