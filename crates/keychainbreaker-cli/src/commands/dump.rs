//! `keychainbreaker dump`: extract every record type to a JSON file.

use std::path::PathBuf;

use crate::cli::GlobalArgs;
use crate::output::{DumpOutput, print_summary, write_json_file};

const DEFAULT_OUTPUT_PATH: &str = "./keychain_dump.json";

pub(crate) fn run(global: &GlobalArgs) -> anyhow::Result<()> {
    let (mut kc, _path) = super::open_keychain(global)?;
    super::try_unlock_with_credential(&mut kc, global)?;

    let dump = DumpOutput {
        generic_passwords: kc.generic_passwords()?,
        internet_passwords: kc.internet_passwords()?,
        private_keys: kc.private_keys()?,
        certificates: kc.certificates()?,
    };

    let output_path = global
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT_PATH));
    write_json_file(&output_path, &dump)?;

    print_summary(&dump, kc.unlocked(), &output_path);
    Ok(())
}
