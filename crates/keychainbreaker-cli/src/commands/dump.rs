//! `keychainbreaker dump`: extract every record type to a JSON file.

use std::path::PathBuf;

use crate::cli::GlobalArgs;
use crate::output::{print_summary, write_json_file, DumpOutput};

const DEFAULT_OUTPUT_PATH: &str = "./keychain_dump.json";

pub(crate) fn run(global: &GlobalArgs) -> anyhow::Result<()> {
    let (mut kc, _path) = super::open_keychain(global)?;
    super::try_unlock_with_credential(&mut kc, global)?;

    let generic_passwords = kc.generic_passwords()?;
    let internet_passwords = kc.internet_passwords()?;
    let private_keys = kc.private_keys()?;
    let certificates = kc.certificates()?;

    let gps_len = generic_passwords.len();
    let ips_len = internet_passwords.len();
    let pks_len = private_keys.len();
    let certs_len = certificates.len();

    let output_path = global
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT_PATH));

    let dump = DumpOutput {
        generic_passwords,
        internet_passwords,
        private_keys,
        certificates,
    };
    write_json_file(&output_path, &dump)?;

    print_summary(
        gps_len,
        ips_len,
        pks_len,
        certs_len,
        kc.unlocked(),
        &output_path,
    );
    Ok(())
}
