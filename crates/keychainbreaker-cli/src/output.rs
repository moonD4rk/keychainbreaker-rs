//! JSON dump layout and the stderr summary formatter.

use std::io::Write as _;
use std::path::Path;

use anyhow::Context;
use keychainbreaker::{Certificate, GenericPassword, InternetPassword, PrivateKey};
use serde::Serialize;

/// The top-level JSON object emitted by `keychainbreaker dump`. Field
/// order, key naming, and empty-field omission all match Go's
/// `dumpOutput` (`cmd/keychainbreaker/cmd/output.go`).
#[derive(Serialize)]
pub(crate) struct DumpOutput {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) generic_passwords: Vec<GenericPassword>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) internet_passwords: Vec<InternetPassword>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) private_keys: Vec<PrivateKey>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) certificates: Vec<Certificate>,
}

/// Write `output` as pretty-printed JSON (2-space indent) to `path`,
/// matching Go's `json.Encoder.SetIndent("", "  ")` + trailing newline
/// behaviour.
pub(crate) fn write_json_file(path: &Path, output: &DumpOutput) -> anyhow::Result<()> {
    let file = std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut writer = std::io::BufWriter::new(file);
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"  ");
    let mut ser = serde_json::Serializer::with_formatter(&mut writer, formatter);
    output
        .serialize(&mut ser)
        .with_context(|| format!("serialize JSON to {}", path.display()))?;
    // Go's json.Encoder appends a trailing newline; serde_json does not.
    writer
        .write_all(b"\n")
        .with_context(|| format!("write trailing newline to {}", path.display()))?;
    writer
        .flush()
        .with_context(|| format!("flush {}", path.display()))?;
    Ok(())
}

/// Print the per-table extraction summary to stderr in the format
/// `printDumpSummary` from `cmd/keychainbreaker/cmd/output.go` produces.
pub(crate) fn print_summary(
    gps_len: usize,
    ips_len: usize,
    pks_len: usize,
    certs_len: usize,
    unlocked: bool,
    output_path: &Path,
) {
    let suffix = if unlocked { "" } else { " (metadata only)" };
    eprintln!("Extracted:");
    eprintln!("  Generic passwords:  {gps_len}{suffix}");
    eprintln!("  Internet passwords: {ips_len}{suffix}");
    eprintln!("  Private keys:       {pks_len}{suffix}");
    eprintln!("  Certificates:       {certs_len}");
    eprintln!("Output: {}", output_path.display());
}
