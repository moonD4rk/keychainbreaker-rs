//! CLI-side [`Logger`] implementation that writes structured diagnostics
//! to stderr in the same shape as the Go CLI's `verbose.go`.

use std::fmt;
use std::fmt::Write as _;

use keychainbreaker::Logger;

/// Logger that emits `[LEVEL] msg key=value, key=value` lines to stderr.
///
/// Construct one per process and pass it to
/// `keychainbreaker::Keychain::builder().logger(...)`. Diagnostics are
/// suppressed entirely if the `--verbose` flag is not set (the CLI
/// installs `NopLogger` in that case rather than this type).
pub(crate) struct CliLogger;

impl Logger for CliLogger {
    fn debug(&self, msg: &str, fields: &[(&str, &dyn fmt::Display)]) {
        emit("DEBUG", msg, fields);
    }
    fn info(&self, msg: &str, fields: &[(&str, &dyn fmt::Display)]) {
        emit("INFO", msg, fields);
    }
    fn warn(&self, msg: &str, fields: &[(&str, &dyn fmt::Display)]) {
        emit("WARN", msg, fields);
    }
    fn error(&self, msg: &str, fields: &[(&str, &dyn fmt::Display)]) {
        emit("ERROR", msg, fields);
    }
}

fn emit(level: &str, msg: &str, fields: &[(&str, &dyn fmt::Display)]) {
    // Match Go's `[INFO]  msg                      key=value` alignment:
    // the bracketed level + trailing space takes 8 characters, then the
    // message is padded to 24 characters, then the key/value list.
    let level_tag = format!("[{level}]");
    let mut kv = String::new();
    for (i, (k, v)) in fields.iter().enumerate() {
        if i > 0 {
            kv.push_str(", ");
        }
        // Writing to a String is infallible; ignore the result deliberately.
        let _ = write!(kv, "{k}={v}");
    }
    eprintln!("{level_tag:<8}{msg:<24} {kv}");
}
