//! Logger trait for diagnostic output.

use core::fmt;

/// Diagnostic logger used internally by the parser and unlock pipeline.
///
/// Implement this trait and pass an instance via `KeychainBuilder::logger`
/// to observe internal events. The library does not log anything when the
/// default [`NopLogger`] is used.
///
/// The trait is intentionally minimal and object-safe so it can be stored
/// as `Box<dyn Logger>` without generics on the public API.
pub trait Logger: Send + Sync {
    /// Debug-level event with optional structured fields.
    fn debug(&self, msg: &str, fields: &[(&str, &dyn fmt::Display)]);
    /// Info-level event with optional structured fields.
    fn info(&self, msg: &str, fields: &[(&str, &dyn fmt::Display)]);
    /// Warning event with optional structured fields.
    fn warn(&self, msg: &str, fields: &[(&str, &dyn fmt::Display)]);
    /// Error event (non-fatal) with optional structured fields.
    fn error(&self, msg: &str, fields: &[(&str, &dyn fmt::Display)]);
}

/// Logger implementation that discards every event. Used by default.
#[derive(Debug, Default, Clone, Copy)]
pub struct NopLogger;

impl Logger for NopLogger {
    fn debug(&self, _msg: &str, _fields: &[(&str, &dyn fmt::Display)]) {}
    fn info(&self, _msg: &str, _fields: &[(&str, &dyn fmt::Display)]) {}
    fn warn(&self, _msg: &str, _fields: &[(&str, &dyn fmt::Display)]) {}
    fn error(&self, _msg: &str, _fields: &[(&str, &dyn fmt::Display)]) {}
}
