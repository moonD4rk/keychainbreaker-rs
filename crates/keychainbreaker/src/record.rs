//! Schema-driven record reader.
//!
//! Direct port of the `record` type and its `*Attr` accessors in
//! `parse.go`. A record is a flat sequence of fixed fields (size, blob
//! size, ...) followed by per-attribute offsets, followed by the blob
//! area and attribute payloads.
//!
//! Each attribute offset is `1`-based: a stored value of `0` means "no
//! value for this attribute"; any non-zero value `n` resolves to the
//! byte offset `n - 1` within the record buffer.

use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

use crate::error::{Error, Result};
use crate::parse::{ATOM_SIZE, read_u32, slice};
use crate::schema::TableSchema;

/// Number of fixed `u32` fields ahead of the per-attribute offsets:
/// `RecSize`, `RecNumber`, `unk1`, `unk2`, `BlobSize`, `Reserved`.
const RECORD_FIXED_FIELDS: usize = 6;

/// Byte length of a keychain time attribute (`YYYYMMDDhhmmssZ\0`).
const TIME_ATTR_LEN: usize = 16;

/// Format description for keychain time attributes (CSSM `TimeDate`).
/// The keychain stores `20060102150405Z`-style ASCII with a trailing
/// `\x00` padding byte; the trailing null is stripped before parsing.
const KEYCHAIN_TIME_FORMAT: &[time::format_description::BorrowedFormatItem<'_>] =
    format_description!("[year][month][day][hour][minute][second]Z");

/// A parsed keychain record with schema-driven attribute access.
#[derive(Debug)]
pub(crate) struct Record<'a> {
    /// The record-local byte buffer, sliced from the keychain file.
    pub(crate) buf: &'a [u8],
    /// The fixed-size blob area immediately after the per-attribute offsets.
    pub(crate) blob_data: &'a [u8],
    /// Everything after the per-attribute offsets (blob area + attribute
    /// payloads). Used by the private-key path which reads its own header.
    pub(crate) raw_payload: &'a [u8],
    attr_offsets: Vec<u32>,
    schema: &'a TableSchema,
}

/// Parse a single record at `offset` in `buf`, interpreting attributes
/// according to `schema`.
pub(crate) fn parse_record<'a>(
    buf: &'a [u8],
    offset: usize,
    schema: &'a TableSchema,
) -> Result<Record<'a>> {
    let rec_size = read_u32(buf, offset, "record size")? as usize;
    if rec_size == 0 {
        return Err(Error::ParseFailed(format!(
            "record at offset {offset} has zero size"
        )));
    }
    let rec_buf = slice(buf, offset, rec_size, "record body")?;

    let attr_count = schema.attrs.len();
    let header_len = (RECORD_FIXED_FIELDS + attr_count) * ATOM_SIZE;
    if rec_buf.len() < header_len {
        return Err(Error::ParseFailed(format!(
            "record too small for header: need {header_len}, got {}",
            rec_buf.len()
        )));
    }

    let blob_size = read_u32(rec_buf, 16, "record blobSize")? as usize;

    let mut attr_offsets = Vec::with_capacity(attr_count);
    for i in 0..attr_count {
        let pos = (RECORD_FIXED_FIELDS + i) * ATOM_SIZE;
        attr_offsets.push(read_u32(rec_buf, pos, "record attr offset")?);
    }

    let blob_data = if blob_size > 0 && header_len.saturating_add(blob_size) <= rec_buf.len() {
        slice(rec_buf, header_len, blob_size, "record blob area")?
    } else {
        &[]
    };
    let payload_len = rec_buf.len().saturating_sub(header_len);
    let raw_payload = slice(rec_buf, header_len, payload_len, "record payload")?;

    Ok(Record {
        buf: rec_buf,
        blob_data,
        raw_payload,
        attr_offsets,
        schema,
    })
}

impl Record<'_> {
    /// Resolve the byte offset (within `self.buf`) of a named attribute,
    /// honouring the `1`-based encoding. `None` if the attribute is not in
    /// the schema or the stored offset is zero.
    fn attr_offset(&self, name: &str) -> Option<usize> {
        let idx = self.schema.attr_index(name)?;
        let stored = *self.attr_offsets.get(idx)?;
        if stored == 0 {
            return None;
        }
        usize::try_from(stored - 1).ok()
    }

    /// Read a big-endian `u32` attribute. Returns `0` if the attribute is
    /// absent or its bytes cannot be read — matching Go's silent default.
    pub(crate) fn read_u32_attr(&self, name: &str) -> u32 {
        let Some(pos) = self.attr_offset(name) else {
            return 0;
        };
        read_u32(self.buf, pos, "attr u32").unwrap_or(0)
    }

    /// Read a length-prefixed UTF-8 string attribute with trailing-null
    /// trimming. Empty if absent or undecodable.
    pub(crate) fn read_string_attr(&self, name: &str) -> String {
        let Some(pos) = self.attr_offset(name) else {
            return String::new();
        };
        let Ok(length_u32) = read_u32(self.buf, pos, "attr string length") else {
            return String::new();
        };
        let length = length_u32 as usize;
        let start = pos.saturating_add(ATOM_SIZE);
        let Ok(payload) = slice(self.buf, start, length, "attr string payload") else {
            return String::new();
        };
        String::from_utf8_lossy(trim_trailing_nulls(payload)).into_owned()
    }

    /// Read a length-prefixed binary blob attribute. Empty if absent or
    /// out of bounds.
    pub(crate) fn read_blob_attr(&self, name: &str) -> Vec<u8> {
        let Some(pos) = self.attr_offset(name) else {
            return Vec::new();
        };
        let Ok(length_u32) = read_u32(self.buf, pos, "attr blob length") else {
            return Vec::new();
        };
        let length = length_u32 as usize;
        if length == 0 {
            return Vec::new();
        }
        let start = pos.saturating_add(ATOM_SIZE);
        let Ok(payload) = slice(self.buf, start, length, "attr blob payload") else {
            return Vec::new();
        };
        payload.to_vec()
    }

    /// Read a `TimeDate` attribute (16 ASCII bytes `YYYYMMDDhhmmssZ\0`).
    /// `None` if absent, all-null, or unparseable.
    pub(crate) fn read_time_attr(&self, name: &str) -> Option<OffsetDateTime> {
        let pos = self.attr_offset(name)?;
        let raw = slice(self.buf, pos, TIME_ATTR_LEN, "attr time").ok()?;
        let trimmed = trim_trailing_nulls(raw);
        if trimmed.is_empty() {
            return None;
        }
        let text = core::str::from_utf8(trimmed).ok()?;
        let pdt = PrimitiveDateTime::parse(text, KEYCHAIN_TIME_FORMAT).ok()?;
        Some(pdt.assume_utc())
    }

    /// Read a 4-byte FourCC attribute (no length prefix), trimming
    /// trailing nulls.
    pub(crate) fn read_fourcc_attr(&self, name: &str) -> String {
        let Some(pos) = self.attr_offset(name) else {
            return String::new();
        };
        let Ok(bytes) = slice(self.buf, pos, ATOM_SIZE, "attr fourcc") else {
            return String::new();
        };
        String::from_utf8_lossy(trim_trailing_nulls(bytes)).into_owned()
    }
}

fn trim_trailing_nulls(s: &[u8]) -> &[u8] {
    let trimmed_len = s.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    s.split_at(trimmed_len.min(s.len())).0
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "test code uses direct expect assertions"
    )]

    use super::*;
    use crate::schema::{ATTR_FORMAT_STRING, ATTR_FORMAT_UINT32, AttrDef};

    fn schema_with(names: &[&str]) -> TableSchema {
        let attrs = names
            .iter()
            .map(|n| AttrDef {
                name: (*n).to_owned(),
                format: ATTR_FORMAT_STRING,
            })
            .collect();
        TableSchema::build(0, attrs)
    }

    fn record_with_offsets<'a>(
        buf: &'a [u8],
        offsets: Vec<u32>,
        schema: &'a TableSchema,
    ) -> Record<'a> {
        Record {
            buf,
            blob_data: &[],
            raw_payload: &[],
            attr_offsets: offsets,
            schema,
        }
    }

    #[test]
    fn trim_trailing_nulls_removes_padding() {
        assert_eq!(trim_trailing_nulls(b"abc\0\0\0"), b"abc");
        assert_eq!(trim_trailing_nulls(b"abc"), b"abc");
        assert_eq!(trim_trailing_nulls(b"\0\0\0").len(), 0);
        assert_eq!(trim_trailing_nulls(b"").len(), 0);
    }

    #[test]
    fn attr_offset_handles_one_based_and_zero_marker() {
        let schema = schema_with(&["first", "second"]);
        let rec = record_with_offsets(&[], vec![0, 42], &schema);
        assert_eq!(rec.attr_offset("first"), None);
        assert_eq!(rec.attr_offset("second"), Some(41));
        assert_eq!(rec.attr_offset("missing"), None);
    }

    #[test]
    fn read_u32_attr_decodes_big_endian() {
        let schema = TableSchema::build(
            0,
            vec![AttrDef {
                name: "v".to_owned(),
                format: ATTR_FORMAT_UINT32,
            }],
        );
        // Place big-endian 0x12345678 at index 0 of the record buffer.
        let buf: &[u8] = &[0x12, 0x34, 0x56, 0x78];
        let rec = record_with_offsets(buf, vec![1], &schema);
        assert_eq!(rec.read_u32_attr("v"), 0x1234_5678);
    }

    #[test]
    fn read_string_attr_trims_nulls() {
        let schema = schema_with(&["s"]);
        // Length prefix 0x00000005, then "abc\0\0".
        let buf: &[u8] = &[0, 0, 0, 5, b'a', b'b', b'c', 0, 0];
        let rec = record_with_offsets(buf, vec![1], &schema);
        assert_eq!(rec.read_string_attr("s"), "abc");
    }

    #[test]
    fn read_blob_attr_returns_bytes() {
        let schema = schema_with(&["b"]);
        let buf: &[u8] = &[0, 0, 0, 3, 0xDE, 0xAD, 0xBE];
        let rec = record_with_offsets(buf, vec![1], &schema);
        assert_eq!(rec.read_blob_attr("b"), vec![0xDE, 0xAD, 0xBE]);
    }

    #[test]
    fn read_time_attr_parses_keychain_format() {
        let schema = schema_with(&["t"]);
        // 16-byte time attribute: "20230415120530Z\0"
        let buf: &[u8] = b"20230415120530Z\0";
        let rec = record_with_offsets(buf, vec![1], &schema);
        let parsed = rec.read_time_attr("t").expect("parse succeeded");
        assert_eq!(parsed.year(), 2023);
        assert_eq!(u8::from(parsed.month()), 4);
        assert_eq!(parsed.day(), 15);
        assert_eq!(parsed.hour(), 12);
        assert_eq!(parsed.minute(), 5);
        assert_eq!(parsed.second(), 30);
    }

    #[test]
    fn read_fourcc_attr_round_trip() {
        let schema = schema_with(&["f"]);
        let buf: &[u8] = b"abcd";
        let rec = record_with_offsets(buf, vec![1], &schema);
        assert_eq!(rec.read_fourcc_attr("f"), "abcd");
    }

    #[test]
    fn missing_attr_returns_defaults() {
        let schema = schema_with(&["s"]);
        let rec = record_with_offsets(&[], vec![0], &schema);
        assert_eq!(rec.read_u32_attr("s"), 0);
        assert_eq!(rec.read_string_attr("s"), "");
        assert!(rec.read_blob_attr("s").is_empty());
        assert!(rec.read_time_attr("s").is_none());
        assert_eq!(rec.read_fourcc_attr("s"), "");
    }
}
