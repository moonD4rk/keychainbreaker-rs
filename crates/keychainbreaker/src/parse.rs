//! Binary readers for the keychain file format.
//!
//! Direct port of `parse.go` in the Go reference. Every reader validates
//! its slice up front and returns [`Error::ParseFailed`] with a short
//! context-tagged message on any out-of-range read, matching the
//! `errors.New("file too small for header")`-style strings the Go code
//! uses.

// All readers here are `pub(crate)` consumers of M3's open/unlock
// pipeline. Until M3 lands they are exercised only by the in-module
// tests, so non-test builds see every symbol as unused.
#![allow(dead_code)]

use crate::error::{Error, Result};

/// Fixed-format byte lengths (`headerSize` and friends in `parse.go`).
pub(crate) const HEADER_SIZE: usize = 20;
pub(crate) const SCHEMA_SIZE: usize = 8;
pub(crate) const TABLE_HEADER_LEN: usize = 28;
pub(crate) const DB_BLOB_SIZE: usize = 92;
pub(crate) const KEY_BLOB_LEN: usize = 24;
pub(crate) const SSGP_HEADER_LEN: usize = 28;
pub(crate) const ATOM_SIZE: usize = 4;

/// Fixed offset from a Metadata table's base to its embedded `DBBlob`.
pub(crate) const METADATA_OFFSET_ADJUSTMENT: usize = 0x38;

/// First four bytes of a valid keychain file.
pub(crate) const KEYCHAIN_SIGNATURE: &[u8; 4] = b"kych";

/// Magic at the start of every SSGP-encrypted password blob.
pub(crate) const SECURE_STORAGE_GROUP: &[u8; 4] = b"ssgp";

/// Magic at the start of every key blob in a `SymmetricKey` or
/// `PrivateKey` record.
pub(crate) const KEY_BLOB_MAGIC: u32 = 0xFADE_0711;

/// Slice `buf[start..start+len]` or report a parse error tagged with `ctx`.
///
/// All multi-byte reads in this module funnel through this helper so the
/// crate avoids `clippy::indexing_slicing` warnings without sprinkling
/// `#[allow]` attributes.
pub(crate) fn slice<'a>(
    buf: &'a [u8],
    start: usize,
    len: usize,
    ctx: &'static str,
) -> Result<&'a [u8]> {
    let end = start.checked_add(len).ok_or_else(|| {
        Error::ParseFailed(format!("{ctx}: offset {start}+{len} overflows usize"))
    })?;
    buf.get(start..end).ok_or_else(|| {
        Error::ParseFailed(format!(
            "{ctx}: range {start}..{end} out of bounds (buf len {})",
            buf.len()
        ))
    })
}

/// Read a big-endian `u32` at `buf[off..off+4]`.
pub(crate) fn read_u32(buf: &[u8], off: usize, ctx: &'static str) -> Result<u32> {
    let bytes = slice(buf, off, ATOM_SIZE, ctx)?;
    let arr: [u8; 4] = bytes
        .try_into()
        .map_err(|_| Error::ParseFailed(format!("{ctx}: failed to read 4 bytes at {off}")))?;
    Ok(u32::from_be_bytes(arr))
}

/// Read a fixed-length byte array at `buf[off..off+N]`.
pub(crate) fn read_array<const N: usize>(
    buf: &[u8],
    off: usize,
    ctx: &'static str,
) -> Result<[u8; N]> {
    let bytes = slice(buf, off, N, ctx)?;
    bytes
        .try_into()
        .map_err(|_| Error::ParseFailed(format!("{ctx}: failed to read {N} bytes at {off}")))
}

/// The 20-byte `applDBHeader` at the start of every keychain file.
///
/// `inner_size` mirrors the file's `headerSize` field (typically 16 — the
/// self-reported header length before the schema atom). Field renamed from
/// the Go `headerSize` to keep clippy happy about struct-name prefixes.
#[derive(Debug, Clone)]
pub(crate) struct Header {
    pub(crate) signature: [u8; 4],
    pub(crate) version: u32,
    pub(crate) inner_size: u32,
    pub(crate) schema_off: u32,
    pub(crate) auth_off: u32,
}

pub(crate) fn parse_header(buf: &[u8]) -> Result<Header> {
    if buf.len() < HEADER_SIZE {
        return Err(Error::ParseFailed("file too small for header".into()));
    }
    Ok(Header {
        signature: read_array(buf, 0, "header signature")?,
        version: read_u32(buf, 4, "header version")?,
        inner_size: read_u32(buf, 8, "header headerSize")?,
        schema_off: read_u32(buf, 12, "header schemaOff")?,
        auth_off: read_u32(buf, 16, "header authOff")?,
    })
}

/// The table-count atom plus its per-table offsets that immediately follow
/// the file header.
#[derive(Debug, Clone)]
pub(crate) struct SchemaIndex {
    pub(crate) schema_size: u32,
    pub(crate) table_offsets: Vec<u32>,
}

pub(crate) fn parse_schema(buf: &[u8], offset: u32) -> Result<SchemaIndex> {
    let start = offset as usize;
    let schema_size = read_u32(buf, start, "schema size")?;
    let table_count = read_u32(buf, start + ATOM_SIZE, "schema tableCount")?;
    let count = table_count as usize;
    let base = HEADER_SIZE + SCHEMA_SIZE;
    let mut table_offsets = Vec::with_capacity(count);
    for i in 0..count {
        let pos = base + i * ATOM_SIZE;
        table_offsets.push(read_u32(buf, pos, "schema table offset")?);
    }
    Ok(SchemaIndex {
        schema_size,
        table_offsets,
    })
}

/// Parsed `tableInfo`: the 28-byte table header plus the list of record
/// offsets relative to the table base.
#[derive(Debug, Clone)]
pub(crate) struct TableHeader {
    pub(crate) table_id: u32,
    pub(crate) record_count: u32,
    pub(crate) record_offsets: Vec<u32>,
    /// Absolute offset of this table in the keychain buffer.
    pub(crate) base_offset: usize,
}

pub(crate) fn parse_table(buf: &[u8], offset: usize) -> Result<TableHeader> {
    // Anchor the bounds check on the full 28-byte header; record offsets
    // are validated individually below so we don't reject a partially
    // populated tail (matching Go's `break` behaviour).
    let _header_bounds = slice(buf, offset, TABLE_HEADER_LEN, "table header")?;
    let table_id = read_u32(buf, offset + 4, "table id")?;
    let record_count = read_u32(buf, offset + 8, "table recordCount")?;

    let rec_base = offset + TABLE_HEADER_LEN;
    let count = record_count as usize;
    let mut record_offsets = Vec::new();
    for i in 0..count {
        let pos = rec_base + i * ATOM_SIZE;
        // Stop at the first out-of-bounds entry; trailing zero-padding is
        // expected on some keychains.
        let Ok(v) = read_u32(buf, pos, "table record offset") else {
            break;
        };
        if v != 0 && v % 4 == 0 {
            record_offsets.push(v);
        }
    }
    Ok(TableHeader {
        table_id,
        record_count,
        record_offsets,
        base_offset: offset,
    })
}

/// 92-byte database encryption blob located at
/// `metadata_table.base_offset + METADATA_OFFSET_ADJUSTMENT`.
#[derive(Debug, Clone)]
pub(crate) struct DbBlob {
    pub(crate) magic: u32,
    pub(crate) blob_version: u32,
    pub(crate) start_crypto_blob: u32,
    pub(crate) total_length: u32,
    /// 20-byte PBKDF2 salt.
    pub(crate) salt: [u8; 20],
    /// 8-byte 3DES-CBC IV for the wrapped DB key.
    pub(crate) iv: [u8; 8],
}

pub(crate) fn parse_db_blob(buf: &[u8]) -> Result<DbBlob> {
    if buf.len() < DB_BLOB_SIZE {
        return Err(Error::ParseFailed("db blob buffer too small".into()));
    }
    Ok(DbBlob {
        magic: read_u32(buf, 0, "dbBlob magic")?,
        blob_version: read_u32(buf, 4, "dbBlob blobVersion")?,
        start_crypto_blob: read_u32(buf, 8, "dbBlob startCryptoBlob")?,
        total_length: read_u32(buf, 12, "dbBlob totalLength")?,
        salt: read_array(buf, 44, "dbBlob salt")?,
        iv: read_array(buf, 64, "dbBlob iv")?,
    })
}

/// Secure Storage Group (SSGP) header that prefixes every encrypted
/// password blob in a `GenericPassword` or `InternetPassword` record.
#[derive(Debug, Clone)]
pub(crate) struct Ssgp<'a> {
    pub(crate) magic: [u8; 4],
    pub(crate) label: [u8; 16],
    pub(crate) iv: [u8; 8],
    pub(crate) encrypted_password: &'a [u8],
}

pub(crate) fn parse_ssgp(buf: &[u8]) -> Result<Ssgp<'_>> {
    if buf.len() < SSGP_HEADER_LEN {
        return Err(Error::ParseFailed("ssgp buffer too small".into()));
    }
    Ok(Ssgp {
        magic: read_array(buf, 0, "ssgp magic")?,
        label: read_array(buf, 4, "ssgp label")?,
        iv: read_array(buf, 20, "ssgp iv")?,
        encrypted_password: slice(
            buf,
            SSGP_HEADER_LEN,
            buf.len() - SSGP_HEADER_LEN,
            "ssgp body",
        )?,
    })
}

/// 24-byte header at the start of every `SymmetricKey` / `PrivateKey`
/// record payload.
#[derive(Debug, Clone)]
pub(crate) struct KeyBlob {
    pub(crate) magic: u32,
    pub(crate) start_crypto_blob: u32,
    pub(crate) total_length: u32,
    pub(crate) iv: [u8; 8],
}

pub(crate) fn parse_key_blob(buf: &[u8]) -> Result<KeyBlob> {
    if buf.len() < KEY_BLOB_LEN {
        return Err(Error::ParseFailed("key blob buffer too small".into()));
    }
    Ok(KeyBlob {
        magic: read_u32(buf, 0, "keyBlob magic")?,
        start_crypto_blob: read_u32(buf, 8, "keyBlob startCryptoBlob")?,
        total_length: read_u32(buf, 12, "keyBlob totalLength")?,
        iv: read_array(buf, 16, "keyBlob iv")?,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_panics_doc
    )]

    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../tests/data/test.keychain-db");

    #[test]
    fn parse_header_valid() {
        let hdr = parse_header(FIXTURE).unwrap();
        assert_eq!(&hdr.signature, KEYCHAIN_SIGNATURE);
        assert_eq!(hdr.version, 0x0001_0000);
        assert_eq!(hdr.inner_size, 16);
        assert_eq!(hdr.schema_off, 20);
    }

    #[test]
    fn parse_header_too_small() {
        let err = parse_header(&[1, 2, 3]).unwrap_err();
        assert!(matches!(err, Error::ParseFailed(_)));
    }

    #[test]
    fn parse_schema_reports_twelve_tables() {
        let hdr = parse_header(FIXTURE).unwrap();
        let idx = parse_schema(FIXTURE, hdr.schema_off).unwrap();
        assert_eq!(idx.table_offsets.len(), 12);
    }

    #[test]
    fn parse_table_first_nonzero_succeeds() {
        let hdr = parse_header(FIXTURE).unwrap();
        let idx = parse_schema(FIXTURE, hdr.schema_off).unwrap();
        let mut parsed = None;
        for off in &idx.table_offsets {
            if *off == 0 {
                continue;
            }
            let abs = HEADER_SIZE + *off as usize;
            if let Ok(t) = parse_table(FIXTURE, abs) {
                parsed = Some(t);
                break;
            }
        }
        let t = parsed.expect("no parseable table in fixture");
        assert!(t.base_offset > 0);
    }

    #[test]
    fn parse_db_blob_layout_matches_fixture() {
        // Locate the Metadata table by full parse, then verify the DBBlob.
        let hdr = parse_header(FIXTURE).unwrap();
        let idx = parse_schema(FIXTURE, hdr.schema_off).unwrap();
        let mut meta_base = None;
        for off in &idx.table_offsets {
            if *off == 0 {
                continue;
            }
            let abs = HEADER_SIZE + *off as usize;
            if let Ok(t) = parse_table(FIXTURE, abs) {
                if t.table_id == crate::tables::TABLE_METADATA {
                    meta_base = Some(t.base_offset);
                    break;
                }
            }
        }
        let base = meta_base.expect("metadata table missing");
        let start = base + METADATA_OFFSET_ADJUSTMENT;
        let blob = parse_db_blob(&FIXTURE[start..start + DB_BLOB_SIZE]).unwrap();
        assert_eq!(blob.salt.len(), 20);
        assert_eq!(blob.iv.len(), 8);
        assert_eq!(blob.start_crypto_blob, 120);
        assert_eq!(blob.total_length, 168);
        assert_eq!(
            hex::encode(blob.salt),
            "fc143c45cce245f3e54fbb39141a894e2870dd85"
        );
    }

    #[test]
    fn parse_db_blob_too_small() {
        let err = parse_db_blob(&[0_u8; 10]).unwrap_err();
        assert!(matches!(err, Error::ParseFailed(_)));
    }

    #[test]
    fn parse_ssgp_round_trip() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"ssgp");
        buf.extend_from_slice(b"0123456789abcdef");
        buf.extend_from_slice(b"iviviviv");
        buf.extend_from_slice(b"encrypted");

        let block = parse_ssgp(&buf).unwrap();
        assert_eq!(&block.magic, b"ssgp");
        assert_eq!(&block.label, b"0123456789abcdef");
        assert_eq!(&block.iv, b"iviviviv");
        assert_eq!(block.encrypted_password, b"encrypted");
    }

    #[test]
    fn parse_ssgp_too_small() {
        let err = parse_ssgp(&[0_u8; 10]).unwrap_err();
        assert!(matches!(err, Error::ParseFailed(_)));
    }

    #[test]
    fn parse_key_blob_round_trip() {
        let mut buf = vec![0_u8; KEY_BLOB_LEN];
        buf[0] = 0xFA;
        buf[1] = 0xDE;
        buf[2] = 0x07;
        buf[3] = 0x11;
        buf[11] = 0x10; // startCryptoBlob = 0x10
        buf[15] = 0x20; // totalLength    = 0x20

        let blob = parse_key_blob(&buf).unwrap();
        assert_eq!(blob.magic, KEY_BLOB_MAGIC);
        assert_eq!(blob.start_crypto_blob, 0x10);
        assert_eq!(blob.total_length, 0x20);
        assert_eq!(blob.iv.len(), 8);
    }

    #[test]
    fn parse_key_blob_too_small() {
        let err = parse_key_blob(&[0_u8; 10]).unwrap_err();
        assert!(matches!(err, Error::ParseFailed(_)));
    }

    #[test]
    fn slice_reports_out_of_bounds() {
        let buf = [0_u8; 4];
        let err = slice(&buf, 2, 8, "test").unwrap_err();
        match err {
            Error::ParseFailed(msg) => {
                assert!(msg.contains("out of bounds"), "unexpected: {msg}");
            }
            other => panic!("expected ParseFailed, got {other:?}"),
        }
    }
}
