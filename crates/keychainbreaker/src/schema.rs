//! Dynamic schema discovery from the `SchemaAttributes` table.
//!
//! Direct port of `schema.go` from the Go reference. The keychain file
//! does not hardcode attribute layouts — each `.keychain-db` declares its
//! own schema via records in the `SchemaAttributes` table, and other
//! tables reference attributes by FourCC name or descriptive string.
//!
//! Two bootstrap schemas (for `SchemaInfo` and `SchemaAttributes` itself)
//! are hardcoded here because they are needed to parse the discovery
//! records.

// Discovery results are consumed by M3's extraction pipeline; until then
// non-test builds see every symbol here as unused.
#![allow(dead_code)]

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::parse::TableHeader;
use crate::record::parse_record;
use crate::tables;

/// Attribute format codes from Apple's CSSM framework.
pub(crate) const ATTR_FORMAT_STRING: u32 = 0;
pub(crate) const ATTR_FORMAT_SINT32: u32 = 1;
pub(crate) const ATTR_FORMAT_UINT32: u32 = 2;
pub(crate) const ATTR_FORMAT_TIME_DATE: u32 = 5;
pub(crate) const ATTR_FORMAT_BLOB: u32 = 6;
pub(crate) const ATTR_FORMAT_MULTI_UINT: u32 = 7;

#[derive(Debug, Clone)]
pub(crate) struct AttrDef {
    pub(crate) name: String,
    pub(crate) format: u32,
}

/// Attribute layout for a single record type. The index map is built
/// eagerly in [`TableSchema::build`] so lookups stay `O(1)` and avoid the
/// lazy-init pattern Go uses.
#[derive(Debug, Clone)]
pub(crate) struct TableSchema {
    pub(crate) table_id: u32,
    pub(crate) attrs: Vec<AttrDef>,
    indexes: HashMap<String, usize>,
}

impl TableSchema {
    pub(crate) fn build(table_id: u32, attrs: Vec<AttrDef>) -> Self {
        let mut indexes = HashMap::with_capacity(attrs.len());
        for (i, a) in attrs.iter().enumerate() {
            let _previous = indexes.insert(a.name.clone(), i);
        }
        Self {
            table_id,
            attrs,
            indexes,
        }
    }

    pub(crate) fn attr_index(&self, name: &str) -> Option<usize> {
        self.indexes.get(name).copied()
    }
}

#[derive(Debug, Default)]
pub(crate) struct DbSchema {
    tables: HashMap<u32, TableSchema>,
}

impl DbSchema {
    pub(crate) fn for_table(&self, table_id: u32) -> Option<&TableSchema> {
        self.tables.get(&table_id)
    }
}

fn schema_info_bootstrap() -> TableSchema {
    TableSchema::build(
        tables::TABLE_SCHEMA_INFO,
        vec![
            AttrDef {
                name: tables::ATTR_RELATION_ID.to_owned(),
                format: ATTR_FORMAT_UINT32,
            },
            AttrDef {
                name: tables::ATTR_ATTRIBUTE_NAME_FORMAT.to_owned(),
                format: ATTR_FORMAT_UINT32,
            },
            AttrDef {
                name: tables::ATTR_ATTRIBUTE_ID.to_owned(),
                format: ATTR_FORMAT_UINT32,
            },
            AttrDef {
                name: tables::ATTR_ATTRIBUTE_NAME_ID.to_owned(),
                format: ATTR_FORMAT_UINT32,
            },
        ],
    )
}

fn schema_attributes_bootstrap() -> TableSchema {
    TableSchema::build(
        tables::TABLE_SCHEMA_ATTRIBUTES,
        vec![
            AttrDef {
                name: tables::ATTR_RELATION_ID.to_owned(),
                format: ATTR_FORMAT_UINT32,
            },
            AttrDef {
                name: tables::ATTR_ATTRIBUTE_ID.to_owned(),
                format: ATTR_FORMAT_UINT32,
            },
            AttrDef {
                name: tables::ATTR_ATTRIBUTE_NAME_FORMAT.to_owned(),
                format: ATTR_FORMAT_UINT32,
            },
            AttrDef {
                name: tables::ATTR_ATTRIBUTE_NAME_ID.to_owned(),
                format: ATTR_FORMAT_UINT32,
            },
            AttrDef {
                name: tables::ATTR_ATTRIBUTE_FORMAT.to_owned(),
                format: ATTR_FORMAT_UINT32,
            },
        ],
    )
}

/// Walk the `SchemaAttributes` table to discover the attribute layout for
/// every other table in the keychain.
pub(crate) fn build_schema(buf: &[u8], tables_map: &HashMap<u32, TableHeader>) -> Result<DbSchema> {
    let attrs_bootstrap = schema_attributes_bootstrap();
    let sa_table = tables_map
        .get(&tables::TABLE_SCHEMA_ATTRIBUTES)
        .ok_or_else(|| {
            Error::ParseFailed(format!(
                "SchemaAttributes table (0x{:08X}) not found",
                tables::TABLE_SCHEMA_ATTRIBUTES
            ))
        })?;

    let mut attrs_by_table: HashMap<u32, Vec<AttrDef>> = HashMap::new();
    for rec_offset in &sa_table.record_offsets {
        let abs_offset = sa_table.base_offset + (*rec_offset as usize);
        let Ok(rec) = parse_record(buf, abs_offset, &attrs_bootstrap) else {
            continue;
        };
        let relation_id = rec.read_u32_attr(tables::ATTR_RELATION_ID);
        if relation_id == 0 {
            continue;
        }
        let attr_format = rec.read_u32_attr(tables::ATTR_ATTRIBUTE_FORMAT);
        let attr_id = rec.read_u32_attr(tables::ATTR_ATTRIBUTE_ID);
        let name = try_fourcc_from(attr_id).unwrap_or_else(|| {
            let s = rec.read_string_attr(tables::ATTR_ATTRIBUTE_NAME_ID);
            if s.is_empty() || s == "\x00\x00\x00\x00" {
                format!("attr_0x{attr_id:08x}")
            } else {
                s
            }
        });
        attrs_by_table
            .entry(relation_id)
            .or_default()
            .push(AttrDef {
                name,
                format: attr_format,
            });
    }

    let mut tables_out: HashMap<u32, TableSchema> = HashMap::new();
    let _previous = tables_out.insert(tables::TABLE_SCHEMA_INFO, schema_info_bootstrap());
    let _previous = tables_out.insert(tables::TABLE_SCHEMA_ATTRIBUTES, attrs_bootstrap);
    for (table_id, attrs) in attrs_by_table {
        let _previous = tables_out.insert(table_id, TableSchema::build(table_id, attrs));
    }
    Ok(DbSchema { tables: tables_out })
}

/// Decode a `u32` to a 4-character ASCII string if every byte is printable.
/// Returns `None` if any byte is outside `0x20..=0x7E`.
pub(crate) fn try_fourcc_from(v: u32) -> Option<String> {
    let bytes = v.to_be_bytes();
    if !bytes.iter().all(|c| (0x20..=0x7E).contains(c)) {
        return None;
    }
    core::str::from_utf8(&bytes).ok().map(str::to_owned)
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
    use crate::parse::{parse_header, parse_schema, parse_table, HEADER_SIZE};

    const FIXTURE: &[u8] = include_bytes!("../tests/data/test.keychain-db");

    fn parse_fixture_tables() -> HashMap<u32, TableHeader> {
        let hdr = parse_header(FIXTURE).unwrap();
        let idx = parse_schema(FIXTURE, hdr.schema_off).unwrap();
        let mut tables_map = HashMap::new();
        for off in &idx.table_offsets {
            if *off == 0 {
                continue;
            }
            let abs = HEADER_SIZE + *off as usize;
            if let Ok(t) = parse_table(FIXTURE, abs) {
                let _previous = tables_map.entry(t.table_id).or_insert(t);
            }
        }
        tables_map
    }

    #[test]
    fn try_fourcc_from_decodes_known_codes() {
        assert_eq!(try_fourcc_from(0x7376_6365).as_deref(), Some("svce"));
        assert_eq!(try_fourcc_from(0x6163_6374).as_deref(), Some("acct"));
        assert_eq!(try_fourcc_from(0x6b79_6368).as_deref(), Some("kych"));
        assert_eq!(try_fourcc_from(0x0000_0007), None);
    }

    #[test]
    fn attr_index_lookups() {
        let schema = TableSchema::build(
            42,
            vec![
                AttrDef {
                    name: "alpha".to_owned(),
                    format: ATTR_FORMAT_STRING,
                },
                AttrDef {
                    name: "beta".to_owned(),
                    format: ATTR_FORMAT_UINT32,
                },
                AttrDef {
                    name: "gamma".to_owned(),
                    format: ATTR_FORMAT_BLOB,
                },
            ],
        );
        assert_eq!(schema.attr_index("alpha"), Some(0));
        assert_eq!(schema.attr_index("beta"), Some(1));
        assert_eq!(schema.attr_index("gamma"), Some(2));
        assert_eq!(schema.attr_index("missing"), None);
    }

    #[test]
    fn build_schema_discovers_generic_password() {
        let tables_map = parse_fixture_tables();
        let schema = build_schema(FIXTURE, &tables_map).unwrap();

        let gp = schema
            .for_table(tables::TABLE_GENERIC_PASSWORD)
            .expect("GenericPassword schema missing");
        assert!(
            gp.attrs.len() > 10,
            "expected >10 attrs on GenericPassword, got {}",
            gp.attrs.len()
        );
        assert!(gp.attr_index(tables::ATTR_SERVICE_NAME).is_some());
        assert!(gp.attr_index(tables::ATTR_ACCOUNT_NAME).is_some());
        assert!(gp.attr_index(tables::ATTR_PRINT_NAME).is_some());
    }

    #[test]
    fn build_schema_discovers_internet_password() {
        let tables_map = parse_fixture_tables();
        let schema = build_schema(FIXTURE, &tables_map).unwrap();

        let ip = schema
            .for_table(tables::TABLE_INTERNET_PASSWORD)
            .expect("InternetPassword schema missing");
        assert!(ip.attr_index(tables::ATTR_SERVER).is_some());
        assert!(ip.attr_index(tables::ATTR_PROTOCOL).is_some());
        assert!(ip.attr_index(tables::ATTR_PORT).is_some());
    }

    #[test]
    fn build_schema_discovers_symmetric_key() {
        let tables_map = parse_fixture_tables();
        let schema = build_schema(FIXTURE, &tables_map).unwrap();

        let sk = schema
            .for_table(tables::TABLE_SYMMETRIC_KEY)
            .expect("SymmetricKey schema missing");
        assert!(
            sk.attrs.len() > 20,
            "expected >20 attrs on SymmetricKey, got {}",
            sk.attrs.len()
        );
    }
}
