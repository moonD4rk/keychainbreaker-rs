//! Table-ID and attribute-name constants shared by the parser and
//! schema-discovery modules.
//!
//! Values mirror Apple's CSSM framework codes and the constants in the Go
//! reference (`parse.go`). The names match the canonical FourCC strings
//! (e.g. `svce`, `acct`) — they are not Rust identifiers because the keychain
//! file format stores them as four-byte ASCII tags inside record headers.

// M2 introduces the full constant set; M3 wires the per-record-type
// attribute names into the extraction pipeline. Until then the
// extraction-side constants look unused in non-test builds.
#![allow(dead_code)]

// Record-type table identifiers.

pub(crate) const TABLE_SCHEMA_INFO: u32 = 0x0000_0000;
pub(crate) const TABLE_SCHEMA_INDEXES: u32 = 0x0000_0001;
pub(crate) const TABLE_SCHEMA_ATTRIBUTES: u32 = 0x0000_0002;
pub(crate) const TABLE_SCHEMA_PARSING_MODULE: u32 = 0x0000_0003;
pub(crate) const TABLE_PUBLIC_KEY: u32 = 0x0000_000F;
pub(crate) const TABLE_PRIVATE_KEY: u32 = 0x0000_0010;
pub(crate) const TABLE_SYMMETRIC_KEY: u32 = 0x0000_0011;
pub(crate) const TABLE_GENERIC_PASSWORD: u32 = 0x8000_0000;
pub(crate) const TABLE_INTERNET_PASSWORD: u32 = 0x8000_0001;
pub(crate) const TABLE_APPLE_SHARE_PASSWORD: u32 = 0x8000_0002;
pub(crate) const TABLE_X509_CERTIFICATE: u32 = 0x8000_1000;
pub(crate) const TABLE_METADATA: u32 = 0x8000_8000;

// Attribute names. FourCC codes (4-byte ASCII) for record payload fields,
// plus longer descriptive strings used by the SchemaAttributes table.

pub(crate) const ATTR_SERVICE_NAME: &str = "svce";
pub(crate) const ATTR_ACCOUNT_NAME: &str = "acct";
pub(crate) const ATTR_DESCRIPTION: &str = "desc";
pub(crate) const ATTR_COMMENT: &str = "icmt";
pub(crate) const ATTR_CREATOR: &str = "crtr";
pub(crate) const ATTR_TYPE: &str = "type";
pub(crate) const ATTR_PRINT_NAME: &str = "PrintName";
pub(crate) const ATTR_ALIAS: &str = "Alias";
pub(crate) const ATTR_CREATED: &str = "cdat";
pub(crate) const ATTR_MODIFIED: &str = "mdat";
pub(crate) const ATTR_SERVER: &str = "srvr";
pub(crate) const ATTR_SECURITY_DOMAIN: &str = "sdmn";
pub(crate) const ATTR_PROTOCOL: &str = "ptcl";
pub(crate) const ATTR_AUTH_TYPE: &str = "atyp";
pub(crate) const ATTR_PORT: &str = "port";
pub(crate) const ATTR_PATH: &str = "path";
pub(crate) const ATTR_LABEL: &str = "Label";
pub(crate) const ATTR_KEY_CLASS: &str = "KeyClass";
pub(crate) const ATTR_KEY_TYPE: &str = "KeyType";
pub(crate) const ATTR_KEY_SIZE_IN_BITS: &str = "KeySizeInBits";
pub(crate) const ATTR_CERT_TYPE: &str = "ctyp";
pub(crate) const ATTR_CERT_ENCODING: &str = "cenc";
pub(crate) const ATTR_CERT_LABEL: &str = "labl";
pub(crate) const ATTR_SUBJECT: &str = "subj";
pub(crate) const ATTR_ISSUER: &str = "issu";
pub(crate) const ATTR_SERIAL: &str = "snbr";

// Bootstrap attribute names that appear in SchemaInfo / SchemaAttributes
// records. These have to be hardcoded so the parser can read the two
// bootstrap tables before the rest of the schema is discovered.

pub(crate) const ATTR_RELATION_ID: &str = "RelationID";
pub(crate) const ATTR_ATTRIBUTE_ID: &str = "AttributeID";
pub(crate) const ATTR_ATTRIBUTE_NAME_FORMAT: &str = "AttributeNameFormat";
pub(crate) const ATTR_ATTRIBUTE_NAME_ID: &str = "AttributeNameID";
pub(crate) const ATTR_ATTRIBUTE_FORMAT: &str = "AttributeFormat";
