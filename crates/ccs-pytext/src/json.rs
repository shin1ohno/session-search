//! Ordered JSON values for the Python-compatible reader and writer.
//!
//! Objects preserve insertion order and numbers retain their source spelling.
//! Parsing and serialization are deliberately not implemented in S1.

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(Vec<u32>),
    Array(Vec<Value>),
    Object(Vec<(Vec<u32>, Value)>),
}

#[derive(Debug)]
pub struct NotImplemented;

/// Python's JSON value domain includes unpaired surrogate code points.
pub fn loads(_text: &[u32]) -> Result<Value, NotImplemented> {
    Err(NotImplemented)
}

pub fn dumps(
    _value: &Value,
    _ensure_ascii: bool,
    _sort_keys: bool,
) -> Result<String, NotImplemented> {
    Err(NotImplemented)
}
