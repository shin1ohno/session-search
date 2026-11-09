//! Wave 0 boundary; implementation belongs to S2.
use crate::errors::{Error, Result};
use ccs_pytext::json::Value;

pub fn locate(_home: &std::path::Path, _session_id: &str) -> Result<Value> {
    Err(Error::NotImplemented("codex"))
}
