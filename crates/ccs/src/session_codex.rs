//! Wave 0 boundary; implementation belongs to S2.
use crate::errors::{Error, Result};
use ccs_pytext::json::Value;

pub fn normalize(_record: &Value) -> Result<Value> {
    Err(Error::NotImplemented("session_codex"))
}
