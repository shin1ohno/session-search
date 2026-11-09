//! Wave 0 boundary; implementation belongs to S2.
use crate::errors::{Error, Result};
use ccs_pytext::json::Value;

pub fn run(_config: &Value, _request: &Value) -> Result<Value> {
    Err(Error::NotImplemented("ingest"))
}
