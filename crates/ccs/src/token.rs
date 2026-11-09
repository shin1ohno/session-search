//! Wave 0 boundary; implementation belongs to S2.
use crate::errors::{Error, Result};
use ccs_pytext::json::Value;

pub fn get(_config: &Value) -> Result<Value> {
    Err(Error::NotImplemented("token"))
}
