//! Wave 0 boundary; implementation belongs to S2.
use crate::errors::{Error, Result};
use ccs_pytext::json::Value;

pub fn load_state(_path: &std::path::Path) -> Result<Value> {
    Err(Error::NotImplemented("util"))
}
