//! Wave 0 boundary; implementation belongs to S2.
use crate::errors::{Error, Result};
use ccs_pytext::json::Value;

pub fn request(
    _config: &Value,
    _method: &str,
    _path: &str,
    _body: Option<&Value>,
) -> Result<Value> {
    Err(Error::NotImplemented("api"))
}
