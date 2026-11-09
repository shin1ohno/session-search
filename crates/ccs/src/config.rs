//! Validated client settings; no credentials are included in diagnostics.
use crate::errors::{Error, Result};
use ccs_pytext::json::{self, Value};
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct Config {
    pub path: PathBuf,
    pub endpoint: String,
    pub host_label: String,
    pub auth_type: String,
    pub token_url: String,
    pub client_id: String,
    pub secret_file: PathBuf,
    pub audience: String,
    pub hmac_key_file: PathBuf,
}

pub(crate) fn field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let Value::Object(items) = value else {
        return None;
    };
    items
        .iter()
        .rev()
        .find(|(key, _)| key.iter().copied().eq(name.chars().map(u32::from)))
        .map(|(_, v)| v)
}
pub(crate) fn string(value: &Value) -> Option<String> {
    let Value::String(points) = value else {
        return None;
    };
    points.iter().map(|p| char::from_u32(*p)).collect()
}
pub(crate) fn text(value: impl AsRef<str>) -> Value {
    Value::String(value.as_ref().chars().map(u32::from).collect())
}
pub(crate) fn object(items: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Object(
        items
            .into_iter()
            .map(|(k, v)| (k.chars().map(u32::from).collect(), v))
            .collect(),
    )
}
pub(crate) fn number(v: &Value) -> Option<f64> {
    let Value::Number(n) = v else { return None };
    n.parse::<f64>().ok().filter(|n| n.is_finite())
}
pub(crate) fn parse(bytes: &[u8]) -> Option<Value> {
    let s = std::str::from_utf8(bytes).ok()?;
    json::loads(&s.chars().map(u32::from).collect::<Vec<_>>()).ok()
}
pub(crate) fn encode(value: &Value) -> Result<String> {
    json::dumps_compact(value, false, false).map_err(|_| Error::Usage("invalid JSON value".into()))
}
fn required(value: &Value, name: &str) -> Result<String> {
    field(value, name)
        .and_then(string)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::Usage(format!("config: `{name}` is missing")))
}
pub fn default_path() -> PathBuf {
    std::env::var_os("CCS_CONFIG")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config/session-search/config.json"))
}
pub(crate) fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}
fn expand(value: &str) -> PathBuf {
    if value == "~" {
        home()
    } else if let Some(tail) = value.strip_prefix("~/") {
        home().join(tail)
    } else {
        PathBuf::from(value)
    }
}
fn check_url(value: String, name: &str, tailnet: bool) -> Result<String> {
    let valid = value.parse::<ureq::http::Uri>().ok().is_some_and(|uri| {
        let host = uri
            .host()
            .unwrap_or("")
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        match uri.scheme_str() {
            Some("https") => !host.is_empty(),
            Some("http") => {
                matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1")
                    || (tailnet && host.ends_with(".ts.net") && host.len() > 7)
            }
            _ => false,
        }
    });
    if valid {
        Ok(value.trim_end_matches('/').into())
    } else {
        Err(Error::Usage(format!("config: `{name}` must be an https URL (http only to 127.0.0.1, or to a *.ts.net host with tailnet auth)")))
    }
}

impl Config {
    pub fn from_value(data: &Value, path: impl Into<PathBuf>) -> Result<Self> {
        if !matches!(data, Value::Object(_)) {
            return Err(Error::Usage("config: top level must be an object".into()));
        }
        let auth = field(data, "auth")
            .filter(|v| matches!(v, Value::Object(_)))
            .ok_or_else(|| Error::Usage("config: `auth` must be an object".into()))?;
        let auth_type = required(auth, "type")?;
        let tailnet = auth_type == "tailnet";
        if !tailnet && auth_type != "client_credentials" {
            return Err(Error::Usage(
                "config: `auth.type` must be \"tailnet\" or \"client_credentials\"".into(),
            ));
        }
        let endpoint = check_url(required(data, "endpoint")?, "endpoint", tailnet)?;
        let host_label = required(data, "host_label")?;
        if host_label.len() > 63
            || !host_label
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return Err(Error::Usage(
                "config: `host_label` must match ^[a-z0-9-]{1,63}$".into(),
            ));
        }
        let (token_url, client_id, secret_file, audience) = if tailnet {
            (String::new(), String::new(), PathBuf::new(), String::new())
        } else {
            let audience = match field(auth, "audience") {
                None => "memory".into(),
                Some(Value::Null) => String::new(),
                Some(v) => string(v).ok_or_else(|| {
                    Error::Usage("config: `auth.audience` must be a string".into())
                })?,
            };
            (
                check_url(required(auth, "token_url")?, "auth.token_url", false)?,
                required(auth, "client_id")?,
                expand(&required(auth, "secret_file")?),
                audience,
            )
        };
        Ok(Self {
            path: path.into(),
            endpoint,
            host_label,
            auth_type,
            token_url,
            client_id,
            secret_file,
            audience,
            hmac_key_file: expand(&required(data, "hmac_key_file")?),
        })
    }
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path = path.map(PathBuf::from).unwrap_or_else(default_path);
        Self::from_value(&load(Some(&path))?, path)
    }
    pub fn is_tailnet(&self) -> bool {
        self.auth_type == "tailnet"
    }
    pub(crate) fn from_boundary(value: &Value) -> Result<Self> {
        let path = field(value, "__ccs_config_path")
            .and_then(string)
            .map(PathBuf::from)
            .unwrap_or_else(default_path);
        Self::from_value(value, path)
    }
}

/// Preserve the Wave 0 boundary and retain the source path for the token directory.
pub fn load(path: Option<&Path>) -> Result<Value> {
    let path = path.map(PathBuf::from).unwrap_or_else(default_path);
    let raw = std::fs::read(&path).map_err(|e| {
        Error::Usage(if e.kind() == std::io::ErrorKind::NotFound {
            format!("not configured: {} does not exist", path.display())
        } else {
            "config unreadable".into()
        })
    })?;
    let mut data = parse(&raw).ok_or_else(|| Error::Usage("config is not valid JSON".into()))?;
    Config::from_value(&data, &path)?;
    if let Value::Object(items) = &mut data {
        items.retain(|(k, _)| {
            !k.iter()
                .copied()
                .eq("__ccs_config_path".chars().map(u32::from))
        });
        items.push((
            "__ccs_config_path".chars().map(u32::from).collect(),
            text(path.to_string_lossy()),
        ));
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn urls_restrict_cleartext_to_loopback_or_tailnet() {
        for url in [
            "https://example.org/",
            "http://127.0.0.1:99",
            "http://[::1]:99",
        ] {
            assert!(check_url(url.into(), "endpoint", false).is_ok());
        }
        assert!(check_url("http://box.ts.net".into(), "endpoint", true).is_ok());
        for url in [
            "http://box.ts.net",
            "http://example.org",
            "http://evil.ts.net.example.org",
            "file:///tmp/config",
        ] {
            assert!(check_url(url.into(), "endpoint", false).is_err());
        }
    }
}
