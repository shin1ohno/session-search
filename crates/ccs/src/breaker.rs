//! Python-compatible search circuit breaker state.
use crate::config::{encode, field, home, number, object, parse};
use crate::errors::{Error, Result};
use ccs_pytext::json::Value;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const THRESHOLD: u64 = 2;
pub const OPEN_SECONDS: f64 = 60.0;
pub const TIMEOUT: Duration = Duration::from_millis(800);

pub struct Breaker {
    pub path: PathBuf,
}
impl Default for Breaker {
    fn default() -> Self {
        Self::new(home().join(".claude/session-search/breaker.json"))
    }
}
impl Breaker {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
    fn read(&self) -> Value {
        std::fs::read(&self.path)
            .ok()
            .and_then(|b| parse(&b))
            .filter(|v| matches!(v, Value::Object(_)))
            .unwrap_or_else(|| object([]))
    }
    pub fn state(&self) -> Value {
        self.state_at(now())
    }
    pub fn is_open(&self) -> bool {
        field(&self.state(), "open") == Some(&Value::Bool(true))
    }
    pub fn state_at(&self, now: f64) -> Value {
        let value = self.read();
        let failures = field(&value, "failures")
            .and_then(number)
            .unwrap_or(0.0)
            .max(0.0) as u64;
        let until = field(&value, "open_until").and_then(number).unwrap_or(0.0);
        object([
            ("failures", Value::Number(failures.to_string())),
            ("open_until", Value::Number(until.to_string())),
            ("open", Value::Bool(now < until)),
        ])
    }
    pub fn record_failure(&self) -> Result<()> {
        self.record_failure_at(now())
    }
    pub fn record_failure_at(&self, now: f64) -> Result<()> {
        let value = self.state_at(now);
        let failures =
            (field(&value, "failures").and_then(number).unwrap_or(0.0) as u64).saturating_add(1);
        let until = if failures >= THRESHOLD {
            now + OPEN_SECONDS
        } else {
            field(&value, "open_until").and_then(number).unwrap_or(0.0)
        };
        self.write(object([
            ("failures", Value::Number(failures.to_string())),
            ("open_until", Value::Number(until.to_string())),
        ]))
    }
    pub fn record_success(&self) -> Result<()> {
        let value = self.read();
        if ["failures", "open_until"]
            .iter()
            .any(|k| field(&value, k).and_then(number).is_some_and(|v| v != 0.0))
        {
            self.write(object([
                ("failures", Value::Number("0".into())),
                ("open_until", Value::Number("0".into())),
            ]))?;
        }
        Ok(())
    }
    fn write(&self, value: Value) -> Result<()> {
        let parent = self.path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent).map_err(Error::Io)?;
        let mut nonce = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce)
            .map_err(|_| Error::Unavailable("breaker random source unavailable".into()))?;
        let temp = parent.join(format!(
            ".breaker.{}.{}",
            std::process::id(),
            u128::from_ne_bytes(nonce)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(Error::Io)?;
        let result = (|| {
            file.write_all(encode(&value)?.as_bytes())
                .map_err(Error::Io)?;
            std::fs::rename(&temp, &self.path).map_err(Error::Io)
        })();
        let _ = std::fs::remove_file(&temp);
        result
    }
}
fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
pub fn load(state_dir: &Path) -> Result<Value> {
    Ok(Breaker::new(state_dir.join("breaker.json")).state())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn python_state_opens_after_two_failures_and_resets() {
        let root =
            std::env::temp_dir().join(format!("ccs-breaker-{}-{}", std::process::id(), now()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("breaker.json");
        let breaker = Breaker::new(&path);
        std::fs::write(&path, br#"{"failures": 1, "open_until": 0}"#).unwrap();
        assert_eq!(
            field(&breaker.state_at(100.0), "open"),
            Some(&Value::Bool(false))
        );
        breaker.record_failure_at(100.0).unwrap();
        assert_eq!(
            field(&breaker.state_at(159.0), "open"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            field(&breaker.state_at(160.0), "open"),
            Some(&Value::Bool(false))
        );
        let data = parse(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(field(&data, "failures").and_then(number), Some(2.0));
        assert_eq!(field(&data, "open_until").and_then(number), Some(160.0));
        breaker.record_success().unwrap();
        assert_eq!(
            field(&breaker.state_at(110.0), "failures").and_then(number),
            Some(0.0)
        );
        assert_eq!(
            field(&breaker.state_at(110.0), "open_until").and_then(number),
            Some(0.0)
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
