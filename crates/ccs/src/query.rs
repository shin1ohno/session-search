//! Unix query arguments retain Python's surrogateescaped code points.
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

#[derive(Clone, Debug)]
pub struct Query(Vec<u32>);
impl Query {
    pub fn from_os(value: &OsStr) -> Self {
        let mut bytes = value.as_bytes();
        let mut points = Vec::new();
        while !bytes.is_empty() {
            match std::str::from_utf8(bytes) {
                Ok(text) => {
                    points.extend(text.chars().map(u32::from));
                    break;
                }
                Err(error) => {
                    let valid = error.valid_up_to();
                    points.extend(
                        std::str::from_utf8(&bytes[..valid])
                            .unwrap()
                            .chars()
                            .map(u32::from),
                    );
                    let count = error.error_len().unwrap_or(bytes.len() - valid);
                    points.extend(
                        bytes[valid..valid + count]
                            .iter()
                            .map(|b| 0xdc00 + u32::from(*b)),
                    );
                    bytes = &bytes[valid + count..];
                }
            }
        }
        Self(points)
    }
    pub fn points(&self) -> &[u32] {
        &self.0
    }
    pub fn trimmed(&self) -> Self {
        Self(ccs_pytext::strip_points(&self.0).to_vec())
    }
    pub fn utf8(&self) -> Option<String> {
        self.0.iter().map(|p| char::from_u32(*p)).collect()
    }
    pub fn os_string(&self) -> OsString {
        let mut bytes = Vec::new();
        for p in &self.0 {
            if (0xdc80..=0xdcff).contains(p) {
                bytes.push((p - 0xdc00) as u8);
            } else {
                let mut buffer = [0; 4];
                bytes.extend_from_slice(
                    char::from_u32(*p)
                        .unwrap()
                        .encode_utf8(&mut buffer)
                        .as_bytes(),
                );
            }
        }
        OsString::from_vec(bytes)
    }
}
impl From<&str> for Query {
    fn from(value: &str) -> Self {
        Self(value.chars().map(u32::from).collect())
    }
}
