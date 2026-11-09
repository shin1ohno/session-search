//! Native Codex rollout discovery; no database writes or model calls.
use crate::errors::Result;
use crate::util::{self, get, is, object, string, text};
use ccs_pytext::json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Component, Path, PathBuf};

pub fn absolute(path: &Path) -> PathBuf {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    };
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            _ => out.push(part),
        }
    }
    out
}
pub fn home() -> PathBuf {
    let path = std::env::var_os("CODEX_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| util::home().join(".codex"));
    let path = if path == Path::new("~") {
        util::home()
    } else if let Ok(tail) = path.strip_prefix("~/") {
        util::home().join(tail)
    } else {
        path
    };
    absolute(&path)
}
pub fn sessions_dir() -> PathBuf {
    home().join("sessions")
}
pub fn rollout_id(path: &Path) -> Option<String> {
    let name = path
        .file_name()?
        .to_str()?
        .strip_prefix("rollout-")?
        .strip_suffix(".jsonl")?;
    if name.len() < 38 {
        return None;
    }
    let stamp = name.get(..name.len() - 36)?;
    let id = name.get(name.len() - 36..)?;
    let stamp = stamp.strip_suffix('-')?;
    if stamp.is_empty()
        || !stamp
            .bytes()
            .all(|b| b.is_ascii_digit() || b"T:-".contains(&b))
        || !util::valid_session_id(id)
    {
        return None;
    }
    Some(id.to_owned())
}
fn visit(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.to_str().is_none() {
            util::log("WARN", "skipping non-UTF-8 transcript path");
            continue;
        }
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            visit(&path, out);
        } else if !kind.is_symlink() && rollout_id(&path).is_some() {
            out.push(path);
        }
    }
}
pub fn paths() -> Vec<PathBuf> {
    let mut out = vec![];
    visit(&sessions_dir(), &mut out);
    out
}
pub fn metadata(path: &Path) -> Value {
    metadata_under(path, &sessions_dir())
}
fn metadata_under(path: &Path, root: &Path) -> Value {
    let Ok(file) = util::open_regular(path, Some(root)) else {
        return Value::Object(vec![]);
    };
    let mut raw = Vec::new();
    if BufReader::new(file.take(4 * 1024 * 1024 + 1))
        .read_until(b'\n', &mut raw)
        .is_err()
        || !raw.ends_with(b"\n")
    {
        return Value::Object(vec![]);
    }
    let Some(raw) = decode_metadata(&raw) else {
        return Value::Object(vec![]);
    };
    let Ok(rec) = ccs_pytext::json::loads(&raw) else {
        return Value::Object(vec![]);
    };
    if is(get(&rec, "type"), "session_meta") && matches!(get(&rec, "payload"), Value::Object(_)) {
        get(&rec, "payload").clone()
    } else {
        Value::Object(vec![])
    }
}
// json.loads(bytes) detects UTF encodings and permits escaped/raw surrogate code points.
fn decode_metadata(raw: &[u8]) -> Option<Vec<u32>> {
    let (mut bytes, width, little) = if let Some(s) = raw.strip_prefix(&[0xff, 0xfe, 0, 0]) {
        (s, 4, true)
    } else if let Some(s) = raw.strip_prefix(&[0, 0, 0xfe, 0xff]) {
        (s, 4, false)
    } else if let Some(s) = raw.strip_prefix(&[0xff, 0xfe]) {
        (s, 2, true)
    } else if let Some(s) = raw.strip_prefix(&[0xfe, 0xff]) {
        (s, 2, false)
    } else if raw.len() >= 4 && raw[0] == 0 {
        (raw, if raw[1] == 0 { 4 } else { 2 }, false)
    } else if raw.len() >= 4 && raw[1] == 0 {
        (raw, if raw[2] == 0 && raw[3] == 0 { 4 } else { 2 }, true)
    } else {
        (
            raw.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(raw),
            1,
            false,
        )
    };
    if bytes.len() % width != 0 {
        return None;
    }
    if width == 4 {
        return bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| {
                let b = *b;
                let n = if little {
                    u32::from_le_bytes(b)
                } else {
                    u32::from_be_bytes(b)
                };
                (n <= 0x10ffff).then_some(n)
            })
            .collect();
    }
    if width == 2 {
        return Some(
            char::decode_utf16(bytes.as_chunks::<2>().0.iter().map(|b| {
                let b = [b[0], b[1]];
                if little {
                    u16::from_le_bytes(b)
                } else {
                    u16::from_be_bytes(b)
                }
            }))
            .map(|c| c.map_or_else(|e| u32::from(e.unpaired_surrogate()), u32::from))
            .collect(),
        );
    }
    let mut out = Vec::new();
    while !bytes.is_empty() {
        match std::str::from_utf8(bytes) {
            Ok(s) => {
                out.extend(s.chars().map(u32::from));
                break;
            }
            Err(e) => {
                let n = e.valid_up_to();
                out.extend(
                    std::str::from_utf8(&bytes[..n])
                        .ok()?
                        .chars()
                        .map(u32::from),
                );
                bytes = &bytes[n..];
                if bytes.len() < 3
                    || bytes[0] != 0xed
                    || !(0xa0..=0xbf).contains(&bytes[1])
                    || !(0x80..=0xbf).contains(&bytes[2])
                {
                    return None;
                }
                out.push(0xd000 + u32::from(bytes[1] & 0x3f) * 64 + u32::from(bytes[2] & 0x3f));
                bytes = &bytes[3..];
            }
        }
    }
    Some(out)
}
pub fn is_path(path: &Path) -> bool {
    let p = absolute(path);
    let root = absolute(&sessions_dir());
    p != root && p.starts_with(root)
}
pub fn classify(path: &Path) -> Option<Value> {
    classify_under(path, &sessions_dir())
}
fn classify_under(path: &Path, root: &Path) -> Option<Value> {
    let p = absolute(path);
    let root = absolute(root);
    if p == root || !p.starts_with(&root) {
        return None;
    }
    let sid = rollout_id(&p)?;
    let meta = metadata_under(&p, &root);
    let cwd = text(get(&meta, "cwd"))?;
    if !is(get(&meta, "id"), &sid) || !cwd.starts_with('/') {
        return None;
    }
    Some(object([
        ("kind", string("main")),
        ("source", string("codex")),
        ("session_id", string(sid)),
        (
            "project_dir",
            string(format!("codex-{}", util::encode_cwd(&cwd))),
        ),
    ]))
}
pub fn find_local(sid: &str, hint: Option<&Path>) -> Option<PathBuf> {
    find_local_with(sid, hint, paths, |p| classify(p).is_some())
}
fn find_local_with(
    sid: &str,
    hint: Option<&Path>,
    candidates: impl FnOnce() -> Vec<PathBuf>,
    classify: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    if let Some(path) = hint {
        if rollout_id(path).as_deref() == Some(sid) && classify(path) {
            return Some(path.to_path_buf());
        }
    }
    candidates()
        .into_iter()
        .find(|path| rollout_id(path).as_deref() == Some(sid) && classify(path))
}
/// Locate below an explicit Codex home without changing process environment.
pub fn locate(home: &Path, session_id: &str) -> Result<Value> {
    let root = home.join("sessions");
    let mut paths = Vec::new();
    visit(&root, &mut paths);
    Ok(paths
        .into_iter()
        .find(|p| {
            rollout_id(p).as_deref() == Some(session_id) && classify_under(p, &root).is_some()
        })
        .and_then(|p| p.to_str().map(string))
        .unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_local_reads_only_the_matching_header_and_uses_hint_lazily() {
        let sid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        let target = PathBuf::from(format!("rollout-2026-10-25T00-00-00-{sid}.jsonl"));
        let other =
            PathBuf::from("rollout-2026-10-25T00-00-00-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb.jsonl");
        let calls = std::cell::Cell::new(0);
        assert_eq!(
            find_local_with(
                sid,
                Some(&other),
                || vec![other.clone(), target.clone()],
                |_| {
                    calls.set(calls.get() + 1);
                    true
                }
            ),
            Some(target.clone())
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(
            find_local_with(sid, Some(&target), || panic!("unnecessary walk"), |_| true),
            Some(target)
        );
    }

    #[test]
    fn metadata_uses_python_byte_encoding_and_only_the_first_complete_line() {
        let root = std::env::temp_dir().join(format!(
            "ccs-meta-{}-{}",
            std::process::id(),
            util::now_epoch().to_bits()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("header");
        let header =
            "{\"type\":\"session_meta\",\"payload\":{\"id\":\"child\",\"cwd\":\"/日本\"}}\n";
        for bytes in [
            header.as_bytes().to_vec(),
            [vec![0xef, 0xbb, 0xbf], header.as_bytes().to_vec()].concat(),
            header.encode_utf16().flat_map(u16::to_be_bytes).collect(),
            header
                .chars()
                .flat_map(|c| u32::from(c).to_be_bytes())
                .collect(),
        ] {
            fs::write(&path, bytes).unwrap();
            assert_eq!(get(&metadata_under(&path, &root), "cwd"), &string("/日本"));
        }
        fs::write(&path, header.trim_end()).unwrap();
        assert_eq!(metadata_under(&path, &root), Value::Object(vec![]));
        fs::write(&path, format!("{header}invalid remaining body")).unwrap();
        assert_eq!(get(&metadata_under(&path, &root), "id"), &string("child"));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn rollout_name_is_anchored() {
        let name = "rollout-2026-10-25T00-00-00-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.jsonl";
        assert_eq!(
            rollout_id(Path::new(name)).as_deref(),
            Some("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        );
        assert!(rollout_id(Path::new(&format!("{name}\n"))).is_none());
        assert!(rollout_id(Path::new(
            "rollout-☃aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.jsonl"
        ))
        .is_none());
    }
}
