//! Local transcript extraction, retaining only human-readable conversation text.
use crate::errors::Result;
use crate::{codex, session_codex, util};
use ccs_pytext::json::{self, Value};
use std::collections::VecDeque;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use util::{get, is, number, object, string, text};

const LEADING_TAGS: &[&str] = &[
    "system-reminder",
    "command-name",
    "command-message",
    "command-args",
    "local-command-stdout",
    "local-command-stderr",
    "task-notification",
    "bash-stdout",
    "bash-stderr",
];
pub fn strip_leading_blocks(mut value: &str) -> String {
    loop {
        let start = ccs_pytext::lstrip(value);
        let mut removed = false;
        for tag in LEADING_TAGS {
            if let Some(body) = start.strip_prefix(&format!("<{tag}>")) {
                let close = format!("</{tag}>");
                if let Some(end) = body.find(&close) {
                    value = ccs_pytext::lstrip(&body[end + close.len()..]);
                    removed = true;
                    break;
                }
            }
        }
        if !removed {
            return ccs_pytext::strip(value).to_owned();
        }
    }
}
pub fn record_text(rec: &Value) -> String {
    if !["user", "assistant"]
        .iter()
        .any(|s| is(get(rec, "type"), s))
        || get(rec, "isMeta") == &Value::Bool(true)
        || get(rec, "isCompactSummary") == &Value::Bool(true)
    {
        return String::new();
    }
    let content = get(get(rec, "message"), "content");
    let parts = match content {
        Value::String(_) => text(content).into_iter().collect::<Vec<_>>(),
        Value::Array(blocks) => blocks
            .iter()
            .filter(|b| is(get(b, "type"), "text"))
            .filter_map(|b| text(get(b, "text")))
            .collect(),
        _ => vec![],
    };
    strip_leading_blocks(
        &parts
            .iter()
            .map(|s| strip_leading_blocks(s))
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
    )
}
pub fn loads_strict(s: &str) -> Result<Value> {
    match json::from_str_strict(s) {
        Ok(value) => return Ok(value),
        Err(json::Error::Depth) => {}
        Err(_) => return Err(util::invalid("invalid or duplicate-key JSON")),
    }
    // A materialization bound must not change whether local text can be read.
    let parsed = json::parse_bounded(&s.chars().map(u32::from).collect::<Vec<_>>(), usize::MAX)
        .map_err(|_| util::invalid("invalid JSON"))?;
    if parsed.flags.duplicate {
        return Err(util::invalid("duplicate-key JSON"));
    }
    if parsed.flags.big_int {
        return Err(util::invalid("JSON integer exceeds Python digit limit"));
    }
    parsed
        .value
        .ok_or_else(|| util::invalid("JSON nesting cannot be materialized"))
}

pub struct Records {
    reader: Option<BufReader<fs::File>>,
    index: Option<session_codex::IndexState>,
    position: usize,
    entrypoint: Value,
    cwd: Value,
}
pub fn iter_records(path: &Path) -> Records {
    let native = codex::is_path(path);
    let root = if native {
        codex::sessions_dir()
    } else {
        util::projects_dir()
    };
    Records {
        reader: util::open_regular(path, Some(&root))
            .ok()
            .map(BufReader::new),
        index: if native {
            Some(session_codex::IndexState::new(
                codex::rollout_id(path).map(string).unwrap_or(Value::Null),
                None,
            ))
        } else {
            None
        },
        position: 0,
        entrypoint: Value::Null,
        cwd: Value::Null,
    }
}
impl Iterator for Records {
    type Item = Value;
    fn next(&mut self) -> Option<Value> {
        loop {
            let reader = self.reader.as_mut()?;
            let mut raw = Vec::new();
            if reader.read_until(b'\n', &mut raw).is_err() || !raw.ends_with(b"\n") {
                self.reader = None;
                return None;
            }
            let position = self.position;
            self.position += 1;
            let Ok(mut rec) = loads_strict(&ccs_pytext::decode_replace(&raw)) else {
                continue;
            };
            if !matches!(rec, Value::Object(_)) {
                continue;
            }
            if let Some(index) = self.index.as_mut() {
                if !index.accept(&rec) {
                    continue;
                }
                let Ok(normal) = session_codex::normalize_with_context(
                    &rec,
                    position,
                    &self.entrypoint,
                    &self.cwd,
                ) else {
                    continue;
                };
                rec = normal;
                self.entrypoint = get(&rec, "entrypoint").clone();
                if util::truthy(get(&rec, "cwd")) {
                    self.cwd = get(&rec, "cwd").clone();
                }
            }
            return Some(rec);
        }
    }
}
#[derive(Clone, Debug)]
pub struct LocalSession {
    pub path: PathBuf,
    pub session_id: String,
    pub project_dir: String,
    pub agent: String,
    pub title: String,
    pub cwd: String,
    pub cwd_candidates: Vec<String>,
    pub entrypoint: Option<String>,
    pub hits: usize,
    pub last_texts: VecDeque<(String, String)>,
    pub mtime: f64,
}
impl LocalSession {
    pub fn interactive(&self) -> bool {
        self.entrypoint.as_deref().is_some_and(|e| {
            ["cli", "claude-desktop"].contains(&e) || session_codex::INTERACTIVE.contains(&e)
        })
    }
    pub fn resume_cwd(&self) -> &str {
        self.cwd_candidates
            .iter()
            .find(|cwd| util::encode_cwd(cwd) == self.project_dir)
            .map(String::as_str)
            .unwrap_or(&self.cwd)
    }
    pub fn value(&self) -> Value {
        object([
            ("path", string(self.path.to_string_lossy())),
            ("session_id", string(&self.session_id)),
            ("project_dir", string(&self.project_dir)),
            ("agent", string(&self.agent)),
            ("title", string(&self.title)),
            ("cwd", string(&self.cwd)),
            (
                "cwd_candidates",
                Value::Array(self.cwd_candidates.iter().map(string).collect()),
            ),
            (
                "entrypoint",
                self.entrypoint.as_ref().map(string).unwrap_or(Value::Null),
            ),
            ("hits", number(self.hits)),
            (
                "last_texts",
                Value::Array(
                    self.last_texts
                        .iter()
                        .map(|(r, t)| Value::Array(vec![string(r), string(t)]))
                        .collect(),
                ),
            ),
            ("mtime", number(self.mtime)),
            ("interactive", Value::Bool(self.interactive())),
            ("resume_cwd", string(self.resume_cwd())),
        ])
    }
}
pub fn mtime(path: &Path) -> f64 {
    fs::metadata(path)
        .and_then(|s| s.modified())
        .ok()
        .map_or(0.0, |t| {
            t.duration_since(UNIX_EPOCH)
                .map_or_else(|e| -e.duration().as_secs_f64(), |d| d.as_secs_f64())
        })
}
pub fn scan(path: &Path, query: Option<&str>, keep_last: usize) -> LocalSession {
    scan_records(path, query, keep_last, iter_records(path))
}
fn scan_records(
    path: &Path,
    query: Option<&str>,
    keep_last: usize,
    records: impl IntoIterator<Item = Value>,
) -> LocalSession {
    let native = codex::is_path(path);
    let mut s = LocalSession {
        path: path.to_owned(),
        session_id: if native {
            codex::rollout_id(path).unwrap_or_default()
        } else {
            path.file_name()
                .and_then(|s| s.to_str())
                .and_then(|s| s.strip_suffix(".jsonl"))
                .unwrap_or("")
                .into()
        },
        project_dir: path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .into(),
        agent: if native { "codex" } else { "claude" }.into(),
        title: String::new(),
        cwd: String::new(),
        cwd_candidates: vec![],
        entrypoint: None,
        hits: 0,
        last_texts: VecDeque::new(),
        mtime: mtime(path),
    };
    let query = ccs_pytext::casefold(query.unwrap_or(""));
    let mut titles = [None, None, None];
    let mut first = None;
    for rec in records {
        if s.cwd.is_empty() {
            if let Some(cwd) = text(get(&rec, "cwd")) {
                s.cwd = cwd.clone();
                s.cwd_candidates.push(cwd);
            }
        }
        if s.entrypoint.is_none() {
            s.entrypoint = text(get(&rec, "entrypoint"));
        }
        if let Some(cwd) = text(get(&rec, "relocatedCwd")) {
            if !s.cwd_candidates.contains(&cwd) {
                s.cwd_candidates.push(cwd);
            }
        }
        for (i, (kind, key)) in [
            ("custom-title", "customTitle"),
            ("ai-title", "aiTitle"),
            ("summary", "summary"),
        ]
        .iter()
        .enumerate()
        {
            if is(get(&rec, "type"), kind) {
                if let Some(t) = text(get(&rec, key)) {
                    titles[i] = Some(t);
                }
            }
        }
        let content = record_text(&rec);
        if content.is_empty() {
            continue;
        }
        if first.is_none() && is(get(&rec, "type"), "user") {
            first = Some(content.clone());
        }
        if !query.is_empty() && ccs_pytext::casefold(&content).contains(&query) {
            s.hits += 1;
        }
        s.last_texts
            .push_back((text(get(&rec, "type")).unwrap_or_default(), content));
        if s.last_texts.len() > keep_last {
            s.last_texts.pop_front();
        }
    }
    let title = titles
        .into_iter()
        .flatten()
        .find(|s| !s.is_empty())
        .or(first)
        .unwrap_or_default();
    s.title = ccs_pytext::split(&title)
        .join(" ")
        .chars()
        .take(120)
        .collect();
    s
}
pub fn extract(path: &Path) -> Result<Value> {
    Ok(scan(path, None, 4).value())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extractor_strips_leading_blocks_and_meta() {
        assert_eq!(strip_leading_blocks("\x1c<system-reminder>ignore\n</system-reminder><bash-stdout>x</bash-stdout> real text "),"real text");
        assert_eq!(
            strip_leading_blocks("<bash-stdout>x</bash-stderr> keep"),
            "<bash-stdout>x</bash-stderr> keep"
        );
        let mut rec = object([
            ("type", string("user")),
            (
                "message",
                object([(
                    "content",
                    Value::Array(vec![
                        object([
                            ("type", string("text")),
                            ("text", string("<command-name>x</command-name> hello")),
                        ]),
                        object([("type", string("tool_use")), ("text", string("ignore"))]),
                        object([("type", string("text")), ("text", string("world"))]),
                    ]),
                )]),
            ),
        ]);
        assert_eq!(record_text(&rec), "hello\nworld");
        util::set(&mut rec, "isMeta", Value::Bool(true));
        assert_eq!(record_text(&rec), "");
    }

    #[test]
    fn title_and_resume_cwd() {
        let rec = object([
            ("type", string("user")),
            ("cwd", string("/old/place")),
            ("relocatedCwd", string("/work/demo")),
            ("entrypoint", string("cli")),
            ("message", object([("content", string("first ask"))])),
        ]);
        let title = object([
            ("type", string("ai-title")),
            ("aiTitle", string("Demo title")),
        ]);
        let s = scan_records(
            Path::new("/-work-demo/session.jsonl"),
            None,
            4,
            [rec, title],
        );
        assert_eq!(s.title, "Demo title");
        assert_eq!(s.resume_cwd(), "/work/demo");
        assert!(s.interactive());
    }
    #[test]
    fn duplicate_keys_make_the_record_unreadable() {
        assert!(loads_strict(r#"{"cwd":"/a","cwd":"/b"}"#).is_err());
        assert!(loads_strict(r#"{"message":{"a":1,"\u0061":2}}"#).is_err());
        assert!(loads_strict(r#"{"cwd":"/a","message":{"cwd":"/b"}}"#).is_ok());
    }
}
