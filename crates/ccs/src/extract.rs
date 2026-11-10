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
/// UTF-8 display view. Use record_text_points for exact Python/JSON strings.
pub fn record_text(rec: &Value) -> String {
    display_points(&record_text_points(rec))
}
fn points(value: &Value) -> Option<&[u32]> {
    match value {
        Value::String(value) => Some(value),
        _ => None,
    }
}
fn display_points(value: &[u32]) -> String {
    value
        .iter()
        .map(|&c| char::from_u32(c).unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}
pub fn strip_leading_points(mut value: &[u32]) -> Vec<u32> {
    loop {
        let start = ccs_pytext::lstrip_points(value);
        let mut removed = false;
        for tag in LEADING_TAGS {
            let open: Vec<_> = format!("<{tag}>").chars().map(u32::from).collect();
            let close: Vec<_> = format!("</{tag}>").chars().map(u32::from).collect();
            if let Some(body) = start.strip_prefix(open.as_slice()) {
                if let Some(end) = body.windows(close.len()).position(|s| s == close) {
                    value = ccs_pytext::lstrip_points(&body[end + close.len()..]);
                    removed = true;
                    break;
                }
            }
        }
        if !removed {
            return ccs_pytext::strip_points(value).to_vec();
        }
    }
}
/// Exact Python text, including lone surrogates that a Rust String cannot hold.
pub fn record_text_points(rec: &Value) -> Vec<u32> {
    if !["user", "assistant"]
        .iter()
        .any(|s| is(get(rec, "type"), s))
        || get(rec, "isMeta") == &Value::Bool(true)
        || get(rec, "isCompactSummary") == &Value::Bool(true)
    {
        return Vec::new();
    }
    let content = get(get(rec, "message"), "content");
    let parts = match content {
        Value::String(_) => points(content).into_iter().collect::<Vec<_>>(),
        Value::Array(blocks) => blocks
            .iter()
            .filter(|b| is(get(b, "type"), "text"))
            .filter_map(|b| points(get(b, "text")))
            .collect(),
        _ => vec![],
    };
    strip_leading_points(
        &parts
            .iter()
            .map(|s| strip_leading_points(s))
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(&[u32::from('\n')][..]),
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

// Local readers deliberately materialize beyond Python's recursion limit (D10).
// Release consumed records iteratively, including on skipped-record paths, so
// a worker thread's smaller stack does not change that reading behavior.
fn discard_record(value: Value) {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Array(values) => pending.extend(values),
            Value::Object(fields) => pending.extend(fields.into_iter().map(|(_, value)| value)),
            _ => {}
        }
    }
}

pub struct Records {
    reader: Option<BufReader<fs::File>>,
    index: Option<session_codex::IndexState>,
    position: usize,
    entrypoint: Value,
    cwd: Value,
    failure: Option<crate::errors::Error>,
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
        failure: None,
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
                discard_record(rec);
                continue;
            }
            if let Some(index) = self.index.as_mut() {
                if !index.accept(&rec) {
                    discard_record(rec);
                    continue;
                }
                let normal = match session_codex::normalize_with_context(
                    &rec,
                    position,
                    &self.entrypoint,
                    &self.cwd,
                ) {
                    Ok(normal) => normal,
                    Err(error) => {
                        discard_record(rec);
                        self.failure = Some(error);
                        self.reader = None;
                        return None;
                    }
                };
                discard_record(rec);
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
    // UTF-8 fields above are display projections. JSON consumers use value(),
    // which retains Python's full code-point strings rather than these views.
    source: LocalText,
}
#[derive(Clone, Debug, Default)]
struct LocalText {
    title: Vec<u32>,
    cwd: Vec<u32>,
    cwd_candidates: Vec<Vec<u32>>,
    entrypoint: Option<Vec<u32>>,
    last_texts: VecDeque<(String, Vec<u32>)>,
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
    pub fn cwd_points(&self) -> &[u32] {
        &self.source.cwd
    }
    pub fn resume_cwd_points(&self) -> &[u32] {
        self.source
            .cwd_candidates
            .iter()
            .find(|cwd| {
                let encoded: String = cwd
                    .iter()
                    .map(|&c| {
                        char::from_u32(c)
                            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
                            .unwrap_or('-')
                    })
                    .collect();
                encoded == self.project_dir
            })
            .map(Vec::as_slice)
            .unwrap_or(&self.source.cwd)
    }
    pub fn value(&self) -> Value {
        object([
            ("path", string(self.path.to_string_lossy())),
            ("session_id", string(&self.session_id)),
            ("project_dir", string(&self.project_dir)),
            ("agent", string(&self.agent)),
            ("title", Value::String(self.source.title.clone())),
            ("cwd", Value::String(self.source.cwd.clone())),
            (
                "cwd_candidates",
                Value::Array(
                    self.source
                        .cwd_candidates
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            ),
            (
                "entrypoint",
                self.source
                    .entrypoint
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            ),
            ("hits", number(self.hits)),
            (
                "last_texts",
                Value::Array(
                    self.source
                        .last_texts
                        .iter()
                        .map(|(r, t)| Value::Array(vec![string(r), Value::String(t.clone())]))
                        .collect(),
                ),
            ),
            ("mtime", number(format!("{:?}", self.mtime))),
            ("interactive", Value::Bool(self.interactive())),
            (
                "resume_cwd",
                Value::String(self.resume_cwd_points().to_vec()),
            ),
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
/// Production result boundary: normalization errors must not become no matches.
pub fn scan_checked(path: &Path, query: Option<&str>, keep_last: usize) -> Result<LocalSession> {
    scan_reader(path, query, keep_last, iter_records(path))
}
fn scan_reader(
    path: &Path,
    query: Option<&str>,
    keep_last: usize,
    mut records: Records,
) -> Result<LocalSession> {
    let session = scan_records(path, query, keep_last, &mut records);
    match records.failure {
        Some(error) => Err(error),
        None => Ok(session),
    }
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
        source: LocalText::default(),
    };
    let query: Vec<u32> = ccs_pytext::casefold(query.unwrap_or(""))
        .chars()
        .map(u32::from)
        .collect();
    let mut titles = [None, None, None];
    let mut first = None;
    for rec in records {
        if s.source.cwd.is_empty() {
            if let Some(cwd) = points(get(&rec, "cwd")) {
                s.source.cwd = cwd.to_vec();
                s.source.cwd_candidates.push(cwd.to_vec());
            }
        }
        if s.source.entrypoint.is_none() {
            s.source.entrypoint = points(get(&rec, "entrypoint")).map(<[u32]>::to_vec);
        }
        if let Some(cwd) = points(get(&rec, "relocatedCwd")) {
            if !s.source.cwd_candidates.iter().any(|c| c == cwd) {
                s.source.cwd_candidates.push(cwd.to_vec());
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
                if let Some(t) = points(get(&rec, key)) {
                    titles[i] = Some(t.to_vec());
                }
            }
        }
        let content = record_text_points(&rec);
        if content.is_empty() {
            discard_record(rec);
            continue;
        }
        if first.is_none() && is(get(&rec, "type"), "user") {
            first = Some(content.clone());
        }
        if !query.is_empty()
            && ccs_pytext::casefold_points(&content)
                .windows(query.len())
                .any(|s| s == query)
        {
            s.hits += 1;
        }
        s.source
            .last_texts
            .push_back((text(get(&rec, "type")).unwrap_or_default(), content));
        if s.source.last_texts.len() > keep_last {
            s.source.last_texts.pop_front();
        }
        discard_record(rec);
    }
    let title = titles
        .into_iter()
        .flatten()
        .find(|s| !s.is_empty())
        .or(first)
        .unwrap_or_default();
    s.source.title = ccs_pytext::split_points(&title)
        .join(&[u32::from(' ')][..])
        .into_iter()
        .take(120)
        .collect();
    s.title = display_points(&s.source.title);
    s.cwd = display_points(&s.source.cwd);
    s.cwd_candidates = s
        .source
        .cwd_candidates
        .iter()
        .map(|s| display_points(s))
        .collect();
    s.entrypoint = s.source.entrypoint.as_ref().map(|s| display_points(s));
    s.last_texts = s
        .source
        .last_texts
        .iter()
        .map(|(kind, text)| (kind.clone(), display_points(text)))
        .collect();
    s
}
pub fn extract(path: &Path) -> Result<Value> {
    Ok(scan_checked(path, None, 4)?.value())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalization_failure_reaches_result_boundary() {
        let path = std::env::temp_dir().join(format!(
            "ccs-normalize-error-{}-{}",
            std::process::id(),
            util::now_epoch().to_bits()
        ));
        fs::write(&path, concat!(r#"{"type":"response_item","payload":{"type":"message","role":"user","content":"needle\ud800"}}"#, "\n")).unwrap();
        let records = Records {
            reader: Some(BufReader::new(fs::File::open(&path).unwrap())),
            index: Some(session_codex::IndexState::new(Value::Null, None)),
            position: 0,
            entrypoint: Value::Null,
            cwd: Value::Null,
            failure: None,
        };
        let error = scan_reader(&path, Some("needle"), 4, records).unwrap_err();
        assert_eq!(error.exit_status().code(), 1);
        fs::remove_file(path).unwrap();
    }
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
    #[test]
    fn codepoint_records_remain_searchable() {
        let rec = loads_strict(r#"{"type":"user","cwd":"/work/\udc80","relocatedCwd":"/resume/\ud800","entrypoint":"cli","message":{"content":"\u001c<system-reminder>\ud800</system-reminder> Stra\u00dfe\ud800needle "}}"#).unwrap();
        let expected = loads_strict(r#""Stra\u00dfe\ud800needle""#).unwrap();
        assert_eq!(Value::String(record_text_points(&rec)), expected);
        let session = scan_records(
            Path::new("/-resume--/session.jsonl"),
            Some("STRASSE"),
            4,
            [rec.clone()],
        );
        let value = session.value();
        assert_eq!(session.hits, 1);
        assert!(session.interactive());
        assert_eq!(get(&value, "title"), &expected);
        assert_eq!(get(&value, "cwd"), get(&rec, "cwd"));
        assert_eq!(get(&value, "mtime"), &Value::Number("0.0".into()));
        assert_eq!(get(&value, "resume_cwd"), get(&rec, "relocatedCwd"));
        assert_eq!(
            get(&value, "last_texts"),
            &Value::Array(vec![Value::Array(vec![string("user"), expected])])
        );
        assert_eq!(
            scan_records(
                Path::new("/session.jsonl"),
                Some("\u{fffd}"),
                4,
                [rec.clone()]
            )
            .hits,
            0
        );
        let title = loads_strict(
            r#"{"type":"custom-title","customTitle":"\u001c custom\udfff\u2003title "}"#,
        )
        .unwrap();
        let value = scan_records(Path::new("/session.jsonl"), None, 0, [rec, title]).value();
        assert_eq!(
            get(&value, "title"),
            &loads_strict(r#""custom\udfff title""#).unwrap()
        );
        assert_eq!(get(&value, "last_texts"), &Value::Array(vec![]));
    }
}
