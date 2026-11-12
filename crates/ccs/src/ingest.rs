//! Incremental, masked transcript shipping with Python-compatible cursors.
use crate::api::Api;
use crate::config::Config;
use crate::errors::{Error, ExitStatus, Result};
use crate::util::{self, get, number, object, set, string, text, truthy};
use crate::{codex, extract};
use ccs_pytext::json::{self, Value};
use ccs_redact::Redactor;
use std::collections::BTreeMap;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_SEGMENT: usize = 4 * 1024 * 1024;
const MAX_BLOB: usize = 4 * 1024 * 1024;

pub enum IngestMode {
    File(PathBuf),
    Sweep,
    Backfill,
}
pub struct IngestRequest {
    pub mode: IngestMode,
    pub with_subagents: bool,
    pub quiet: bool,
}

// Keep transport failures separate from a rejected individual file and the budget.
#[derive(Debug)]
enum Failure {
    Ship(String),
    Budget,
    Client(Error),
}
type ShipResult<T> = std::result::Result<T, Failure>;
impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        Self::Client(e)
    }
}
impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Self {
        Self::Client(Error::Io(e))
    }
}
fn ship_error(message: &str) -> Failure {
    Failure::Ship(message.into())
}
fn remove(value: &mut Value, key: &str) {
    if let Value::Object(items) = value {
        items.retain(|(k, _)| !k.iter().copied().eq(key.chars().map(u32::from)));
    }
}
// Retain arbitrary JSON integers for the protocol; narrow only for local I/O.
fn python_integer(value: &Value) -> Option<String> {
    match value {
        Value::Bool(b) => Some(u8::from(*b).to_string()),
        Value::Number(s) => decimal_integer(s),
        _ => None,
    }
}
fn decimal_integer(s: &str) -> Option<String> {
    let digits = s
        .strip_prefix('-')
        .or_else(|| s.strip_prefix('+'))
        .unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let digits = digits.trim_start_matches('0');
    Some(if digits.is_empty() {
        "0".into()
    } else if s.starts_with('-') {
        format!("-{digits}")
    } else {
        digits.into()
    })
}
fn integer(value: &Value) -> Option<u64> {
    python_integer(value)?.parse().ok()
}
fn nonnegative_integer(value: &Value) -> bool {
    python_integer(value).is_some_and(|s| !s.starts_with('-'))
}
fn offset_cmp(value: &Value, size: u64) -> Result<std::cmp::Ordering> {
    if let Some(n) = python_integer(value) {
        if n.starts_with('-') {
            return Ok(std::cmp::Ordering::Less);
        }
        let size = size.to_string();
        return Ok(n.len().cmp(&size.len()).then_with(|| n.cmp(&size)));
    }
    if let Value::Number(n) = value {
        if let Ok(n) = n.parse::<f64>() {
            return Ok(n
                .partial_cmp(&(size as f64))
                .unwrap_or(std::cmp::Ordering::Equal));
        }
    }
    Err(util::invalid("invalid state offset"))
}
fn increment_generation(value: &Value) -> Result<Value> {
    let n = if let Some(n) = python_integer(value) {
        n
    } else {
        match value {
            Value::Number(s) => {
                let f = s
                    .parse::<f64>()
                    .ok()
                    .filter(|f| f.is_finite())
                    .ok_or_else(|| util::invalid("invalid state generation"))?;
                decimal_integer(&format!("{:.0}", f.trunc()))
                    .ok_or_else(|| util::invalid("invalid state generation"))?
            }
            Value::String(points) => {
                let s =
                    json::scalar(points).map_err(|_| util::invalid("invalid state generation"))?;
                let s = ccs_pytext::strip(&s);
                let digits = regex::Regex::new(r"\A\p{Nd}\z").expect("decimal digit pattern");
                let mut ascii = String::new();
                for (i, c) in s.chars().enumerate() {
                    if c == '_' || (i == 0 && matches!(c, '+' | '-')) {
                        ascii.push(c);
                    } else if digits.is_match(&c.to_string()) {
                        let mut base = c as u32;
                        while base > 0
                            && char::from_u32(base - 1)
                                .is_some_and(|p| digits.is_match(&p.to_string()))
                        {
                            base -= 1;
                        }
                        ascii.push(char::from(b'0' + ((c as u32 - base) % 10) as u8));
                    } else {
                        return Err(util::invalid("invalid state generation"));
                    }
                }
                let bytes = ascii.as_bytes();
                if bytes.iter().enumerate().any(|(i, b)| {
                    *b == b'_'
                        && (i == 0
                            || i + 1 == bytes.len()
                            || !bytes[i - 1].is_ascii_digit()
                            || !bytes[i + 1].is_ascii_digit())
                }) {
                    return Err(util::invalid("invalid state generation"));
                }
                decimal_integer(&ascii.replace('_', ""))
                    .ok_or_else(|| util::invalid("invalid state generation"))?
            }
            _ => return Err(util::invalid("invalid state generation")),
        }
    };
    let negative = n.starts_with('-');
    let mut digits = n.trim_start_matches('-').as_bytes().to_vec();
    for d in digits.iter_mut().rev() {
        if negative {
            if *d == b'0' {
                *d = b'9';
            } else {
                *d -= 1;
                break;
            }
        } else if *d == b'9' {
            *d = b'0';
        } else {
            *d += 1;
            return Ok(number(String::from_utf8(digits).unwrap()));
        }
    }
    if !negative {
        digits.insert(0, b'1');
    }
    let value = format!(
        "{}{}",
        if negative { "-" } else { "" },
        String::from_utf8(digits).unwrap()
    );
    Ok(number(decimal_integer(&value).unwrap()))
}
fn response_json(body: &[u8]) -> Value {
    std::str::from_utf8(body)
        .ok()
        .and_then(|s| util::parse_json(s).ok())
        .unwrap_or(Value::Null)
}
fn python_str(value: &Value) -> Result<String> {
    Ok(match value {
        Value::String(_) => text(value).ok_or_else(|| util::invalid("invalid log text"))?,
        Value::Bool(b) => if *b { "True" } else { "False" }.into(),
        Value::Null => "None".into(),
        Value::Number(_) => match compact(value)?.as_str() {
            "NaN" => "nan".into(),
            "Infinity" => "inf".into(),
            "-Infinity" => "-inf".into(),
            n => n.into(),
        },
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(python_repr)
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        ),
        Value::Object(items) => format!(
            "{{{}}}",
            items
                .iter()
                .map(|(k, v)| Ok(format!(
                    "{}: {}",
                    python_repr(&Value::String(k.clone()))?,
                    python_repr(v)?
                )))
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        ),
    })
}
fn python_repr(value: &Value) -> Result<String> {
    let Value::String(_) = value else {
        return python_str(value);
    };
    let s = python_str(value)?;
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = quote.to_string();
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\\' => out.push_str("\\\\"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push(quote);
    Ok(out)
}
fn kind_items(kinds: &Value) -> Result<Vec<Value>> {
    match kinds {
        Value::Array(items) => Ok(items.clone()),
        Value::String(points) => Ok(points.iter().map(|p| Value::String(vec![*p])).collect()),
        Value::Object(items) => Ok(items
            .iter()
            .map(|(k, _)| Value::String(k.clone()))
            .collect()),
        _ => Err(util::invalid("invalid tombstone kinds")),
    }
}
fn utf8_path(path: &Path) -> bool {
    if path.to_str().is_some() {
        return true;
    }
    util::log("WARN", "ingest: non-UTF-8 name skipped");
    false
}
fn empty_object() -> Value {
    Value::Object(vec![])
}
fn digest(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn compact(value: &Value) -> Result<String> {
    json::dumps_compact(value, true, false).map_err(|_| util::invalid("invalid ingest JSON"))
}
fn tombstone(reason: &str, kinds: &Value, offset: u64) -> Result<String> {
    // Python's list(kinds) accepts sequences and dictionary keys, and the
    // tombstone itself uses ensure_ascii=True even though the HTTP JSON does not.
    let kinds = match kinds {
        Value::Array(_) => kinds.clone(),
        Value::String(points) => {
            Value::Array(points.iter().map(|p| Value::String(vec![*p])).collect())
        }
        Value::Object(items) => Value::Array(
            items
                .iter()
                .map(|(key, _)| Value::String(key.clone()))
                .collect(),
        ),
        _ => return Err(util::invalid("invalid tombstone kinds")),
    };
    compact(&object([
        ("type", string("session-search-tombstone")),
        ("reason", string(reason)),
        ("kinds", kinds),
        ("line_offset", number(offset)),
    ]))
}

fn classify(path: &Path) -> Option<Value> {
    if codex::is_path(path) {
        return codex::classify(path);
    }
    let root = codex::absolute(&util::projects_dir());
    let path = codex::absolute(path);
    if !util::is_within(&path, &root) {
        return None;
    }
    let relative = path.strip_prefix(&root).ok()?.to_str()?;
    let parts: Vec<_> = relative.split('/').collect();
    let (project, sid, agent) = match parts.as_slice() {
        [project, file] => (*project, file.strip_suffix(".jsonl")?, None),
        [project, sid, "subagents", file] => (
            *project,
            *sid,
            Some(file.strip_prefix("agent-")?.strip_suffix(".jsonl")?),
        ),
        _ => return None,
    };
    if project.is_empty() || sid.is_empty() || agent.is_some_and(str::is_empty) {
        return None;
    }
    let mut info = object([
        (
            "kind",
            string(if agent.is_some() { "subagent" } else { "main" }),
        ),
        ("project_dir", string(project)),
        ("session_id", string(sid)),
    ]);
    if let Some(agent) = agent {
        set(&mut info, "parent_session_id", string(sid));
        set(&mut info, "agent_id", string(agent));
    }
    Some(info)
}
fn subagent_files(session: &Path) -> Vec<PathBuf> {
    let sub = session.join("subagents");
    if sub.is_symlink() || !sub.is_dir() {
        return vec![];
    }
    let mut paths: Vec<_> = entries(&sub)
        .filter(|e| {
            utf8_path(&e.path())
                && e.file_type().is_ok_and(|t| t.is_file())
                && e.file_name()
                    .to_str()
                    .is_some_and(|s| s.starts_with("agent-") && s.ends_with(".jsonl"))
        })
        .map(|e| e.path())
        .collect();
    paths.sort();
    paths
}
fn entries(path: &Path) -> impl Iterator<Item = fs::DirEntry> {
    fs::read_dir(path)
        .into_iter()
        .flatten()
        .filter_map(std::result::Result::ok)
}
fn discover() -> Vec<PathBuf> {
    let mut out = codex::paths();
    for project in entries(&util::projects_dir()) {
        if !utf8_path(&project.path()) || !project.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        for entry in entries(&project.path()) {
            if !utf8_path(&entry.path()) {
                continue;
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_file()
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|s| s.ends_with(".jsonl"))
            {
                out.push(entry.path());
            } else if kind.is_dir() {
                out.extend(subagent_files(&entry.path()));
            }
        }
    }
    out.sort_by(|a, b| extract::mtime(b).total_cmp(&extract::mtime(a)));
    out
}

struct State {
    data: Value,
}
impl State {
    fn load() -> Self {
        let mut data = util::read_json(&util::state_path(), Value::Null);
        if !(crate::config::number(get(&data, "version")) == Some(1.0)
            || matches!(get(&data, "version"), Value::Bool(true)))
            || !matches!(get(&data, "files"), Value::Object(_))
        {
            data = object([("version", number(1)), ("files", empty_object())]);
        }
        Self { data }
    }
    fn files(&self) -> &Value {
        get(&self.data, "files")
    }
    fn files_mut(&mut self) -> &mut Value {
        let Value::Object(items) = &mut self.data else {
            unreachable!()
        };
        &mut items
            .iter_mut()
            .find(|(k, _)| k.iter().copied().eq("files".chars().map(u32::from)))
            .unwrap()
            .1
    }
    fn save(&self) -> Result<()> {
        let output = json::dumps_pretty(&self.data, true, true, 1)
            .map_err(|_| util::invalid("invalid ingest state"))?;
        util::atomic_write(&util::state_path(), &output, 0o600)
    }
}
struct Shipper {
    api: Api,
    redactor: Redactor,
    key: Vec<u8>,
    state: State,
    deadline: Option<Instant>,
    stats: BTreeMap<&'static str, u64>,
    codex_ready: Option<bool>,
}
#[derive(PartialEq)]
enum Outcome {
    Ok,
    Resync,
    TooLarge,
}
enum Segment {
    Partial,
    Lines(Vec<u8>),
    Oversize(Vec<u8>),
}
impl Shipper {
    fn check_budget(&self) -> ShipResult<()> {
        if self.deadline.is_some_and(|d| Instant::now() > d) {
            Err(Failure::Budget)
        } else {
            Ok(())
        }
    }
    fn bump(&mut self, key: &'static str, count: u64) {
        *self.stats.entry(key).or_default() += count;
    }
    fn entry_for(&self, path: &str, st: &Metadata) -> Result<Value> {
        let mut entry = get(self.state.files(), path).clone();
        if matches!(entry, Value::Null) {
            return Ok(object([
                ("dev", number(st.dev())),
                ("inode", number(st.ino())),
                ("size", number(0)),
                ("offset", number(0)),
                ("generation", number(0)),
                ("session_key", Value::Null),
                ("last_ok", Value::Null),
            ]));
        }
        if !matches!(entry, Value::Object(_)) {
            return Err(util::invalid("invalid state entry"));
        }
        let stored_offset = if util::has(&entry, "offset") {
            get(&entry, "offset").clone()
        } else {
            number(0)
        };
        if integer(get(&entry, "dev")) != Some(st.dev())
            || integer(get(&entry, "inode")) != Some(st.ino())
            || offset_cmp(&stored_offset, st.len())?.is_gt()
        {
            let generation = increment_generation(if util::has(&entry, "generation") {
                get(&entry, "generation")
            } else {
                &Value::Bool(false)
            })?;
            set(&mut entry, "generation", generation.clone());
            let generation = compact(&generation)?;
            set(&mut entry, "offset", number(0));
            set(&mut entry, "dev", number(st.dev()));
            set(&mut entry, "inode", number(st.ino()));
            remove(&mut entry, "blobs");
            util::log(
                "INFO",
                &format!("ingest: {path} rewritten or truncated -> generation {generation}"),
            );
        }
        Ok(entry)
    }
    fn read_segment(file: &mut File, offset: u64, size: u64, limit: usize) -> ShipResult<Segment> {
        file.seek(SeekFrom::Start(offset))?;
        let mut data = Vec::new();
        file.take((limit as u64).min(size - offset))
            .read_to_end(&mut data)?;
        if let Some(nl) = data.iter().rposition(|b| *b == b'\n') {
            data.truncate(nl + 1);
            return Ok(Segment::Lines(data));
        }
        if offset + data.len() as u64 >= size {
            return Ok(Segment::Partial);
        }
        loop {
            let remaining = size.saturating_sub(file.stream_position()?);
            let mut more = Vec::new();
            file.take(remaining.min(1 << 20)).read_to_end(&mut more)?;
            if more.is_empty() {
                return Ok(Segment::Partial);
            }
            if let Some(nl) = more.iter().position(|b| *b == b'\n') {
                data.extend_from_slice(&more[..=nl]);
                return Ok(if data.len() > MAX_SEGMENT {
                    Segment::Oversize(data)
                } else {
                    Segment::Lines(data)
                });
            }
            data.extend_from_slice(&more);
        }
    }
    fn mask_chunk(&mut self, chunk: &[u8], offset: u64) -> ShipResult<(Vec<String>, Vec<u64>)> {
        let mut lines = Vec::new();
        let mut offsets = Vec::new();
        let mut position = offset;
        let mut counts = BTreeMap::<String, u64>::new();
        for raw in chunk[..chunk.len() - 1].split(|b| *b == b'\n') {
            let masked = self
                .redactor
                .mask_line(raw, position, &self.key)
                .map_err(|_| util::invalid("line masking failed"))?;
            if let Some(output) = masked.output {
                if masked.route == "tombstone" {
                    self.bump("tombstones", 1);
                    if output.contains("\"reason\":\"surrogate\"") {
                        util::log(
                            "WARN",
                            &format!("ingest: surrogate at offset {position} -> tombstoned"),
                        );
                    }
                }
                for (kind, count) in masked.counts {
                    *counts.entry(kind).or_default() += count;
                }
                lines.push(output);
                offsets.push(position);
            }
            position += raw.len() as u64 + 1;
        }
        if !counts.is_empty() {
            util::log(
                "INFO",
                &format!(
                    "ingest: masked {}",
                    counts
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            );
        }
        Ok((lines, offsets))
    }
    fn body(
        &self,
        info: &Value,
        path: &str,
        entry: &Value,
        end: u64,
        lines: &[String],
    ) -> Result<Value> {
        if !util::has(entry, "generation") {
            return Err(util::invalid("missing state generation"));
        }
        let mut file = object([
            ("session_id", get(info, "session_id").clone()),
            ("project_dir", get(info, "project_dir").clone()),
            (
                "jsonl_path",
                string(codex::absolute(Path::new(path)).to_string_lossy()),
            ),
            ("kind", get(info, "kind").clone()),
        ]);
        for key in ["source", "parent_session_id", "agent_id"] {
            if util::has(info, key) {
                set(&mut file, key, get(info, key).clone());
            }
        }
        let payload = format!("{}\n", lines.join("\n"));
        Ok(object([
            (
                "client",
                object([
                    ("host", string(&self.api.config.host_label)),
                    ("client_version", string(env!("CARGO_PKG_VERSION"))),
                    ("redact_version", string(ccs_redact::REDACT_VERSION)),
                ]),
            ),
            ("file", file),
            (
                "segment",
                object([
                    ("generation", get(entry, "generation").clone()),
                    ("offset", get(entry, "offset").clone()),
                    ("end_offset", number(end)),
                    ("sha256", string(digest(payload.as_bytes()))),
                    ("lines", Value::Array(lines.iter().map(string).collect())),
                ]),
            ),
        ]))
    }
    fn send(
        &mut self,
        info: &Value,
        path: &str,
        entry: &mut Value,
        range: (u64, u64),
        mut lines: Vec<String>,
        offsets: &[u64],
    ) -> ShipResult<Outcome> {
        let (offset, end) = range;
        for _ in 0..3 {
            self.check_budget()?;
            let body = self.body(info, path, entry, end, &lines)?;
            let response = self.api.post("/ingest", &body, true, None)?;
            let data = response_json(&response.body);
            match response.status {
                200..=299 => {
                    if text(get(&data, "session_key")).is_some_and(|s| !s.is_empty()) {
                        set(entry, "session_key", get(&data, "session_key").clone());
                    }
                    let next = if nonnegative_integer(get(&data, "next_offset")) {
                        get(&data, "next_offset").clone()
                    } else {
                        number(end)
                    };
                    set(entry, "offset", next);
                    set(entry, "last_ok", string(util::iso(util::now_epoch())));
                    self.bump("segments", 1);
                    self.bump("bytes", end - offset);
                    return Ok(Outcome::Ok);
                }
                409 => {
                    let expected = python_integer(get(&data, "expected_offset"))
                        .filter(|s| !s.starts_with('-'))
                        .ok_or_else(|| ship_error("409 without a usable expected_offset"))?;
                    util::log(
                        "WARN",
                        &format!("ingest: {path} resync offset {offset} -> {expected}"),
                    );
                    set(entry, "offset", get(&data, "expected_offset").clone());
                    return Ok(Outcome::Resync);
                }
                413 => {
                    util::log(
                        "WARN",
                        &format!(
                            "ingest: {path} segment at {offset} too large ({} lines)",
                            lines.len()
                        ),
                    );
                    return Ok(Outcome::TooLarge);
                }
                422 => {
                    let Value::Array(indexes) = get(&data, "lines") else {
                        return Err(ship_error("422 without line indexes"));
                    };
                    if indexes.is_empty() {
                        return Err(ship_error("422 without line indexes"));
                    }
                    let kinds = if truthy(get(&data, "kinds")) {
                        get(&data, "kinds").clone()
                    } else {
                        Value::Array(vec![])
                    };
                    for index in indexes {
                        let index = integer(index)
                            .and_then(|i| usize::try_from(i).ok())
                            .filter(|i| *i < lines.len())
                            .ok_or_else(|| ship_error("422 named a line outside the segment"))?;
                        lines[index] = tombstone(
                            "unmasked_secret",
                            &kinds,
                            offsets.get(index).copied().unwrap_or(offset),
                        )?;
                        self.bump("tombstones", 1);
                    }
                    util::log(
                        "WARN",
                        &format!(
                            "ingest: {path} 422 at offset {offset} lines={} kinds={} -> tombstoned",
                            python_str(&Value::Array(indexes.clone()))?,
                            kind_items(&kinds)?
                                .iter()
                                .map(python_str)
                                .collect::<Result<Vec<_>>>()?
                                .join(",")
                        ),
                    );
                }
                status => return Err(ship_error(&format!("/ingest answered HTTP {status}"))),
            }
        }
        Err(ship_error("segment still rejected after tombstoning"))
    }
    fn ship_file(&mut self, path: &Path) -> ShipResult<()> {
        let info = classify(path).ok_or_else(|| ship_error("not a transcript path"))?;
        if util::is(get(&info, "source"), "codex") {
            if self.codex_ready.is_none() {
                let response = self.api.get("/status", &[], None)?;
                let data = response_json(&response.body);
                if response.status != 200 || !matches!(data, Value::Object(_)) {
                    return Err(ship_error("server capability check failed"));
                }
                self.codex_ready = Some(
                    matches!(get(&data, "sources"), Value::Array(v) if v.iter().any(|s| util::is(s,"codex"))),
                );
                if self.codex_ready == Some(false) {
                    util::log("INFO", "ingest: server has no Codex parser; Codex cursors held until the server is updated");
                }
            }
            if self.codex_ready == Some(false) {
                return Ok(());
            }
        }
        let root = if util::is(get(&info, "source"), "codex") {
            codex::sessions_dir()
        } else {
            util::projects_dir()
        };
        let mut file = util::open_regular(path, Some(&root))?;
        let st = file.metadata()?;
        let path = path
            .to_str()
            .ok_or_else(|| ship_error("non-UTF-8 path skipped"))?;
        let mut entry = self.entry_for(path, &st)?;
        let result = self.ship_open(path, &info, &mut file, &st, &mut entry);
        set(self.state.files_mut(), path, entry);
        result
    }
    fn ship_open(
        &mut self,
        path: &str,
        info: &Value,
        file: &mut File,
        st: &Metadata,
        entry: &mut Value,
    ) -> ShipResult<()> {
        let mut limit = MAX_SEGMENT;
        let mut resyncs = 0;
        if offset_cmp(get(entry, "offset"), st.len())?.is_lt() {
            self.bump("files", 1);
        }
        while offset_cmp(get(entry, "offset"), st.len())?.is_lt() {
            self.check_budget()?;
            let previous_offset = get(entry, "offset").clone();
            let offset = integer(get(entry, "offset"))
                .ok_or_else(|| util::invalid("invalid state offset"))?;
            let (chunk, forced) = match Self::read_segment(file, offset, st.len(), limit)? {
                Segment::Partial => break,
                Segment::Lines(c) => (c, false),
                Segment::Oversize(c) => (c, true),
            };
            let (lines, offsets) = if forced {
                (
                    vec![tombstone("too_large", &Value::Array(vec![]), offset)?],
                    vec![offset],
                )
            } else {
                self.mask_chunk(&chunk, offset)?
            };
            let count = lines.len();
            let end = offset + chunk.len() as u64;
            match self.send(info, path, entry, (offset, end), lines, &offsets)? {
                Outcome::Ok => {
                    limit = MAX_SEGMENT;
                    if forced {
                        self.bump("tombstones", 1);
                    }
                }
                Outcome::Resync => {
                    resyncs += 1;
                    self.bump("resyncs", 1);
                    if resyncs > 3 {
                        return Err(ship_error("offset resync did not converge"));
                    }
                    if offset_cmp(get(entry, "offset"), st.len())?.is_gt() {
                        set(entry, "offset", previous_offset);
                        return Err(ship_error("server expects offset beyond local size"));
                    }
                }
                Outcome::TooLarge if count > 1 => {
                    limit = (chunk.len() / 2).max(1);
                }
                Outcome::TooLarge => {
                    let lines = vec![tombstone("too_large", &Value::Array(vec![]), offset)?];
                    if self.send(info, path, entry, (offset, end), lines, &[offset])? != Outcome::Ok
                    {
                        return Err(ship_error("tombstone for an oversized line was refused"));
                    }
                    self.bump("tombstones", 1);
                }
            }
            set(self.state.files_mut(), path, entry.clone());
            self.state.save()?;
        }
        set(entry, "size", number(st.len()));
        self.ship_blobs(Path::new(path), info, entry)
    }
    fn ship_blobs(&mut self, path: &Path, info: &Value, entry: &mut Value) -> ShipResult<()> {
        if util::is(get(info, "source"), "codex")
            || !util::is(get(info, "kind"), "main")
            || !truthy(get(entry, "session_key"))
        {
            return Ok(());
        }
        let session = path
            .parent()
            .unwrap()
            .join(text(get(info, "session_id")).unwrap_or_default());
        let directory = session.join("tool-results");
        if session.is_symlink() || directory.is_symlink() {
            util::log("WARN", "ingest: symlink; tool-results not shipped");
            return Ok(());
        }
        let Ok(items) = fs::read_dir(&directory) else {
            return Ok(());
        };
        let mut names: Vec<_> = items
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name())
            .collect();
        names.sort();
        let mut sent = if util::has(entry, "blobs") {
            get(entry, "blobs").clone()
        } else {
            empty_object()
        };
        let result = (|| {
            for name in names {
                let Some(name) = name.to_str() else {
                    util::log("WARN", "ingest: non-UTF-8 name skipped");
                    continue;
                };
                if !util::valid_tool_result_name(name) {
                    util::log("WARN", "ingest: tool-results name invalid; not sent");
                    continue;
                }
                let Ok(mut file) =
                    util::open_regular(&directory.join(name), Some(&util::projects_dir()))
                else {
                    continue;
                };
                if file.metadata()?.len() > MAX_BLOB as u64 {
                    continue;
                }
                let mut raw = Vec::new();
                Read::by_ref(&mut file)
                    .take(MAX_BLOB as u64 + 1)
                    .read_to_end(&mut raw)?;
                if raw.len() > MAX_BLOB {
                    continue;
                }
                let raw_sha = digest(&raw);
                if !matches!(sent, Value::Object(_)) {
                    return Err(util::invalid("invalid state blobs").into());
                }
                if util::is(get(&sent, name), &raw_sha) {
                    continue;
                }
                self.check_budget()?;
                let (content, _) = self
                    .redactor
                    .redact_text(&String::from_utf8_lossy(&raw), &self.key)
                    .map_err(|_| util::invalid("blob masking failed"))?;
                let body = object([
                    ("session_key", get(entry, "session_key").clone()),
                    ("name", string(name)),
                    ("sha256", string(digest(content.as_bytes()))),
                    ("content", string(content)),
                ]);
                let response = self.api.post("/blob", &body, true, None)?;
                if (200..300).contains(&response.status) {
                    set(&mut sent, name, string(raw_sha));
                    self.bump("blobs", 1);
                } else {
                    util::log(
                        "WARN",
                        &format!("ingest: /blob {name} answered HTTP {}", response.status),
                    );
                }
            }
            Ok(())
        })();
        set(entry, "blobs", sent);
        result
    }
    fn report_gone(&mut self) -> ShipResult<()> {
        let Value::Object(files) = self.state.files() else {
            unreachable!()
        };
        let paths: Vec<_> = files
            .iter()
            .filter_map(|(k, _)| json::scalar(k).ok())
            .collect();
        for path in paths {
            if Path::new(&path).exists() {
                continue;
            }
            let entry = get(self.state.files(), &path);
            let key = get(entry, "session_key").clone();
            if truthy(&key) {
                self.check_budget()?;
                let response = self.api.post(
                    "/state",
                    &object([("session_key", key), ("jsonl_exists", Value::Bool(false))]),
                    false,
                    None,
                )?;
                if !(200..300).contains(&response.status) && response.status != 404 {
                    util::log(
                        "WARN",
                        &format!(
                            "ingest: /state for gone {path} answered HTTP {}",
                            response.status
                        ),
                    );
                    continue;
                }
            }
            remove(self.state.files_mut(), &path);
            self.bump("gone", 1);
        }
        self.state.save()?;
        Ok(())
    }
}

fn say(quiet: bool, message: &str) -> Result<()> {
    if !quiet {
        std::io::stdout()
            .write_all(format!("{message}\n").as_bytes())
            .map_err(Error::Io)?;
    }
    Ok(())
}
/// Python `ingest.run`, including the nonblocking process lock and final save.
pub fn run_ingest(request: &IngestRequest) -> Result<ExitStatus> {
    util::ensure_dir(&util::state_dir(), 0o700)?;
    let lock = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o666)
        .open(util::lock_path())
        .map_err(Error::Io)?;
    match lock.try_lock() {
        Ok(()) => (),
        Err(std::fs::TryLockError::WouldBlock) => {
            util::log("INFO", "ingest: another run holds the lock; exiting");
            return Ok(ExitStatus::Success);
        }
        Err(std::fs::TryLockError::Error(e)) => return Err(Error::Io(e)),
    }
    let config_path = util::config_path();
    let cfg = match Config::load(Some(&config_path)) {
        Ok(cfg) => cfg,
        Err(Error::Usage(message)) => {
            let missing = message.starts_with("not configured:");
            util::log(
                if missing { "INFO" } else { "ERROR" },
                &format!("ingest: {message}"),
            );
            say(request.quiet, &format!("ccs: {message}"))?;
            return Ok(if missing {
                ExitStatus::Success
            } else {
                ExitStatus::Usage
            });
        }
        Err(e) => return Err(e),
    };
    let key = fs::read(&cfg.hmac_key_file)
        .ok()
        .map(|v| {
            let whitespace = |b: &u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c);
            let start = v.iter().position(|b| !whitespace(b)).unwrap_or(v.len());
            let end = v
                .iter()
                .rposition(|b| !whitespace(b))
                .map_or(start, |i| i + 1);
            v[start..end].to_vec()
        })
        .filter(|v| !v.is_empty());
    let Some(key) = key else {
        util::log(
            "ERROR",
            "ingest: HMAC key unavailable (KeyMissing) — fail closed, cursor held",
        );
        say(
            request.quiet,
            &format!(
                "ccs: HMAC key unavailable at {}; nothing shipped",
                cfg.hmac_key_file.display()
            ),
        )?;
        return Ok(ExitStatus::Unavailable);
    };
    let (files, budget, mode) = match &request.mode {
        IngestMode::File(path) => {
            if !utf8_path(path) {
                return Ok(ExitStatus::Success);
            }
            if classify(path).is_none() {
                let message = format!(
                    "{} is not a transcript under {}",
                    path.display(),
                    util::projects_dir().display()
                );
                util::log("WARN", &format!("ingest: --file {message}"));
                say(request.quiet, &format!("ccs: {message}"))?;
                return Ok(ExitStatus::Usage);
            }
            let mut files = vec![codex::absolute(path)];
            if request.with_subagents {
                files.extend(subagent_files(&path.with_extension("")));
            }
            (files, Some(20), "file")
        }
        IngestMode::Sweep => (discover(), Some(120), "sweep"),
        IngestMode::Backfill => (discover(), None, "backfill"),
    };
    let mut shipper = Shipper {
        api: Api::new(cfg),
        redactor: Redactor::new(),
        key,
        state: State::load(),
        deadline: budget.map(|s| Instant::now() + Duration::from_secs(s)),
        codex_ready: None,
        stats: [
            "files",
            "segments",
            "bytes",
            "tombstones",
            "resyncs",
            "errors",
            "blobs",
            "gone",
        ]
        .into_iter()
        .map(|k| (k, 0))
        .collect(),
    };
    let result = (|| {
        for path in files {
            match shipper.ship_file(&path) {
                Ok(()) => (),
                Err(Failure::Client(Error::Io(e))) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(Failure::Client(e)) if util::is_unsafe_path(&e) => {
                    shipper.bump("errors", 1);
                    util::log(
                        "WARN",
                        &format!("ingest: {}: unsafe path skipped", path.display()),
                    );
                }
                Err(Failure::Ship(message)) => {
                    shipper.bump("errors", 1);
                    util::log("WARN", &format!("ingest: {}: {message}", path.display()));
                }
                Err(e) => return Err(e),
            }
        }
        if matches!(request.mode, IngestMode::Sweep) {
            shipper.report_gone()?;
        }
        Ok(())
    })();
    shipper.state.save()?;
    let code = match result {
        Ok(()) => ExitStatus::Success,
        Err(Failure::Budget) => {
            util::log(
                "INFO",
                &format!("ingest: {mode} budget used; the next run continues"),
            );
            ExitStatus::Success
        }
        Err(Failure::Client(Error::Unavailable(_) | Error::Usage(_))) => {
            util::log("WARN", "ingest: server unavailable; cursor held");
            ExitStatus::Unavailable
        }
        Err(Failure::Client(e)) => return Err(e),
        Err(Failure::Ship(_)) => unreachable!(),
    };
    let stats = util::json_string(
        &object(shipper.stats.iter().map(|(k, v)| (*k, number(v)))),
        true,
        true,
    )?;
    util::log("INFO", &format!("ingest: {mode} done {stats}"));
    say(request.quiet, &format!("ccs ingest: {stats}"))?;
    Ok(code)
}

/// Preserve the original JSON dispatch boundary for existing callers.
pub fn run(_config: &Value, request: &Value) -> Result<Value> {
    let mode = match text(get(request, "mode")).as_deref() {
        Some("file") => IngestMode::File(PathBuf::from(
            text(get(request, "file_path"))
                .ok_or_else(|| Error::Usage("missing file path".into()))?,
        )),
        Some("sweep") => IngestMode::Sweep,
        Some("backfill") => IngestMode::Backfill,
        _ => return Err(Error::Usage("invalid ingest mode".into())),
    };
    run_ingest(&IngestRequest {
        mode,
        with_subagents: truthy(get(request, "with_subagents")),
        quiet: truthy(get(request, "quiet")),
    })
    .map(|status| number(status.code()))
}
