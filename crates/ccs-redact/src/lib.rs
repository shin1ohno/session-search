//! I/O-free Python-compatible redaction. Tables are generated from the pinned Python oracle.
#![forbid(unsafe_code)]
mod tables;
use ccs_pytext::json::{self, scalar, Value};
use regex_automata::{meta::Regex, util::captures::Captures, Anchored, Input};
use std::collections::HashSet;
use tables::{CLS, G, RULES, SPACE, WORD};

pub use tables::SOURCE_BLOB as REDACT_SOURCE_BLOB;

pub const REDACT_VERSION: &str = "r1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    EmptyKey,
    InvalidRecord,
    Json(json::Error),
}
impl From<json::Error> for Error {
    fn from(e: json::Error) -> Self {
        Self::Json(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "redaction {:?}", self)
    }
}
impl std::error::Error for Error {}

#[derive(Debug)]
pub struct MaskedLine {
    pub route: &'static str,
    pub output: Option<String>,
    pub counts: Counts,
    pub offsets: Vec<u64>,
}

pub const MAX_VALUE_CHARS: usize = 1_000_000;
pub const MAX_RECORD_CHARS: usize = 4_000_000;
const MAX_KEY_NAME_CHARS: usize = 128;
pub const MAX_RECORD_DEPTH: usize = 64;
const OVERSIZE: &str = "[REDACTED:oversize]";
const CFG_MIN_LEN: usize = 8;
pub const MAX_PASSES: usize = 8;
/// Counts retain first-hit order, like Python dictionaries.
pub type Counts = Vec<(String, u64)>;
fn bump(counts: &mut Counts, kind: &str) {
    if let Some((_, n)) = counts.iter_mut().find(|(k, _)| k == kind) {
        *n += 1;
    } else {
        counts.push((kind.into(), 1));
    }
}

fn in_table(t: &[(u32, u32)], c: char) -> bool {
    let c = c as u32;
    t.binary_search_by(|&(a, b)| {
        if c < a {
            std::cmp::Ordering::Greater
        } else if c > b {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Equal
        }
    })
    .is_ok()
}

struct Rule {
    re: Regex,
    start: G,
    end: G,
    first: [bool; 256],
}

pub struct Redactor {
    placeholder: Rule,
    private_key: Rule,
    tagged: Vec<(&'static str, Rule)>,
    bearer: Rule,
    url: Rule,
    cfg_json: Rule,
    cfg_kv: Rule,
    anchor: Rule,
    cfg_key_full: Rule,
}

fn first_table(bytes: &[u8]) -> [bool; 256] {
    let mut t = [false; 256];
    for &b in bytes {
        t[b as usize] = true;
    }
    t
}

fn make(name: &str, pat: &str, start: G, end: G, first: &[u8]) -> Rule {
    Rule {
        re: Regex::new(pat).unwrap_or_else(|e| panic!("{name}: {e}")),
        start,
        end,
        first: first_table(first),
    }
}

impl Redactor {
    fn rule(&self, name: &str) -> Rule {
        let (_, p, s, e, f) = RULES.iter().find(|r| r.0 == name).unwrap();
        make(name, p, *s, *e, f)
    }
    fn by_name(&self, name: &str) -> &Rule {
        match name {
            "placeholder" => &self.placeholder,
            "private-key" => &self.private_key,
            "bearer" => &self.bearer,
            "url-credential" => &self.url,
            "cfg-json" => &self.cfg_json,
            "cfg-kv" => &self.cfg_kv,
            "anchor" => &self.anchor,
            "cfg-key-full" => &self.cfg_key_full,
            other => &self.tagged.iter().find(|t| t.0 == other).unwrap().1,
        }
    }
    fn cls(&self, i: usize) -> &[(u32, u32)] {
        CLS[i]
    }
    fn word(&self, c: char) -> bool {
        in_table(WORD, c)
    }
    fn boundary(&self, seg: &str, at: usize) -> bool {
        let p = seg[..at]
            .chars()
            .next_back()
            .map(|c| self.word(c))
            .unwrap_or(false);
        let n = seg[at..]
            .chars()
            .next()
            .map(|c| self.word(c))
            .unwrap_or(false);
        p != n
    }
    fn start_ok(&self, g: G, seg: &str, at: usize) -> bool {
        match g {
            G::None => true,
            G::Boundary => self.boundary(seg, at),
            G::NotAfter(i) => match seg[..at].chars().next_back() {
                Some(c) => !in_table(self.cls(i), c),
                None => true,
            },
        }
    }
    fn end_ok(&self, g: G, seg: &str, at: usize) -> bool {
        match g {
            G::Boundary => self.boundary(seg, at),
            _ => true,
        }
    }
    // re.sub. A guarded rule tries each start position in order: guard first, then an anchored
    // match. Refusing a start costs one table lookup, as in Python, so it stays linear.
    fn sub(
        &self,
        r: &Rule,
        seg: &str,
        f: &mut dyn FnMut(&Captures, &str) -> Option<String>,
    ) -> String {
        let mut out = String::with_capacity(seg.len());
        let mut caps = r.re.create_captures();
        let (mut last, mut pos) = (0, 0);
        let bytes = seg.as_bytes();
        if matches!(r.start, G::None) && matches!(r.end, G::None) {
            while pos <= seg.len() {
                r.re.search_captures(&Input::new(seg).span(pos..seg.len()), &mut caps);
                let Some(m) = caps.get_match() else { break };
                out.push_str(&seg[last..m.start()]);
                match f(&caps, seg) {
                    Some(rep) => out.push_str(&rep),
                    None => out.push_str(&seg[m.range()]),
                }
                last = m.end();
                pos = m.end().max(pos + 1);
            }
        } else {
            while pos < seg.len() {
                if r.first[bytes[pos] as usize] && self.start_ok(r.start, seg, pos) {
                    r.re.search_captures(
                        &Input::new(seg).span(pos..seg.len()).anchored(Anchored::Yes),
                        &mut caps,
                    );
                    if let Some(m) = caps.get_match() {
                        if self.end_ok(r.end, seg, m.end()) {
                            out.push_str(&seg[last..m.start()]);
                            match f(&caps, seg) {
                                Some(rep) => out.push_str(&rep),
                                None => out.push_str(&seg[m.range()]),
                            }
                            last = m.end();
                            pos = m.end();
                            continue;
                        }
                    }
                }
                pos += seg[pos..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            }
        }
        out.push_str(&seg[last..]);
        out
    }
    fn outside(&self, text: &str, fun: &mut dyn FnMut(&str) -> String) -> String {
        let mut out = String::with_capacity(text.len());
        let mut pos = 0;
        for m in self.placeholder.re.find_iter(text) {
            if m.start() > pos {
                out.push_str(&fun(&text[pos..m.start()]));
            }
            out.push_str(&text[m.range()]);
            pos = m.end();
        }
        if pos < text.len() {
            out.push_str(&fun(&text[pos..]));
        }
        out
    }
    fn py_strip<'a>(&self, v: &'a str) -> &'a str {
        v.trim_matches(|c| in_table(SPACE, c))
    }
    fn is_value_placeholder(&self, value: &str) -> bool {
        let v = self.py_strip(value);
        let xxx = v
            .chars()
            .take(3)
            .map(|c| c.to_lowercase().collect::<String>())
            .collect::<String>()
            .starts_with("xxx");
        v.starts_with("${")
            || v.starts_with('<')
            || xxx
            || v.starts_with("***")
            || v.starts_with("[REDACTED")
    }
    fn maskable(&self, v: &str) -> bool {
        v.chars().count() >= CFG_MIN_LEN && !self.is_value_placeholder(v)
    }
    fn tag(&self, key: &[u8], v: &str) -> String {
        let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
        let s = ring::hmac::sign(&k, v.as_bytes());
        s.as_ref()[..4].iter().map(|b| format!("{b:02x}")).collect()
    }
    fn one_pass(&self, text: String, key: &[u8], counts: &mut Counts) -> String {
        fn g<'a>(c: &Captures, s: &'a str, i: usize) -> &'a str {
            c.get_group(i).map(|m| &s[m.range()]).unwrap_or("")
        }
        let mut text = text;
        text = self.outside(&text, &mut |s| {
            self.sub(&self.private_key, s, &mut |_, _| {
                bump(counts, "private-key");
                Some("[REDACTED:private-key]".to_string())
            })
        });
        for (kind, r) in &self.tagged {
            text = self.outside(&text, &mut |s| {
                self.sub(r, s, &mut |c, h| {
                    bump(counts, kind);
                    Some(format!("[REDACTED:{}:{}]", kind, self.tag(key, g(c, h, 0))))
                })
            });
        }
        text = self.outside(&text, &mut |s| {
            self.sub(&self.bearer, s, &mut |c, h| {
                bump(counts, "bearer");
                Some(format!("{}[REDACTED:bearer]", g(c, h, 1)))
            })
        });
        text = self.outside(&text, &mut |s| {
            self.sub(&self.url, s, &mut |c, h| {
                bump(counts, "url-credential");
                Some(format!(
                    "{}[REDACTED:url-credential]{}",
                    g(c, h, 1),
                    g(c, h, 3)
                ))
            })
        });
        {
            text = self.outside(&text, &mut |s| {
                self.sub(&self.cfg_json, s, &mut |c, h| {
                    if !self.maskable(g(c, h, 2)) {
                        return None;
                    }
                    bump(counts, "config-secret");
                    Some(format!(
                        "{}[REDACTED:config-secret]{}",
                        g(c, h, 1),
                        g(c, h, 3)
                    ))
                })
            });
        }
        text = self.outside(&text, &mut |s| {
            self.sub(&self.cfg_kv, s, &mut |c, h| {
                if !self.maskable(g(c, h, 2)) {
                    return None;
                }
                bump(counts, "config-secret");
                Some(format!("{}[REDACTED:config-secret]", g(c, h, 1)))
            })
        });
        text
    }
    fn mask_text(&self, text: &str, key: &[u8], counts: &mut Counts, max: usize) -> String {
        if text.chars().count() > max {
            bump(counts, "oversize");
            return OVERSIZE.to_string();
        }
        if !self.anchor.re.is_match(text) {
            return text.to_string();
        }
        let mut t = text.to_string();
        for _ in 0..MAX_PASSES {
            let new = self.one_pass(t.clone(), key, counts);
            if new == t {
                break;
            }
            t = new;
        }
        t
    }
    fn dict_key_secret(&self, name: &str, value: &str) -> bool {
        name.chars().count() <= MAX_KEY_NAME_CHARS
            && self.cfg_key_full.re.is_match(name)
            && self.maskable(value)
    }
    fn text_budget(&self, v: &str, key: &[u8], counts: &mut Counts, used: &mut usize) -> String {
        *used += v.chars().count();
        if *used > MAX_RECORD_CHARS {
            bump(counts, "oversize");
            return OVERSIZE.to_string();
        }
        self.mask_text(v, key, counts, MAX_VALUE_CHARS)
    }
    // Depth-first with children visited last-to-first: the order Python's LIFO stack produces.
    // Recursion is bounded: a line deeper than MAX_RECORD_DEPTH never reaches this function.
    fn walk(
        &self,
        v: Value,
        name: Option<&str>,
        key: &[u8],
        counts: &mut Counts,
        used: &mut usize,
    ) -> Value {
        match v {
            Value::String(s) => {
                let s = scalar(&s).expect("validated scalar domain");
                if let Some(n) = name {
                    if self.dict_key_secret(n, &s) {
                        *used += s.chars().count();
                        bump(counts, "config-secret");
                        return Value::string("[REDACTED:config-secret]");
                    }
                }
                Value::string(&self.text_budget(&s, key, counts, used))
            }
            Value::Array(a) => {
                let mut out: Vec<Value> = Vec::with_capacity(a.len());
                for x in a.into_iter().rev() {
                    out.push(self.walk(x, None, key, counts, used));
                }
                out.reverse();
                Value::Array(out)
            }
            Value::Object(m) => {
                let mut entries: Vec<(String, String, Value)> = Vec::with_capacity(m.len());
                let mut seen = HashSet::new();
                for (ok, ov) in m {
                    let ok = scalar(&ok).expect("validated scalar key");
                    let mut nk = self.text_budget(&ok, key, counts, used);
                    if seen.contains(&nk) {
                        let mut i = 2;
                        while seen.contains(&format!("{nk}#{i}")) {
                            i += 1;
                        }
                        nk = format!("{nk}#{i}");
                    }
                    seen.insert(nk.clone());
                    entries.push((nk, ok, ov));
                }
                let mut done: Vec<(String, Value)> = Vec::with_capacity(entries.len());
                for (nk, ok, ov) in entries.into_iter().rev() {
                    let nv = self.walk(ov, Some(&ok), key, counts, used);
                    done.push((nk, nv));
                }
                done.reverse();
                Value::Object(
                    done.into_iter()
                        .map(|(k, v)| (k.chars().map(u32::from).collect(), v))
                        .collect(),
                )
            }
            other => other,
        }
    }

    pub fn new() -> Self {
        let dummy = || make("x", "x", G::None, G::None, &[]);
        let mut r = Self {
            placeholder: dummy(),
            private_key: dummy(),
            tagged: Vec::new(),
            bearer: dummy(),
            url: dummy(),
            cfg_json: dummy(),
            cfg_kv: dummy(),
            anchor: dummy(),
            cfg_key_full: dummy(),
        };
        r.placeholder = r.rule("placeholder");
        r.private_key = r.rule("private-key");
        r.tagged = [
            "aws-key",
            "github-token",
            "anthropic-key",
            "openai-key",
            "slack-token",
            "google-api-key",
            "gitlab-token",
            "jwt",
        ]
        .iter()
        .map(|k| (*k, r.rule(k)))
        .collect();
        r.bearer = r.rule("bearer");
        r.url = r.rule("url-credential");
        r.cfg_json = r.rule("cfg-json");
        r.cfg_kv = r.rule("cfg-kv");
        r.anchor = r.rule("anchor");
        r.cfg_key_full = r.rule("cfg-key-full");
        r
    }
    pub fn redact_text(&self, text: &str, key: &[u8]) -> Result<(String, Counts), Error> {
        self.redact_text_capped(text, key, MAX_VALUE_CHARS)
    }
    pub fn redact_text_capped(
        &self,
        text: &str,
        key: &[u8],
        max_chars: usize,
    ) -> Result<(String, Counts), Error> {
        if key.is_empty() {
            return Err(Error::EmptyKey);
        }
        let mut counts = Counts::new();
        let out = self.mask_text(text, key, &mut counts, max_chars);
        Ok((out, counts))
    }
    pub fn redact_record(&self, value: &Value, key: &[u8]) -> Result<(Value, Counts), Error> {
        if key.is_empty() {
            return Err(Error::EmptyKey);
        }
        let mut stack = vec![(value, 1)];
        while let Some((v, depth)) = stack.pop() {
            if depth > MAX_RECORD_DEPTH {
                return Err(Error::InvalidRecord);
            }
            match v {
                Value::String(s) => {
                    scalar(s)?;
                }
                Value::Array(a) => stack.extend(a.iter().map(|v| (v, depth + 1))),
                Value::Object(o) => {
                    for (k, v) in o {
                        scalar(k)?;
                        stack.push((v, depth + 1));
                    }
                }
                _ => {}
            }
        }
        let mut counts = Counts::new();
        let out = self.walk(value.clone(), None, key, &mut counts, &mut 0);
        Ok((out, counts))
    }
    /// Inspect a complete raw line before masking. Guard failures never fall back to text.
    pub fn mask_line(&self, raw: &[u8], offset: u64, key: &[u8]) -> Result<MaskedLine, Error> {
        if key.is_empty() {
            return Err(Error::EmptyKey);
        }
        if raw
            .iter()
            .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c))
        {
            return Ok(MaskedLine {
                route: "skip",
                output: None,
                counts: vec![],
                offsets: vec![],
            });
        }
        let text = String::from_utf8_lossy(raw);
        let cp: Vec<_> = text.chars().map(u32::from).collect();
        let (route, output, counts) = match json::parse_bounded(&cp, MAX_RECORD_DEPTH) {
            Err(_) => {
                let (out, c) = self.redact_text(&text, key)?;
                ("text", out, c)
            }
            Ok(p) => {
                let reason = if p.flags.surrogate {
                    Some("surrogate")
                } else if p.flags.too_deep {
                    Some("too-deep")
                } else if p.flags.big_int {
                    Some("invalid-json")
                } else {
                    None
                };
                if let Some(reason) = reason {
                    ("tombstone", format!("{{\"type\":\"session-search-tombstone\",\"reason\":\"{reason}\",\"kinds\":[],\"line_offset\":{offset}}}"), vec![])
                } else {
                    let (masked, c) =
                        self.redact_record(&p.value.ok_or(Error::InvalidRecord)?, key)?;
                    ("record", json::dumps_compact(&masked, false, false)?, c)
                }
            }
        };
        Ok(MaskedLine {
            route,
            output: Some(output),
            counts,
            offsets: vec![offset],
        })
    }
    /// Conformance instrumentation: capture spans are Unicode character offsets, like Python.
    pub fn rule_spans(&self, name: &str, text: &str) -> Result<Vec<Vec<(i64, i64)>>, Error> {
        if !RULES.iter().any(|r| r.0 == name) {
            return Err(Error::InvalidRecord);
        }
        let mut out = Vec::new();
        self.sub(self.by_name(name), text, &mut |c, h| {
            out.push(
                (0..c.group_len())
                    .map(|i| match c.get_group(i) {
                        Some(m) => (
                            h[..m.start].chars().count() as i64,
                            h[..m.end].chars().count() as i64,
                        ),
                        None => (-1, -1),
                    })
                    .collect(),
            );
            None
        });
        Ok(out)
    }
}
impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}
