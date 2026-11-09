//! Codex normalization and persisted inherited-history filtering.
use crate::errors::Result;
use crate::util::{get, has, is, json_string, number, object, set, string, text, truthy};
use ccs_pytext::json::Value;

pub const INTERACTIVE: &[&str] = &[
    "codex-cli",
    "codex-vscode",
    "codex-appServer",
    "codex-unknown",
];
pub fn is_codex(value: &Value) -> bool {
    text(value).is_some_and(|s| s.starts_with("codex-"))
}
pub fn text_content(content: &Value) -> Vec<u32> {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(blocks) => {
            let mut out = Vec::new();
            let mut first = true;
            for block in blocks {
                if ["input_text", "output_text", "text"]
                    .iter()
                    .any(|s| is(get(block, "type"), s))
                {
                    if let Value::String(s) = get(block, "text") {
                        if !first {
                            out.push(10);
                        }
                        first = false;
                        out.extend(s);
                    }
                }
            }
            out
        }
        _ => vec![],
    }
}
fn nonnegative_integer(v: &Value) -> Option<String> {
    if let Value::Number(s) = v {
        let s = if s == "-0" { "0" } else { s };
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            return Some(s.trim_start_matches('0').to_owned()).map(|s| {
                if s.is_empty() {
                    "0".into()
                } else {
                    s
                }
            });
        }
    }
    None
}
fn increment(s: &str) -> String {
    let mut bytes = s.as_bytes().to_vec();
    for b in bytes.iter_mut().rev() {
        if *b < b'9' {
            *b += 1;
            return String::from_utf8(bytes).unwrap();
        }
        *b = b'0';
    }
    bytes.insert(0, b'1');
    String::from_utf8(bytes).unwrap()
}
fn at_least(a: &str, b: &str) -> bool {
    a.len() > b.len() || (a.len() == b.len() && a >= b)
}
#[derive(Clone, Debug)]
pub struct IndexState {
    pub session_id: Value,
    pub state: Value,
}
impl IndexState {
    pub fn new(session_id: Value, saved: Option<&Value>) -> Self {
        Self {
            session_id,
            state: saved
                .filter(|v| matches!(v, Value::Object(_)))
                .cloned()
                .unwrap_or(Value::Object(vec![])),
        }
    }
    pub fn accept(&mut self, rec: &Value) -> bool {
        let ordinal = nonnegative_integer(get(rec, "ordinal"))
            .or_else(|| nonnegative_integer(get(&self.state, "next_ordinal")))
            .unwrap_or_else(|| "0".into());
        set(&mut self.state, "next_ordinal", number(increment(&ordinal)));
        let kind = get(rec, "type");
        let payload = get(rec, "payload");
        if is(kind, "session_meta") {
            if !matches!(payload, Value::Object(_))
                || get(payload, "id") != &self.session_id
                || truthy(get(&self.state, "header_seen"))
            {
                return false;
            }
            set(&mut self.state, "header_seen", Value::Bool(true));
            set(
                &mut self.state,
                "forked",
                Value::Bool(truthy(get(payload, "forked_from_id"))),
            );
            let start = get(
                payload,
                if has(payload, "ccs_index_start_ordinal") {
                    "ccs_index_start_ordinal"
                } else {
                    "subagent_history_start_ordinal"
                },
            );
            if let Some(start) = nonnegative_integer(start) {
                set(&mut self.state, "start_ordinal", number(start));
            }
            return true;
        }
        if is(kind, "session-search-tombstone") {
            return true;
        }
        if let Some(start) = nonnegative_integer(get(&self.state, "start_ordinal")) {
            return at_least(&ordinal, &start);
        }
        if truthy(get(&self.state, "forked")) && !truthy(get(&self.state, "own_started")) {
            if is(kind, "event_msg")
                && is(get(payload, "type"), "thread_settings_applied")
                && get(payload, "thread_id") == &self.session_id
            {
                set(&mut self.state, "own_started", Value::Bool(true));
            } else {
                return false;
            }
        }
        true
    }
}

pub fn normalize(record: &Value) -> Result<Value> {
    normalize_with_context(record, 0, &Value::Null, &Value::Null)
}
/// Context values retain Python's JSON value domain, including null and strings.
pub fn normalize_with_context(
    rec: &Value,
    position: usize,
    entrypoint: &Value,
    cwd: &Value,
) -> Result<Value> {
    let kind = get(rec, "type");
    let payload = get(rec, "payload");
    if is(kind, "session-search-tombstone") {
        return Ok(rec.clone());
    }
    let mut base = object([
        ("type", string("system")),
        ("timestamp", get(rec, "timestamp").clone()),
    ]);
    if !matches!(payload, Value::Object(_)) {
        return Ok(base);
    }
    set(&mut base, "cwd", cwd.clone());
    set(&mut base, "entrypoint", entrypoint.clone());
    if is(kind, "session_meta") {
        let source = get(payload, "source");
        let source = if matches!(source, Value::Object(_))
            && (has(source, "subagent") || has(source, "subAgent"))
        {
            "subagent".to_owned()
        } else {
            text(source)
                .filter(|s| ["cli", "vscode", "appServer", "exec"].contains(&s.as_str()))
                .unwrap_or_else(|| "unknown".into())
        };
        set(&mut base, "cwd", get(payload, "cwd").clone());
        set(&mut base, "entrypoint", string(format!("codex-{source}")));
        set(&mut base, "version", get(payload, "cli_version").clone());
        set(
            &mut base,
            "gitBranch",
            get(get(payload, "git"), "branch").clone(),
        );
        return Ok(base);
    }
    if is(kind, "turn_context") {
        let next = get(payload, "cwd");
        set(
            &mut base,
            "cwd",
            if truthy(next) { next } else { cwd }.clone(),
        );
        return Ok(base);
    }
    if !is(kind, "response_item") {
        return Ok(base);
    }
    let typ = get(payload, "type");
    let mut role = get(payload, "role").clone();
    let content = if is(typ, "message") && (is(&role, "user") || is(&role, "assistant")) {
        if is(get(payload, "channel"), "analysis") {
            return Ok(base);
        }
        let text = text_content(get(payload, "content"));
        let start = text
            .iter()
            .position(|&cp| !char::from_u32(cp).is_some_and(ccs_pytext::is_space))
            .unwrap_or(text.len());
        if ["# AGENTS.md instructions", "<environment_context>"]
            .iter()
            .any(|p| text[start..].starts_with(&p.chars().map(u32::from).collect::<Vec<_>>()))
        {
            return Ok(base);
        }
        object([("type", string("text")), ("text", Value::String(text))])
    } else if is(typ, "function_call") || is(typ, "custom_tool_call") {
        role = string("assistant");
        let args = get(
            payload,
            if is(typ, "function_call") {
                "arguments"
            } else {
                "input"
            },
        );
        let args = if matches!(args, Value::String(_)) {
            args.clone()
        } else {
            string(json_string(args, false, false)?)
        };
        let name = get(payload, "name");
        object([
            ("type", string("tool_use")),
            ("name", if truthy(name) { name } else { typ }.clone()),
            ("input", object([("command", args)])),
        ])
    } else if is(typ, "function_call_output") || is(typ, "custom_tool_call_output") {
        role = string("user");
        let output = get(payload, "output");
        let output = if matches!(output, Value::String(_)) {
            output.clone()
        } else {
            string(json_string(output, false, false)?)
        };
        object([("type", string("tool_result")), ("content", output)])
    } else {
        return Ok(base);
    };
    let uid = get(payload, "id");
    let uid = if matches!(uid,Value::String(s) if !s.is_empty()) {
        uid.clone()
    } else {
        let bytes = format!("{position}{}", json_string(rec, false, true)?);
        let digest = ring::digest::digest(&ring::digest::SHA256, bytes.as_bytes());
        string(
            digest
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )
    };
    let mut uuid = "codex-".chars().map(u32::from).collect::<Vec<_>>();
    if let Value::String(id) = &uid {
        uuid.extend(id);
    }
    set(&mut base, "type", role.clone());
    set(&mut base, "uuid", Value::String(uuid));
    set(
        &mut base,
        "message",
        object([
            ("role", role),
            ("id", uid),
            ("content", Value::Array(vec![content])),
        ]),
    );
    Ok(base)
}

/// Project only fields consumed by the client, as specified by the corpus.
pub fn conformance_projection(rec: &Value) -> Value {
    let mut out = Value::Object(vec![]);
    if let Value::Object(items) = rec {
        for (key, value) in items {
            if [
                "type",
                "cwd",
                "entrypoint",
                "timestamp",
                "gitBranch",
                "version",
            ]
            .iter()
            .any(|s| key.iter().copied().eq(s.chars().map(u32::from)))
            {
                if let Value::Object(items) = &mut out {
                    items.push((key.clone(), value.clone()));
                }
            }
        }
    }
    if has(rec, "message") {
        set(
            &mut out,
            "message",
            object([("content", get(get(rec, "message"), "content").clone())]),
        );
    }
    out
}
/// Evaluate one normalized record or resumable index sequence from the v1 corpus.
pub fn conformance_case(op: &str, input: &Value, kwargs: &Value) -> Result<Value> {
    match op {
        "normalize" => Ok(conformance_projection(&normalize_with_context(
            input,
            nonnegative_integer(get(kwargs, "position"))
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            get(kwargs, "entrypoint"),
            get(kwargs, "cwd"),
        )?)),
        "index_sequence" => {
            let mut state =
                IndexState::new(get(input, "session_id").clone(), Some(get(input, "saved")));
            let mut steps = Vec::new();
            if let Value::Array(records) = get(input, "records") {
                for rec in records {
                    let accepted = state.accept(rec);
                    steps.push(object([
                        ("accept", Value::Bool(accepted)),
                        ("state", state.state.clone()),
                    ]));
                }
            }
            Ok(Value::Array(steps))
        }
        _ => Err(crate::util::invalid("unknown Codex conformance operation")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn session_codex_reference_corpus() {
        let corpus = include_str!("../../../vendor/memory-mcp/conformance/session_codex_v1.jsonl");
        let mut rows = corpus.lines();
        let header = crate::util::parse_json(rows.next().unwrap()).unwrap();
        let mut count = 0;
        for line in rows {
            let v = crate::util::parse_json(line).unwrap();
            let op = text(get(&v, "op")).unwrap();
            assert_eq!(
                conformance_case(&op, get(&v, "input"), get(&v, "kwargs")).unwrap(),
                *get(&v, "expect"),
                "{}",
                text(get(&v, "id")).unwrap()
            );
            count += 1;
        }
        assert_eq!(number(count), *get(&header, "vectors"));
        assert!(count >= 100);
    }
    #[test]
    fn index_large_ordinals_and_tombstones() {
        let mut state = IndexState::new(string("child"), None);
        let huge = "184467440737095516160";
        assert!(state.accept(&object([
            ("type", string("session_meta")),
            (
                "payload",
                object([
                    ("id", string("child")),
                    ("ccs_index_start_ordinal", number(huge))
                ])
            )
        ])));
        assert!(!state.accept(&object([("ordinal", number("184467440737095516159"))])));
        assert!(state.accept(&object([("type", string("session-search-tombstone"))])));
        assert_eq!(
            get(&state.state, "next_ordinal"),
            &number("184467440737095516161")
        );
    }
}
