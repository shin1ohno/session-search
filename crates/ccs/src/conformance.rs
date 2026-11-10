//! Offline conformance protocol. Diagnostics identify cases without echoing their content.
use ccs_pytext::json::{self, Value};
use ccs_redact::{Counts, Redactor};
use std::collections::HashSet;
use std::io::{BufRead, Write};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn field<'a>(v: &'a Value, key: &str) -> Result<&'a Value> {
    v.get(key).ok_or_else(|| "missing protocol field".into())
}
fn text(v: &Value, key: &str) -> Result<String> {
    Ok(field(v, key)?.as_str()?)
}
fn object(entries: Vec<(&str, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(k, v)| (k.chars().map(u32::from).collect(), v))
            .collect(),
    )
}
fn number(n: u64) -> Value {
    Value::Number(n.to_string())
}
fn count_value(counts: Counts) -> Value {
    Value::Object(
        counts
            .into_iter()
            .map(|(k, n)| (k.chars().map(u32::from).collect(), number(n)))
            .collect(),
    )
}
fn hex(t: &str) -> Result<Vec<u8>> {
    if !t.is_ascii() || !t.len().is_multiple_of(2) {
        return Err("invalid hex".into());
    }
    (0..t.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&t[i..i + 2], 16).map_err(Into::into))
        .collect()
}
fn expand(v: Value) -> Result<Value> {
    Ok(match v {
        Value::Object(mut o)
            if o.len() == 1 && o[0].0.iter().copied().eq("$repeat".chars().map(u32::from)) =>
        {
            let Value::Array(a) = o.pop().unwrap().1 else {
                return Err("invalid repeat".into());
            };
            if a.len() != 2 {
                return Err("invalid repeat".into());
            }
            let s = a[0].as_str()?;
            let count = usize::try_from(a[1].as_u64()?)?;
            if count > 10_000_001 || s.len().checked_mul(count).is_none_or(|n| n > 100_000_000) {
                return Err("repeat limit".into());
            }
            Value::string(&s.repeat(count))
        }
        Value::Object(o) => Value::Object(
            o.into_iter()
                .map(|(k, v)| Ok((k, expand(v)?)))
                .collect::<Result<_>>()?,
        ),
        Value::Array(a) => Value::Array(a.into_iter().map(expand).collect::<Result<_>>()?),
        v => v,
    })
}
fn evaluate(rs: &Redactor, v: &Value, key: &[u8]) -> Result<Value> {
    let op = text(v, "op")?;
    let input = field(v, "input")?;
    if let Some(version) = v.get("kwargs").and_then(|v| v.get("version")) {
        if version.as_str()? != ccs_redact::REDACT_VERSION {
            return Err("unsupported version".into());
        }
    }
    if op == "mask_line" {
        let line = rs.mask_line(
            &hex(&text(input, "hex")?)?,
            field(input, "offset")?.as_u64()?,
            key,
        )?;
        return Ok(object(vec![
            ("route", Value::string(line.route)),
            (
                "output",
                line.output
                    .map(|s| Value::string(&s))
                    .unwrap_or(Value::Null),
            ),
            ("counts", count_value(line.counts)),
            (
                "offsets",
                Value::Array(line.offsets.into_iter().map(number).collect()),
            ),
        ]));
    }
    let detect = matches!(op.as_str(), "detect_text" | "detect_record");
    let key = if detect {
        b"detect-only".as_slice()
    } else {
        key
    };
    let (out, counts) = match op.as_str() {
        "redact_text" | "detect_text" => {
            let max = v
                .get("kwargs")
                .and_then(|k| k.get("max_chars"))
                .map(Value::as_u64)
                .transpose()?
                .unwrap_or(ccs_redact::MAX_VALUE_CHARS as u64);
            let (s, c) = rs.redact_text_capped(&input.as_str()?, key, usize::try_from(max)?)?;
            (Value::string(&s), c)
        }
        "redact_record" | "detect_record" => rs.redact_record(input, key)?,
        _ => return Err("unknown operation".into()),
    };
    if detect {
        let mut kinds: Vec<_> = counts.into_iter().map(|(k, _)| k).collect();
        kinds.sort();
        Ok(Value::Array(
            kinds.into_iter().map(|s| Value::string(&s)).collect(),
        ))
    } else {
        Ok(object(vec![
            ("output", out),
            ("counts", count_value(counts)),
        ]))
    }
}

/// Stream protocol for generated differential/span cases; never selects alternative rules.
fn request(rs: &Redactor, v: &Value) -> Result<Value> {
    let mode = text(v, "mode")?;
    if mode == "json" || mode == "json_strict" {
        let input = field(v, "input")?.as_str()?;
        let parsed = if mode == "json_strict" {
            json::from_str_strict(&input)
        } else {
            json::from_str(&input)
        };
        return match parsed {
            Ok(value) => Ok(object(vec![
                ("ok", Value::Bool(true)),
                (
                    "output",
                    Value::string(&json::dumps_compact(&value, true, false)?),
                ),
            ])),
            Err(json::Error::Duplicate) => Ok(object(vec![
                ("ok", Value::Bool(false)),
                ("duplicate", Value::Bool(true)),
            ])),
            Err(_) => Ok(object(vec![("ok", Value::Bool(false))])),
        };
    }
    let key = b"test-key-not-a-secret";
    let (out, counts) = match mode.as_str() {
        "text" => {
            let (s, c) = rs.redact_text(&text(v, "input")?, key)?;
            (Value::string(&s), c)
        }
        "detect" => {
            let (_, c) = rs.redact_text(&text(v, "input")?, b"detect-only")?;
            (Value::Null, c)
        }
        "record" => rs.redact_record(field(v, "input")?, key)?,
        "spans" => {
            let spans = rs.rule_spans(&text(v, "rule")?, &text(v, "input")?)?;
            (
                Value::Array(
                    spans
                        .into_iter()
                        .map(|caps| {
                            Value::Array(
                                caps.into_iter()
                                    .map(|(a, b)| {
                                        Value::Array(vec![
                                            Value::Number(a.to_string()),
                                            Value::Number(b.to_string()),
                                        ])
                                    })
                                    .collect(),
                            )
                        })
                        .collect(),
                ),
                vec![],
            )
        }
        "line" => {
            let line = rs.mask_line(
                &hex(&text(v, "hex")?)?,
                v.get("off").map(Value::as_u64).transpose()?.unwrap_or(0),
                key,
            )?;
            return Ok(object(vec![
                (
                    "out",
                    line.output
                        .map(|s| Value::string(&s))
                        .unwrap_or(Value::Null),
                ),
                ("counts", count_value(line.counts)),
                ("route", Value::string(line.route)),
            ]));
        }
        _ => return Err("unknown request".into()),
    };
    Ok(object(vec![("out", out), ("counts", count_value(counts))]))
}

fn run_inner(args: &[std::ffi::OsString]) -> Result<()> {
    if args.first().is_none_or(|s| s != "redact") || args.len() > 2 {
        return Err("unsupported conformance suite".into());
    }
    let emit = args.get(1).is_some_and(|s| s == "--emit");
    let requests = args.get(1).is_some_and(|s| s == "--requests");
    if args.len() == 2 && !emit && !requests {
        return Err("unsupported conformance option".into());
    }
    let rs = Redactor::new();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    if requests {
        for line in stdin.lock().lines() {
            let req = json::from_str(&line?)?;
            writeln!(
                out,
                "{}",
                json::dumps_compact(&request(&rs, &req)?, true, false)?
            )?;
            out.flush()?;
        }
        return Ok(());
    }
    let mut lines = stdin.lock().lines();
    let header = json::from_str(&lines.next().ok_or("missing corpus header")??)?;
    if text(&header, "format")? != "ccs-redact-conformance/1"
        || text(&header, "ruleset")? != ccs_redact::REDACT_VERSION
        || text(&header, "source_blob")? != ccs_redact::REDACT_SOURCE_BLOB
    {
        return Err("corpus identity mismatch".into());
    }
    let key = hex(&text(&header, "hmac_key_hex")?)?;
    let minimum = field(&header, "min_vectors")?.as_u64()?;
    let expected_count = field(&header, "vectors")?.as_u64()?;
    if minimum < 8000 || expected_count < minimum {
        return Err("corpus count below minimum".into());
    }
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    let mut seen = HashSet::new();
    let mut failures = 0;
    let mut count = 0;
    let mut emitted = 0;
    for line in lines {
        let line = line?;
        hash.update(line.as_bytes());
        hash.update(b"\n");
        let vector = expand(json::from_str(&line)?)?;
        let id = text(&vector, "id")?;
        if !seen.insert(id.clone()) {
            return Err("duplicate corpus id".into());
        }
        let op = text(&vector, "op")?;
        let vector_key = vector
            .get("hmac_key_hex")
            .map(|v| hex(&v.as_str()?))
            .transpose()?;
        let result = evaluate(&rs, &vector, vector_key.as_deref().unwrap_or(&key))?;
        let expected = field(
            &vector,
            if op == "mask_line" {
                "rust_expect"
            } else {
                "expect"
            },
        )?;
        if json::dumps_compact(&result, true, false)? != json::dumps_compact(expected, true, false)?
        {
            eprintln!(
                "FAIL conformance: {}",
                json::dumps_compact(&Value::string(&id), true, false)?
            );
            failures += 1;
        }
        if emit && matches!(op.as_str(), "redact_text" | "redact_record" | "mask_line") {
            writeln!(
                out,
                "{}",
                json::dumps_compact(
                    &object(vec![("id", Value::string(&id)), ("result", result)]),
                    true,
                    false
                )?
            )?;
            emitted += 1;
        }
        count += 1;
    }
    out.flush()?;
    let digest: String = hash
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if count != expected_count || digest != text(&header, "sha256_of_vectors")? {
        return Err("corpus count or digest mismatch".into());
    }
    eprintln!(
        "conformance redact: vectors={count} failures={failures} emitted={emitted} pass_limit={}",
        ccs_redact::MAX_PASSES
    );
    if failures != 0 {
        return Err("conformance mismatch".into());
    }
    Ok(())
}

pub fn run(args: &[std::ffi::OsString]) -> std::process::ExitCode {
    match run_inner(args) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("ccs: conformance failed");
            std::process::ExitCode::FAILURE
        }
    }
}
