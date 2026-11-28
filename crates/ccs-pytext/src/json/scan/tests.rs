//! Differential tests: the reader must keep exactly the texts a strict load
//! keeps, and the values it reads must equal parse_bounded's tree.
use super::*;
use crate::json::{dumps, dumps_compact, from_str, parse_bounded, Value};

fn short(text: &str) -> String {
    let mut s: String = text.chars().take(160).collect();
    if s.len() < text.len() {
        s.push('…');
    }
    s
}

/// The strict-load decision of extract::loads_strict: no syntax error, no
/// duplicate key at any depth, no oversized integer; depth is unlimited.
/// Returns whether the text is kept, and its value when it is shallow enough
/// to compare. Deep values are released iteratively, as extract.rs does.
fn oracle(text: &str) -> (bool, Option<Value>) {
    let cps: Vec<u32> = text.chars().map(u32::from).collect();
    let Ok(p) = parse_bounded(&cps, usize::MAX) else {
        return (false, None);
    };
    let keep = !p.flags.duplicate && !p.flags.big_int;
    match p.value {
        Some(v) if keep && nesting(text) <= 200 => (true, Some(v)),
        Some(v) => {
            discard(v);
            (keep, None)
        }
        None => (keep, None),
    }
}

fn discard(value: Value) {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Array(values) => pending.extend(values),
            Value::Object(fields) => pending.extend(fields.into_iter().map(|(_, v)| v)),
            _ => {}
        }
    }
}

/// parse_bounded drops a deep subtree recursively on some error paths, so
/// tests with deep inputs run on a large stack.
fn on_big_stack(f: fn()) {
    std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

fn nesting(text: &str) -> usize {
    let (mut depth, mut max) = (0usize, 0usize);
    for b in text.bytes() {
        match b {
            b'[' | b'{' => {
                depth += 1;
                max = max.max(depth);
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

fn build(r: &mut Reader<'_>) -> Result<Value, Error> {
    if let Some(s) = r.string()? {
        return Ok(Value::String(s.points()));
    }
    if let Some(raw) = r.scalar()? {
        return Ok(match raw {
            "null" => Value::Null,
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            n => Value::Number(n.to_string()),
        });
    }
    let mut entries = Vec::new();
    if r.object(|k, r| {
        let v = build(r)?;
        entries.push((k.points(), v));
        Ok(())
    })? {
        return Ok(Value::Object(entries));
    }
    let mut items = Vec::new();
    if r.array(|r| {
        items.push(build(r)?);
        Ok(())
    })? {
        return Ok(Value::Array(items));
    }
    Err(Error::Syntax)
}

/// Reads only odd-positioned members of every object; the rest are skipped.
fn build_odd(r: &mut Reader<'_>) -> Result<Value, Error> {
    let mut entries = Vec::new();
    let mut position = 0usize;
    if r.object(|k, r| {
        if position % 2 == 1 {
            entries.push((k.points(), build_odd(r)?));
        }
        position += 1;
        Ok(())
    })? {
        return Ok(Value::Object(entries));
    }
    let mut items = Vec::new();
    if r.array(|r| {
        items.push(build_odd(r)?);
        Ok(())
    })? {
        return Ok(Value::Array(items));
    }
    build(r)
}

fn odd(v: &Value) -> Value {
    match v {
        Value::Object(entries) => Value::Object(
            entries
                .iter()
                .enumerate()
                .filter(|(i, _)| i % 2 == 1)
                .map(|(_, (k, v))| (k.clone(), odd(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(odd).collect()),
        other => other.clone(),
    }
}

fn read_with(text: &str, f: fn(&mut Reader<'_>) -> Result<Value, Error>) -> Result<Value, Error> {
    let mut r = Reader::new(text);
    let v = f(&mut r)?;
    r.finish()?;
    Ok(v)
}

fn check(text: &str) {
    let (keep, expected) = oracle(text);
    assert_eq!(
        validate(text).is_ok(),
        keep,
        "validate disagrees on {:?}",
        short(text)
    );
    if nesting(text) > 200 {
        return;
    }
    match expected {
        Some(value) => {
            assert_eq!(
                read_with(text, build).as_ref(),
                Ok(&value),
                "build on {:?}",
                short(text)
            );
            assert_eq!(
                read_with(text, build_odd).as_ref(),
                Ok(&odd(&value)),
                "partial read on {:?}",
                short(text)
            );
        }
        None => {
            assert!(
                read_with(text, build).is_err(),
                "build accepted {:?}",
                short(text)
            );
            assert!(
                read_with(text, build_odd).is_err(),
                "partial read accepted {:?}",
                short(text)
            );
        }
    }
}

fn corpus(name: &str) -> String {
    let path = format!(
        "{}/../../vendor/memory-mcp/conformance/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn hostile() -> Vec<String> {
    let mut out: Vec<String> = [
        r#"{"a":1,"\u0061":2}"#,
        r#"{"a":{"b":1,"b":2}}"#,
        r#"[{"x":[{"y":1,"y":1}]}]"#,
        "{\"\u{1f600}\":1,\"\\ud83d\\ude00\":2}",
        r#"{"\ud800":1,"\ud800":2}"#,
        r#"{"\ud800":1,"\udc00":2}"#,
        r#"{"\ud83d":1,"\ud83d\ude00":2}"#,
        r#"{"\ud83d\ude00":1,"\ud83d\ude00":2}"#,
        r#"{"a\u0062":1,"ab":2}"#,
        r#"{"\/":1,"/":2}"#,
        r#""\ud800\u0041""#,
        r#""\ud800\ud800\udc00""#,
        r#""\ud800\uZZZZ""#,
        r#""\ud800\u12""#,
        r#""\udc00\ud800""#,
        r#""\u""#,
        r#""\u1""#,
        r#""\u12""#,
        r#""\u123""#,
        r#""\u123g""#,
        r#""\x""#,
        r#""\'""#,
        "\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"",
        "\"\u{1}\"",
        "\"\t\"",
        "\"\u{7f}\"",
        "\"é\u{1f600}\u{2028}\u{85}\"",
        "nul",
        "tru",
        "fals",
        "Nan",
        "NaN",
        "Infinity",
        "-Infinity",
        "-Inf",
        "-NaN",
        "-",
        "01",
        "-01",
        "1.",
        ".5",
        "1e",
        "1e+",
        "1E-5",
        "1.5e",
        "-0",
        "0e+1",
        "+1",
        "[1.]",
        "[01]",
        "\u{feff}1",
        "\u{85}1",
        "\u{2028}1",
        "\u{b}1",
        "  1  ",
        "1 2",
        "",
        " ",
        "{}x",
        "[]]",
        r#"{"a":1}}"#,
        "1",
        r#""s""#,
        "[1,2]",
        "null",
        "{}",
        "[]",
        "[[]]",
        r#"{"a":{}}"#,
        "[,]",
        "[1,]",
        "{,}",
        r#"{"a":1,}"#,
        r#"{"a"}"#,
        r#"{"a":}"#,
        "{1:2}",
        r#"{"a" "b"}"#,
        r#"{"a":1 "b":2}"#,
        "[1 2]",
        "true",
        "truex",
        "[true]",
        "[truefalse]",
        " {\"a\" : [ 1 , { \"b\" : null } ] } \n",
        "{\"a\":1}\r\n",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let digits = |n: usize| "1".repeat(n);
    for n in [4299, 4300, 4301] {
        for form in [
            digits(n),
            format!("-{}", digits(n)),
            format!("{}.0", digits(n)),
            format!("{}e5", digits(n)),
            format!("{}e", digits(n)),
            format!("{{\"a\":{}}}", digits(n)),
            format!("[{},1]", digits(n)),
            format!("{{\"a\":1,\"b\":[{{\"c\":{}}}]}}", digits(n)),
        ] {
            out.push(form);
        }
    }
    out.push(format!("0.{}", digits(10_000)));
    for depth in [1usize, 64, 65, 256, 257, 20_000] {
        out.push(format!("{}{}", "[".repeat(depth), "]".repeat(depth)));
        out.push(format!("{}1{}", "{\"a\":".repeat(depth), "}".repeat(depth)));
        out.push(format!(
            "{}{{\"b\":1,\"b\":2}}{}",
            "{\"a\":".repeat(depth),
            "}".repeat(depth)
        ));
        out.push(format!(
            "{}{{\"b\":1,\"\\u0062\":2}}{}",
            "[".repeat(depth),
            "]".repeat(depth)
        ));
        out.push(format!("{}1{}", "[".repeat(depth), "]".repeat(depth + 1)));
    }
    for keys in [15usize, 16, 17, 1000, 100_000] {
        let body: Vec<String> = (0..keys).map(|i| format!("\"k{i}\":{i}")).collect();
        out.push(format!("{{{}}}", body.join(",")));
        out.push(format!("{{{},\"k3\":0}}", body.join(",")));
        out.push(format!("{{{},\"k\\u0033\":0}}", body.join(",")));
        out.push(format!("[{{{}}},{{{}}}]", body.join(","), body.join(",")));
    }
    for n in 0..24 {
        let pad = "x".repeat(n);
        for special in [
            "\\n",
            "\\\"",
            "\\u0041",
            "\\ud83d\\ude00",
            "\u{1}",
            "\"",
            "é",
            "\u{1f600}",
        ] {
            out.push(format!("\"{pad}{special}{pad}\""));
            out.push(format!("{{\"{pad}\":\"{special}{pad}\",\"y\":1}}"));
        }
    }
    out
}

#[test]
fn special_matches_the_byte_test() {
    let naive = |w: u64| {
        w.to_le_bytes()
            .iter()
            .any(|&b| b == b'"' || b == b'\\' || b < 0x20)
    };
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..2_000_000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        assert_eq!(special(x), naive(x), "{x:#018x}");
    }
    for background in [0u8, 0x20, 0x41, 0x7f, 0x80, 0xc3, 0xff] {
        for position in 0..8 {
            for byte in 0..=255u8 {
                let mut bytes = [background; 8];
                bytes[position] = byte;
                let w = u64::from_le_bytes(bytes);
                assert_eq!(special(w), naive(w), "{bytes:?}");
            }
        }
    }
}

#[test]
fn hostile_inputs_match_strict_loading() {
    on_big_stack(|| {
        for text in hostile() {
            check(&text);
        }
    });
}

#[test]
fn conformance_corpora_match_strict_loading() {
    let mut checked = 0usize;
    for name in ["session_redact_r1.jsonl", "session_codex_v1.jsonl"] {
        let text = corpus(name);
        for (n, line) in text.lines().enumerate() {
            check(line);
            check(&format!("{line}\n"));
            checked += 1;
            if n < 400 && line.len() < 400 {
                for (cut, _) in line.char_indices() {
                    check(&line[..cut]);
                }
            }
            let Ok(Value::Object(fields)) = from_str(line) else {
                continue;
            };
            for (key, value) in fields {
                if key != "input".chars().map(u32::from).collect::<Vec<_>>() {
                    continue;
                }
                if let Value::String(points) = &value {
                    if let Ok(s) = crate::json::scalar(points) {
                        check(&s);
                    }
                }
                for dumped in [
                    dumps_compact(&value, false, false),
                    dumps(&value, true, false),
                ]
                .into_iter()
                .flatten()
                {
                    check(&dumped);
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 100_000, "corpus too small: {checked}");
}

const ALPHABET: [&str; 20] = [
    "{", "}", "[", "]", ",", ":", "\"", "\\", "u", "0", "1", "e", "-", ".", "n", "t", " ", "a",
    "\u{1}", "é",
];

#[test]
fn every_short_text_matches_strict_loading() {
    let mut text = String::new();
    let mut stack = vec![0usize];
    fn walk(prefix: &mut Vec<usize>, out: &mut dyn FnMut(&str)) {
        let s: String = prefix.iter().map(|&i| ALPHABET[i]).collect();
        out(&s);
        if prefix.len() == 4 {
            return;
        }
        for i in 0..ALPHABET.len() {
            prefix.push(i);
            walk(prefix, out);
            prefix.pop();
        }
    }
    stack.clear();
    walk(&mut stack, &mut |s| {
        check(s);
        text.clear();
        text.push_str("{\"a\":");
        text.push_str(s);
        text.push_str(",\"b\":1}");
        check(&text);
        text.clear();
        text.push('[');
        text.push_str(s);
        text.push_str(",1]");
        check(&text);
    });
}

fn fuzz(cases: usize, seed: u64) {
    let mut seeds = hostile();
    seeds.retain(|s| s.len() < 4000);
    let redact = corpus("session_redact_r1.jsonl");
    seeds.extend(
        redact
            .lines()
            .step_by(37)
            .filter(|l| l.len() < 2000)
            .map(str::to_string),
    );
    let symbols: Vec<char> =
        "{}[],:\"\\u0123456789abcdefABCDEF.eE+-ntrlsNIfy \t\n\r\u{1}é\u{1f600}\u{feff}"
            .chars()
            .collect();
    let mut x = seed | 1;
    let mut next = |n: usize| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x % n as u64) as usize
    };
    for _ in 0..cases {
        let mut chars: Vec<char> = seeds[next(seeds.len())].chars().collect();
        for _ in 0..=next(4) {
            let at = if chars.is_empty() {
                0
            } else {
                next(chars.len())
            };
            match next(5) {
                0 if !chars.is_empty() => chars[at] = symbols[next(symbols.len())],
                1 => chars.insert(at, symbols[next(symbols.len())]),
                2 if !chars.is_empty() => {
                    chars.remove(at);
                }
                3 if chars.len() > 2 => {
                    let end = (at + 1 + next(8)).min(chars.len());
                    let piece: Vec<char> = chars[at..end].to_vec();
                    let to = next(chars.len());
                    chars.splice(to..to, piece);
                }
                _ => chars.insert(at, '"'),
            }
        }
        check(&chars.into_iter().collect::<String>());
    }
}

#[test]
fn mutated_texts_match_strict_loading() {
    on_big_stack(|| fuzz(200_000, 0x5eed_0001));
}

#[test]
#[ignore = "long fuzz run before merging: cargo test --release -p ccs-pytext -- --ignored"]
fn mutated_texts_match_strict_loading_long() {
    on_big_stack(|| fuzz(50_000_000, 0x5eed_0002));
}

#[test]
fn strings_decode_and_compare() {
    let mut r = Reader::new(r#""a\u0062\ud83d\ude00\ud800é""#);
    let s = r.string().unwrap().unwrap();
    assert_eq!(s.points(), vec![0x61, 0x62, 0x1f600, 0xd800, 0xe9]);
    let mut r = Reader::new(r#""c\u0077d""#);
    let s = r.string().unwrap().unwrap();
    assert!(s.eq_str("cwd"));
    assert!(!s.eq_str("cw"));
    assert!(!s.eq_str("cwdx"));
    let mut r = Reader::new(r#""cwd""#);
    assert!(r.string().unwrap().unwrap().eq_str("cwd"));
}

#[test]
#[ignore = "throughput on a real file: CCS_SCAN_BENCH_FILE=<jsonl> cargo test --release -p ccs-pytext -- --ignored throughput"]
fn throughput() {
    let Ok(path) = std::env::var("CCS_SCAN_BENCH_FILE") else {
        return;
    };
    let bytes = std::fs::read(path).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text
        .split_inclusive('\n')
        .filter(|l| l.ends_with('\n'))
        .collect();
    let total: usize = lines.iter().map(|l| l.len()).sum();
    let started = std::time::Instant::now();
    let kept = lines.iter().filter(|l| validate(l).is_ok()).count();
    let validate_s = started.elapsed().as_secs_f64();
    let started = std::time::Instant::now();
    let strict = lines
        .iter()
        .filter(|l| crate::json::from_str_strict(l).is_ok())
        .count();
    let strict_s = started.elapsed().as_secs_f64();
    println!(
        "{{\"lines\":{},\"mb\":{:.1},\"kept\":{kept},\"strict_kept\":{strict},\"validate_mb_s\":{:.0},\"strict_mb_s\":{:.0}}}",
        lines.len(),
        total as f64 / 1e6,
        total as f64 / 1e6 / validate_s,
        total as f64 / 1e6 / strict_s
    );
}
