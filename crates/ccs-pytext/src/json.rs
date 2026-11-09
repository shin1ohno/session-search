//! Ordered JSON with CPython's grammar, including non-finite numbers and surrogate code points.
//! Bounded parsing continues validating after a limit, so limits never select the text route.
use std::collections::{HashMap, HashSet};

pub const MAX_INT_DIGITS: usize = 4300;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(Vec<u32>),
    Array(Vec<Value>),
    Object(Vec<(Vec<u32>, Value)>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Syntax,
    Depth,
    Integer,
    Surrogate,
    CodePoint,
    Duplicate,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JSON {:?}", self)
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Default, Clone, Copy)]
pub struct Flags {
    pub surrogate: bool,
    pub too_deep: bool,
    pub big_int: bool,
    pub duplicate: bool,
}

pub struct Parsed {
    /// None once a value was deeper than `max_depth`; the rest of the line is still validated.
    pub value: Option<Value>,
    pub flags: Flags,
}

struct ObjFrame {
    entries: Vec<(Vec<u32>, Value)>,
    index: HashMap<Vec<u32>, usize>,
    key: Vec<u32>,
}

enum Frame {
    Arr(Vec<Value>),
    Obj(ObjFrame),
}

fn ws(b: &[u32], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], 32 | 9 | 10 | 13) {
        i += 1;
    }
    i
}

fn hex4(b: &[u32], i: usize) -> Option<u32> {
    if i + 4 > b.len() {
        return None;
    }
    let mut v = 0u32;
    for &c in &b[i..i + 4] {
        v = v << 4
            | match c {
                48..=57 => c - 48,
                97..=102 => c - 97 + 10,
                65..=70 => c - 65 + 10,
                _ => return None,
            };
    }
    Some(v)
}

/// Decode a JSON string without replacing unpaired surrogates.
fn string(s: &[u32], mut i: usize, flags: &mut Flags) -> Result<(Vec<u32>, usize), Error> {
    let mut out = Vec::new();
    loop {
        let c = *s.get(i).ok_or(Error::Syntax)?;
        i += 1;
        match c {
            0x22 => return Ok((out, i)),
            0x5c => {
                let escaped = *s.get(i).ok_or(Error::Syntax)?;
                i += 1;
                let c = match escaped {
                    0x22 | 0x5c | 0x2f => escaped,
                    0x62 => 8,
                    0x66 => 12,
                    0x6e => 10,
                    0x72 => 13,
                    0x74 => 9,
                    0x75 => {
                        let mut cp = hex4(s, i).ok_or(Error::Syntax)?;
                        i += 4;
                        if (0xd800..=0xdbff).contains(&cp) && s.get(i..i + 2) == Some(&[0x5c, 0x75])
                        {
                            let low = hex4(s, i + 2).ok_or(Error::Syntax)?;
                            if (0xdc00..=0xdfff).contains(&low) {
                                cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
                                i += 6;
                            }
                        }
                        cp
                    }
                    _ => return Err(Error::Syntax),
                };
                flags.surrogate |= (0xd800..=0xdfff).contains(&c);
                out.push(c);
            }
            0..=0x1f => return Err(Error::Syntax),
            0x110000.. => return Err(Error::CodePoint),
            _ => {
                flags.surrogate |= (0xd800..=0xdfff).contains(&c);
                out.push(c);
            }
        }
    }
}

fn number(s: &[u32], start: usize, flags: &mut Flags) -> Result<(Value, usize), Error> {
    let mut i = start;
    if s[i] == 0x2d {
        i += 1;
    }
    let digits = i;
    match s.get(i) {
        Some(0x31..=0x39) => {
            i += 1;
            while matches!(s.get(i), Some(0x30..=0x39)) {
                i += 1;
            }
        }
        Some(0x30) => i += 1,
        _ => return Err(Error::Syntax),
    }
    let digit_count = i - digits;
    let mut float = false;
    if s.get(i) == Some(&0x2e) && matches!(s.get(i + 1), Some(0x30..=0x39)) {
        float = true;
        i += 2;
        while matches!(s.get(i), Some(0x30..=0x39)) {
            i += 1;
        }
    }
    if matches!(s.get(i), Some(0x65 | 0x45)) {
        let mut j = i + 1;
        if matches!(s.get(j), Some(0x2b | 0x2d)) {
            j += 1;
        }
        let first = j;
        while matches!(s.get(j), Some(0x30..=0x39)) {
            j += 1;
        }
        if j > first {
            float = true;
            i = j;
        }
    }
    flags.big_int |= !float && digit_count > MAX_INT_DIGITS;
    let text: String = s[start..i]
        .iter()
        .map(|&c| char::from_u32(c).unwrap())
        .collect();
    Ok((Value::Number(text), i))
}

pub fn parse_bounded(s: &[u32], max_depth: usize) -> Result<Parsed, Error> {
    let b = s;
    let mut flags = Flags::default();
    let mut kinds: Vec<u32> = Vec::new();
    let mut frames: Vec<Frame> = Vec::new();
    let mut key_sets: Vec<HashSet<Vec<u32>>> = Vec::new();
    let mut building = true;
    let mut i = ws(b, 0);
    'value: loop {
        if kinds.len() + 1 > max_depth && building {
            flags.too_deep = true;
            building = false;
            frames.clear();
        }
        let mut v: Value = match *b.get(i).ok_or(Error::Syntax)? {
            34 => {
                let (t, n) = string(s, i + 1, &mut flags)?;
                i = n;
                Value::String(t)
            }
            91 => {
                i = ws(b, i + 1);
                if b.get(i) == Some(&93) {
                    i += 1;
                    Value::Array(Vec::new())
                } else {
                    kinds.push(91);
                    if building {
                        frames.push(Frame::Arr(Vec::new()));
                    }
                    continue 'value;
                }
            }
            123 => {
                i = ws(b, i + 1);
                if b.get(i) == Some(&125) {
                    i += 1;
                    Value::Object(Vec::new())
                } else {
                    if b.get(i) != Some(&34) {
                        return Err(Error::Syntax);
                    }
                    let (k, n) = string(s, i + 1, &mut flags)?;
                    i = ws(b, n);
                    if b.get(i) != Some(&58) {
                        return Err(Error::Syntax);
                    }
                    i = ws(b, i + 1);
                    kinds.push(123);
                    key_sets.push(HashSet::from([k.clone()]));
                    if building {
                        frames.push(Frame::Obj(ObjFrame {
                            entries: Vec::new(),
                            index: HashMap::new(),
                            key: k,
                        }));
                    }
                    continue 'value;
                }
            }
            110 if s[i..].starts_with(&[110, 117, 108, 108]) => {
                i += 4;
                Value::Null
            }
            116 if s[i..].starts_with(&[116, 114, 117, 101]) => {
                i += 4;
                Value::Bool(true)
            }
            102 if s[i..].starts_with(&[102, 97, 108, 115, 101]) => {
                i += 5;
                Value::Bool(false)
            }
            78 if s[i..].starts_with(&[78, 97, 78]) => {
                i += 3;
                Value::Number("NaN".into())
            }
            73 if s[i..].starts_with(&[73, 110, 102, 105, 110, 105, 116, 121]) => {
                i += 8;
                Value::Number("Infinity".into())
            }
            45 if s[i..].starts_with(&[45, 73, 110, 102, 105, 110, 105, 116, 121]) => {
                i += 9;
                Value::Number("-Infinity".into())
            }
            45 | 48..=57 => {
                let (n, next) = number(s, i, &mut flags)?;
                i = next;
                n
            }
            _ => return Err(Error::Syntax),
        };
        // `v` is complete: attach it, closing as many containers as the text closes.
        loop {
            let Some(&kind) = kinds.last() else {
                i = ws(b, i);
                if i != b.len() {
                    return Err(Error::Syntax);
                }
                return Ok(Parsed {
                    value: if building { Some(v) } else { None },
                    flags,
                });
            };
            if building {
                match frames.last_mut().unwrap() {
                    Frame::Arr(a) => a.push(v),
                    Frame::Obj(o) => {
                        // A dict: the first position and the last value.
                        if let Some(&at) = o.index.get(&o.key) {
                            o.entries[at].1 = v;
                        } else {
                            o.index.insert(o.key.clone(), o.entries.len());
                            o.entries.push((std::mem::take(&mut o.key), v));
                        }
                    }
                }
            }
            v = Value::Null;
            i = ws(b, i);
            match (kind, b.get(i)) {
                (91, Some(44)) => {
                    i = ws(b, i + 1);
                    continue 'value;
                }
                (123, Some(44)) => {
                    i = ws(b, i + 1);
                    if b.get(i) != Some(&34) {
                        return Err(Error::Syntax);
                    }
                    let (k, n) = string(s, i + 1, &mut flags)?;
                    i = ws(b, n);
                    if b.get(i) != Some(&58) {
                        return Err(Error::Syntax);
                    }
                    i = ws(b, i + 1);
                    flags.duplicate |= !key_sets.last_mut().unwrap().insert(k.clone());
                    if building {
                        if let Frame::Obj(o) = frames.last_mut().unwrap() {
                            o.key = k;
                        }
                    }
                    continue 'value;
                }
                (91, Some(93)) | (123, Some(125)) => {
                    i += 1;
                    kinds.pop();
                    if kind == 123 {
                        key_sets.pop();
                    }
                    if building {
                        v = match frames.pop().unwrap() {
                            Frame::Arr(a) => Value::Array(a),
                            Frame::Obj(o) => Value::Object(o.entries),
                        };
                    }
                }
                _ => return Err(Error::Syntax),
            }
        }
    }
}

/// General reader. Limit errors stay distinct from syntax errors.
pub fn loads(text: &[u32]) -> Result<Value, Error> {
    let p = parse_bounded(text, 256)?;
    if p.flags.too_deep {
        return Err(Error::Depth);
    }
    if p.flags.big_int {
        return Err(Error::Integer);
    }
    p.value.ok_or(Error::Depth)
}

/// Extraction uses Python grammar while rejecting decoded duplicate keys.
pub fn loads_strict(text: &[u32]) -> Result<Value, Error> {
    let p = parse_bounded(text, 256)?;
    if p.flags.duplicate {
        return Err(Error::Duplicate);
    }
    if p.flags.too_deep {
        return Err(Error::Depth);
    }
    if p.flags.big_int {
        return Err(Error::Integer);
    }
    p.value.ok_or(Error::Depth)
}
pub fn from_str_strict(text: &str) -> Result<Value, Error> {
    loads_strict(&text.chars().map(u32::from).collect::<Vec<_>>())
}

pub fn from_str(text: &str) -> Result<Value, Error> {
    loads(&text.chars().map(u32::from).collect::<Vec<_>>())
}

pub fn scalar(text: &[u32]) -> Result<String, Error> {
    text.iter()
        .map(|&c| char::from_u32(c).ok_or(Error::Surrogate))
        .collect()
}

impl Value {
    pub fn string(text: &str) -> Self {
        Self::String(text.chars().map(u32::from).collect())
    }
    pub fn get(&self, key: &str) -> Option<&Self> {
        if let Self::Object(o) = self {
            o.iter()
                .find(|(k, _)| k.iter().copied().eq(key.chars().map(u32::from)))
                .map(|(_, v)| v)
        } else {
            None
        }
    }
    pub fn as_str(&self) -> Result<String, Error> {
        if let Self::String(s) = self {
            scalar(s)
        } else {
            Err(Error::Syntax)
        }
    }
    pub fn as_u64(&self) -> Result<u64, Error> {
        if let Self::Number(n) = self {
            n.parse().map_err(|_| Error::Syntax)
        } else {
            Err(Error::Syntax)
        }
    }
}

fn number_text(n: &str) -> Result<String, Error> {
    if matches!(n, "NaN" | "Infinity" | "-Infinity") {
        return Ok(n.into());
    }
    // Validate constructed Number values too; they must never inject JSON structure.
    let cps: Vec<_> = n.chars().map(u32::from).collect();
    if cps.is_empty() {
        return Err(Error::Syntax);
    }
    let mut flags = Flags::default();
    let (_, end) = number(&cps, 0, &mut flags)?;
    if end != cps.len() {
        return Err(Error::Syntax);
    }
    if flags.big_int {
        return Err(Error::Integer);
    }
    if !n.contains(['.', 'e', 'E']) {
        return Ok(if n == "-0" { "0".into() } else { n.into() });
    }
    let value: f64 = n.parse().map_err(|_| Error::Syntax)?;
    if value.is_infinite() {
        return Ok(if value.is_sign_negative() {
            "-Infinity"
        } else {
            "Infinity"
        }
        .into());
    }
    Ok(python_float(value))
}

// Rust's shortest formatter can choose the odd decimal at an exact midpoint.
// Python chooses the even one. Test midpoint equality in integer arithmetic,
// without a floating multiply that could introduce a second rounding.
fn midpoint(value: f64, odd: u128, scale: i32) -> bool {
    if !(-24..=24).contains(&scale) {
        return false;
    }
    let power = 5u128.pow(scale.unsigned_abs());
    let decimal = if scale >= 0 {
        odd * power
    } else {
        if !odd.is_multiple_of(power) {
            return false;
        }
        odd / power
    };
    let bits = value.abs().to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    let significand = (bits & ((1u64 << 52) - 1)) | if exponent == 0 { 0 } else { 1u64 << 52 };
    if significand == 0 {
        return false;
    }
    let zeros = significand.trailing_zeros();
    let binary_exponent = if exponent == 0 {
        -1074
    } else {
        exponent - 1023 - 52
    } + zeros as i32;
    decimal == (significand >> zeros) as u128 && scale - 1 == binary_exponent
}

fn python_float(value: f64) -> String {
    let sign = if value.is_sign_negative() { "-" } else { "" };
    if value == 0.0 {
        return format!("{sign}0.0");
    }
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific.split_once('e').expect("finite float exponent");
    let mut digits = mantissa.replace('.', "");
    let mut scale: i32 = exponent.parse::<i32>().unwrap() - digits.len() as i32 + 1;
    let mut integer: u128 = digits.parse().unwrap();
    // At a power of two the rounding interval is asymmetric: an adjacent
    // decimal at the midpoint is eligible only if it preserves this float.
    let roundtrips = |candidate: u128| {
        format!("{candidate}e{scale}")
            .parse::<f64>()
            .is_ok_and(|v| v == value.abs())
    };
    if integer % 2 == 1 {
        if midpoint(value, 2 * integer - 1, scale) && roundtrips(integer - 1) {
            integer -= 1;
        } else if midpoint(value, 2 * integer + 1, scale) && roundtrips(integer + 1) {
            integer += 1;
        }
    }
    while integer.is_multiple_of(10) {
        integer /= 10;
        scale += 1;
    }
    digits = integer.to_string();
    let exp = scale + digits.len() as i32 - 1;
    if !(-4..16).contains(&exp) {
        let fraction = if digits.len() > 1 {
            format!(".{}", &digits[1..])
        } else {
            String::new()
        };
        format!(
            "{sign}{}{fraction}e{}{abs:02}",
            &digits[..1],
            if exp < 0 { '-' } else { '+' },
            abs = exp.abs()
        )
    } else {
        let point = digits.len() as i32 + scale;
        if point <= 0 {
            format!("{sign}0.{}{digits}", "0".repeat((-point) as usize))
        } else if point >= digits.len() as i32 {
            format!(
                "{sign}{digits}{}.0",
                "0".repeat((point - digits.len() as i32) as usize)
            )
        } else {
            format!(
                "{sign}{}.{}",
                &digits[..point as usize],
                &digits[point as usize..]
            )
        }
    }
}

fn escape(text: &[u32], ascii: bool, out: &mut String) -> Result<(), Error> {
    use std::fmt::Write;
    out.push('"');
    for &c in text {
        match c {
            0x22 => out.push_str("\\\""),
            0x5c => out.push_str("\\\\"),
            8 => out.push_str("\\b"),
            12 => out.push_str("\\f"),
            10 => out.push_str("\\n"),
            13 => out.push_str("\\r"),
            9 => out.push_str("\\t"),
            0..=0x1f => {
                write!(out, "\\u{c:04x}").unwrap();
            }
            0x110000.. => return Err(Error::CodePoint),
            _ if ascii && c > 0x7e => {
                if c <= 0xffff {
                    write!(out, "\\u{c:04x}").unwrap();
                } else {
                    let n = c - 0x10000;
                    write!(
                        out,
                        "\\u{:04x}\\u{:04x}",
                        0xd800 + (n >> 10),
                        0xdc00 + (n & 1023)
                    )
                    .unwrap();
                }
            }
            _ => out.push(char::from_u32(c).ok_or(Error::Surrogate)?),
        }
    }
    out.push('"');
    Ok(())
}

/// Python's default comma/colon spacing.
pub fn dumps(value: &Value, ensure_ascii: bool, sort_keys: bool) -> Result<String, Error> {
    write_json(value, ensure_ascii, sort_keys, false)
}

/// Python's separators=(",", ":") form, used for transcript lines.
pub fn dumps_compact(value: &Value, ensure_ascii: bool, sort_keys: bool) -> Result<String, Error> {
    write_json(value, ensure_ascii, sort_keys, true)
}

/// Python's indent=N form (comma without a space, colon followed by a space).
pub fn dumps_pretty(
    value: &Value,
    ensure_ascii: bool,
    sort_keys: bool,
    indent: usize,
) -> Result<String, Error> {
    let compact = dumps_compact(value, ensure_ascii, sort_keys)?;
    let mut out = String::new();
    let mut depth: usize = 0;
    let mut quoted = false;
    let mut escaped = false;
    let mut chars = compact.chars().peekable();
    let newline = |out: &mut String, depth: usize| -> Result<(), Error> {
        out.push('\n');
        let width = indent.checked_mul(depth).ok_or(Error::Depth)?;
        out.extend(std::iter::repeat_n(' ', width));
        Ok(())
    };
    while let Some(c) = chars.next() {
        if quoted {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
            }
            continue;
        }
        match c {
            '"' => {
                quoted = true;
                out.push(c);
            }
            '[' | '{' => {
                out.push(c);
                let end = if c == '[' { ']' } else { '}' };
                if chars.peek() == Some(&end) {
                    out.push(chars.next().unwrap());
                } else {
                    depth += 1;
                    newline(&mut out, depth)?;
                }
            }
            ']' | '}' => {
                depth -= 1;
                newline(&mut out, depth)?;
                out.push(c);
            }
            ',' => {
                out.push(c);
                newline(&mut out, depth)?;
            }
            ':' => out.push_str(": "),
            _ => out.push(c),
        }
    }
    Ok(out)
}

fn write_json(value: &Value, ascii: bool, sort: bool, compact: bool) -> Result<String, Error> {
    // Iterative writing also supports caller-created trees without recursive descent.
    enum Part<'a> {
        Value(&'a Value),
        Key(&'a [u32]),
        Literal(&'static str),
    }
    let mut stack = vec![Part::Value(value)];
    let mut out = String::new();
    let comma = if compact { "," } else { ", " };
    let colon = if compact { ":" } else { ": " };
    while let Some(part) = stack.pop() {
        match part {
            Part::Literal(s) => out.push_str(s),
            Part::Key(s) => escape(s, ascii, &mut out)?,
            Part::Value(v) => match v {
                Value::Null => out.push_str("null"),
                Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
                Value::Number(n) => out.push_str(&number_text(n)?),
                Value::String(s) => escape(s, ascii, &mut out)?,
                Value::Array(a) => {
                    out.push('[');
                    stack.push(Part::Literal("]"));
                    for (i, v) in a.iter().enumerate().rev() {
                        stack.push(Part::Value(v));
                        if i > 0 {
                            stack.push(Part::Literal(comma));
                        }
                    }
                }
                Value::Object(o) => {
                    out.push('{');
                    stack.push(Part::Literal("}"));
                    let mut entries: Vec<_> = o.iter().collect();
                    if sort {
                        entries.sort_by(|a, b| a.0.cmp(&b.0));
                    }
                    for (i, (k, v)) in entries.into_iter().enumerate().rev() {
                        stack.push(Part::Value(v));
                        stack.push(Part::Literal(colon));
                        stack.push(Part::Key(k));
                        if i > 0 {
                            stack.push(Part::Literal(comma));
                        }
                    }
                }
            },
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordered_duplicates_surrogates_and_number_grammar() {
        let v = from_str(r#"{"b":1,"a":2,"b":-0}"#).unwrap();
        assert_eq!(dumps(&v, false, false).unwrap(), r#"{"b": 0, "a": 2}"#);
        for input in [
            "01",
            "1.",
            "+1",
            "[1,]",
            "{\"x\":1,}",
            "\u{feff}1",
            "\u{85}1",
        ] {
            assert!(from_str(input).is_err(), "{input:?}");
        }
        let v = from_str(r#"["\ud800", "\ud83d\ude00"]"#).unwrap();
        assert_eq!(
            dumps_compact(&v, true, false).unwrap(),
            r#"["\ud800","\ud83d\ude00"]"#
        );
        assert_eq!(dumps(&v, false, false), Err(Error::Surrogate));
        for (input, out) in [
            ("-0", "0"),
            ("-0.0", "-0.0"),
            ("1e5", "100000.0"),
            ("1e-5", "1e-05"),
            ("1e16", "1e+16"),
            ("1e400", "Infinity"),
            ("29210820432377.562", "29210820432377.562"),
            ("575429980542138.2", "575429980542138.2"),
        ] {
            assert_eq!(dumps(&from_str(input).unwrap(), false, false).unwrap(), out);
        }
    }
    #[test]
    fn bounded_parser_finishes_grammar_and_remembers_discarded_values() {
        let good = format!("{}0{}", "[".repeat(100_000), "]".repeat(100_000));
        let parse = |s: &str| parse_bounded(&s.chars().map(u32::from).collect::<Vec<_>>(), 64);
        let p = parse(&good).unwrap();
        assert!(p.flags.too_deep);
        assert!(p.value.is_none());
        assert_eq!(parse(&(good + "garbage")).err(), Some(Error::Syntax));
        let p = parse(r#"{"x":"\ud800","x":"valid"}"#).unwrap();
        assert!(p.flags.surrogate);
        let huge = format!("{{\"x\":{},\"x\":0}}", "1".repeat(4301));
        assert!(parse(&huge).unwrap().flags.big_int);
        for d in [63, 64, 65] {
            let p = parse(&format!("{}0{}", "[".repeat(d - 1), "]".repeat(d - 1))).unwrap();
            assert_eq!(p.flags.too_deep, d > 64);
        }
    }
}

#[cfg(test)]
mod strict_and_pretty_tests {
    use super::*;
    #[test]
    fn strict_extraction_and_indent_state_bytes() {
        for s in [r#"{"a":1,"\u0061":2}"#, r#"[{"x":1,"x":2}]"#] {
            assert!(from_str(s).is_ok());
            assert_eq!(from_str_strict(s), Err(Error::Duplicate));
        }
        assert!(from_str_strict("[NaN,Infinity,-Infinity]").is_ok());
        let v = from_str(r#"{"z":[],"a":[1,{"x":"a,b:c"}]}"#).unwrap();
        assert_eq!(
            dumps_pretty(&v, true, true, 1).unwrap(),
            "{\n \"a\": [\n  1,\n  {\n   \"x\": \"a,b:c\"\n  }\n ],\n \"z\": []\n}"
        );
    }
}
