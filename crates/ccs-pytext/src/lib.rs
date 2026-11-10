//! Python-compatible Unicode and shell/URL text helpers.
#![forbid(unsafe_code)]

pub mod json;
mod tables;

fn in_ranges(c: char, ranges: &[(u32, u32)]) -> bool {
    let n = c as u32;
    ranges.partition_point(|&(_, end)| end < n) < ranges.len()
        && ranges[ranges.partition_point(|&(_, end)| end < n)].0 <= n
}

pub fn is_space(c: char) -> bool {
    in_ranges(c, tables::SPACE)
}
pub fn is_word(c: char) -> bool {
    in_ranges(c, tables::WORD)
}
pub fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}
pub fn lstrip(s: &str) -> &str {
    s.trim_start_matches(is_space)
}
pub fn split(s: &str) -> Vec<&str> {
    s.split(is_space).filter(|s| !s.is_empty()).collect()
}

/// Python splitlines excludes the empty field after a final line boundary.
pub fn splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if matches!(
            c,
            '\n' | '\r' | '\x0b' | '\x0c' | '\x1c'..='\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}'
        ) {
            out.push(&s[start..i]);
            start = i + c.len_utf8();
            if c == '\r' && chars.peek().is_some_and(|&(_, c)| c == '\n') {
                start = chars.next().unwrap().0 + 1;
            }
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

fn map_case(s: &str, table: &[(u32, &str)]) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match table.binary_search_by_key(&(c as u32), |&(cp, _)| cp) {
            Ok(i) => out.push_str(table[i].1),
            Err(_) => out.push(c),
        }
    }
    out
}
fn lower(s: &str) -> String {
    let chars: Vec<_> = s.chars().collect();
    let mut out = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if c == 'Σ' {
            let before = chars[..i]
                .iter()
                .rev()
                .find(|&&c| !in_ranges(c, tables::CASE_IGNORABLE));
            let after = chars[i + 1..]
                .iter()
                .find(|&&c| !in_ranges(c, tables::CASE_IGNORABLE));
            let final_sigma = before.is_some_and(|&c| in_ranges(c, tables::CASED))
                && !after.is_some_and(|&c| in_ranges(c, tables::CASED));
            out.push(if final_sigma { 'ς' } else { 'σ' });
        } else {
            match tables::LOWER.binary_search_by_key(&(c as u32), |&(cp, _)| cp) {
                Ok(i) => out.push_str(tables::LOWER[i].1),
                Err(_) => out.push(c),
            }
        }
    }
    out
}
pub fn casefold(s: &str) -> String {
    map_case(s, tables::CASEFOLD)
}
/// Python strings can contain lone surrogates; keep them as code points.
pub fn is_space_point(c: u32) -> bool {
    char::from_u32(c).is_some_and(is_space)
}
pub fn lstrip_points(s: &[u32]) -> &[u32] {
    &s[s.iter()
        .position(|&c| !is_space_point(c))
        .unwrap_or(s.len())..]
}
pub fn strip_points(s: &[u32]) -> &[u32] {
    let start = s
        .iter()
        .position(|&c| !is_space_point(c))
        .unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|&c| !is_space_point(c))
        .map_or(start, |i| i + 1);
    &s[start..end]
}
pub fn split_points(s: &[u32]) -> Vec<&[u32]> {
    s.split(|&c| is_space_point(c))
        .filter(|s| !s.is_empty())
        .collect()
}
pub fn casefold_points(s: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    for &c in s {
        match tables::CASEFOLD.binary_search_by_key(&c, |&(cp, _)| cp) {
            Ok(i) => out.extend(tables::CASEFOLD[i].1.chars().map(u32::from)),
            Err(_) => out.push(c),
        }
    }
    out
}
pub fn decode_replace(s: &[u8]) -> String {
    String::from_utf8_lossy(s).into_owned()
}

/// Python json.dumps returns a string, before any UTF-8 encoding boundary.
pub fn json_dumps_points(
    value: &json::Value,
    ascii: bool,
    sorted: bool,
) -> Result<Vec<u32>, json::Error> {
    enum Part<'a> {
        Value(&'a json::Value),
        Key(&'a [u32]),
        Literal(&'static str),
    }
    fn quoted(s: &[u32], ascii: bool, out: &mut Vec<u32>) -> Result<(), json::Error> {
        if ascii {
            out.extend(
                json::dumps(&json::Value::String(s.to_vec()), true, false)?
                    .chars()
                    .map(u32::from),
            );
            return Ok(());
        }
        out.push(34);
        for &cp in s {
            let escape = match cp {
                34 => Some("\\\""),
                92 => Some("\\\\"),
                8 => Some("\\b"),
                12 => Some("\\f"),
                10 => Some("\\n"),
                13 => Some("\\r"),
                9 => Some("\\t"),
                _ => None,
            };
            if let Some(s) = escape {
                out.extend(s.chars().map(u32::from));
            } else if cp < 32 {
                out.extend(format!("\\u{cp:04x}").chars().map(u32::from));
            } else if cp <= 0x10ffff {
                out.push(cp);
            } else {
                return Err(json::Error::CodePoint);
            }
        }
        out.push(34);
        Ok(())
    }
    let mut out = Vec::new();
    let mut stack = vec![Part::Value(value)];
    while let Some(part) = stack.pop() {
        match part {
            Part::Literal(s) => out.extend(s.chars().map(u32::from)),
            Part::Key(s) => quoted(s, ascii, &mut out)?,
            Part::Value(json::Value::String(s)) => quoted(s, ascii, &mut out)?,
            Part::Value(json::Value::Array(values)) => {
                out.push(91);
                stack.push(Part::Literal("]"));
                for (i, value) in values.iter().enumerate().rev() {
                    stack.push(Part::Value(value));
                    if i > 0 {
                        stack.push(Part::Literal(", "));
                    }
                }
            }
            Part::Value(json::Value::Object(values)) => {
                let mut values: Vec<_> = values.iter().collect();
                if sorted {
                    values.sort_by(|a, b| a.0.cmp(&b.0));
                }
                out.push(123);
                stack.push(Part::Literal("}"));
                for (i, (key, value)) in values.into_iter().enumerate().rev() {
                    stack.push(Part::Value(value));
                    stack.push(Part::Literal(": "));
                    stack.push(Part::Key(key));
                    if i > 0 {
                        stack.push(Part::Literal(", "));
                    }
                }
            }
            Part::Value(value) => {
                out.extend(json::dumps(value, ascii, sorted)?.chars().map(u32::from))
            }
        }
    }
    Ok(out)
}

pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b))
    {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}

pub fn quote(s: &str, safe: &str) -> String {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric()
            || b"_.-~".contains(&b)
            || (b.is_ascii() && safe.as_bytes().contains(&b))
        {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[(b >> 4) as usize]));
            out.push(char::from(HEX[(b & 15) as usize]));
        }
    }
    out
}
pub fn urlencode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                quote(k, "").replace("%20", "+"),
                quote(v, "").replace("%20", "+")
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlParts {
    pub scheme: String,
    pub netloc: String,
    pub path: String,
    pub query: String,
    pub fragment: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UrlError;
impl UrlParts {
    pub fn hostname(&self) -> Option<String> {
        let hostport = self.netloc.rsplit('@').next()?;
        let host = if hostport.starts_with('[') {
            hostport.get(1..)?.split(']').next()?
        } else {
            hostport.split(':').next()?
        };
        if host.is_empty() {
            return None;
        }
        // Zone identifiers are case-sensitive, unlike the address/name portion.
        let (host, zone) = host
            .split_once('%')
            .map_or((host, None), |(h, z)| (h, Some(z)));
        Some(lower(host) + &zone.map(|s| format!("%{s}")).unwrap_or_default())
    }
}
pub fn urlsplit(value: &str) -> Result<UrlParts, UrlError> {
    let clean: String = value
        .trim_start_matches(|c: char| c <= '\x20')
        .chars()
        .filter(|c| !matches!(c, '\n' | '\r' | '\t'))
        .collect();
    let mut rest = clean.as_str();
    let mut scheme = String::new();
    if let Some((candidate, tail)) = rest.split_once(':') {
        if candidate.starts_with(|c: char| c.is_ascii_alphabetic())
            && candidate
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
        {
            scheme = candidate.to_ascii_lowercase();
            rest = tail;
        }
    }
    let mut netloc = "";
    if let Some(tail) = rest.strip_prefix("//") {
        let end = tail.find(['/', '?', '#']).unwrap_or(tail.len());
        netloc = &tail[..end];
        rest = &tail[end..];
        if netloc
            .chars()
            .any(|c| tables::INVALID_NETLOC.binary_search(&(c as u32)).is_ok())
        {
            return Err(UrlError);
        }
        if netloc.contains('[') != netloc.contains(']') {
            return Err(UrlError);
        }
        if let Some((before, after)) = netloc.rsplit('@').next().unwrap_or("").split_once('[') {
            if !before.is_empty()
                || after
                    .split_once(']')
                    .is_some_and(|(_, tail)| !tail.is_empty() && !tail.starts_with(':'))
            {
                return Err(UrlError);
            }
            let address = after.split(']').next().ok_or(UrlError)?;
            if let Some(future) = address.strip_prefix('v') {
                if !future.split_once('.').is_some_and(|(version, host)| {
                    !version.is_empty()
                        && version.bytes().all(|b| b.is_ascii_hexdigit())
                        && !host.is_empty()
                }) {
                    return Err(UrlError);
                }
            } else if address
                .split_once('%')
                .is_some_and(|(_, zone)| zone.is_empty() || zone.contains('%'))
                || address
                    .split('%')
                    .next()
                    .unwrap_or("")
                    .parse::<std::net::Ipv6Addr>()
                    .is_err()
            {
                return Err(UrlError);
            }
        }
    }
    let (rest, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    Ok(UrlParts {
        scheme,
        netloc: netloc.into(),
        path: path.into(),
        query: query.into(),
        fragment: fragment.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn python_unicode_and_lines() {
        assert_eq!(casefold("Straße Σςİﬃ"), "strasse σσi\u{307}ffi");
        assert!(is_word('²'));
        assert!(!is_word('\u{301}'));
        assert!(is_space('\x1c'));
        assert_eq!(split("\x1cone\u{85}two\u{2003}"), ["one", "two"]);
        assert_eq!(splitlines("a\r\nb\x1ec\u{2028}\n"), ["a", "b", "c", ""]);
        assert_eq!(splitlines(""), Vec::<&str>::new());
    }
    #[test]
    fn python_quoting_and_urls() {
        assert_eq!(shell_quote("a'b"), "'a'\"'\"'b'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(quote("/日本 +", "/"), "/%E6%97%A5%E6%9C%AC%20%2B");
        assert_eq!(urlencode(&[("a b", "+")]), "a+b=%2B");
        let u = urlsplit("\x00HtTps://u:p@[::1]:80/path?q#f").unwrap();
        assert_eq!(u.hostname().as_deref(), Some("::1"));
        assert_eq!(u.path, "/path");
        assert!(urlsplit("https://host\u{ff0f}evil").is_err());
        assert!(urlsplit("https://[127.0.0.1]").is_err());
        assert_eq!(decode_replace(&[0xed, 0xa0, 0x80]), "���");
    }
}
