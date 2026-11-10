//! Line protocol for the independent Python text oracle (hex fields, no JSON).
use ccs_pytext::*;
use std::io::{self, BufRead};
fn hex(s: &str) -> String {
    s.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut fields = line.split('\t');
        let op = fields.next().unwrap();
        let raw = decode(fields.next().unwrap_or(""));
        let s = String::from_utf8_lossy(&raw);
        let extra = String::from_utf8(decode(fields.next().unwrap_or(""))).unwrap();
        let values: Result<Vec<String>, UrlError> = match op {
            "casefold" => Ok(vec![casefold(&s)]),
            "strip" => Ok(vec![strip(&s).into()]),
            "split" => Ok(split(&s).into_iter().map(String::from).collect()),
            "splitlines" => Ok(splitlines(&s).into_iter().map(String::from).collect()),
            "quote" => Ok(vec![quote(&s, &extra)]),
            "shell" => Ok(vec![shell_quote(&s)]),
            "urlsplit" => urlsplit(&s).map(|u| {
                vec![
                    u.scheme.clone(),
                    u.netloc.clone(),
                    u.path.clone(),
                    u.query.clone(),
                    u.fragment.clone(),
                    u.hostname().unwrap_or_default(),
                ]
            }),
            "decode" => Ok(vec![decode_replace(&raw)]),
            "word" => Ok(vec![s.chars().all(is_word).to_string()]),
            "space" => Ok(vec![s.chars().all(is_space).to_string()]),
            _ => panic!("unknown operation"),
        };
        match values {
            Ok(values) => println!(
                "{}:{}",
                values.len(),
                values.iter().map(|s| hex(s)).collect::<Vec<_>>().join("\t")
            ),
            Err(_) => println!("!error"),
        }
    }
}
