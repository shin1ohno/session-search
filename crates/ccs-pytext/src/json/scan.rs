//! Validating projection over one JSON text.
//!
//! A [`Reader`] walks a text with exactly the grammar of
//! [`super::parse_bounded`]: the four whitespace bytes, CPython's escapes
//! (including how a `\u` surrogate pair combines), its number syntax,
//! `NaN`/`Infinity`/`-Infinity`, and trailing whitespace only. It also
//! rejects what [`super::loads_strict`] refuses at any depth: a key repeated
//! in one object after decoding, and an integer longer than
//! [`MAX_INT_DIGITS`] digits. Depth is unlimited.
//!
//! Values the caller asks for come back as borrowed slices. Every other value
//! is validated and skipped without being built. Any error means a strict
//! load of the same text would fail, so the caller drops the text.
use super::{Error, MAX_INT_DIGITS};
use std::collections::HashSet;

/// A JSON string as written between its quotes.
#[derive(Clone, Copy, Debug)]
pub struct Str<'a> {
    raw: &'a str,
    escaped: bool,
}

impl<'a> Str<'a> {
    /// The decoded code points, keeping unpaired surrogates as parse_bounded does.
    pub fn points(&self) -> Vec<u32> {
        if !self.escaped {
            return self.raw.chars().map(u32::from).collect();
        }
        let mut out = Vec::with_capacity(self.raw.len());
        decode(self.raw, |cp| out.push(cp));
        out
    }
    /// Whether the decoded value equals `text`.
    pub fn eq_str(&self, text: &str) -> bool {
        if !self.escaped {
            return self.raw == text;
        }
        let mut expected = text.chars().map(u32::from);
        let mut equal = true;
        decode(self.raw, |cp| equal &= expected.next() == Some(cp));
        equal && expected.next().is_none()
    }
    /// The key's identity: its decoded code points, each written as UTF-8
    /// would write it (surrogates as three bytes). Distinct code point
    /// sequences give distinct bytes, and an unescaped key is its raw text.
    fn identity(&self) -> Key<'a> {
        if !self.escaped {
            return Key::Raw(self.raw.as_bytes());
        }
        let mut out = Vec::with_capacity(self.raw.len());
        decode(self.raw, |cp| push_utf8(&mut out, cp));
        Key::Owned(out)
    }
}

/// Decode a validated string body; the reader has already checked every escape.
fn decode(raw: &str, mut emit: impl FnMut(u32)) {
    let b = raw.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            let ch = raw[i..].chars().next().unwrap();
            emit(u32::from(ch));
            i += ch.len_utf8();
            continue;
        }
        let e = b[i + 1];
        i += 2;
        let cp = match e {
            b'b' => 8,
            b'f' => 12,
            b'n' => 10,
            b'r' => 13,
            b't' => 9,
            b'u' => {
                let mut cp = hex4(b, i).unwrap();
                i += 4;
                if (0xd800..=0xdbff).contains(&cp) && b.get(i..i + 2) == Some(&b"\\u"[..]) {
                    let low = hex4(b, i + 2).unwrap();
                    if (0xdc00..=0xdfff).contains(&low) {
                        cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
                        i += 6;
                    }
                }
                cp
            }
            other => u32::from(other),
        };
        emit(cp);
    }
}

fn push_utf8(out: &mut Vec<u8>, cp: u32) {
    match cp {
        0..=0x7f => out.push(cp as u8),
        0x80..=0x7ff => out.extend([0xc0 | (cp >> 6) as u8, 0x80 | (cp & 0x3f) as u8]),
        0x800..=0xffff => out.extend([
            0xe0 | (cp >> 12) as u8,
            0x80 | ((cp >> 6) & 0x3f) as u8,
            0x80 | (cp & 0x3f) as u8,
        ]),
        _ => out.extend([
            0xf0 | (cp >> 18) as u8,
            0x80 | ((cp >> 12) & 0x3f) as u8,
            0x80 | ((cp >> 6) & 0x3f) as u8,
            0x80 | (cp & 0x3f) as u8,
        ]),
    }
}

fn hex4(b: &[u8], i: usize) -> Option<u32> {
    let digits = b.get(i..i + 4)?;
    let mut v = 0u32;
    for &c in digits {
        v = v << 4
            | match c {
                b'0'..=b'9' => u32::from(c - b'0'),
                b'a'..=b'f' => u32::from(c - b'a' + 10),
                b'A'..=b'F' => u32::from(c - b'A' + 10),
                _ => return None,
            };
    }
    Some(v)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Key<'a> {
    Raw(&'a [u8]),
    Owned(Vec<u8>),
}
impl Key<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Key::Raw(b) => b,
            Key::Owned(b) => b,
        }
    }
}

/// The keys of one open object. Small objects compare linearly; past
/// `SMALL` keys a hash set bounds the cost of huge objects.
#[derive(Default)]
struct KeySet<'a> {
    small: Vec<Key<'a>>,
    large: HashSet<Vec<u8>>,
}
const SMALL: usize = 16;
impl<'a> KeySet<'a> {
    /// False when the key was already present.
    fn insert(&mut self, key: Key<'a>) -> bool {
        if self.large.is_empty() {
            if self.small.iter().any(|k| k.bytes() == key.bytes()) {
                return false;
            }
            if self.small.len() < SMALL {
                self.small.push(key);
                return true;
            }
            self.large
                .extend(self.small.drain(..).map(|k| k.bytes().to_vec()));
        }
        self.large.insert(key.bytes().to_vec())
    }
    fn clear(&mut self) {
        self.small.clear();
        self.large.clear();
    }
}

enum Open {
    Array,
    Object(usize),
}

/// One pass over one JSON text. See the module documentation.
pub struct Reader<'a> {
    text: &'a str,
    b: &'a [u8],
    i: usize,
    sets: Vec<KeySet<'a>>,
    used: usize,
    open: Vec<Open>,
}

const LO: u64 = 0x0101_0101_0101_0101;
const HI: u64 = 0x8080_8080_8080_8080;
/// Whether any byte of `w` is `"`, `\` or below 0x20 (exact for these bytes).
fn special(w: u64) -> bool {
    let zero = |x: u64| x.wrapping_sub(LO) & !x & HI;
    (zero(w ^ (u64::from(b'"') * LO))
        | zero(w ^ (u64::from(b'\\') * LO))
        | (w.wrapping_sub(0x20 * LO) & !w & HI))
        != 0
}

impl<'a> Reader<'a> {
    pub fn new(text: &'a str) -> Self {
        let mut r = Reader {
            text,
            b: text.as_bytes(),
            i: 0,
            sets: Vec::new(),
            used: 0,
            open: Vec::new(),
        };
        r.ws();
        r
    }

    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn peek(&self) -> Result<u8, Error> {
        self.b.get(self.i).copied().ok_or(Error::Syntax)
    }

    fn take_set(&mut self) -> usize {
        if self.used == self.sets.len() {
            self.sets.push(KeySet::default());
        }
        self.used += 1;
        self.used - 1
    }

    fn release_set(&mut self) {
        self.used -= 1;
        self.sets[self.used].clear();
    }

    /// The string token at the cursor, which must be a `"`.
    fn token(&mut self) -> Result<Str<'a>, Error> {
        self.i += 1;
        let start = self.i;
        let b = self.b;
        let mut escaped = false;
        loop {
            while let Some(chunk) = b.get(self.i..self.i + 8) {
                if special(u64::from_le_bytes(chunk.try_into().unwrap())) {
                    break;
                }
                self.i += 8;
            }
            match *b.get(self.i).ok_or(Error::Syntax)? {
                b'"' => {
                    let raw = &self.text[start..self.i];
                    self.i += 1;
                    return Ok(Str { raw, escaped });
                }
                b'\\' => {
                    escaped = true;
                    let e = *b.get(self.i + 1).ok_or(Error::Syntax)?;
                    self.i += 2;
                    match e {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                        b'u' => {
                            let cp = hex4(b, self.i).ok_or(Error::Syntax)?;
                            self.i += 4;
                            if (0xd800..=0xdbff).contains(&cp)
                                && b.get(self.i..self.i + 2) == Some(&b"\\u"[..])
                            {
                                let low = hex4(b, self.i + 2).ok_or(Error::Syntax)?;
                                if (0xdc00..=0xdfff).contains(&low) {
                                    self.i += 6;
                                }
                            }
                        }
                        _ => return Err(Error::Syntax),
                    }
                }
                0..=0x1f => return Err(Error::Syntax),
                _ => self.i += 1,
            }
        }
    }

    fn digits(&mut self) {
        while matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
            self.i += 1;
        }
    }

    fn number(&mut self) -> Result<(), Error> {
        if self.b[self.i] == b'-' {
            self.i += 1;
        }
        let start = self.i;
        match self.b.get(self.i) {
            Some(b'1'..=b'9') => {
                self.i += 1;
                self.digits();
            }
            Some(b'0') => self.i += 1,
            _ => return Err(Error::Syntax),
        }
        let count = self.i - start;
        let mut float = false;
        if self.b.get(self.i) == Some(&b'.') && matches!(self.b.get(self.i + 1), Some(b'0'..=b'9'))
        {
            float = true;
            self.i += 2;
            self.digits();
        }
        if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
            let mut j = self.i + 1;
            if matches!(self.b.get(j), Some(b'+' | b'-')) {
                j += 1;
            }
            let first = j;
            while matches!(self.b.get(j), Some(b'0'..=b'9')) {
                j += 1;
            }
            if j > first {
                float = true;
                self.i = j;
            }
        }
        if !float && count > MAX_INT_DIGITS {
            return Err(Error::Integer);
        }
        Ok(())
    }

    /// Consume a number or literal at the cursor; false when the cursor holds something else.
    fn try_scalar(&mut self) -> Result<bool, Error> {
        let rest = &self.b[self.i..];
        let literal = |word: &[u8]| rest.starts_with(word).then_some(word.len());
        let width = match rest.first() {
            Some(b'n') => literal(b"null"),
            Some(b't') => literal(b"true"),
            Some(b'f') => literal(b"false"),
            Some(b'N') => literal(b"NaN"),
            Some(b'I') => literal(b"Infinity"),
            Some(b'-') if rest.starts_with(b"-Infinity") => Some(9),
            Some(b'-' | b'0'..=b'9') => {
                self.number()?;
                return Ok(true);
            }
            Some(b'"' | b'[' | b'{') => return Ok(false),
            _ => return Err(Error::Syntax),
        };
        self.i += width.ok_or(Error::Syntax)?;
        Ok(true)
    }

    /// Read `"key"` and `:` inside the object whose key set is `set`.
    fn key(&mut self, set: usize) -> Result<Str<'a>, Error> {
        if self.peek()? != b'"' {
            return Err(Error::Syntax);
        }
        let key = self.token()?;
        if !self.sets[set].insert(key.identity()) {
            return Err(Error::Duplicate);
        }
        self.ws();
        if self.peek()? != b':' {
            return Err(Error::Syntax);
        }
        self.i += 1;
        self.ws();
        Ok(key)
    }

    /// Validate and pass over the value at the cursor, at any depth.
    pub fn skip(&mut self) -> Result<(), Error> {
        let base = self.open.len();
        'value: loop {
            match self.peek()? {
                b'"' => {
                    self.token()?;
                }
                b'[' => {
                    self.i += 1;
                    self.ws();
                    if self.peek()? == b']' {
                        self.i += 1;
                    } else {
                        self.open.push(Open::Array);
                        continue 'value;
                    }
                }
                b'{' => {
                    self.i += 1;
                    self.ws();
                    if self.peek()? == b'}' {
                        self.i += 1;
                    } else {
                        let set = self.take_set();
                        self.open.push(Open::Object(set));
                        self.key(set)?;
                        continue 'value;
                    }
                }
                _ => {
                    if !self.try_scalar()? {
                        return Err(Error::Syntax);
                    }
                }
            }
            loop {
                let Some(open) = self.open.last() else {
                    return Ok(());
                };
                if self.open.len() == base {
                    return Ok(());
                }
                let set = match open {
                    Open::Array => None,
                    Open::Object(set) => Some(*set),
                };
                self.ws();
                match (set, self.peek()?) {
                    (_, b',') => {
                        self.i += 1;
                        self.ws();
                        if let Some(set) = set {
                            self.key(set)?;
                        }
                        continue 'value;
                    }
                    (None, b']') | (Some(_), b'}') => {
                        self.i += 1;
                        if set.is_some() {
                            self.release_set();
                        }
                        self.open.pop();
                    }
                    _ => return Err(Error::Syntax),
                }
            }
        }
    }

    /// Read the string at the cursor; `None`, consuming nothing, if it is not a string.
    pub fn string(&mut self) -> Result<Option<Str<'a>>, Error> {
        if self.peek()? != b'"' {
            return Ok(None);
        }
        self.token().map(Some)
    }

    /// Consume the literal `true` at the cursor; false, consuming nothing, otherwise.
    pub fn is_true(&mut self) -> Result<bool, Error> {
        if self.b[self.i..].starts_with(b"true") {
            self.i += 4;
            return Ok(true);
        }
        Ok(false)
    }

    /// Read the number or literal at the cursor as written; `None`, consuming nothing, otherwise.
    pub fn scalar(&mut self) -> Result<Option<&'a str>, Error> {
        let start = self.i;
        Ok(self.try_scalar()?.then(|| &self.text[start..self.i]))
    }

    /// Visit each member of the object at the cursor. A member the callback
    /// leaves unread is validated and skipped. The callback reads at most
    /// one value. Returns false, consuming nothing, if it is not an object.
    pub fn object(
        &mut self,
        mut visit: impl FnMut(Str<'a>, &mut Self) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        if self.peek()? != b'{' {
            return Ok(false);
        }
        self.i += 1;
        self.ws();
        if self.peek()? == b'}' {
            self.i += 1;
            return Ok(true);
        }
        let set = self.take_set();
        let mut key = self.key(set)?;
        loop {
            let start = self.i;
            visit(key, self)?;
            if self.i == start {
                self.skip()?;
            }
            self.ws();
            match self.peek()? {
                b',' => {
                    self.i += 1;
                    self.ws();
                    key = self.key(set)?;
                }
                b'}' => {
                    self.i += 1;
                    self.release_set();
                    return Ok(true);
                }
                _ => return Err(Error::Syntax),
            }
        }
    }

    /// Visit each element of the array at the cursor, as [`Reader::object`] does.
    pub fn array(
        &mut self,
        mut visit: impl FnMut(&mut Self) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        if self.peek()? != b'[' {
            return Ok(false);
        }
        self.i += 1;
        self.ws();
        if self.peek()? == b']' {
            self.i += 1;
            return Ok(true);
        }
        loop {
            let start = self.i;
            visit(self)?;
            if self.i == start {
                self.skip()?;
            }
            self.ws();
            match self.peek()? {
                b',' => {
                    self.i += 1;
                    self.ws();
                }
                b']' => {
                    self.i += 1;
                    return Ok(true);
                }
                _ => return Err(Error::Syntax),
            }
        }
    }

    /// Require that only whitespace follows the top-level value.
    pub fn finish(mut self) -> Result<(), Error> {
        self.ws();
        if self.i != self.b.len() {
            return Err(Error::Syntax);
        }
        Ok(())
    }
}

/// Whether a strict load of `text` would succeed, without building it.
pub fn validate(text: &str) -> Result<(), Error> {
    let mut r = Reader::new(text);
    r.skip()?;
    r.finish()
}

#[cfg(test)]
mod tests;
