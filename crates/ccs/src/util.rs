//! Paths, safe local reads, atomic state files and Python-compatible parsers.
use crate::errors::{Error, Result};
use ccs_pytext::json::{self, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn string(s: impl AsRef<str>) -> Value {
    Value::String(s.as_ref().chars().map(u32::from).collect())
}
pub fn object(items: impl IntoIterator<Item = (impl AsRef<str>, Value)>) -> Value {
    Value::Object(
        items
            .into_iter()
            .map(|(k, v)| (k.as_ref().chars().map(u32::from).collect(), v))
            .collect(),
    )
}
pub fn get<'a>(value: &'a Value, key: &str) -> &'a Value {
    static NULL: Value = Value::Null;
    if let Value::Object(items) = value {
        items
            .iter()
            .find(|(k, _)| k.iter().copied().eq(key.chars().map(u32::from)))
            .map(|(_, v)| v)
            .unwrap_or(&NULL)
    } else {
        &NULL
    }
}
pub fn has(value: &Value, key: &str) -> bool {
    matches!(value, Value::Object(items) if items.iter().any(|(k,_)| k.iter().copied().eq(key.chars().map(u32::from))))
}
pub fn set(value: &mut Value, key: &str, new: Value) {
    if let Value::Object(items) = value {
        if let Some((_, v)) = items
            .iter_mut()
            .find(|(k, _)| k.iter().copied().eq(key.chars().map(u32::from)))
        {
            *v = new;
        } else {
            items.push((key.chars().map(u32::from).collect(), new));
        }
    }
}
pub fn text(value: &Value) -> Option<String> {
    if let Value::String(s) = value {
        s.iter().map(|&c| char::from_u32(c)).collect()
    } else {
        None
    }
}
pub fn is(value: &Value, s: &str) -> bool {
    matches!(value, Value::String(v) if v.iter().copied().eq(s.chars().map(u32::from)))
}
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(v) => *v,
        Value::Number(n) => n.parse::<f64>() != Ok(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}
pub fn number(n: impl ToString) -> Value {
    Value::Number(n.to_string())
}
pub fn invalid(message: &str) -> Error {
    Error::Io(io::Error::new(io::ErrorKind::InvalidData, message))
}
/// A refused filesystem object, distinct from an ordinary OS read failure.
/// Kept inside Error::Io so consumers can retain the shared error enum.
#[derive(Debug)]
pub struct UnsafePath(pub String);
impl std::fmt::Display for UnsafePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for UnsafePath {}
fn unsafe_path(message: &str) -> Error {
    Error::Io(io::Error::other(UnsafePath(message.into())))
}
/// Call before handling plain Error::Io when unsafe objects need a warning.
pub fn is_unsafe_path(error: &Error) -> bool {
    matches!(error, Error::Io(error) if error.get_ref().is_some_and(|source| source.is::<UnsafePath>()))
}
pub fn parse_json(s: &str) -> Result<Value> {
    let p = json::parse_bounded(&s.chars().map(u32::from).collect::<Vec<_>>(), usize::MAX)
        .map_err(|_| invalid("invalid JSON"))?;
    if p.flags.big_int {
        return Err(invalid("JSON integer exceeds Python digit limit"));
    }
    p.value
        .ok_or_else(|| invalid("JSON nesting cannot be materialized"))
}

pub fn json_string(v: &Value, ascii: bool, sorted: bool) -> Result<String> {
    json::dumps(v, ascii, sorted).map_err(|_| invalid("cannot encode JSON"))
}

pub fn home() -> PathBuf {
    let home = std::env::var_os("HOME").or_else(|| {
        let mut size = 4096;
        loop {
            let mut buffer = vec![0_u8; size];
            let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
            let mut result = std::ptr::null_mut();
            // SAFETY: buffers and result storage remain live during getpwuid_r.
            let error = unsafe {
                libc::getpwuid_r(
                    libc::getuid(),
                    pwd.as_mut_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut result,
                )
            };
            if error == libc::ERANGE {
                size *= 2;
                continue;
            }
            if error != 0 || result.is_null() {
                return None;
            }
            // SAFETY: successful getpwuid_r initialized pwd and its NUL-terminated pw_dir.
            let bytes = unsafe { std::ffi::CStr::from_ptr(pwd.assume_init().pw_dir) }.to_bytes();
            return Some(std::ffi::OsString::from_vec(bytes.to_vec()));
        }
    });
    let Some(home) = home else {
        return PathBuf::from("~");
    };
    let bytes = home.as_bytes();
    let end = bytes.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1);
    if end == 0 {
        PathBuf::from("/")
    } else {
        PathBuf::from(std::ffi::OsStr::from_bytes(&bytes[..end]))
    }
}
pub fn claude_dir() -> PathBuf {
    home().join(".claude")
}
pub fn projects_dir() -> PathBuf {
    claude_dir().join("projects")
}
pub fn state_dir() -> PathBuf {
    claude_dir().join("session-search")
}
pub fn state_path() -> PathBuf {
    state_dir().join("state.json")
}
pub fn lock_path() -> PathBuf {
    state_dir().join("lock")
}
pub fn restored_path() -> PathBuf {
    state_dir().join("restored.json")
}
pub fn breaker_path() -> PathBuf {
    state_dir().join("breaker.json")
}
pub fn log_path() -> PathBuf {
    claude_dir().join("session-search.log")
}
pub fn config_path() -> PathBuf {
    std::env::var_os("CCS_CONFIG")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config/session-search/config.json"))
}
pub fn current_session_id() -> Option<String> {
    std::env::var("CLAUDE_CODE_SESSION_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("CODEX_THREAD_ID").ok())
}
pub fn encode_cwd(cwd: &str) -> String {
    cwd.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}
pub fn valid_session_id(s: &str) -> bool {
    s.len() == 36
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
}
pub fn valid_host_label(s: &str) -> bool {
    (1..=63).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub fn valid_tool_result_name(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && (s.as_bytes()[0].is_ascii_alphanumeric() || s.starts_with('_'))
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn realpath(path: &Path) -> PathBuf {
    enum Part {
        Name(std::ffi::OsString),
        Resolved(PathBuf),
    }
    fn parts(path: &Path) -> Vec<Part> {
        path.as_os_str()
            .as_bytes()
            .split(|&b| b == b'/')
            .rev()
            .map(|s| Part::Name(std::ffi::OsString::from_vec(s.to_vec())))
            .collect()
    }
    let mut pending = parts(path);
    let mut resolved = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"))
    };
    let mut seen = std::collections::HashMap::<PathBuf, Option<PathBuf>>::new();
    while let Some(part) = pending.pop() {
        let name = match part {
            Part::Resolved(link) => {
                seen.insert(link, Some(resolved.clone()));
                continue;
            }
            Part::Name(name) => name,
        };
        if name.is_empty() || name == "." {
            continue;
        }
        if name == ".." {
            resolved.pop();
            continue;
        }
        let next = resolved.join(name);
        if fs::symlink_metadata(&next).is_ok_and(|st| st.file_type().is_symlink()) {
            if let Some(target) = seen.get(&next) {
                resolved = target.clone().unwrap_or(next);
                continue;
            }
            if let Ok(target) = fs::read_link(&next) {
                if target.is_absolute() {
                    resolved = PathBuf::from("/");
                }
                seen.insert(next.clone(), None);
                pending.push(Part::Resolved(next));
                pending.extend(parts(&target));
                continue;
            }
        }
        resolved = next;
    }
    resolved
}
pub fn is_within(path: &Path, root: &Path) -> bool {
    let root = realpath(root);
    let path = realpath(path);
    // Python uses the literal root + separator prefix (including root == "/").
    let mut prefix = root.as_os_str().as_bytes().to_vec();
    prefix.push(b'/');
    path.as_os_str().as_bytes().starts_with(&prefix)
}
pub fn open_regular(path: &Path, root: Option<&Path>) -> Result<File> {
    if root.is_some_and(|r| !is_within(path, r)) {
        return Err(unsafe_path("path resolves outside its root"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::EMLINK)) {
                unsafe_path("path is a symlink")
            } else {
                Error::Io(error)
            }
        })?;
    let st = file.metadata().map_err(Error::Io)?;
    if !st.is_file() {
        return Err(unsafe_path("path is not a regular file"));
    }
    if let Some(root) = root {
        let resolved = fs::canonicalize(path).map_err(Error::Io)?;
        if !is_within(&resolved, root) {
            return Err(unsafe_path("path changed while opening"));
        }
        let rst = fs::metadata(resolved).map_err(Error::Io)?;
        if (st.dev(), st.ino()) != (rst.dev(), rst.ino()) {
            return Err(unsafe_path("path changed while opening"));
        }
    }
    use std::os::fd::AsRawFd;
    // SAFETY: file owns an open descriptor; F_GETFL/F_SETFL take no pointer.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0
    {
        return Err(Error::Io(io::Error::last_os_error()));
    }
    Ok(file)
}
pub fn ensure_dir(path: &Path, mode: u32) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
        .map_err(Error::Io)
}
pub fn atomic_write(path: &Path, data: &str, mode: u32) -> Result<()> {
    static SERIAL: AtomicU64 = AtomicU64::new(0);
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_dir(dir, 0o700)?;
    let (tmp, mut file) = loop {
        let tmp = dir.join(format!(
            ".tmp-{}-{}-{}",
            std::process::id(),
            now_epoch().to_bits(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    };
    let result = (|| {
        file.write_all(data.as_bytes())?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        drop(file);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(Error::Io)
}
pub fn read_json(path: &Path, default: Value) -> Value {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| parse_json(&s).ok())
        .unwrap_or(default)
}
pub fn load_state(path: &Path) -> Result<Value> {
    Ok(read_json(
        path,
        object([("version", number(1)), ("files", Value::Object(vec![]))]),
    ))
}
pub fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or_else(|e| -e.duration().as_secs_f64(), |d| d.as_secs_f64())
}

fn civil_days(y: i64, m: i64, d: i64) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    era * 146097 + yoe * 365 + yoe / 4 - yoe / 100
        + (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5
        + d
        - 1
        - 719468
}
pub fn iso(epoch: f64) -> String {
    let seconds = epoch.floor() as i64;
    let days = seconds.div_euclid(86400);
    let rem = seconds.rem_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let y = year + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}
pub fn log(level: &str, msg: &str) {
    let _ = ensure_dir(&claude_dir(), 0o755);
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path())
    {
        let _ = write_log_line(&mut f, &iso(now_epoch()), level, msg);
    }
}
fn write_log_line(
    writer: &mut impl Write,
    timestamp: &str,
    level: &str,
    msg: &str,
) -> io::Result<()> {
    let line = format!("{timestamp} {level} {}\n", msg.replace('\n', " "));
    writer.write_all(line.as_bytes())
}
pub fn parse_duration(s: &str) -> Result<u64> {
    let split = s.len().saturating_sub(1);
    let (Some(digits), Some(unit)) = (s.get(..split), s.get(split..)) else {
        return Err(Error::Usage("invalid duration".into()));
    };
    if !(1..=6).contains(&digits.len())
        || digits.starts_with('0')
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::Usage(
            "duration must look like 30m, 12h, 7d or 2w".into(),
        ));
    }
    let mult = match unit {
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        "w" => 604800,
        _ => {
            return Err(Error::Usage(
                "duration must look like 30m, 12h, 7d or 2w".into(),
            ))
        }
    };
    Ok(digits.parse::<u64>().unwrap() * mult)
}
fn decimal(s: &str) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        None
    } else {
        s.parse().ok()
    }
}
fn date_separator(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if b.len() < 7 {
        return None;
    }
    if b.len() == 7 {
        return Some(7);
    }
    if b[4] == b'-' {
        if b[5] == b'W' {
            if b.get(8) == Some(&b'-') {
                if b.len() == 9 {
                    None
                } else if b.get(10).is_some_and(u8::is_ascii_digit) {
                    Some(8)
                } else {
                    Some(10)
                }
            } else {
                Some(8)
            }
        } else {
            Some(10)
        }
    } else if b[4] == b'W' {
        let mut i = 7;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        Some(if i < 9 {
            i
        } else if i % 2 == 0 {
            7
        } else {
            8
        })
    } else {
        Some(8)
    }
}
fn parse_date(s: &str) -> Option<i64> {
    let y = decimal(s.get(..4)?)?;
    if !(1..=9999).contains(&y) {
        return None;
    }
    let separated = s.as_bytes().get(4) == Some(&b'-');
    let mut rest = s.get(if separated { 5 } else { 4 }..)?;
    if let Some(week) = rest.strip_prefix('W') {
        let w = decimal(week.get(..2)?)?;
        let day = week.get(2..)?;
        let d = if day.is_empty() {
            1
        } else {
            let day = if separated {
                day.strip_prefix('-')?
            } else {
                day
            };
            if day.len() != 1 {
                return None;
            }
            decimal(day)?
        };
        let first = civil_days(y, 1, 4);
        let monday = first - (first + 3).rem_euclid(7);
        let next = civil_days(y + 1, 1, 4);
        let next = next - (next + 3).rem_euclid(7);
        if !(1..=7).contains(&d) || w < 1 || w > (next - monday) / 7 {
            return None;
        }
        let result = monday + (w - 1) * 7 + d - 1;
        if result < civil_days(1, 1, 1) || result >= civil_days(10000, 1, 1) {
            return None;
        }
        return Some(result);
    }
    let m = decimal(rest.get(..2)?)?;
    rest = rest.get(2..)?;
    if separated {
        rest = rest.strip_prefix('-')?;
    }
    if rest.len() != 2 {
        return None;
    }
    let d = decimal(rest)?;
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let maxd = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => return None,
    };
    if !(1..=maxd).contains(&d) {
        None
    } else {
        Some(civil_days(y, m, d))
    }
}
// CPython's C parser returns a positive trailing-data status at a timezone.
// The clock parser accepts that status; the offset parser requires end-of-input.
fn parse_time(s: &str, end: usize) -> Option<([i64; 4], bool)> {
    let bytes = s.as_bytes();
    let mut out = [0; 4];
    let mut pos = 0;
    let mut separated = true;
    for (i, part) in out.iter_mut().enumerate().take(3) {
        *part = decimal(s.get(pos..pos + 2)?)?;
        pos += 2;
        let c = bytes.get(pos).copied().unwrap_or(0);
        pos += 1;
        if i == 0 {
            separated = c == b':';
        }
        if pos >= end {
            return Some((out, c != 0));
        }
        if separated && c == b':' {
            continue;
        }
        if matches!(c, b'.' | b',') {
            break;
        }
        if !separated {
            pos -= 1;
        } else {
            return None;
        }
    }
    let digits = end.checked_sub(pos)?.min(6);
    out[3] = decimal(s.get(pos..pos + digits)?)? * 10_i64.pow((6 - digits) as u32);
    pos += digits;
    while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
        pos += 1;
    }
    Some((out, pos != bytes.len()))
}
pub fn parse_ts(value: &Value) -> Option<f64> {
    let Value::String(points) = value else {
        return None;
    };
    let mut points = ccs_pytext::strip_points(points).to_vec();
    if points.last() == Some(&u32::from('Z')) {
        points.pop();
        points.extend("+00:00".chars().map(u32::from));
    }
    // fromisoformat sanitizes a single surrogate at a possible separator.
    if let Some(pos) = [7, 8, 10]
        .into_iter()
        .find(|&i| points.get(i).is_some_and(|p| (0xd800..=0xdfff).contains(p)))
    {
        points[pos] = u32::from('T');
    }
    let s: String = points
        .into_iter()
        .map(char::from_u32)
        .collect::<Option<_>>()?;
    let s = s.as_str();
    let sep = date_separator(s)?;
    let days = parse_date(s.get(..sep)?)?;
    if s.len() == sep {
        return Some((days * 86400) as f64);
    }
    let separator = s.get(sep..)?.chars().next()?;
    let time = s.get(sep + separator.len_utf8()..)?;
    let zone = time.find(['-', '+', 'Z']);
    let tz = zone.map(|i| &time[i..]);
    let ([h, m, sec, micro], trailing) = parse_time(time, zone.unwrap_or(time.len()))?;
    if trailing && zone.is_none() {
        return None;
    }
    if h > 23 || m > 59 || sec > 59 {
        return None;
    }
    let mut offset = 0_i64;
    if let Some(tz) = tz {
        if tz != "Z" {
            let tail = tz.get(1..)?;
            let ([h, m, s, us], trailing) = parse_time(tail, tail.len())?;
            if trailing {
                return None;
            }
            // CPython treats an offset of zero hours/minutes/seconds as UTC.
            if h != 0 || m != 0 || s != 0 {
                offset = (h * 3600 + m * 60 + s) * 1_000_000 + us;
            }
            if offset >= 86400 * 1_000_000 {
                return None;
            }
            if tz.starts_with('-') {
                offset = -offset;
            }
        }
    }
    let total = (days * 86400 + h * 3600 + m * 60 + sec) * 1_000_000 + micro - offset;
    Some(total.div_euclid(1_000_000) as f64 + total.rem_euclid(1_000_000) as f64 / 1_000_000.0)
}
pub fn human_age(seconds: f64) -> String {
    let s = seconds.max(0.0) as u64;
    if s < 3600 {
        format!("{}m", s / 60)
    } else if s < 86400 {
        format!("{}h", s / 3600)
    } else if s < 86400 * 60 {
        format!("{}d", s / 86400)
    } else {
        format!("{}mo", s / (86400 * 30))
    }
}
pub fn short_cwd(cwd: &str, width: usize) -> String {
    if cwd.is_empty() {
        return "?".into();
    }
    let h = home();
    let h = h.to_string_lossy();
    let cwd = if cwd == h
        || cwd
            .strip_prefix(h.as_ref())
            .is_some_and(|s| s.starts_with('/'))
    {
        format!("~{}", &cwd[h.len()..])
    } else {
        cwd.into()
    };
    let chars: Vec<_> = cwd.chars().collect();
    if chars.len() <= width {
        cwd
    } else if width == 1 {
        format!("…{cwd}")
    } else if width == 0 {
        format!("…{}", chars[1..].iter().collect::<String>())
    } else {
        format!(
            "…{}",
            chars[chars.len().saturating_sub(width.saturating_sub(1))..]
                .iter()
                .collect::<String>()
        )
    }
}

/// One write per stderr line; a closed pipe neither panics nor delivers SIGPIPE.
pub fn stderr_line(line: &str) {
    let line = format!("{}\n", line.replace(['\n', '\r'], " "));
    // Blocking is per-thread, so stdout and child processes retain SIGPIPE's
    // default disposition. Drain only the signal generated by this write.
    unsafe {
        let mut blocked: libc::sigset_t = std::mem::zeroed();
        let mut previous: libc::sigset_t = std::mem::zeroed();
        let mut pending: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut blocked);
        libc::sigaddset(&mut blocked, libc::SIGPIPE);
        let ok = libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous) == 0;
        libc::sigpending(&mut pending);
        let was_pending = libc::sigismember(&pending, libc::SIGPIPE) == 1;
        let failed = io::stderr().write(line.as_bytes()).is_err();
        if ok {
            if failed && !was_pending {
                libc::sigpending(&mut pending);
                if libc::sigismember(&pending, libc::SIGPIPE) == 1 {
                    let mut signal = 0;
                    libc::sigwait(&blocked, &mut signal);
                }
            }
            libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn log_line_is_one_write() {
        #[derive(Default)]
        struct Counter {
            writes: usize,
            bytes: Vec<u8>,
        }
        impl Write for Counter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.writes += 1;
                self.bytes.extend(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = Counter::default();
        write_log_line(&mut writer, "2026-01-01T00:00:00Z", "WARN", "first\nsecond").unwrap();
        assert_eq!(writer.writes, 1);
        assert_eq!(writer.bytes, b"2026-01-01T00:00:00Z WARN first second\n");
    }
    #[test]
    fn identifiers_reject_trailing_newlines_and_separators() {
        assert!(valid_session_id("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        assert!(!valid_session_id("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n"));
        assert!(valid_host_label("pro-dev"));
        assert!(!valid_host_label("pro-dev\n"));
        for s in ["", ".hidden", "a/b", "a\n", "../file", "a☃"] {
            assert!(!valid_tool_result_name(s), "{s:?}");
        }
        assert!(valid_tool_result_name("_file-1.txt"));
        assert_eq!(encode_cwd("/work/日本/one_two"), "-work----one-two");
    }
    #[test]
    fn durations_timestamps_and_ages() {
        assert_eq!(parse_duration("7d").unwrap(), 604800);
        for s in ["", "0m", "12h\n", "☃", "0001d", "1000000d"] {
            assert!(parse_duration(s).is_err());
        }
        assert_eq!(parse_ts(&string("1970-01-01T01:00:00+01:00")), Some(0.0));
        assert_eq!(
            parse_ts(&string("1969-12-31T23:59:59.1234567Z")),
            Some(-0.876544)
        );
        assert_eq!(parse_ts(&string("2023-02-29")), None);
        assert_eq!(iso(0.0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(-1.0), "1969-12-31T23:59:59Z");
        assert_eq!(human_age(86400.0 * 60.0), "2mo");
    }
    #[test]
    fn safe_reads_and_atomic_permissions() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!(
            "ccs-safe-read-{}-{}",
            std::process::id(),
            now_epoch().to_bits()
        ));
        let nested = root.join("nested");
        ensure_dir(&nested, 0o700).unwrap();
        let p = nested.join("state");
        atomic_write(&p, "first", 0o600).unwrap();
        assert_eq!(
            open_regular(&p, Some(&root))
                .unwrap()
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        atomic_write(&p, "second", 0o600).unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "second");
        let link = root.join("alias");
        symlink(&p, &link).unwrap();
        assert!(is_unsafe_path(
            &open_regular(&link, Some(&root)).unwrap_err()
        ));
        assert!(is_unsafe_path(
            &open_regular(&nested, Some(&root)).unwrap_err()
        ));
        assert!(is_unsafe_path(
            &open_regular(&p, Some(&nested.join("wrong"))).unwrap_err()
        ));
        let missing = open_regular(&root.join("missing"), Some(&root)).unwrap_err();
        assert!(!is_unsafe_path(&missing));
        assert!(matches!(missing, Error::Io(e) if e.kind() == io::ErrorKind::NotFound));
        let fifo = root.join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: name is a valid NUL-terminated path in our disposable directory.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(is_unsafe_path(
            &open_regular(&fifo, Some(&root)).unwrap_err()
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
