//! Resume uses locally trusted directories; archive metadata never selects a cwd.
use crate::api::{Api, Response};
use crate::config::Config;
use crate::errors::{Error, ExitStatus, Result};
use crate::util::{self, get, has, is, number, object, set, string, text, truthy};
use crate::{codex, extract, session_codex};
use ccs_pytext::{json, shell_quote, strip};
use json::Value;
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

const RESTORED_NOTE: &str = "restored masked transcript (secrets appear as [REDACTED:…])";

pub struct ResumeRequest {
    pub session_key: String,
    pub print: bool,
    pub fork: bool,
    pub to_dir: Option<PathBuf>,
    pub force: bool,
}

fn refused(message: impl Into<String>) -> Error {
    Error::ResumePrecondition(message.into())
}
struct Diagnostics {
    open_at_entry: bool,
}
impl Diagnostics {
    fn capture() -> Self {
        // SAFETY: F_GETFD inspects the borrowed descriptor without a pointer.
        Self {
            open_at_entry: unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_GETFD) } >= 0,
        }
    }
    fn write(&self, message: &str) -> Result<()> {
        // A network socket may reuse a closed fd 2 while downloading. Never
        // send diagnostics to that socket, and retain Python's I/O exit status.
        if !self.open_at_entry {
            return Err(Error::Io(io::Error::from_raw_os_error(libc::EBADF)));
        }
        let line = format!("{message}\n");
        util::stderr_write(line.as_bytes()).map_err(Error::Io)
    }
}
fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
pub(crate) fn repr(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(v) => if *v { "True" } else { "False" }.into(),
        Value::String(points) => {
            let quote = if points.contains(&39) && !points.contains(&34) {
                '"'
            } else {
                '\''
            };
            let mut out = quote.to_string();
            for &point in points {
                match char::from_u32(point) {
                    Some('\n') => out.push_str("\\n"),
                    Some('\r') => out.push_str("\\r"),
                    Some('\t') => out.push_str("\\t"),
                    Some('\\') => out.push_str("\\\\"),
                    Some(c) if c == quote => {
                        out.push('\\');
                        out.push(c);
                    }
                    Some(c) if printable(point) => out.push(c),
                    _ if point < 256 => out.push_str(&format!("\\x{point:02x}")),
                    _ if point <= 0xffff => out.push_str(&format!("\\u{point:04x}")),
                    _ => out.push_str(&format!("\\U{point:08x}")),
                }
            }
            out.push(quote);
            out
        }
        _ => util::json_string(value, true, false).unwrap_or_default(),
    }
}
fn printable(point: u32) -> bool {
    let index = NONPRINTABLE.partition_point(|&(_, end)| end < point);
    NONPRINTABLE
        .get(index)
        .is_none_or(|&(start, _)| point < start)
}
fn validate_session_id(value: &Value) -> Result<String> {
    text(value)
        .filter(|sid| util::valid_session_id(sid))
        .ok_or_else(|| {
            refused(format!(
                "refusing session_id {}: it does not match ^[0-9a-f-]{{36}}$",
                repr(value)
            ))
        })
}
fn symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}
fn expand(path: &Path) -> PathBuf {
    if path == Path::new("~") {
        return util::home();
    }
    if let Ok(tail) = path.strip_prefix("~/") {
        return util::home().join(tail);
    }
    let bytes = path.as_os_str().as_bytes();
    if !bytes.starts_with(b"~") {
        return path.to_path_buf();
    }
    let end = bytes.iter().position(|&b| b == b'/').unwrap_or(bytes.len());
    let Ok(name) = std::ffi::CString::new(&bytes[1..end]) else {
        return path.to_path_buf();
    };
    let mut size = 4096;
    loop {
        let mut buffer = vec![0_u8; size];
        let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: the NUL-terminated name and all result buffers stay live.
        let error = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
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
            return path.to_path_buf();
        }
        // SAFETY: successful getpwnam_r initialized pwd and its pw_dir string.
        let home = unsafe { std::ffi::CStr::from_ptr(pwd.assume_init().pw_dir) }.to_bytes();
        let mut expanded = home.to_vec();
        while expanded.last() == Some(&b'/') {
            expanded.pop();
        }
        expanded.extend_from_slice(&bytes[end..]);
        if expanded.is_empty() {
            expanded.push(b'/');
        }
        return PathBuf::from(std::ffi::OsString::from_vec(expanded));
    }
}
fn directory(path: &Path) -> Option<PathBuf> {
    path.is_dir().then(|| fs::canonicalize(path).ok()).flatten()
}
fn utf8_cwd(path: PathBuf) -> Result<PathBuf> {
    if path.to_str().is_none() {
        return Err(refused("WARN: refusing non-UTF-8 resume cwd"));
    }
    Ok(path)
}
fn cwd_text(value: &Value) -> Result<Option<String>> {
    if let Value::String(points) = value {
        if points.iter().any(|p| (0xdc80..=0xdcff).contains(p)) {
            return Err(refused("WARN: refusing non-UTF-8 resume cwd"));
        }
    }
    Ok(text(value))
}
// os.makedirs applies mode to the leaf; ancestors use 0777 & umask.
fn ensure_dir(path: &Path, mode: u32) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(Error::Io)?;
    }
    match fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => Ok(()),
        Err(_) if path.is_dir() => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}
fn load_restored() -> Value {
    let d = util::read_json(&util::restored_path(), Value::Null);
    if (matches!(get(&d, "version"), Value::Number(n) if n.parse::<f64>() == Ok(1.0))
        || matches!(get(&d, "version"), Value::Bool(true)))
        && matches!(get(&d, "sessions"), Value::Object(_))
    {
        return d;
    }
    object([("version", number(1)), ("sessions", Value::Object(vec![]))])
}
fn record_restore(sid: &str, project: &str, cwd: &Path) -> Result<()> {
    let mut d = load_restored();
    let mut sessions = get(&d, "sessions").clone();
    set(
        &mut sessions,
        &format!("{project}/{sid}"),
        object([
            ("session_id", string(sid)),
            ("project_dir", string(project)),
            ("cwd", string(display(cwd))),
            ("restored_at", string(util::iso(util::now_epoch()))),
        ]),
    );
    set(&mut d, "sessions", sessions);
    let data = json::dumps_pretty(&d, true, true, 1)
        .map_err(|_| util::invalid("restore state cannot be encoded"))?;
    util::atomic_write(&util::restored_path(), &data, 0o600)
}
fn local_jsonl_ok(path: &Path, sid: &str) -> bool {
    let root = codex::absolute(&util::projects_dir());
    let p = codex::absolute(path);
    let Some(parent) = p.parent() else {
        return false;
    };
    p.file_name()
        .is_some_and(|s| s == format!("{sid}.jsonl").as_str())
        && parent.parent() == Some(root.as_path())
        && !symlink(parent)
        && !symlink(&p)
        && util::open_regular(&p, Some(&root)).is_ok()
}
fn find_local_jsonl(sid: &str, hint: Option<&Path>) -> Option<PathBuf> {
    if let Some(hint) = hint.filter(|p| local_jsonl_ok(p, sid)) {
        return Some(codex::absolute(hint));
    }
    let mut dirs: Vec<_> = fs::read_dir(util::projects_dir())
        .ok()?
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    dirs.sort();
    dirs.into_iter()
        .map(|d| d.join(format!("{sid}.jsonl")))
        .find(|p| local_jsonl_ok(p, sid))
}
fn local_resume_cwd(path: &Path, to: Option<&Path>) -> Result<PathBuf> {
    let absolute = codex::absolute(path);
    let project = display(
        absolute
            .parent()
            .and_then(Path::file_name)
            .map(Path::new)
            .unwrap_or(Path::new("")),
    );
    let sid = absolute
        .file_stem()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();
    let restored = load_restored();
    let rec = get(get(&restored, "sessions"), &format!("{project}/{sid}"));
    if matches!(rec, Value::Object(_)) {
        let cwd = get(rec, "cwd");
        if let Some(c) = cwd_text(cwd)?.filter(|c| {
            c.starts_with('/') && Path::new(c).is_dir() && util::encode_cwd(c) == project
        }) {
            return Ok(c.into());
        }
        return Err(refused(format!(
            "restored session {sid} was placed in {}, which is gone; pass --to DIR",
            repr(cwd)
        )));
    }
    if let Some(to) = to.filter(|p| !p.as_os_str().is_empty()) {
        if let Some(d) = directory(&expand(to)).filter(|d| util::encode_cwd(&display(d)) == project)
        {
            return utf8_cwd(d);
        }
        return Err(refused(format!(
            "--to {} does not encode to {project}, the directory this transcript lives in",
            display(to)
        )));
    }
    let mut found = Vec::new();
    let local = extract::scan(path, None, 0).value();
    let Value::Array(candidates) = get(&local, "cwd_candidates") else {
        return Err(util::invalid("invalid cwd candidates"));
    };
    for candidate in candidates {
        let Some(c) = cwd_text(candidate)? else {
            continue;
        };
        if c.starts_with('/')
            && util::encode_cwd(&c) == project
            && directory(Path::new(&c)).is_some_and(|p| p.as_os_str() == c.as_str())
            && !found.contains(&c)
        {
            found.push(c);
        }
    }
    match found.len() {
        1 => Ok(PathBuf::from(&found[0])),
        0 => Err(refused(format!("no cwd recorded in {} encodes to {project} and exists on this host as a real path; not resuming from a guessed directory (pass --to DIR)", display(path)))),
        n => Err(refused(format!("{n} recorded directories match {project} ({}); pass --to DIR to choose", found.join(", ")))),
    }
}
fn codex_resume_cwd(path: &Path, to: Option<&Path>) -> Result<PathBuf> {
    let meta = codex::metadata(path);
    let c = if let Some(to) = to.filter(|p| !p.as_os_str().is_empty()) {
        Some(to.to_path_buf())
    } else {
        cwd_text(get(&meta, "cwd"))?.map(PathBuf::from)
    };
    let cwd = c
        .filter(|c| c.is_absolute())
        .and_then(|c| directory(&c))
        .ok_or_else(|| refused("Codex session directory does not exist here; pass --to DIR"))?;
    utf8_cwd(cwd)
}
fn ask(prompt: &str) -> Result<String> {
    io::stdout()
        .write_all(prompt.as_bytes())
        .map_err(Error::Io)?;
    io::stdout().flush().map_err(Error::Io)?;
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).map_err(Error::Io)? == 0 {
        return Err(util::invalid("end of input"));
    }
    Ok(strip(&answer).to_owned())
}
fn choose_restore_cwd(
    meta: &Value,
    req: &ResumeRequest,
    diagnostics: &Diagnostics,
) -> Result<PathBuf> {
    if let Some(to) = req.to_dir.as_deref().filter(|p| !p.as_os_str().is_empty()) {
        return utf8_cwd(
            directory(&expand(to))
                .ok_or_else(|| refused(format!("--to {} is not a directory", display(to))))?,
        );
    }
    if req.print || !io::stdin().is_terminal() {
        return Err(refused("this session must be restored from the archive; pass --to DIR to choose where it resumes (required with --print or without a terminal)"));
    }
    let here = utf8_cwd(
        fs::canonicalize(std::env::current_dir().map_err(Error::Io)?).map_err(Error::Io)?,
    )?;
    if let Some(rc) =
        cwd_text(get(meta, "resume_cwd"))?.filter(|c| c.starts_with('/') && Path::new(c).is_dir())
    {
        diagnostics.write(&format!("The session's original directory exists on this host:\n  {rc}\nStarting an agent there loads that directory's project settings and instructions."))?;
        if matches!(
            ask("Resume in that directory? [y/N] ")?
                .to_lowercase()
                .as_str(),
            "y" | "yes"
        ) {
            return utf8_cwd(fs::canonicalize(rc).map_err(Error::Io)?);
        }
    }
    let answer = ask(&format!("Directory to resume in [{}]: ", display(&here)))?;
    if answer.is_empty() {
        return Ok(here);
    }
    let d = expand(Path::new(&answer));
    directory(&d).ok_or_else(|| {
        refused(format!(
            "{} is not a directory",
            display(&codex::absolute(&d))
        ))
    })
}
fn exec_agent(cwd: &Path, sid: &str, agent: &str, req: &ResumeRequest) -> Result<ExitStatus> {
    utf8_cwd(cwd.to_owned())?;
    if !cwd.is_dir() {
        return Err(refused(format!(
            "resume cwd {} does not exist on this host; not resuming from a different directory",
            display(cwd)
        )));
    }
    let mut args = if agent == "codex" {
        vec![if req.fork { "fork" } else { "resume" }, sid]
    } else {
        vec!["--resume", sid]
    };
    if agent == "claude" && req.fork {
        args.push("--fork-session");
    }
    if req.print {
        let cmd = format!(
            "cd {} && {agent} {}\n",
            shell_quote(&display(cwd)),
            args.iter()
                .map(|s| shell_quote(s))
                .collect::<Vec<_>>()
                .join(" ")
        );
        io::stdout().write_all(cmd.as_bytes()).map_err(Error::Io)?;
        return Ok(ExitStatus::Success);
    }
    validate_session_id(&string(sid))?;
    std::env::set_current_dir(cwd).map_err(Error::Io)?;
    let err = exec_path(agent, &args);
    if err.kind() == io::ErrorKind::NotFound {
        Err(refused(format!("{agent} is not on PATH")))
    } else {
        Err(Error::Io(err))
    }
}
// os._execvpe searches PATH with execv; unlike libc execvp it never runs a
// shebang-less executable through /bin/sh after ENOEXEC.
fn exec_path(agent: &str, args: &[&str]) -> io::Error {
    let cstring = |bytes: &[u8]| {
        std::ffi::CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
    };
    let argv: std::result::Result<Vec<_>, _> = std::iter::once(agent)
        .chain(args.iter().copied())
        .map(|s| cstring(s.as_bytes()))
        .collect();
    let argv = match argv {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut pointers: Vec<_> = argv.iter().map(|s| s.as_ptr()).collect();
    pointers.push(std::ptr::null());
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/bin:/usr/bin".into());
    let mut saved = None;
    let mut last = io::Error::from_raw_os_error(libc::ENOENT);
    for dir in std::env::split_paths(&path) {
        let candidate = match cstring(dir.join(agent).as_os_str().as_bytes()) {
            Ok(v) => v,
            Err(e) => return e,
        };
        // SAFETY: path and argv are NUL-terminated, remain live, and argv ends
        // in a null pointer. execv preserves the process environment.
        unsafe {
            libc::execv(candidate.as_ptr(), pointers.as_ptr());
        }
        last = io::Error::last_os_error();
        if !matches!(last.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) && saved.is_none() {
            saved = Some(io::Error::from_raw_os_error(
                last.raw_os_error().unwrap_or(libc::EIO),
            ));
        }
    }
    saved.unwrap_or(last)
}
fn sha(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn archive(api: &mut Api, key: &str, codex: bool) -> Result<Response> {
    let response = api.get_archive(
        "/archive",
        &[("session_key", key)],
        Some(Duration::from_secs(120)),
    )?;
    if !codex && response.status == 409 {
        let data = response.json().unwrap_or(Value::Null);
        if truthy(&data) && !matches!(data, Value::Object(_)) {
            return Err(util::invalid("invalid archive conflict object"));
        }
        let error = get(&data, "error");
        let error = if truthy(error) {
            text(error).unwrap_or_else(|| repr(error))
        } else {
            "conflict".into()
        };
        return Err(refused(format!("archive refused by the server: {error}")));
    }
    if response.status != 200 {
        return Err(refused(format!(
            "archive download answered HTTP {}",
            response.status
        )));
    }
    let want = strip(response.header("X-Archive-Sha256").unwrap_or("")).to_lowercase();
    let got = sha(&response.body);
    if want.len() != 64 || want != got {
        return Err(refused(if codex {
            "archive sha256 mismatch; nothing restored".into()
        } else {
            format!(
                "archive sha256 mismatch (header {}, body {got}); nothing restored",
                if want.is_empty() { "missing" } else { &want }
            )
        }));
    }
    Ok(response)
}
// Adapt the two header-reading differences before tar's entry parser sees them:
// Python accepts signed checksums, and treats a later invalid header as EOF.
// Only headers/extensions are buffered; regular member payloads stay streaming.
struct PythonTar<R> {
    input: R,
    header: [u8; 512],
    position: usize,
    remaining: u64,
    seen: bool,
    done: bool,
    sparse_extensions: bool,
    extension: Option<(bool, u64, Vec<u8>)>,
    global_size: Option<u64>,
    local_size: Option<u64>,
}
impl<R: Read> PythonTar<R> {
    fn new(input: R) -> Self {
        Self {
            input,
            header: [0; 512],
            position: 512,
            remaining: 0,
            seen: false,
            done: false,
            sparse_extensions: false,
            extension: None,
            global_size: None,
            local_size: None,
        }
    }
    fn invalid_header(&mut self, error: io::Error) -> io::Result<usize> {
        if self.seen {
            self.done = true;
            Ok(0)
        } else {
            Err(error)
        }
    }
}
impl<R: Read> Read for PythonTar<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.done {
            return Ok(0);
        }
        loop {
            if self.position < 512 {
                let count = out.len().min(512 - self.position);
                out[..count].copy_from_slice(&self.header[self.position..self.position + count]);
                self.position += count;
                return Ok(count);
            }
            if self.sparse_extensions {
                self.input.read_exact(&mut self.header)?;
                self.sparse_extensions = self.header[504] != 0;
                self.position = 0;
                continue;
            }
            if self.remaining > 0 {
                let count = (out.len() as u64).min(self.remaining) as usize;
                let n = self.input.read(&mut out[..count])?;
                if n == 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                if let Some((_, left, data)) = &mut self.extension {
                    let length = (n as u64).min(*left) as usize;
                    data.extend_from_slice(&out[..length]);
                    *left -= length as u64;
                }
                self.remaining -= n as u64;
                return Ok(n);
            }
            if let Some((global, _, data)) = self.extension.take() {
                // Size overrides affect the physical boundary of the next
                // header. Other PAX attributes are handled by tar/ToolMember.
                let mut rest = data.as_slice();
                while let Some(space) = rest.iter().position(|&b| b == b' ') {
                    let size = std::str::from_utf8(&rest[..space])
                        .ok()
                        .and_then(|s| s.parse::<usize>().ok());
                    let Some(size) = size.filter(|&n| n > space + 1 && n <= rest.len()) else {
                        break;
                    };
                    if let Some(value) = rest[space + 1..size]
                        .strip_prefix(b"size=")
                        .and_then(|s| s.strip_suffix(b"\n"))
                    {
                        let value = std::str::from_utf8(value).ok().and_then(|s| s.parse().ok());
                        if global {
                            self.global_size = value;
                        } else {
                            self.local_size = value;
                        }
                    }
                    rest = &rest[size..];
                }
            }
            let mut filled = 0;
            while filled < self.header.len() {
                let n = self.input.read(&mut self.header[filled..])?;
                if n == 0 {
                    return self.invalid_header(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                filled += n;
            }
            if self.header.iter().all(|&b| b == 0) {
                self.done = true;
                return Ok(0);
            }
            let mut header = tar::Header::new_old();
            header.as_mut_bytes().copy_from_slice(&self.header);
            let fields = header.as_bytes()[..148]
                .iter()
                .chain(&header.as_bytes()[156..]);
            let unsigned = fields.clone().map(|&b| u32::from(b)).sum::<u32>() + 8 * 32;
            let signed = fields.map(|&b| i32::from(b as i8)).sum::<i32>() + 8 * 32;
            let sum = match header.cksum() {
                Ok(v) => v,
                Err(e) => return self.invalid_header(e),
            };
            if sum != unsigned && i64::from(sum) != i64::from(signed) {
                return self.invalid_header(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid tar checksum",
                ));
            }
            let kind = header.entry_type();
            let extension = kind.is_pax_global_extensions()
                || kind.is_pax_local_extensions()
                || kind.is_gnu_longname()
                || kind.is_gnu_longlink();
            if !extension {
                if let Some(size) = self.local_size.take().or(self.global_size) {
                    header.set_size(size);
                }
            }
            let size = match header.entry_size() {
                Ok(v) => v,
                Err(e) => return self.invalid_header(e),
            };
            self.remaining = size
                .checked_add(511)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "tar size overflow"))?
                & !511;
            if kind.is_pax_global_extensions() || kind.is_pax_local_extensions() {
                self.extension = Some((kind.is_pax_global_extensions(), size, Vec::new()));
            }
            self.sparse_extensions = header
                .as_gnu()
                .is_some_and(|g| kind.is_gnu_sparse() && g.is_extended());
            header.set_cksum();
            self.header.copy_from_slice(header.as_bytes());
            self.position = 0;
            self.seen = true;
        }
    }
}
fn tool_input(bytes: &[u8]) -> PythonTar<Box<dyn Read + '_>> {
    let input: Box<dyn Read + '_> = if bytes.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::MultiGzDecoder::new(bytes))
    } else {
        Box::new(bytes)
    };
    PythonTar::new(input)
}
#[derive(Debug, PartialEq)]
struct ToolMember {
    name: String,
    mode: u32,
    mtime: f64,
}
fn tool_member<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    global: &mut std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<Option<ToolMember>> {
    let kind = entry.header().entry_type();
    let mut attributes = global.clone();
    if let Some(fields) = entry.pax_extensions().map_err(Error::Io)? {
        for field in fields {
            let field = field.map_err(Error::Io)?;
            attributes.insert(field.key_bytes().to_vec(), field.value_bytes().to_vec());
        }
    }
    if kind.is_pax_global_extensions() {
        *global = attributes;
        return Ok(None);
    }
    let raw = attributes
        .get(b"path".as_slice())
        .cloned()
        .unwrap_or_else(|| entry.path_bytes().into_owned());
    let mut name = String::from_utf8_lossy(&raw).into_owned();
    if kind.is_dir() {
        name = name.trim_end_matches('/').to_owned();
    }
    if !(kind.is_file() || kind == tar::EntryType::Continuous || kind.is_gnu_sparse())
        || !util::valid_tool_result_name(&name)
    {
        return Err(refused(format!(
            "refusing tool-results archive: unsafe member {}",
            repr(&string(&name))
        )));
    }
    let mut mode = entry.header().mode().map_err(Error::Io)? & 0o755;
    if mode & 0o100 == 0 {
        mode &= !0o111;
    }
    mode |= 0o600;
    let mtime = if let Some(time) = attributes.get(b"mtime".as_slice()) {
        std::str::from_utf8(time)
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0)
    } else if entry.header().as_old().mtime[0] == 0xff {
        // GNU base-256 signed timestamp; Header::mtime exposes only u64.
        entry
            .header()
            .as_old()
            .mtime
            .iter()
            .fold(-1_i128, |time, &byte| (time << 8) | i128::from(byte)) as f64
    } else {
        entry.header().mtime().map_err(Error::Io)? as f64
    };
    Ok(Some(ToolMember { name, mode, mtime }))
}
fn extract_tool_results(bytes: &[u8], dest: &Path) -> Result<()> {
    // The block/end marker distinguishes bzip2 from a valid plain tar filename.
    let bzip2 = bytes.starts_with(b"BZh")
        && matches!(bytes.get(3), Some(b'1'..=b'9'))
        && bytes
            .get(4..10)
            .is_some_and(|magic| magic == b"1AY&SY" || magic == b"\x17rE8P\x90");
    // LZMA-alone has a property byte, little-endian dictionary size, and an
    // uncompressed size (often unknown). It belongs to D11's xz family.
    let plain_tar = bytes.get(..512).is_some_and(|block| {
        let mut header = tar::Header::new_old();
        header.as_mut_bytes().copy_from_slice(block);
        let expected = header.cksum().ok();
        header.set_cksum();
        expected == header.cksum().ok()
    });
    let lzma = !plain_tar
        && bytes.len() >= 13
        && bytes[0] < 225
        && {
            let dictionary = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
            dictionary >= 4096
                && (dictionary.is_power_of_two()
                    || (dictionary % 3 == 0 && (dictionary / 3).is_power_of_two()))
        }
        && (bytes[5..13] == [0xff; 8] || bytes[9..13] == [0; 4]);
    let xz = bytes.starts_with(b"\xfd7zXZ\0") || lzma;
    if bzip2 || xz {
        let kind = if bzip2 { "bzip2" } else { "xz" };
        return Err(refused(format!("refusing tool-results archive: unsupported {kind} compression (only uncompressed and gzip are supported)")));
    }
    ensure_dir(dest, 0o700)?;
    let mut archive = tar::Archive::new(tool_input(bytes));
    let mut global = std::collections::BTreeMap::new();
    let mut files = Vec::new();
    // Validate every header before opening any destination. Dropping an entry
    // lets tar discard its payload with a fixed-size buffer.
    for entry in archive.entries().map_err(Error::Io)? {
        let mut entry = entry.map_err(Error::Io)?;
        if let Some(member) = tool_member(&mut entry, &mut global)? {
            files.push(member);
        }
    }
    let root = fs::canonicalize(dest).map_err(Error::Io)?;
    let mut archive = tar::Archive::new(tool_input(bytes));
    let mut global = std::collections::BTreeMap::new();
    let mut files = files.into_iter();
    for entry in archive.entries().map_err(Error::Io)? {
        let mut entry = entry.map_err(Error::Io)?;
        let Some(member) = tool_member(&mut entry, &mut global)? else {
            continue;
        };
        if files.next().as_ref() != Some(&member) {
            return Err(util::invalid("tar changed between passes"));
        }
        let target = dest.join(&member.name);
        if symlink(&target) && !util::is_within(&target, &root) {
            return Err(util::invalid(
                "tool-results member resolves outside destination",
            ));
        }
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&target)
            .map_err(Error::Io)?;
        io::copy(&mut entry, &mut f).map_err(Error::Io)?;
        f.set_permissions(fs::Permissions::from_mode(member.mode))
            .map_err(Error::Io)?;
        let duration = Duration::try_from_secs_f64(member.mtime.abs())
            .map_err(|_| util::invalid("invalid tar mtime"))?;
        let modified = if member.mtime >= 0.0 {
            UNIX_EPOCH.checked_add(duration)
        } else {
            UNIX_EPOCH.checked_sub(duration)
        }
        .ok_or_else(|| util::invalid("tar mtime out of range"))?;
        f.set_modified(modified).map_err(Error::Io)?;
    }
    Ok(())
}
fn restore_claude(
    api: &mut Api,
    meta: &Value,
    cwd: &Path,
    sid: &str,
    req: &ResumeRequest,
    diagnostics: &Diagnostics,
) -> Result<()> {
    let project = util::encode_cwd(&display(cwd));
    let pdir = util::projects_dir().join(&project);
    let target = pdir.join(format!("{sid}.jsonl"));
    let tmp = pdir.join(format!("{sid}.jsonl.tmp"));
    let response = archive(api, &req.session_key, false)?;
    let tr_dir = pdir.join(sid).join("tool-results");
    for p in [&pdir, &pdir.join(sid), &tr_dir, &target] {
        if symlink(p) {
            return Err(refused(format!(
                "{} is a symlink; refusing to restore through it",
                display(p)
            )));
        }
    }
    let mut data = ccs_pytext::decode_replace(&response.body);
    if let Some(orig) = text(get(meta, "project_dir")).filter(|s| {
        (1..=255).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        // Python's \s includes the four ASCII information separators.
        let pattern = format!(
            r#"(?:/[^\s\x1c-\x1f"'\\]*)?/\.claude/projects/{}/{}/tool-results/"#,
            regex::escape(&orig),
            regex::escape(sid)
        );
        let re =
            regex::Regex::new(&pattern).map_err(|_| util::invalid("invalid rewrite pattern"))?;
        data = re
            .replace_all(
                &data,
                regex::NoExpand(&format!("{}/", display(&tr_dir).trim_end_matches('/'))),
            )
            .into_owned();
    }
    if target.exists()
        && !req.force
        && sha(data.as_bytes()) != sha(&fs::read(&target).map_err(Error::Io)?)
    {
        return Err(refused(format!(
            "{} already exists and differs from the archive; pass --force to replace it",
            display(&target)
        )));
    }
    ensure_dir(&pdir, 0o700)?;
    let result = (|| {
        if fs::symlink_metadata(&tmp).is_ok() {
            fs::remove_file(&tmp).map_err(Error::Io)?;
        }
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
            .map_err(Error::Io)?;
        f.write_all(data.as_bytes()).map_err(Error::Io)?;
        drop(f);
        let tools = api.get_archive(
            "/archive/tool-results",
            &[("session_key", req.session_key.as_str())],
            Some(Duration::from_secs(120)),
        )?;
        if tools.status == 200 && !tools.body.is_empty() {
            extract_tool_results(&tools.body, &tr_dir)?;
        } else if !matches!(tools.status, 200 | 404) {
            return Err(refused(format!(
                "tool-results download answered HTTP {}",
                tools.status
            )));
        }
        fs::rename(&tmp, &target).map_err(Error::Io)
    })();
    if fs::symlink_metadata(&tmp).is_ok() {
        fs::remove_file(&tmp).map_err(Error::Io)?;
    }
    result?;
    record_restore(sid, &project, cwd)?;
    diagnostics.write(RESTORED_NOTE)?;
    Ok(())
}
fn display_event(rec: &Value) -> bool {
    is(get(rec, "type"), "event_msg")
        && ["user_message", "agent_message"]
            .iter()
            .any(|s| is(get(get(rec, "payload"), "type"), s))
}
fn codex_records(bytes: &[u8], sid: &str, cwd: &Path) -> Result<String> {
    let invalid = || refused("invalid Codex archive; nothing restored");
    let records: Vec<_> = bytes
        .split(|&b| b == b'\n')
        .filter(|b| b.iter().any(|c| !b" \t\n\r\x0b\x0c".contains(c)))
        .map(|b| {
            std::str::from_utf8(b)
                .map_err(|_| invalid())
                .and_then(|s| extract::loads_strict(s).map_err(|_| invalid()))
        })
        .collect::<Result<_>>()?;
    let first = records.first().ok_or_else(invalid)?;
    let payload = get(first, "payload");
    if !is(get(first, "type"), "session_meta") || !is(get(payload, "id"), sid) {
        return Err(invalid());
    }
    let rebuild = is(get(payload, "history_mode"), "paginated");
    let has_display = records.iter().any(display_event);
    let mut state = session_codex::IndexState::new(string(sid), None);
    let mut own_start = None;
    let mut lines = Vec::new();
    for (index, mut rec) in records.into_iter().enumerate() {
        if !matches!(rec, Value::Object(_)) {
            return Err(invalid());
        }
        let owned = state.accept(&rec);
        if index > 0 && owned && own_start.is_none() {
            own_start = Some(lines.len());
        }
        let kind = get(&rec, "type");
        let payload = get(&rec, "payload");
        if (index > 0 && is(kind, "session_meta"))
            || is(kind, "turn_context")
            || is(kind, "world_state")
            || (is(kind, "event_msg") && is(get(payload, "type"), "thread_settings_applied"))
            || (rebuild && display_event(&rec))
        {
            continue;
        }
        if is(kind, "session_meta") {
            let mut p = payload.clone();
            set(&mut p, "cwd", string(display(cwd)));
            set(&mut p, "session_id", string(sid));
            set(&mut p, "history_mode", string("legacy"));
            set(
                &mut p,
                "runtime_workspace_roots",
                Value::Array(vec![string(display(cwd))]),
            );
            set(&mut rec, "payload", p);
        }
        let payload = get(&rec, "payload");
        if (rebuild || !has_display)
            && is(get(&rec, "type"), "response_item")
            && is(get(payload, "type"), "message")
            && (is(get(payload, "role"), "user") || is(get(payload, "role"), "assistant"))
            && !is(get(payload, "channel"), "analysis")
        {
            let common = session_codex::normalize(&rec).map_err(|_| invalid())?;
            let mut points = Vec::new();
            if let Value::Array(content) = get(get(&common, "message"), "content") {
                for (i, block) in content.iter().enumerate() {
                    if i > 0 {
                        points.push(10);
                    }
                    if let Value::String(s) = get(block, "text") {
                        points.extend_from_slice(s);
                    }
                }
            }
            if !points.is_empty() {
                lines.push(object([
                    ("type", string("event_msg")),
                    ("timestamp", get(&rec, "timestamp").clone()),
                    (
                        "payload",
                        object([
                            (
                                "type",
                                string(if is(get(payload, "role"), "user") {
                                    "user_message"
                                } else {
                                    "agent_message"
                                }),
                            ),
                            ("message", Value::String(points)),
                            ("images", Value::Array(vec![])),
                            ("local_images", Value::Array(vec![])),
                            ("text_elements", Value::Array(vec![])),
                        ]),
                    ),
                ]));
            }
        }
        lines.push(rec);
    }
    let count = lines.len();
    let mut payload = get(&lines[0], "payload").clone();
    if truthy(get(&payload, "forked_from_id"))
        || has(&payload, "subagent_history_start_ordinal")
        || has(&payload, "ccs_index_start_ordinal")
    {
        let start = number(own_start.unwrap_or(count));
        set(&mut payload, "ccs_index_start_ordinal", start.clone());
        if has(&payload, "subagent_history_start_ordinal") {
            set(&mut payload, "subagent_history_start_ordinal", start);
        }
        set(&mut lines[0], "payload", payload);
    }
    let mut data = String::new();
    for (ordinal, mut rec) in lines.into_iter().enumerate() {
        set(&mut rec, "ordinal", number(ordinal));
        data.push_str(
            &json::dumps_compact(&rec, false, false)
                .map_err(|_| util::invalid("Codex archive cannot be encoded"))?,
        );
        data.push('\n');
    }
    Ok(data)
}
fn restore_codex(
    api: &mut Api,
    cwd: &Path,
    sid: &str,
    req: &ResumeRequest,
    diagnostics: &Diagnostics,
) -> Result<()> {
    let response = archive(api, &req.session_key, true)?;
    let data = codex_records(&response.body, sid, cwd)?;
    let stamp = util::iso(util::now_epoch());
    let root = codex::sessions_dir();
    let target = codex::find_local(sid, None).unwrap_or_else(|| {
        root.join(&stamp[..4])
            .join(&stamp[5..7])
            .join(&stamp[8..10])
            .join(format!(
                "rollout-{}-{sid}.jsonl",
                stamp[..19].replace(':', "-")
            ))
    });
    let pdir = target
        .parent()
        .ok_or_else(|| util::invalid("restore target has no parent"))?;
    let mut check = pdir;
    loop {
        if symlink(check) {
            return Err(refused(format!(
                "{} is a symlink; refusing to restore through it",
                display(check)
            )));
        }
        if check == root {
            break;
        }
        check = check
            .parent()
            .ok_or_else(|| util::invalid("restore target outside sessions root"))?;
    }
    if let Ok(st) = fs::symlink_metadata(&target) {
        if st.file_type().is_symlink() || !st.is_file() {
            return Err(refused("unsafe Codex restore target"));
        }
        if !req.force && sha(&fs::read(&target).map_err(Error::Io)?) != sha(data.as_bytes()) {
            return Err(refused(format!(
                "{} already exists and differs from the archive; pass --force to replace it",
                display(&target)
            )));
        }
    }
    ensure_dir(pdir, 0o700)?;
    util::atomic_write(&target, &data, 0o600)?;
    diagnostics.write(RESTORED_NOTE)?;
    Ok(())
}
fn resume_inner(req: &ResumeRequest, diagnostics: &Diagnostics) -> Result<ExitStatus> {
    let to = req.to_dir.as_deref();
    if let Some(raw_path) = req.session_key.strip_prefix("local:") {
        let path = Path::new(raw_path);
        if codex::is_path(path) {
            let info = codex::classify(path)
                .ok_or_else(|| refused("local Codex transcript is missing or unsafe"))?;
            let sid = validate_session_id(get(&info, "session_id"))?;
            return exec_agent(&codex_resume_cwd(path, to)?, &sid, "codex", req);
        }
        let name = raw_path.rsplit('/').next().unwrap_or("");
        let sid = validate_session_id(&string(name.strip_suffix(".jsonl").unwrap_or("")))?;
        if !local_jsonl_ok(path, &sid) {
            return Err(refused(format!(
                "local transcript {} no longer exists or is not a plain file under {}",
                display(path),
                display(&util::projects_dir())
            )));
        }
        return exec_agent(&local_resume_cwd(path, to)?, &sid, "claude", req);
    }
    let cfg = Config::load(None).map_err(|e| match e {
        Error::Usage(s) | Error::Unavailable(s) => Error::Unavailable(s),
        other => other,
    })?;
    let host = cfg.host_label.clone();
    let mut api = Api::new(cfg);
    let response = api
        .get(
            "/preview",
            &[("session_key", req.session_key.as_str()), ("q", "")],
            Some(Duration::from_secs(10)),
        )
        .map_err(|e| match e {
            Error::Unavailable(s) => Error::Unavailable(format!("server unreachable: {s}")),
            e => e,
        })?;
    if response.status == 404 {
        return Err(refused(format!("unknown session_key {}", req.session_key)));
    }
    if response.status != 200 {
        return Err(Error::Unavailable(format!(
            "preview answered HTTP {}",
            response.status
        )));
    }
    let value = response.json().unwrap_or(Value::Null);
    if truthy(&value) && !matches!(value, Value::Object(_)) {
        return Err(util::invalid("invalid preview object"));
    }
    let meta = get(&value, "session");
    if truthy(meta) && !matches!(meta, Value::Object(_)) {
        return Err(util::invalid("invalid session object"));
    }
    let sid = validate_session_id(get(meta, "session_id"))?;
    let agent = if text(get(meta, "entrypoint")).is_some_and(|e| e.starts_with("codex-")) {
        "codex"
    } else {
        "claude"
    };
    if is(get(meta, "host"), &host) {
        let hint = text(get(meta, "jsonl_path")).map(PathBuf::from);
        let local = if agent == "codex" {
            codex::find_local(&sid, hint.as_deref())
        } else {
            find_local_jsonl(&sid, hint.as_deref())
        };
        if let Some(local) = local {
            let cwd = if agent == "codex" {
                codex_resume_cwd(&local, to)?
            } else {
                local_resume_cwd(&local, to)?
            };
            return exec_agent(&cwd, &sid, agent, req);
        }
    }
    if truthy(get(meta, "archived")) && truthy(get(meta, "archive_complete")) {
        let cwd = choose_restore_cwd(meta, req, diagnostics)?;
        let result = if agent == "codex" {
            restore_codex(&mut api, &cwd, &sid, req, diagnostics)
        } else {
            restore_claude(&mut api, meta, &cwd, &sid, req, diagnostics)
        };
        result.map_err(|e| match e {
            Error::Unavailable(s)
                if s.starts_with("token ") || s == "client secret unreadable or empty" =>
            {
                util::invalid("archive response or authentication failed")
            }
            Error::Unavailable(s) => Error::Unavailable(format!("server unreachable: {s}")),
            e => e,
        })?;
        return exec_agent(&cwd, &sid, agent, req);
    }
    // Mirrors picker.view_only_reason without coupling this boundary to its UI.
    let reason = if is(get(meta, "host"), &host) && truthy(get(meta, "jsonl_exists")) {
        "not resumable"
    } else if truthy(get(meta, "archived")) {
        "archive incomplete"
    } else if is(get(meta, "kind"), "subagent") || truthy(get(meta, "is_sidechain")) {
        "not archived (subagent)"
    } else {
        "not archived"
    };
    Err(refused(format!("view-only: {reason}")))
}

/// Python `resume.resume`. Successful exec replaces this process.
pub fn resume(request: &ResumeRequest) -> Result<ExitStatus> {
    let diagnostics = Diagnostics::capture();
    match resume_inner(request, &diagnostics) {
        Err(error) if crate::token::is_credential_error(&error) => {
            Err(util::invalid("credential error"))
        }
        Err(e @ (Error::ResumePrecondition(_) | Error::Unavailable(_))) => {
            if let Error::ResumePrecondition(message) | Error::Unavailable(message) = &e {
                diagnostics.write(&format!("ccs: {message}"))?;
            }
            Ok(e.exit_status())
        }
        result => result,
    }
}

pub fn run(_config: &Value, request: &Value) -> Result<Value> {
    let status = resume(&ResumeRequest {
        session_key: text(get(request, "session_key")).unwrap_or_default(),
        print: truthy(get(request, "print")),
        fork: truthy(get(request, "fork")),
        to_dir: text(get(request, "to_dir")).map(PathBuf::from),
        force: truthy(get(request, "force")),
    })?;
    Ok(number(status.code()))
}

// BEGIN PYTHON NONPRINTABLE
// Generated by tests/resume_printable.py; Python 3.13.5 / Unicode 15.1.0.
const NONPRINTABLE: &[(u32, u32)] = &[
    (0x0, 0x1f),
    (0x7f, 0xa0),
    (0xad, 0xad),
    (0x378, 0x379),
    (0x380, 0x383),
    (0x38b, 0x38b),
    (0x38d, 0x38d),
    (0x3a2, 0x3a2),
    (0x530, 0x530),
    (0x557, 0x558),
    (0x58b, 0x58c),
    (0x590, 0x590),
    (0x5c8, 0x5cf),
    (0x5eb, 0x5ee),
    (0x5f5, 0x605),
    (0x61c, 0x61c),
    (0x6dd, 0x6dd),
    (0x70e, 0x70f),
    (0x74b, 0x74c),
    (0x7b2, 0x7bf),
    (0x7fb, 0x7fc),
    (0x82e, 0x82f),
    (0x83f, 0x83f),
    (0x85c, 0x85d),
    (0x85f, 0x85f),
    (0x86b, 0x86f),
    (0x88f, 0x897),
    (0x8e2, 0x8e2),
    (0x984, 0x984),
    (0x98d, 0x98e),
    (0x991, 0x992),
    (0x9a9, 0x9a9),
    (0x9b1, 0x9b1),
    (0x9b3, 0x9b5),
    (0x9ba, 0x9bb),
    (0x9c5, 0x9c6),
    (0x9c9, 0x9ca),
    (0x9cf, 0x9d6),
    (0x9d8, 0x9db),
    (0x9de, 0x9de),
    (0x9e4, 0x9e5),
    (0x9ff, 0xa00),
    (0xa04, 0xa04),
    (0xa0b, 0xa0e),
    (0xa11, 0xa12),
    (0xa29, 0xa29),
    (0xa31, 0xa31),
    (0xa34, 0xa34),
    (0xa37, 0xa37),
    (0xa3a, 0xa3b),
    (0xa3d, 0xa3d),
    (0xa43, 0xa46),
    (0xa49, 0xa4a),
    (0xa4e, 0xa50),
    (0xa52, 0xa58),
    (0xa5d, 0xa5d),
    (0xa5f, 0xa65),
    (0xa77, 0xa80),
    (0xa84, 0xa84),
    (0xa8e, 0xa8e),
    (0xa92, 0xa92),
    (0xaa9, 0xaa9),
    (0xab1, 0xab1),
    (0xab4, 0xab4),
    (0xaba, 0xabb),
    (0xac6, 0xac6),
    (0xaca, 0xaca),
    (0xace, 0xacf),
    (0xad1, 0xadf),
    (0xae4, 0xae5),
    (0xaf2, 0xaf8),
    (0xb00, 0xb00),
    (0xb04, 0xb04),
    (0xb0d, 0xb0e),
    (0xb11, 0xb12),
    (0xb29, 0xb29),
    (0xb31, 0xb31),
    (0xb34, 0xb34),
    (0xb3a, 0xb3b),
    (0xb45, 0xb46),
    (0xb49, 0xb4a),
    (0xb4e, 0xb54),
    (0xb58, 0xb5b),
    (0xb5e, 0xb5e),
    (0xb64, 0xb65),
    (0xb78, 0xb81),
    (0xb84, 0xb84),
    (0xb8b, 0xb8d),
    (0xb91, 0xb91),
    (0xb96, 0xb98),
    (0xb9b, 0xb9b),
    (0xb9d, 0xb9d),
    (0xba0, 0xba2),
    (0xba5, 0xba7),
    (0xbab, 0xbad),
    (0xbba, 0xbbd),
    (0xbc3, 0xbc5),
    (0xbc9, 0xbc9),
    (0xbce, 0xbcf),
    (0xbd1, 0xbd6),
    (0xbd8, 0xbe5),
    (0xbfb, 0xbff),
    (0xc0d, 0xc0d),
    (0xc11, 0xc11),
    (0xc29, 0xc29),
    (0xc3a, 0xc3b),
    (0xc45, 0xc45),
    (0xc49, 0xc49),
    (0xc4e, 0xc54),
    (0xc57, 0xc57),
    (0xc5b, 0xc5c),
    (0xc5e, 0xc5f),
    (0xc64, 0xc65),
    (0xc70, 0xc76),
    (0xc8d, 0xc8d),
    (0xc91, 0xc91),
    (0xca9, 0xca9),
    (0xcb4, 0xcb4),
    (0xcba, 0xcbb),
    (0xcc5, 0xcc5),
    (0xcc9, 0xcc9),
    (0xcce, 0xcd4),
    (0xcd7, 0xcdc),
    (0xcdf, 0xcdf),
    (0xce4, 0xce5),
    (0xcf0, 0xcf0),
    (0xcf4, 0xcff),
    (0xd0d, 0xd0d),
    (0xd11, 0xd11),
    (0xd45, 0xd45),
    (0xd49, 0xd49),
    (0xd50, 0xd53),
    (0xd64, 0xd65),
    (0xd80, 0xd80),
    (0xd84, 0xd84),
    (0xd97, 0xd99),
    (0xdb2, 0xdb2),
    (0xdbc, 0xdbc),
    (0xdbe, 0xdbf),
    (0xdc7, 0xdc9),
    (0xdcb, 0xdce),
    (0xdd5, 0xdd5),
    (0xdd7, 0xdd7),
    (0xde0, 0xde5),
    (0xdf0, 0xdf1),
    (0xdf5, 0xe00),
    (0xe3b, 0xe3e),
    (0xe5c, 0xe80),
    (0xe83, 0xe83),
    (0xe85, 0xe85),
    (0xe8b, 0xe8b),
    (0xea4, 0xea4),
    (0xea6, 0xea6),
    (0xebe, 0xebf),
    (0xec5, 0xec5),
    (0xec7, 0xec7),
    (0xecf, 0xecf),
    (0xeda, 0xedb),
    (0xee0, 0xeff),
    (0xf48, 0xf48),
    (0xf6d, 0xf70),
    (0xf98, 0xf98),
    (0xfbd, 0xfbd),
    (0xfcd, 0xfcd),
    (0xfdb, 0xfff),
    (0x10c6, 0x10c6),
    (0x10c8, 0x10cc),
    (0x10ce, 0x10cf),
    (0x1249, 0x1249),
    (0x124e, 0x124f),
    (0x1257, 0x1257),
    (0x1259, 0x1259),
    (0x125e, 0x125f),
    (0x1289, 0x1289),
    (0x128e, 0x128f),
    (0x12b1, 0x12b1),
    (0x12b6, 0x12b7),
    (0x12bf, 0x12bf),
    (0x12c1, 0x12c1),
    (0x12c6, 0x12c7),
    (0x12d7, 0x12d7),
    (0x1311, 0x1311),
    (0x1316, 0x1317),
    (0x135b, 0x135c),
    (0x137d, 0x137f),
    (0x139a, 0x139f),
    (0x13f6, 0x13f7),
    (0x13fe, 0x13ff),
    (0x1680, 0x1680),
    (0x169d, 0x169f),
    (0x16f9, 0x16ff),
    (0x1716, 0x171e),
    (0x1737, 0x173f),
    (0x1754, 0x175f),
    (0x176d, 0x176d),
    (0x1771, 0x1771),
    (0x1774, 0x177f),
    (0x17de, 0x17df),
    (0x17ea, 0x17ef),
    (0x17fa, 0x17ff),
    (0x180e, 0x180e),
    (0x181a, 0x181f),
    (0x1879, 0x187f),
    (0x18ab, 0x18af),
    (0x18f6, 0x18ff),
    (0x191f, 0x191f),
    (0x192c, 0x192f),
    (0x193c, 0x193f),
    (0x1941, 0x1943),
    (0x196e, 0x196f),
    (0x1975, 0x197f),
    (0x19ac, 0x19af),
    (0x19ca, 0x19cf),
    (0x19db, 0x19dd),
    (0x1a1c, 0x1a1d),
    (0x1a5f, 0x1a5f),
    (0x1a7d, 0x1a7e),
    (0x1a8a, 0x1a8f),
    (0x1a9a, 0x1a9f),
    (0x1aae, 0x1aaf),
    (0x1acf, 0x1aff),
    (0x1b4d, 0x1b4f),
    (0x1b7f, 0x1b7f),
    (0x1bf4, 0x1bfb),
    (0x1c38, 0x1c3a),
    (0x1c4a, 0x1c4c),
    (0x1c89, 0x1c8f),
    (0x1cbb, 0x1cbc),
    (0x1cc8, 0x1ccf),
    (0x1cfb, 0x1cff),
    (0x1f16, 0x1f17),
    (0x1f1e, 0x1f1f),
    (0x1f46, 0x1f47),
    (0x1f4e, 0x1f4f),
    (0x1f58, 0x1f58),
    (0x1f5a, 0x1f5a),
    (0x1f5c, 0x1f5c),
    (0x1f5e, 0x1f5e),
    (0x1f7e, 0x1f7f),
    (0x1fb5, 0x1fb5),
    (0x1fc5, 0x1fc5),
    (0x1fd4, 0x1fd5),
    (0x1fdc, 0x1fdc),
    (0x1ff0, 0x1ff1),
    (0x1ff5, 0x1ff5),
    (0x1fff, 0x200f),
    (0x2028, 0x202f),
    (0x205f, 0x206f),
    (0x2072, 0x2073),
    (0x208f, 0x208f),
    (0x209d, 0x209f),
    (0x20c1, 0x20cf),
    (0x20f1, 0x20ff),
    (0x218c, 0x218f),
    (0x2427, 0x243f),
    (0x244b, 0x245f),
    (0x2b74, 0x2b75),
    (0x2b96, 0x2b96),
    (0x2cf4, 0x2cf8),
    (0x2d26, 0x2d26),
    (0x2d28, 0x2d2c),
    (0x2d2e, 0x2d2f),
    (0x2d68, 0x2d6e),
    (0x2d71, 0x2d7e),
    (0x2d97, 0x2d9f),
    (0x2da7, 0x2da7),
    (0x2daf, 0x2daf),
    (0x2db7, 0x2db7),
    (0x2dbf, 0x2dbf),
    (0x2dc7, 0x2dc7),
    (0x2dcf, 0x2dcf),
    (0x2dd7, 0x2dd7),
    (0x2ddf, 0x2ddf),
    (0x2e5e, 0x2e7f),
    (0x2e9a, 0x2e9a),
    (0x2ef4, 0x2eff),
    (0x2fd6, 0x2fef),
    (0x3000, 0x3000),
    (0x3040, 0x3040),
    (0x3097, 0x3098),
    (0x3100, 0x3104),
    (0x3130, 0x3130),
    (0x318f, 0x318f),
    (0x31e4, 0x31ee),
    (0x321f, 0x321f),
    (0xa48d, 0xa48f),
    (0xa4c7, 0xa4cf),
    (0xa62c, 0xa63f),
    (0xa6f8, 0xa6ff),
    (0xa7cb, 0xa7cf),
    (0xa7d2, 0xa7d2),
    (0xa7d4, 0xa7d4),
    (0xa7da, 0xa7f1),
    (0xa82d, 0xa82f),
    (0xa83a, 0xa83f),
    (0xa878, 0xa87f),
    (0xa8c6, 0xa8cd),
    (0xa8da, 0xa8df),
    (0xa954, 0xa95e),
    (0xa97d, 0xa97f),
    (0xa9ce, 0xa9ce),
    (0xa9da, 0xa9dd),
    (0xa9ff, 0xa9ff),
    (0xaa37, 0xaa3f),
    (0xaa4e, 0xaa4f),
    (0xaa5a, 0xaa5b),
    (0xaac3, 0xaada),
    (0xaaf7, 0xab00),
    (0xab07, 0xab08),
    (0xab0f, 0xab10),
    (0xab17, 0xab1f),
    (0xab27, 0xab27),
    (0xab2f, 0xab2f),
    (0xab6c, 0xab6f),
    (0xabee, 0xabef),
    (0xabfa, 0xabff),
    (0xd7a4, 0xd7af),
    (0xd7c7, 0xd7ca),
    (0xd7fc, 0xf8ff),
    (0xfa6e, 0xfa6f),
    (0xfada, 0xfaff),
    (0xfb07, 0xfb12),
    (0xfb18, 0xfb1c),
    (0xfb37, 0xfb37),
    (0xfb3d, 0xfb3d),
    (0xfb3f, 0xfb3f),
    (0xfb42, 0xfb42),
    (0xfb45, 0xfb45),
    (0xfbc3, 0xfbd2),
    (0xfd90, 0xfd91),
    (0xfdc8, 0xfdce),
    (0xfdd0, 0xfdef),
    (0xfe1a, 0xfe1f),
    (0xfe53, 0xfe53),
    (0xfe67, 0xfe67),
    (0xfe6c, 0xfe6f),
    (0xfe75, 0xfe75),
    (0xfefd, 0xff00),
    (0xffbf, 0xffc1),
    (0xffc8, 0xffc9),
    (0xffd0, 0xffd1),
    (0xffd8, 0xffd9),
    (0xffdd, 0xffdf),
    (0xffe7, 0xffe7),
    (0xffef, 0xfffb),
    (0xfffe, 0xffff),
    (0x1000c, 0x1000c),
    (0x10027, 0x10027),
    (0x1003b, 0x1003b),
    (0x1003e, 0x1003e),
    (0x1004e, 0x1004f),
    (0x1005e, 0x1007f),
    (0x100fb, 0x100ff),
    (0x10103, 0x10106),
    (0x10134, 0x10136),
    (0x1018f, 0x1018f),
    (0x1019d, 0x1019f),
    (0x101a1, 0x101cf),
    (0x101fe, 0x1027f),
    (0x1029d, 0x1029f),
    (0x102d1, 0x102df),
    (0x102fc, 0x102ff),
    (0x10324, 0x1032c),
    (0x1034b, 0x1034f),
    (0x1037b, 0x1037f),
    (0x1039e, 0x1039e),
    (0x103c4, 0x103c7),
    (0x103d6, 0x103ff),
    (0x1049e, 0x1049f),
    (0x104aa, 0x104af),
    (0x104d4, 0x104d7),
    (0x104fc, 0x104ff),
    (0x10528, 0x1052f),
    (0x10564, 0x1056e),
    (0x1057b, 0x1057b),
    (0x1058b, 0x1058b),
    (0x10593, 0x10593),
    (0x10596, 0x10596),
    (0x105a2, 0x105a2),
    (0x105b2, 0x105b2),
    (0x105ba, 0x105ba),
    (0x105bd, 0x105ff),
    (0x10737, 0x1073f),
    (0x10756, 0x1075f),
    (0x10768, 0x1077f),
    (0x10786, 0x10786),
    (0x107b1, 0x107b1),
    (0x107bb, 0x107ff),
    (0x10806, 0x10807),
    (0x10809, 0x10809),
    (0x10836, 0x10836),
    (0x10839, 0x1083b),
    (0x1083d, 0x1083e),
    (0x10856, 0x10856),
    (0x1089f, 0x108a6),
    (0x108b0, 0x108df),
    (0x108f3, 0x108f3),
    (0x108f6, 0x108fa),
    (0x1091c, 0x1091e),
    (0x1093a, 0x1093e),
    (0x10940, 0x1097f),
    (0x109b8, 0x109bb),
    (0x109d0, 0x109d1),
    (0x10a04, 0x10a04),
    (0x10a07, 0x10a0b),
    (0x10a14, 0x10a14),
    (0x10a18, 0x10a18),
    (0x10a36, 0x10a37),
    (0x10a3b, 0x10a3e),
    (0x10a49, 0x10a4f),
    (0x10a59, 0x10a5f),
    (0x10aa0, 0x10abf),
    (0x10ae7, 0x10aea),
    (0x10af7, 0x10aff),
    (0x10b36, 0x10b38),
    (0x10b56, 0x10b57),
    (0x10b73, 0x10b77),
    (0x10b92, 0x10b98),
    (0x10b9d, 0x10ba8),
    (0x10bb0, 0x10bff),
    (0x10c49, 0x10c7f),
    (0x10cb3, 0x10cbf),
    (0x10cf3, 0x10cf9),
    (0x10d28, 0x10d2f),
    (0x10d3a, 0x10e5f),
    (0x10e7f, 0x10e7f),
    (0x10eaa, 0x10eaa),
    (0x10eae, 0x10eaf),
    (0x10eb2, 0x10efc),
    (0x10f28, 0x10f2f),
    (0x10f5a, 0x10f6f),
    (0x10f8a, 0x10faf),
    (0x10fcc, 0x10fdf),
    (0x10ff7, 0x10fff),
    (0x1104e, 0x11051),
    (0x11076, 0x1107e),
    (0x110bd, 0x110bd),
    (0x110c3, 0x110cf),
    (0x110e9, 0x110ef),
    (0x110fa, 0x110ff),
    (0x11135, 0x11135),
    (0x11148, 0x1114f),
    (0x11177, 0x1117f),
    (0x111e0, 0x111e0),
    (0x111f5, 0x111ff),
    (0x11212, 0x11212),
    (0x11242, 0x1127f),
    (0x11287, 0x11287),
    (0x11289, 0x11289),
    (0x1128e, 0x1128e),
    (0x1129e, 0x1129e),
    (0x112aa, 0x112af),
    (0x112eb, 0x112ef),
    (0x112fa, 0x112ff),
    (0x11304, 0x11304),
    (0x1130d, 0x1130e),
    (0x11311, 0x11312),
    (0x11329, 0x11329),
    (0x11331, 0x11331),
    (0x11334, 0x11334),
    (0x1133a, 0x1133a),
    (0x11345, 0x11346),
    (0x11349, 0x1134a),
    (0x1134e, 0x1134f),
    (0x11351, 0x11356),
    (0x11358, 0x1135c),
    (0x11364, 0x11365),
    (0x1136d, 0x1136f),
    (0x11375, 0x113ff),
    (0x1145c, 0x1145c),
    (0x11462, 0x1147f),
    (0x114c8, 0x114cf),
    (0x114da, 0x1157f),
    (0x115b6, 0x115b7),
    (0x115de, 0x115ff),
    (0x11645, 0x1164f),
    (0x1165a, 0x1165f),
    (0x1166d, 0x1167f),
    (0x116ba, 0x116bf),
    (0x116ca, 0x116ff),
    (0x1171b, 0x1171c),
    (0x1172c, 0x1172f),
    (0x11747, 0x117ff),
    (0x1183c, 0x1189f),
    (0x118f3, 0x118fe),
    (0x11907, 0x11908),
    (0x1190a, 0x1190b),
    (0x11914, 0x11914),
    (0x11917, 0x11917),
    (0x11936, 0x11936),
    (0x11939, 0x1193a),
    (0x11947, 0x1194f),
    (0x1195a, 0x1199f),
    (0x119a8, 0x119a9),
    (0x119d8, 0x119d9),
    (0x119e5, 0x119ff),
    (0x11a48, 0x11a4f),
    (0x11aa3, 0x11aaf),
    (0x11af9, 0x11aff),
    (0x11b0a, 0x11bff),
    (0x11c09, 0x11c09),
    (0x11c37, 0x11c37),
    (0x11c46, 0x11c4f),
    (0x11c6d, 0x11c6f),
    (0x11c90, 0x11c91),
    (0x11ca8, 0x11ca8),
    (0x11cb7, 0x11cff),
    (0x11d07, 0x11d07),
    (0x11d0a, 0x11d0a),
    (0x11d37, 0x11d39),
    (0x11d3b, 0x11d3b),
    (0x11d3e, 0x11d3e),
    (0x11d48, 0x11d4f),
    (0x11d5a, 0x11d5f),
    (0x11d66, 0x11d66),
    (0x11d69, 0x11d69),
    (0x11d8f, 0x11d8f),
    (0x11d92, 0x11d92),
    (0x11d99, 0x11d9f),
    (0x11daa, 0x11edf),
    (0x11ef9, 0x11eff),
    (0x11f11, 0x11f11),
    (0x11f3b, 0x11f3d),
    (0x11f5a, 0x11faf),
    (0x11fb1, 0x11fbf),
    (0x11ff2, 0x11ffe),
    (0x1239a, 0x123ff),
    (0x1246f, 0x1246f),
    (0x12475, 0x1247f),
    (0x12544, 0x12f8f),
    (0x12ff3, 0x12fff),
    (0x13430, 0x1343f),
    (0x13456, 0x143ff),
    (0x14647, 0x167ff),
    (0x16a39, 0x16a3f),
    (0x16a5f, 0x16a5f),
    (0x16a6a, 0x16a6d),
    (0x16abf, 0x16abf),
    (0x16aca, 0x16acf),
    (0x16aee, 0x16aef),
    (0x16af6, 0x16aff),
    (0x16b46, 0x16b4f),
    (0x16b5a, 0x16b5a),
    (0x16b62, 0x16b62),
    (0x16b78, 0x16b7c),
    (0x16b90, 0x16e3f),
    (0x16e9b, 0x16eff),
    (0x16f4b, 0x16f4e),
    (0x16f88, 0x16f8e),
    (0x16fa0, 0x16fdf),
    (0x16fe5, 0x16fef),
    (0x16ff2, 0x16fff),
    (0x187f8, 0x187ff),
    (0x18cd6, 0x18cff),
    (0x18d09, 0x1afef),
    (0x1aff4, 0x1aff4),
    (0x1affc, 0x1affc),
    (0x1afff, 0x1afff),
    (0x1b123, 0x1b131),
    (0x1b133, 0x1b14f),
    (0x1b153, 0x1b154),
    (0x1b156, 0x1b163),
    (0x1b168, 0x1b16f),
    (0x1b2fc, 0x1bbff),
    (0x1bc6b, 0x1bc6f),
    (0x1bc7d, 0x1bc7f),
    (0x1bc89, 0x1bc8f),
    (0x1bc9a, 0x1bc9b),
    (0x1bca0, 0x1ceff),
    (0x1cf2e, 0x1cf2f),
    (0x1cf47, 0x1cf4f),
    (0x1cfc4, 0x1cfff),
    (0x1d0f6, 0x1d0ff),
    (0x1d127, 0x1d128),
    (0x1d173, 0x1d17a),
    (0x1d1eb, 0x1d1ff),
    (0x1d246, 0x1d2bf),
    (0x1d2d4, 0x1d2df),
    (0x1d2f4, 0x1d2ff),
    (0x1d357, 0x1d35f),
    (0x1d379, 0x1d3ff),
    (0x1d455, 0x1d455),
    (0x1d49d, 0x1d49d),
    (0x1d4a0, 0x1d4a1),
    (0x1d4a3, 0x1d4a4),
    (0x1d4a7, 0x1d4a8),
    (0x1d4ad, 0x1d4ad),
    (0x1d4ba, 0x1d4ba),
    (0x1d4bc, 0x1d4bc),
    (0x1d4c4, 0x1d4c4),
    (0x1d506, 0x1d506),
    (0x1d50b, 0x1d50c),
    (0x1d515, 0x1d515),
    (0x1d51d, 0x1d51d),
    (0x1d53a, 0x1d53a),
    (0x1d53f, 0x1d53f),
    (0x1d545, 0x1d545),
    (0x1d547, 0x1d549),
    (0x1d551, 0x1d551),
    (0x1d6a6, 0x1d6a7),
    (0x1d7cc, 0x1d7cd),
    (0x1da8c, 0x1da9a),
    (0x1daa0, 0x1daa0),
    (0x1dab0, 0x1deff),
    (0x1df1f, 0x1df24),
    (0x1df2b, 0x1dfff),
    (0x1e007, 0x1e007),
    (0x1e019, 0x1e01a),
    (0x1e022, 0x1e022),
    (0x1e025, 0x1e025),
    (0x1e02b, 0x1e02f),
    (0x1e06e, 0x1e08e),
    (0x1e090, 0x1e0ff),
    (0x1e12d, 0x1e12f),
    (0x1e13e, 0x1e13f),
    (0x1e14a, 0x1e14d),
    (0x1e150, 0x1e28f),
    (0x1e2af, 0x1e2bf),
    (0x1e2fa, 0x1e2fe),
    (0x1e300, 0x1e4cf),
    (0x1e4fa, 0x1e7df),
    (0x1e7e7, 0x1e7e7),
    (0x1e7ec, 0x1e7ec),
    (0x1e7ef, 0x1e7ef),
    (0x1e7ff, 0x1e7ff),
    (0x1e8c5, 0x1e8c6),
    (0x1e8d7, 0x1e8ff),
    (0x1e94c, 0x1e94f),
    (0x1e95a, 0x1e95d),
    (0x1e960, 0x1ec70),
    (0x1ecb5, 0x1ed00),
    (0x1ed3e, 0x1edff),
    (0x1ee04, 0x1ee04),
    (0x1ee20, 0x1ee20),
    (0x1ee23, 0x1ee23),
    (0x1ee25, 0x1ee26),
    (0x1ee28, 0x1ee28),
    (0x1ee33, 0x1ee33),
    (0x1ee38, 0x1ee38),
    (0x1ee3a, 0x1ee3a),
    (0x1ee3c, 0x1ee41),
    (0x1ee43, 0x1ee46),
    (0x1ee48, 0x1ee48),
    (0x1ee4a, 0x1ee4a),
    (0x1ee4c, 0x1ee4c),
    (0x1ee50, 0x1ee50),
    (0x1ee53, 0x1ee53),
    (0x1ee55, 0x1ee56),
    (0x1ee58, 0x1ee58),
    (0x1ee5a, 0x1ee5a),
    (0x1ee5c, 0x1ee5c),
    (0x1ee5e, 0x1ee5e),
    (0x1ee60, 0x1ee60),
    (0x1ee63, 0x1ee63),
    (0x1ee65, 0x1ee66),
    (0x1ee6b, 0x1ee6b),
    (0x1ee73, 0x1ee73),
    (0x1ee78, 0x1ee78),
    (0x1ee7d, 0x1ee7d),
    (0x1ee7f, 0x1ee7f),
    (0x1ee8a, 0x1ee8a),
    (0x1ee9c, 0x1eea0),
    (0x1eea4, 0x1eea4),
    (0x1eeaa, 0x1eeaa),
    (0x1eebc, 0x1eeef),
    (0x1eef2, 0x1efff),
    (0x1f02c, 0x1f02f),
    (0x1f094, 0x1f09f),
    (0x1f0af, 0x1f0b0),
    (0x1f0c0, 0x1f0c0),
    (0x1f0d0, 0x1f0d0),
    (0x1f0f6, 0x1f0ff),
    (0x1f1ae, 0x1f1e5),
    (0x1f203, 0x1f20f),
    (0x1f23c, 0x1f23f),
    (0x1f249, 0x1f24f),
    (0x1f252, 0x1f25f),
    (0x1f266, 0x1f2ff),
    (0x1f6d8, 0x1f6db),
    (0x1f6ed, 0x1f6ef),
    (0x1f6fd, 0x1f6ff),
    (0x1f777, 0x1f77a),
    (0x1f7da, 0x1f7df),
    (0x1f7ec, 0x1f7ef),
    (0x1f7f1, 0x1f7ff),
    (0x1f80c, 0x1f80f),
    (0x1f848, 0x1f84f),
    (0x1f85a, 0x1f85f),
    (0x1f888, 0x1f88f),
    (0x1f8ae, 0x1f8af),
    (0x1f8b2, 0x1f8ff),
    (0x1fa54, 0x1fa5f),
    (0x1fa6e, 0x1fa6f),
    (0x1fa7d, 0x1fa7f),
    (0x1fa89, 0x1fa8f),
    (0x1fabe, 0x1fabe),
    (0x1fac6, 0x1facd),
    (0x1fadc, 0x1fadf),
    (0x1fae9, 0x1faef),
    (0x1faf9, 0x1faff),
    (0x1fb93, 0x1fb93),
    (0x1fbcb, 0x1fbef),
    (0x1fbfa, 0x1ffff),
    (0x2a6e0, 0x2a6ff),
    (0x2b73a, 0x2b73f),
    (0x2b81e, 0x2b81f),
    (0x2cea2, 0x2ceaf),
    (0x2ebe1, 0x2ebef),
    (0x2ee5e, 0x2f7ff),
    (0x2fa1e, 0x2ffff),
    (0x3134b, 0x3134f),
    (0x323b0, 0xe00ff),
    (0xe01f0, 0x10ffff),
];
// END PYTHON NONPRINTABLE
