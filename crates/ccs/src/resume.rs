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
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

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
        // SAFETY: line stays live; fd 2 is borrowed, never closed here.
        let written = unsafe { libc::write(libc::STDERR_FILENO, line.as_ptr().cast(), line.len()) };
        if written < 0 {
            Err(Error::Io(io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }
}
fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
fn repr(value: &Value) -> String {
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
                    Some(c) if !c.is_control() => out.push(c),
                    _ if point < 256 => out.push_str(&format!("\\x{point:02x}")),
                    _ => out.push_str(&format!("\\u{point:04x}")),
                }
            }
            out.push(quote);
            out
        }
        _ => util::json_string(value, true, false).unwrap_or_default(),
    }
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
        if let Some(c) = text(cwd).filter(|c| {
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
            return Ok(d);
        }
        return Err(refused(format!(
            "--to {} does not encode to {project}, the directory this transcript lives in",
            display(to)
        )));
    }
    let mut found = Vec::new();
    for c in extract::scan(path, None, 0).cwd_candidates {
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
    let c = to
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .or_else(|| text(get(&meta, "cwd")).map(PathBuf::from));
    c.filter(|c| c.is_absolute())
        .and_then(|c| directory(&c))
        .ok_or_else(|| refused("Codex session directory does not exist here; pass --to DIR"))
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
        return directory(&expand(to))
            .ok_or_else(|| refused(format!("--to {} is not a directory", display(to))));
    }
    if req.print || !io::stdin().is_terminal() {
        return Err(refused("this session must be restored from the archive; pass --to DIR to choose where it resumes (required with --print or without a terminal)"));
    }
    let here = fs::canonicalize(std::env::current_dir().map_err(Error::Io)?).map_err(Error::Io)?;
    if let Some(rc) =
        text(get(meta, "resume_cwd")).filter(|c| c.starts_with('/') && Path::new(c).is_dir())
    {
        diagnostics.write(&format!("The session's original directory exists on this host:\n  {rc}\nStarting an agent there loads that directory's project settings and instructions."))?;
        if matches!(
            ask("Resume in that directory? [y/N] ")?
                .to_lowercase()
                .as_str(),
            "y" | "yes"
        ) {
            return fs::canonicalize(rc).map_err(Error::Io);
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
    let err = Command::new(agent).args(args).exec();
    if err.kind() == io::ErrorKind::NotFound {
        Err(refused(format!("{agent} is not on PATH")))
    } else {
        Err(Error::Io(err))
    }
}
fn sha(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn archive(api: &mut Api, key: &str, codex: bool) -> Result<Response> {
    let response = api.get(
        "/archive",
        &[("session_key", key)],
        Some(Duration::from_secs(120)),
    )?;
    if !codex && response.status == 409 {
        let data = response.json().unwrap_or(Value::Null);
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
fn extract_tool_results(bytes: &[u8], dest: &Path) -> Result<()> {
    // D11: recognize unsupported streams before creating or modifying dest.
    // The block/end marker distinguishes bzip2 from a plain tar whose first
    // member has a valid name such as BZh9report.txt.
    let bzip2 = bytes.starts_with(b"BZh")
        && matches!(bytes.get(3), Some(b'1'..=b'9'))
        && bytes
            .get(4..10)
            .is_some_and(|magic| magic == b"1AY&SY" || magic == b"\x17rE8P\x90");
    let xz = bytes.starts_with(b"\xfd7zXZ\0");
    if bzip2 || xz {
        let kind = if bzip2 { "bzip2" } else { "xz" };
        return Err(refused(format!(
            "refusing tool-results archive: unsupported {kind} compression (only uncompressed and gzip are supported)"
        )));
    }
    util::ensure_dir(dest, 0o700)?;
    let input: Box<dyn Read + '_> = if bytes.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::MultiGzDecoder::new(bytes))
    } else {
        Box::new(bytes)
    };
    let mut archive = tar::Archive::new(input);
    let mut files = Vec::new();
    // Validate every member before writing any one, as tarfile.getmembers does.
    for entry in archive.entries().map_err(Error::Io)? {
        let mut entry = entry.map_err(Error::Io)?;
        let mut name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        if entry.header().entry_type().is_dir() {
            name = name.trim_end_matches('/').to_owned();
        }
        if !entry.header().entry_type().is_file() || !util::valid_tool_result_name(&name) {
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
        let mut data = Vec::new();
        entry.read_to_end(&mut data).map_err(Error::Io)?;
        files.push((name, data, mode));
    }
    let root = fs::canonicalize(dest).map_err(Error::Io)?;
    for (name, bytes, mode) in files {
        let target = dest.join(name);
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
        f.write_all(&bytes).map_err(Error::Io)?;
        f.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(Error::Io)?;
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
    util::ensure_dir(&pdir, 0o700)?;
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
        let tools = api.get(
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
    util::atomic_write(&target, &data, 0o600)?;
    diagnostics.write(RESTORED_NOTE)?;
    Ok(())
}
fn resume_inner(req: &ResumeRequest, diagnostics: &Diagnostics) -> Result<ExitStatus> {
    let to = req.to_dir.as_deref();
    if let Some(path) = req.session_key.strip_prefix("local:") {
        let path = Path::new(path);
        if codex::is_path(path) {
            let info = codex::classify(path)
                .ok_or_else(|| refused("local Codex transcript is missing or unsafe"))?;
            let sid = validate_session_id(get(&info, "session_id"))?;
            return exec_agent(&codex_resume_cwd(path, to)?, &sid, "codex", req);
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
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
