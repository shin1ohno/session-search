//! fzf callbacks, row formatting and semantic debounce.
use crate::api::Api;
use crate::breaker::{Breaker, TIMEOUT};
use crate::config::Config;
use crate::errors::{Error, ExitStatus, Result};
use crate::helper::SharedApi;
use crate::util::{self, get, object, set, string, text, truthy};
use ccs_pytext::json::Value;
use ccs_pytext::{casefold, shell_quote, split, strip};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub type Environment = HashMap<String, String>;
pub fn environment() -> Environment {
    std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect()
}
fn env_value<'a>(env: &'a Environment, name: &str) -> &'a str {
    env.get(name).map(String::as_str).unwrap_or("")
}
fn current_id(env: &Environment) -> Option<&str> {
    ["CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID"]
        .into_iter()
        .map(|key| env_value(env, key))
        .find(|s| !s.is_empty())
}
pub fn prompt_for(flags: &str) -> String {
    let flags: String = "sda".chars().filter(|c| flags.contains(*c)).collect();
    if flags.is_empty() {
        "ccs> ".into()
    } else {
        format!("ccs:{flags}> ")
    }
}
pub fn parse_prompt(prompt: &str) -> Option<String> {
    if prompt == "ccs> " {
        return Some(String::new());
    }
    let flags = prompt.strip_prefix("ccs:")?.strip_suffix("> ")?;
    (!flags.is_empty() && flags.len() <= 3 && flags.chars().all(|c| "sda".contains(c)))
        .then(|| flags.into())
}
pub fn current_flags(env: &Environment) -> Result<String> {
    if let Some(flags) = parse_prompt(env_value(env, "FZF_PROMPT")) {
        return Ok(flags);
    }
    match fs::read_to_string(env_value(env, "CCS_PICK_STATE")) {
        Ok(value) => {
            if let Some(flags) = parse_prompt(&value) {
                return Ok(flags);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => return Err(Error::Io(e)),
        Err(_) => {}
    }
    let raw = env_value(env, "CCS_PICK");
    let opts = util::parse_json(if raw.is_empty() { "{}" } else { raw })?;
    if !matches!(opts, Value::Object(_)) {
        return Err(util::invalid("invalid picker options"));
    }
    let flags = get(&opts, "flags");
    if !truthy(flags) {
        return Ok(String::new());
    }
    match flags {
        Value::String(points) => Ok("sda"
            .chars()
            .filter(|c| points.contains(&u32::from(*c)))
            .collect()),
        Value::Array(items)
            if items
                .iter()
                .all(|v| !matches!(v, Value::Array(_) | Value::Object(_))) =>
        {
            Ok("sda"
                .chars()
                .filter(|c| items.iter().any(|v| util::is(v, &c.to_string())))
                .collect())
        }
        Value::Object(items) => Ok("sda"
            .chars()
            .filter(|c| items.iter().any(|(key, _)| key == &vec![u32::from(*c)]))
            .collect()),
        _ => Err(util::invalid("invalid picker flags")),
    }
}

pub fn pick_opts(env: &Environment) -> Value {
    util::parse_json(env_value(env, "CCS_PICK"))
        .ok()
        .filter(|v| matches!(v, Value::Object(_)))
        .unwrap_or_else(|| object(Vec::<(&str, Value)>::new()))
}
pub fn toggle(letter: &str, env: &Environment) -> Result<String> {
    let mut flags = current_flags(env)?;
    if letter.len() == 1 && "sda".contains(letter) {
        if flags.contains(letter) {
            flags = flags.replace(letter, "");
        } else {
            flags.push_str(letter);
        }
    }
    let prompt = prompt_for(&flags);
    if !env_value(env, "CCS_PICK_STATE").is_empty() {
        util::atomic_write(Path::new(env_value(env, "CCS_PICK_STATE")), &prompt, 0o600)?;
    }
    Ok(prompt)
}
pub fn launcher() -> PathBuf {
    std::env::var_os("CCS_LAUNCHER")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::current_exe().ok())
        .unwrap_or_else(|| PathBuf::from("ccs"))
}
pub fn fzf_argv(
    query: &str,
    flags: &str,
    self_cmd: &str,
    banner: Option<&str>,
    socket: Option<&str>,
) -> Vec<String> {
    let s = match socket {
        Some(socket) => format!(
            "CCS_HELPER_SOCKET={} {}",
            shell_quote(socket),
            shell_quote(self_cmd)
        ),
        None => shell_quote(self_cmd),
    };
    let backend = format!("reload({s} _backend {{q}})");
    let mut argv: Vec<String> = [
        "--disabled",
        "--ansi",
        "--layout=reverse",
        "--delimiter=\t",
        "--with-nth=2..",
        "--prompt",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    argv.extend([
        prompt_for(flags),
        "--query".into(),
        query.into(),
        "--bind".into(),
        format!("start:{backend}"),
        "--bind".into(),
        format!("change:{backend}"),
    ]);
    for letter in "sda".chars() {
        argv.extend([
            "--bind".into(),
            format!("ctrl-{letter}:transform-prompt({s} _toggle {letter})+{backend}"),
        ]);
    }
    argv.extend([
        "--preview".into(),
        format!("{s} _preview {{1}} {{q}}"),
        "--preview-window".into(),
        "down,45%,wrap".into(),
        "--expect=ctrl-y".into(),
        "--listen".into(),
    ]);
    if let Some(banner) = banner {
        argv.extend(["--header".into(), banner.into()]);
    }
    argv
}
/// Python str() for display values; JSON remains codepoint-preserving elsewhere.
pub fn display(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(s) => s.clone(),
        Value::String(s) => s
            .iter()
            .map(|&v| char::from_u32(v).unwrap_or('\u{fffd}'))
            .collect(),
        _ => util::json_string(value, false, false).unwrap_or_default(),
    }
}
fn clean(value: &Value, width: usize) -> String {
    let t = if truthy(value) {
        split(&display(value)).join(" ")
    } else {
        String::new()
    };
    if width > 0 && t.chars().count() > width {
        t.chars().take(width - 1).collect::<String>() + "…"
    } else {
        t
    }
}
fn default<'a>(value: &'a Value, fallback: &'a Value) -> &'a Value {
    if truthy(value) {
        value
    } else {
        fallback
    }
}
pub fn resumable(s: &Value, host: &str) -> bool {
    (util::is(get(s, "host"), host) && truthy(get(s, "jsonl_exists")))
        || (truthy(get(s, "archived")) && truthy(get(s, "archive_complete")))
}
pub fn server_row(s: &Value, host: &str, now: f64) -> String {
    let age = util::parse_ts(get(s, "updated_at"))
        .filter(|t| *t != 0.0)
        .map(|t| util::human_age(now - t))
        .unwrap_or_else(|| "?".into());
    let mark = if resumable(s, host) { "  " } else { "· " };
    let hits = get(s, "hit_count");
    let tail = match hits {
        Value::Bool(true) => " │ True".into(),
        Value::Number(n) if !n.contains(['.', 'e', 'E']) && !n.starts_with('-') && n != "0" => {
            format!(" │ {n}")
        }
        _ => String::new(),
    };
    let agent = if text(get(s, "entrypoint")).is_some_and(|s| s.starts_with("codex-")) {
        " [Codex]"
    } else {
        ""
    };
    format!(
        "{}\t{mark}{age} {} {} │ {}{agent}{tail}",
        clean(get(s, "session_key"), 0),
        clean(get(s, "host"), 0),
        util::short_cwd(&text(get(s, "cwd")).unwrap_or_default(), 28),
        clean(default(get(s, "title"), &string("(untitled)")), 80)
    )
}
fn local_row(s: &crate::extract::LocalSession, host: &str) -> String {
    let tail = if s.hits > 0 {
        format!(" │ {}", s.hits)
    } else {
        String::new()
    };
    let agent = if s.agent == "codex" { " [Codex]" } else { "" };
    format!(
        "local:{}\t  {} {host} {} │ {}{agent}{tail}",
        s.path.display(),
        util::human_age(util::now_epoch() - s.mtime),
        util::short_cwd(&s.cwd, 28),
        clean(
            &string(if s.title.is_empty() {
                "(untitled)"
            } else {
                &s.title
            }),
            80
        )
    )
}
pub fn banner_row(s: &str) -> String {
    format!("-\t\x1b[33m{s}\x1b[0m")
}
pub fn host_label(cfg: Option<&Config>) -> String {
    if let Some(cfg) = cfg {
        return cfg.host_label.clone();
    }
    let mut name = [0u8; 256];
    unsafe {
        libc::gethostname(name.as_mut_ptr().cast(), name.len());
    }
    let end = name.iter().position(|c| *c == 0).unwrap_or(name.len());
    let name = String::from_utf8_lossy(&name[..end]);
    let host = name.split('.').next().unwrap_or("").to_lowercase();
    if host.is_empty() {
        "local".into()
    } else {
        host
    }
}
pub fn search_body(q: &str, flags: &str, opts: &Value, mode: Option<&str>) -> Value {
    let q = strip(q);
    let mut body = object([
        ("q", string(if q.chars().count() >= 2 { q } else { "" })),
        (
            "mode",
            string(mode.unwrap_or(if flags.contains('s') {
                "hybrid"
            } else {
                "lexical"
            })),
        ),
        ("deep", Value::Bool(flags.contains('d'))),
        ("include_headless", Value::Bool(flags.contains('a'))),
        (
            "include_sidechain",
            Value::Bool(truthy(get(opts, "sidechain"))),
        ),
        ("limit", util::number(50)),
    ]);
    for key in ["hosts", "cwd_prefix", "since"] {
        if truthy(get(opts, key)) {
            set(&mut body, key, get(opts, key).clone());
        }
    }
    body
}
pub fn local_search(
    q: &str,
    flags: &str,
    opts: &Value,
    current: Option<&str>,
) -> Result<Vec<crate::extract::LocalSession>> {
    let cwd = text(get(opts, "cwd_prefix"));
    crate::fallback::search_options(
        q,
        &crate::fallback::SearchOptions {
            include_headless: flags.contains('a'),
            cwd_prefix: cwd.as_deref(),
            since_epoch: util::parse_ts(get(opts, "since")),
            exclude_session_id: current,
            root: None,
        },
    )
}
pub fn host_selected(opts: &Value, host: &str) -> bool {
    match get(opts, "hosts") {
        Value::Array(hosts) if !hosts.is_empty() => hosts.iter().any(|h| util::is(h, host)),
        _ => true,
    }
}
fn offline_rows(
    q: &str,
    flags: &str,
    opts: &Value,
    host: &str,
    env: &Environment,
) -> Result<Vec<String>> {
    let mut rows = vec![banner_row(crate::fallback::BANNER)];
    if !host_selected(opts, host) {
        rows.push(banner_row(
            "(this host is not in --host; nothing local to show)",
        ));
        return Ok(rows);
    }
    match local_search(q, flags, opts, current_id(env)) {
        Ok(found) => rows.extend(found.iter().map(|s| local_row(s, host))),
        Err(Error::Unavailable(s)) => rows.push(banner_row(&s)),
        Err(e) => return Err(e),
    }
    Ok(rows)
}
fn api_request(
    cfg: &Config,
    shared: Option<&Arc<SharedApi>>,
    method: &str,
    path: &str,
    body: Option<&Value>,
    params: &[(&str, &str)],
    timeout: Duration,
) -> Result<crate::api::Response> {
    if let Some(shared) = shared {
        shared.request(cfg, method, path, body, params, timeout)
    } else {
        Api::new(cfg.clone()).request(method, path, body, params, false, Some(timeout))
    }
}
struct Search<'a> {
    q: &'a str,
    flags: &'a str,
    opts: &'a Value,
    env: &'a Environment,
    mode: Option<&'a str>,
    timeout: Duration,
}
fn server_rows(
    cfg: &Config,
    shared: Option<&Arc<SharedApi>>,
    request: Search<'_>,
) -> Result<Vec<String>> {
    let body = search_body(request.q, request.flags, request.opts, request.mode);
    let resp = api_request(
        cfg,
        shared,
        "POST",
        "/search",
        Some(&body),
        &[],
        request.timeout,
    )?;
    if resp.status != 200 {
        return Err(Error::Unavailable(format!(
            "/search answered HTTP {}",
            resp.status
        )));
    }
    let data = resp.json().unwrap_or(Value::Null);
    if truthy(&data) && !matches!(data, Value::Object(_)) {
        return Err(util::invalid("invalid server response"));
    }
    let mut rows = vec![];
    if let Value::Array(sessions) = get(&data, "sessions") {
        for s in sessions {
            if !matches!(s, Value::Object(_))
                || current_id(request.env).is_some_and(|id| util::is(get(s, "session_id"), id))
            {
                continue;
            }
            rows.push(server_row(s, &cfg.host_label, util::now_epoch()));
        }
    }
    if truthy(get(&data, "degraded")) {
        rows.insert(
            0,
            banner_row(&format!("degraded: {}", clean(get(&data, "degraded"), 40))),
        );
    }
    Ok(rows)
}
pub fn backend(q: &str, env: &Environment, shared: Option<&Arc<SharedApi>>) -> Result<String> {
    let flags = current_flags(env)?;
    let opts = pick_opts(env);
    let cfg = Config::load(None).ok();
    let host = host_label(cfg.as_ref());
    let breaker = Breaker::default();
    let online = cfg
        .as_ref()
        .filter(|_| !truthy(get(&opts, "offline")) && !breaker.is_open());
    let rows = if let Some(cfg) = online {
        let later = flags.contains('s') && !env_value(env, "FZF_PORT").is_empty();
        let request = Search {
            q,
            flags: &flags,
            opts: &opts,
            env,
            mode: if later { Some("lexical") } else { None },
            timeout: if flags.contains('s') && !later {
                Duration::from_secs(2)
            } else {
                TIMEOUT
            },
        };
        match server_rows(cfg, shared, request) {
            Ok(rows) => {
                breaker.record_success()?;
                if later {
                    schedule_fuse(q, env, shared)?;
                }
                rows
            }
            Err(Error::Unavailable(_) | Error::Usage(_)) => {
                breaker.record_failure()?;
                offline_rows(q, &flags, &opts, &host, env)?
            }
            Err(e) => return Err(e),
        }
    } else {
        offline_rows(q, &flags, &opts, &host, env)?
    };
    Ok(rows_text(&rows, false))
}
fn rows_text(rows: &[String], always_newline: bool) -> String {
    let mut text = rows.join("\n");
    if !rows.is_empty() || always_newline {
        text.push('\n');
    }
    text
}
fn port(env: &Environment, default: &str) -> String {
    env.get("FZF_PORT")
        .map(String::as_str)
        .unwrap_or(default)
        .chars()
        .filter(char::is_ascii_digit)
        .collect()
}
fn cache_path(env: &Environment, suffix: &str) -> PathBuf {
    util::state_dir().join(format!("picker-{}.{suffix}", port(env, "0")))
}
fn random_hex() -> Result<String> {
    use ring::rand::SecureRandom;
    let mut bytes = [0; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| util::invalid("random generator failed"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn schedule_fuse(q: &str, env: &Environment, shared: Option<&Arc<SharedApi>>) -> Result<()> {
    let seq = format!("{}-{}", util::now_epoch(), random_hex()?);
    util::atomic_write(&cache_path(env, "seq"), &seq, 0o600)?;
    if let Some(shared) = shared {
        let Some(permit) = shared.worker() else {
            return Ok(());
        };
        let shared = Arc::clone(shared);
        let env = env.clone();
        let q = q.to_owned();
        std::thread::spawn(move || {
            let _permit = permit;
            let _ = fuse(&seq, &q, &env, Some(&shared));
        });
    } else {
        let mut cmd = Command::new(launcher());
        cmd.args(["_fuse", &seq, q])
            .envs(env)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        if let Ok(mut child) = cmd.spawn() {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
    Ok(())
}
pub fn fuse(seq: &str, q: &str, env: &Environment, shared: Option<&Arc<SharedApi>>) -> Result<()> {
    std::thread::sleep(Duration::from_millis(400));
    let path = cache_path(env, "seq");
    if fs::read_to_string(&path).ok().as_deref() != Some(seq) {
        return Ok(());
    }
    let cfg = match Config::load(None) {
        Ok(cfg) => cfg,
        Err(_) => return Ok(()),
    };
    let flags = current_flags(env)?;
    let opts = pick_opts(env);
    let rows = match server_rows(
        &cfg,
        shared,
        Search {
            q,
            flags: &flags,
            opts: &opts,
            env,
            mode: Some("hybrid"),
            timeout: Duration::from_secs(2),
        },
    ) {
        Ok(rows) => rows,
        Err(_) => return Ok(()),
    };
    if fs::read_to_string(&path).ok().as_deref() != Some(seq) {
        return Ok(());
    }
    let cache = cache_path(env, "rows");
    util::atomic_write(&cache, &rows_text(&rows, true), 0o600)?;
    post_fzf(
        env,
        &format!("reload(cat {})", shell_quote(&cache.to_string_lossy())),
    );
    Ok(())
}
fn post_fzf(env: &Environment, action: &str) {
    let port = port(env, "");
    if port.is_empty() {
        return;
    }
    let agent = ureq::Agent::config_builder()
        .proxy(None)
        .timeout_global(Some(Duration::from_secs(1)))
        .build()
        .new_agent();
    let mut req = agent.post(format!("http://127.0.0.1:{port}"));
    if !env_value(env, "FZF_API_KEY").is_empty() {
        req = req.header("x-api-key", env_value(env, "FZF_API_KEY"));
    }
    let _ = req.send(action.as_bytes());
}
pub fn view_only_reason(s: &Value, host: &str) -> Option<&'static str> {
    if resumable(s, host) {
        None
    } else if truthy(get(s, "archived")) && !truthy(get(s, "archive_complete")) {
        Some("archive incomplete")
    } else if !truthy(get(s, "archived")) {
        Some(
            if util::is(get(s, "kind"), "subagent") || truthy(get(s, "is_sidechain")) {
                "not archived (subagent)"
            } else {
                "not archived"
            },
        )
    } else {
        Some("older than retention")
    }
}
pub fn preview(
    key: &str,
    q: &str,
    _env: &Environment,
    shared: Option<&Arc<SharedApi>>,
) -> Result<String> {
    if key == "-" {
        return Ok("Offline fallback: only this host's local transcripts are searched (text only, no archive,\nno other hosts, no semantic). Resume works for local files only.\n".into());
    }
    if let Some(path) = key.strip_prefix("local:") {
        let s = crate::extract::scan_checked(Path::new(path), Some(q), 4)?;
        let mut out = format!(
            "\x1b[1m{}\x1b[0m\n{}\n{}\n\n",
            clean(
                &string(if s.title.is_empty() {
                    "(untitled)"
                } else {
                    &s.title
                }),
                0
            ),
            s.resume_cwd(),
            s.path.display()
        );
        let ql = casefold(q);
        for (role, text) in &s.last_texts {
            if ql.is_empty() || casefold(text).contains(&ql) {
                out.push_str(&format!("[{role}] {}\n\n", clean(&string(text), 400)));
            }
        }
        return Ok(out);
    }
    let cfg = match Config::load(None) {
        Ok(cfg) => cfg,
        Err(e) => return Ok(format!("ccs: {}\n", crate::cli::message(&e))),
    };
    let breaker = Breaker::default();
    if breaker.is_open() {
        return Ok("server unavailable (circuit open); preview needs the server\n".into());
    }
    let resp = match api_request(
        &cfg,
        shared,
        "GET",
        "/preview",
        None,
        &[("session_key", key), ("q", q)],
        Duration::from_millis(1500),
    ) {
        Ok(resp) => resp,
        Err(e) => {
            breaker.record_failure()?;
            return Ok(format!("server unreachable: {}\n", crate::cli::message(&e)));
        }
    };
    if resp.status != 200 {
        return Ok(format!("preview: HTTP {}\n", resp.status));
    }
    let data = resp.json().unwrap_or(Value::Null);
    if truthy(&data) && !matches!(data, Value::Object(_)) {
        return Err(util::invalid("invalid server response"));
    }
    let s = get(&data, "session");
    if truthy(s) && !matches!(s, Value::Object(_)) {
        return Err(util::invalid("invalid preview session"));
    }
    let cwd = default(get(s, "resume_cwd"), get(s, "cwd"));
    let mut out = format!(
        "\x1b[1m{}\x1b[0m\n{}  {}  {}\n",
        clean(default(get(s, "title"), &string("(untitled)")), 0),
        clean(get(s, "host"), 0),
        display(default(cwd, &string("?"))),
        clean(get(s, "updated_at"), 0)
    );
    if let Some(reason) = view_only_reason(s, &cfg.host_label) {
        out.push_str(&format!("view-only: {reason}\n"));
    } else {
        out.push_str("Enter: resume  ctrl-y: print command\n");
    }
    out.push('\n');
    if let Value::Array(snippets) = get(&data, "snippets") {
        for sn in snippets.iter().filter(|s| matches!(s, Value::Object(_))) {
            let fragment = clean(get(sn, "fragment"), 0)
                .replace("<em>", "\x1b[1m")
                .replace("</em>", "\x1b[0m");
            out.push_str(&format!(
                "[{} {}] {fragment}\n\n",
                clean(get(sn, "ts"), 20),
                clean(get(sn, "role"), 10)
            ));
        }
    }
    Ok(out)
}
fn executable(name: &str) -> bool {
    use std::os::unix::ffi::OsStrExt;
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).any(|dir| {
        let path = dir.join(name);
        std::ffi::CString::new(path.as_os_str().as_bytes())
            .is_ok_and(|p| path.is_file() && unsafe { libc::access(p.as_ptr(), libc::X_OK) == 0 })
    })
}
struct TemporaryDirectory(PathBuf);
impl TemporaryDirectory {
    fn new(base: &Path, prefix: &str) -> Result<Self> {
        let path = base.join(format!("{prefix}{}", random_hex()?));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(Error::Io)?;
        Ok(Self(path))
    }
}
fn picker_directory() -> Result<TemporaryDirectory> {
    let mut candidates: Vec<PathBuf> = ["TMPDIR", "TEMP", "TMP"]
        .into_iter()
        .filter_map(std::env::var_os)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();
    candidates.extend([
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
        PathBuf::from("/usr/tmp"),
    ]);
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd);
    }
    for base in candidates {
        let base = if base.is_absolute() {
            base
        } else {
            std::env::current_dir().map_err(Error::Io)?.join(base)
        };
        if let Ok(dir) = TemporaryDirectory::new(&base, "ccs-pick-") {
            return Ok(dir);
        }
    }
    Err(util::invalid("no usable temporary directory"))
}
impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
static TERMINATED: AtomicI32 = AtomicI32::new(0);
extern "C" fn terminate(signal: libc::c_int) {
    TERMINATED.store(signal, Ordering::Relaxed);
}
struct Signals(Vec<(i32, libc::sigaction)>);
impl Signals {
    fn trap() -> Self {
        TERMINATED.store(0, Ordering::Relaxed);
        let mut saved = vec![];
        for signal in [libc::SIGTERM, libc::SIGHUP, libc::SIGINT] {
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                let mut old = std::mem::zeroed();
                action.sa_sigaction = terminate as *const () as usize;
                libc::sigemptyset(&mut action.sa_mask);
                if libc::sigaction(signal, &action, &mut old) == 0 {
                    saved.push((signal, old));
                }
            }
        }
        Self(saved)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for (signal, action) in &self.0 {
            unsafe {
                libc::sigaction(*signal, action, std::ptr::null_mut());
            }
        }
    }
}
pub fn pick(query: &str, flags: &str, opts: &Value, print: bool, fork: bool) -> Result<ExitStatus> {
    if !executable("fzf") {
        return Err(Error::Unavailable(
            "fzf is not installed; the picker needs it (ccs resume KEY still works)".into(),
        ));
    }
    let signals = Signals::trap();
    let tmp = picker_directory()?;
    let mut pick = opts.clone();
    let sorted: String = "ads".chars().filter(|c| flags.contains(*c)).collect();
    set(&mut pick, "flags", string(sorted));
    let state = tmp.0.join("prompt");
    util::atomic_write(&state, &prompt_for(flags), 0o600)?;
    let mut env = environment();
    env.insert("CCS_PICK".into(), util::json_string(&pick, true, false)?);
    env.insert("CCS_PICK_STATE".into(), state.to_string_lossy().into());
    env.insert("CCS_LAUNCHER".into(), launcher().to_string_lossy().into());
    if !env.contains_key("FZF_API_KEY") {
        env.insert("FZF_API_KEY".into(), random_hex()?);
    }
    let short = if tmp.0.join("s").as_os_str().len() > 100 {
        TemporaryDirectory::new(Path::new("/tmp"), "ccs-").ok()
    } else {
        None
    };
    let directory = short.as_ref().map(|d| d.0.as_path()).unwrap_or(&tmp.0);
    let helper = crate::helper::Helper::start(&env, directory).ok();
    if let Some(helper) = &helper {
        env.insert(
            "CCS_HELPER_SOCKET".into(),
            helper.path.to_string_lossy().into(),
        );
    } else {
        env.remove("CCS_HELPER_SOCKET");
    }
    let args = fzf_argv(
        query,
        flags,
        env_value(&env, "CCS_LAUNCHER"),
        truthy(get(opts, "offline")).then_some(crate::fallback::BANNER),
        env.get("CCS_HELPER_SOCKET").map(String::as_str),
    );
    let mut child = Command::new("fzf")
        .args(args)
        .envs(&env)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(Error::Io)?;
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut bytes = vec![];
        let result = stdout.read_to_end(&mut bytes);
        result.map(|_| bytes)
    });
    let exit = loop {
        let signal = TERMINATED.load(Ordering::Relaxed);
        if signal != 0 {
            let _ = child.kill();
            let _ = child.wait();
            break Err(signal);
        }
        if let Some(status) = child.try_wait().map_err(Error::Io)? {
            break Ok(status);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let bytes = reader
        .join()
        .map_err(|_| util::invalid("fzf reader failed"))?
        .map_err(Error::Io)?;
    drop(helper);
    drop(short);
    drop(tmp);
    drop(signals);
    let status = match exit {
        Ok(status) => status,
        Err(signal) => return Ok(ExitStatus::Signal(signal as u8)),
    };
    let code = status
        .code()
        .unwrap_or_else(|| -status.signal().unwrap_or(1));
    if code == 1 || code == 130 {
        return Ok(ExitStatus::Success);
    }
    if code != 0 {
        return Err(Error::Unavailable(format!("fzf exited {code}")));
    }
    let decoded = ccs_pytext::decode_replace(&bytes);
    let lines = ccs_pytext::splitlines(&decoded);
    let pressed = lines.first().copied().unwrap_or("");
    let selected = lines
        .get(1)
        .copied()
        .unwrap_or("")
        .split('\t')
        .next()
        .unwrap_or("");
    if selected.is_empty() || selected == "-" {
        return Ok(ExitStatus::Success);
    }
    crate::cli::resume_dispatch(selected, print || pressed == "ctrl-y", fork, None, false)
}
pub fn run(config: &Value, query: &Value) -> Result<Value> {
    pick(&text(query).unwrap_or_default(), "", config, false, false).map(|s| util::number(s.code()))
}
