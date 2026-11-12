//! Command parsing, stable structured output and the process error boundary.
use crate::api::Api;
use crate::config::Config;
use crate::errors::{Error, ExitStatus, Result};
use crate::util::{self, get, number, object, set, string, text, truthy};
use ccs_pytext::json::Value;
use clap::builder::TypedValueParser;
use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn flag(name: &'static str) -> Arg {
    Arg::new(name).long(name).action(ArgAction::SetTrue)
}
fn command(name: &'static str) -> Command {
    Command::new(name)
        .infer_long_args(true)
        .args_override_self(true)
        .disable_help_subcommand(true)
}
fn picker_command(structured: bool) -> Command {
    let mut cmd = command("ccs")
        .version(env!("CARGO_PKG_VERSION"))
        .disable_version_flag(true)
        .arg(
            Arg::new("version")
                .long("version")
                .action(ArgAction::Version),
        )
        .arg(Arg::new("query").num_args(0..).action(ArgAction::Append))
        .args([
            flag("deep"),
            flag("semantic"),
            flag("all"),
            flag("sidechain"),
            flag("here"),
            flag("offline"),
            flag("print"),
            flag("fork"),
        ])
        .arg(Arg::new("host").long("host").action(ArgAction::Append))
        .arg(Arg::new("since").long("since"));
    if structured {
        cmd = cmd.arg(
            Arg::new("limit")
                .long("limit")
                .default_value("50")
                .value_parser(parse_limit),
        );
    }
    cmd
}
fn subcommand(name: &'static str) -> Command {
    let cmd = command(name);
    match name {
        "preview" => cmd
            .arg(Arg::new("session_key").required(true))
            .arg(Arg::new("query").default_value("")),
        "resume" => cmd
            .arg(Arg::new("session_key").required(true))
            .args([flag("print"), flag("fork"), flag("force")])
            .arg(
                Arg::new("to")
                    .long("to")
                    .value_parser(clap::builder::OsStringValueParser::new().map(PathBuf::from)),
            ),
        "ingest" => cmd
            .arg(
                Arg::new("file")
                    .long("file")
                    .value_parser(clap::builder::OsStringValueParser::new().map(PathBuf::from)),
            )
            .args([
                flag("sweep"),
                flag("backfill"),
                flag("quiet"),
                flag("with-subagents").requires("file"),
            ])
            .group(
                ArgGroup::new("mode")
                    .args(["file", "sweep", "backfill"])
                    .required(true),
            ),
        "purge" => cmd.arg(Arg::new("session_key").required(true)),
        "_backend" => cmd.arg(Arg::new("q").default_value("")),
        "_preview" => cmd
            .arg(Arg::new("key").required(true))
            .arg(Arg::new("q").default_value("")),
        "_toggle" => cmd.arg(
            Arg::new("letter")
                .required(true)
                .value_parser(["s", "d", "a"]),
        ),
        "_fuse" => cmd
            .arg(Arg::new("seq").required(true))
            .arg(Arg::new("q").default_value("")),
        "completion" => cmd.arg(Arg::new("shell").required(true).value_parser(["zsh"])),
        _ => cmd,
    }
}
const SUBCOMMANDS: &[&str] = &[
    "search",
    "preview",
    "resume",
    "ingest",
    "status",
    "purge",
    "_backend",
    "_preview",
    "_toggle",
    "_fuse",
    "completion",
];
fn arg<'a>(matches: &'a ArgMatches, name: &str) -> &'a str {
    matches
        .get_one::<String>(name)
        .map(String::as_str)
        .unwrap_or("")
}
fn options(matches: &ArgMatches) -> Result<(String, Value)> {
    let mut flags = String::new();
    for (name, letter) in [("semantic", 's'), ("deep", 'd'), ("all", 'a')] {
        if matches.get_flag(name) {
            flags.push(letter);
        }
    }
    let mut opts = object([
        ("sidechain", Value::Bool(matches.get_flag("sidechain"))),
        ("offline", Value::Bool(matches.get_flag("offline"))),
    ]);
    if matches.get_flag("here") {
        set(
            &mut opts,
            "cwd_prefix",
            string(
                std::env::current_dir()
                    .map_err(Error::Io)?
                    .to_string_lossy(),
            ),
        );
    }
    if let Some(hosts) = matches.get_many::<String>("host") {
        let hosts: Vec<_> = hosts.collect();
        if hosts.iter().any(|h| !util::valid_host_label(h)) {
            return Err(Error::Usage("--host is not a host label".into()));
        }
        set(
            &mut opts,
            "hosts",
            Value::Array(hosts.into_iter().map(string).collect()),
        );
    }
    let since = arg(matches, "since");
    if !since.is_empty() {
        let seconds = util::parse_duration(since)?;
        set(
            &mut opts,
            "since",
            string(util::iso(util::now_epoch() - seconds as f64)),
        );
    }
    Ok((flags, opts))
}

pub use crate::util::stderr_line;
pub fn message(error: &Error) -> &str {
    match error {
        Error::Usage(s) | Error::Unavailable(s) | Error::ResumePrecondition(s) => s,
        _ => "internal error",
    }
}
pub fn output(out: &str) -> Result<()> {
    io::stdout().write_all(out.as_bytes()).map_err(Error::Io)
}
fn json_output(value: &Value, ascii: bool, sorted: bool) -> Result<()> {
    let points = ccs_pytext::json_dumps_points(value, ascii, sorted)
        .map_err(|_| util::invalid("cannot encode JSON"))?;
    let mut bytes = Vec::new();
    for point in points {
        if let Some(c) = char::from_u32(point) {
            let mut utf8 = [0; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
        } else if (0xdc80..=0xdcff).contains(&point) {
            // Python's Unix stdout uses surrogateescape for filesystem bytes.
            bytes.push((point - 0xdc00) as u8);
        } else {
            return Err(util::invalid("cannot encode JSON"));
        }
    }
    bytes.push(b'\n');
    io::stdout().write_all(&bytes).map_err(Error::Io)
}
fn unavailable(error: Error) -> Error {
    match error {
        Error::Usage(s) => Error::Unavailable(s),
        other => other,
    }
}
fn with_agent(mut value: Value) -> Value {
    let codex = text(get(&value, "entrypoint")).is_some_and(|s| s.starts_with("codex-"));
    set(
        &mut value,
        "agent",
        string(if codex { "codex" } else { "claude" }),
    );
    value
}
fn response_object(response: crate::api::Response, route: &str) -> Result<Value> {
    match response.json() {
        Some(v @ Value::Object(_)) if response.status == 200 => Ok(v),
        _ => Err(Error::Unavailable(format!(
            "{route} answered HTTP {}",
            response.status
        ))),
    }
}
fn search(matches: &ArgMatches, query: &str, flags: &str, opts: &Value) -> Result<ExitStatus> {
    let limit = *matches.get_one::<i64>("limit").unwrap() as usize;
    let current = util::current_session_id();
    let data = if matches.get_flag("offline") {
        let cfg = Config::load(None).ok();
        let host = crate::picker::host_label(cfg.as_ref());
        let found = crate::picker::local_search(query, flags, opts, current.as_deref())?;
        let found = if crate::picker::host_selected(opts, &host) {
            found
        } else {
            vec![]
        };
        let sessions = found
            .into_iter()
            .take(limit)
            .map(|s| {
                let value = s.value();
                object([
                    (
                        "session_key",
                        string(format!("local:{}", s.path.to_string_lossy())),
                    ),
                    ("session_id", string(&s.session_id)),
                    ("title", get(&value, "title").clone()),
                    ("cwd", get(&value, "cwd").clone()),
                    ("entrypoint", get(&value, "entrypoint").clone()),
                    ("host", string(&host)),
                    ("agent", string(&s.agent)),
                    ("hit_count", number(s.hits)),
                    ("updated_at", string(util::iso(s.mtime))),
                ])
            })
            .collect();
        object([
            ("sessions", Value::Array(sessions)),
            (
                "degraded",
                string("offline: local text only, at most 200 candidates per agent"),
            ),
        ])
    } else {
        let cfg = Config::load(None).map_err(unavailable)?;
        let mut body = crate::picker::search_body(query, flags, opts, None);
        set(
            &mut body,
            "limit",
            number((limit + usize::from(current.is_some())).min(50)),
        );
        let mut api = Api::with_timeout(cfg, Duration::from_secs(5));
        let mut data = response_object(
            api.post("/search", &body, false, None)
                .map_err(unavailable)?,
            "/search",
        )?;
        let sessions = match get(&data, "sessions") {
            Value::Array(rows) => rows
                .iter()
                .filter(|s| {
                    current
                        .as_ref()
                        .is_none_or(|id| !util::is(get(s, "session_id"), id))
                })
                .take(limit)
                .cloned()
                .map(with_agent)
                .collect(),
            Value::Null if !util::has(&data, "sessions") => vec![],
            _ => return Err(util::invalid("invalid sessions")),
        };
        set(&mut data, "sessions", Value::Array(sessions));
        data
    };
    json_output(&data, false, false)?;
    Ok(ExitStatus::Success)
}
fn preview(key: &str, query: &str) -> Result<ExitStatus> {
    let data = if let Some(path) = key.strip_prefix("local:") {
        let path = Path::new(path);
        if crate::codex::is_path(path) && crate::codex::classify(path).is_none() {
            return Err(Error::Unavailable(
                "local Codex transcript is missing or unsafe".into(),
            ));
        }
        let session = crate::extract::scan_checked(path, None, 4)?;
        let value = session.value();
        let snippets = if let Value::Array(rows) = get(&value, "last_texts") {
            rows.iter()
                .filter_map(|row| {
                    if let Value::Array(parts) = row {
                        Some(object([
                            ("role", parts[0].clone()),
                            ("fragment", parts[1].clone()),
                        ]))
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            vec![]
        };
        object([
            (
                "session",
                object([
                    ("session_key", string(key)),
                    ("session_id", string(&session.session_id)),
                    ("title", get(&value, "title").clone()),
                    ("cwd", get(&value, "cwd").clone()),
                    ("agent", string(&session.agent)),
                ]),
            ),
            ("snippets", Value::Array(snippets)),
        ])
    } else {
        let cfg = Config::load(None).map_err(unavailable)?;
        let mut api = Api::with_timeout(cfg, Duration::from_secs(5));
        let mut data = response_object(
            api.get("/preview", &[("session_key", key), ("q", query)], None)
                .map_err(unavailable)?,
            "/preview",
        )?;
        let session = get(&data, "session");
        let session = if truthy(session) {
            session.clone()
        } else {
            object(Vec::<(&str, Value)>::new())
        };
        set(&mut data, "session", with_agent(session));
        data
    };
    json_output(&data, false, false)?;
    Ok(ExitStatus::Success)
}
fn purge(key: &str) -> Result<ExitStatus> {
    let cfg = Config::load(None).map_err(unavailable)?;
    let response = Api::new(cfg)
        .request(
            "DELETE",
            "/session",
            None,
            &[("session_key", key)],
            false,
            None,
        )
        .map_err(|e| Error::Unavailable(format!("server unreachable: {}", message(&e))))?;
    if response.status != 200 {
        return Err(Error::Unavailable(format!(
            "purge answered HTTP {}",
            response.status
        )));
    }
    json_output(&response.json().unwrap_or(Value::Null), true, true)?;
    Ok(ExitStatus::Success)
}
fn discover_status() -> Vec<PathBuf> {
    // Status counts all files discoverable for shipping, including subagents.
    let mut paths = crate::codex::paths();
    if let Ok(projects) = std::fs::read_dir(util::projects_dir()) {
        for project in projects
            .flatten()
            .filter(|p| p.file_type().is_ok_and(|t| t.is_dir()))
        {
            if let Ok(entries) = std::fs::read_dir(project.path()) {
                for entry in entries.flatten() {
                    let kind = entry.file_type();
                    if kind.as_ref().is_ok_and(|t| t.is_file())
                        && entry.path().extension().is_some_and(|s| s == "jsonl")
                    {
                        paths.push(entry.path());
                    } else if kind.is_ok_and(|t| t.is_dir()) {
                        let sub = entry.path().join("subagents");
                        if std::fs::symlink_metadata(&sub).is_ok_and(|m| m.is_dir()) {
                            if let Ok(children) = std::fs::read_dir(sub) {
                                paths.extend(
                                    children
                                        .flatten()
                                        .filter(|c| {
                                            c.file_type().is_ok_and(|t| t.is_file())
                                                && c.file_name()
                                                    .to_string_lossy()
                                                    .starts_with("agent-")
                                                && c.path()
                                                    .extension()
                                                    .is_some_and(|s| s == "jsonl")
                                        })
                                        .map(|c| c.path()),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    paths
}
fn status() -> Result<ExitStatus> {
    let cfg = match Config::load(None) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            output(&format!("config: {}\n", message(&e)))?;
            None
        }
    };
    if let Some(cfg) = &cfg {
        let key_ok =
            std::fs::metadata(&cfg.hmac_key_file).is_ok_and(|m| m.is_file() && m.len() > 0);
        output(&format!(
            "endpoint:   {}\nhost_label: {}\nauth:       {}\nconfig:     {}\nhmac key:   {}\n",
            cfg.endpoint,
            cfg.host_label,
            cfg.auth_type,
            cfg.path.display(),
            if key_ok {
                "present"
            } else {
                "MISSING — ingest is fail-closed"
            }
        ))?;
    }
    let br = crate::breaker::Breaker::default().state();
    output(&format!(
        "breaker:    {} (failures={})\n",
        if truthy(get(&br, "open")) {
            "OPEN"
        } else {
            "closed"
        },
        crate::picker::display(get(&br, "failures"))
    ))?;
    let mut state = util::read_json(&util::state_path(), Value::Null);
    let version = get(&state, "version");
    let version_one = version == &Value::Bool(true)
        || matches!(version,Value::Number(n) if n.parse::<f64>()==Ok(1.0));
    if !version_one || !matches!(get(&state, "files"), Value::Object(_)) {
        state = object([("files", object(Vec::<(&str, Value)>::new()))]);
    }
    let mut lag = 0i128;
    let mut tracked = Vec::new();
    if let Value::Object(files) = get(&state, "files") {
        for (path, entry) in files {
            let path =
                ccs_pytext::json::scalar(path).map_err(|_| util::invalid("invalid state path"))?;
            if let Ok(meta) = std::fs::metadata(&path) {
                let offset = if !util::has(entry, "offset") {
                    0
                } else {
                    match get(entry, "offset") {
                        Value::Bool(value) => i128::from(*value),
                        Value::Number(raw) => raw
                            .parse::<i128>()
                            .ok()
                            .or_else(|| {
                                raw.parse::<f64>()
                                    .ok()
                                    .filter(|n| n.is_finite())
                                    .map(|n| n as i128)
                            })
                            .ok_or_else(|| util::invalid("invalid cursor offset"))?,
                        Value::String(_) => text(get(entry, "offset"))
                            .and_then(|s| decimal_integer(&s))
                            .and_then(|s| s.parse::<i128>().ok())
                            .ok_or_else(|| util::invalid("invalid cursor offset"))?,
                        _ => return Err(util::invalid("invalid cursor offset")),
                    }
                };
                lag += (i128::from(meta.len()) - offset).max(0);
            }
            tracked.push(PathBuf::from(path));
        }
    }
    let untracked = discover_status()
        .iter()
        .filter(|p| !tracked.contains(p))
        .count();
    output(&format!(
        "cursor lag: {lag} bytes over {} tracked files; {untracked} files never shipped\n",
        tracked.len()
    ))?;
    let mut code = ExitStatus::Success;
    let mut token_state = "disabled";
    if let Some(cfg) = cfg {
        let mut api = Api::with_timeout(cfg, Duration::from_secs(3));
        match api.get("/status", &[], None) {
            Ok(response) => {
                let body = response.json().unwrap_or(Value::Null);
                output(&format!(
                    "server:     HTTP {} {}\n",
                    response.status,
                    if truthy(&body) {
                        util::json_string(&body, true, true)?
                    } else {
                        String::new()
                    }
                ))?;
                if response.status != 200 {
                    code = ExitStatus::Unavailable;
                }
            }
            Err(e) => {
                output(&format!("server:     unreachable ({})\n", message(&e)))?;
                code = ExitStatus::Unavailable;
            }
        }
        token_state = api.token_status().as_str();
    }
    output(&format!("token:      {token_state}\nlast errors:\n"))?;
    if let Ok(bytes) = std::fs::read(util::log_path()) {
        let contents = ccs_pytext::decode_replace(&bytes)
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        let lines: Vec<_> = contents.split_inclusive('\n').collect();
        let errors: Vec<_> = lines
            .iter()
            .skip(lines.len().saturating_sub(2000))
            .filter(|l| l.contains(" WARN ") || l.contains(" ERROR "))
            .collect();
        for line in errors.iter().skip(errors.len().saturating_sub(8)) {
            output(&format!("  {}\n", line.trim_end_matches('\n')))?;
        }
    }
    Ok(code)
}

// CPython 3.13 uses Unicode 15.1; regex's newer Nd table is not the oracle.
fn normalize_decimal_digits(raw: &str) -> String {
    const DECIMAL_ZERO: &[u32] = &[
        0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66,
        0xde6, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90,
        0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0,
        0xff10, 0x104a0, 0x10d30, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450, 0x114d0,
        0x11650, 0x116c0, 0x11730, 0x118e0, 0x11950, 0x11c50, 0x11d50, 0x11da0, 0x11f50, 0x16a60,
        0x16ac0, 0x16b50, 0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e140, 0x1e2f0, 0x1e4f0,
        0x1e950, 0x1fbf0,
    ];
    raw.chars()
        .map(|c| {
            let point = u32::from(c);
            DECIMAL_ZERO
                .iter()
                .find_map(|&base| {
                    (point >= base && point < base + 10)
                        .then(|| char::from(b'0' + (point - base) as u8))
                })
                .unwrap_or(c)
        })
        .collect()
}
// Match argparse's integer and negative-positional grammar before clap parses.
fn decimal_integer(raw: &str) -> Option<String> {
    let raw =
        raw.trim_matches(|c: char| ccs_pytext::is_space(c) && !('\u{1c}'..='\u{1f}').contains(&c));
    let normalized = normalize_decimal_digits(raw);
    let re = regex::Regex::new(r"\A[+-]?[0-9](?:_?[0-9])*\z").unwrap();
    re.is_match(&normalized)
        .then(|| normalized.replace('_', ""))
}
fn parse_limit(raw: &str) -> std::result::Result<i64, String> {
    decimal_integer(raw)
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| (1..=50).contains(n))
        .ok_or_else(|| "--limit must be in 1..50".into())
}
fn normalize_arguments(
    mut parser: Command,
    rest: &[OsString],
    picker: bool,
) -> Result<(Command, Vec<OsString>)> {
    let negative = regex::Regex::new(r"\A-(?:[0-9]+|[0-9]*\.[0-9]+)\z").unwrap();
    let mut replacements = std::collections::HashMap::<String, String>::new();
    let mut normalized = Vec::new();
    let mut positional = false;
    let mut ended = false;
    let mut takes_value = false;
    let mut escaped = false;
    for (i, value) in rest.iter().enumerate() {
        let raw = value.to_str().unwrap_or("");
        let is_negative = negative.is_match(&normalize_decimal_digits(raw));
        if !escaped && raw == "--" && !takes_value {
            escaped = true;
            normalized.push(value.clone());
            continue;
        }
        if takes_value {
            takes_value = false;
        } else if !escaped && raw.starts_with('-') && raw != "-" && !is_negative {
            if positional {
                ended = true;
            }
            let name = raw.trim_start_matches('-').split('=').next().unwrap_or("");
            let matches: Vec<_> = parser
                .get_arguments()
                .filter(|a| a.get_long().is_some_and(|l| l.starts_with(name)))
                .collect();
            if matches.len() == 1 && !raw.contains('=') {
                takes_value = matches[0].get_action().takes_values();
            }
        } else {
            if picker && ended {
                return Err(Error::Usage(
                    "query words must form one positional group".into(),
                ));
            }
            positional = true;
        }
        if !escaped && is_negative {
            let mut marker = format!("ccs-negative-argument-{i}");
            while rest.iter().any(|s| s == marker.as_str()) {
                marker.push('_');
            }
            replacements.insert(marker.clone(), raw.into());
            normalized.push(marker.into());
        } else {
            normalized.push(value.clone());
        }
    }
    if !replacements.is_empty() {
        let ids: Vec<_> = parser
            .get_arguments()
            .filter(|a| a.get_action().takes_values())
            .map(|a| a.get_id().as_str().to_owned())
            .collect();
        for id in ids {
            let map = replacements.clone();
            parser = parser.mut_arg(&id, |a| match id.as_str() {
                "letter" | "shell" => a,
                "limit" => a.value_parser(move |s: &str| {
                    parse_limit(map.get(s).map(String::as_str).unwrap_or(s))
                }),
                "file" | "to" => {
                    a.value_parser(clap::builder::OsStringValueParser::new().map(move |s| {
                        PathBuf::from(
                            s.to_str()
                                .and_then(|v| map.get(v))
                                .map(OsString::from)
                                .unwrap_or(s),
                        )
                    }))
                }
                _ => a.value_parser(move |s: &str| {
                    Ok::<String, String>(map.get(s).cloned().unwrap_or_else(|| s.into()))
                }),
            });
        }
    }
    Ok((parser, normalized))
}

pub fn dispatch(args: &[OsString]) -> Result<ExitStatus> {
    let first = args.first().and_then(|s| s.to_str()).unwrap_or("");
    let (name, rest) = if let Some(name) = SUBCOMMANDS.iter().find(|&&s| s == first) {
        (*name, &args[1..])
    } else {
        ("pick", if first == "--" { &args[1..] } else { args })
    };
    let parser = if ["pick", "search"].contains(&name) {
        picker_command(name == "search")
    } else {
        subcommand(name)
    };
    let (parser, rest) = normalize_arguments(parser, rest, ["pick", "search"].contains(&name))?;
    let matches = match parser
        .try_get_matches_from(std::iter::once(OsString::from("ccs")).chain(rest.iter().cloned()))
    {
        Ok(m) => m,
        Err(e) => {
            if e.use_stderr() {
                stderr_line(&e.to_string());
                return Ok(ExitStatus::Usage);
            }
            output(&e.to_string())?;
            return Ok(ExitStatus::Success);
        }
    };
    match name {
        "pick" | "search" => {
            let (flags, opts) = options(&matches)?;
            let query = matches
                .get_many::<String>("query")
                .map(|v| v.cloned().collect::<Vec<_>>().join(" "))
                .unwrap_or_default();
            if name == "search" {
                search(&matches, &query, &flags, &opts)
            } else {
                crate::picker::pick(
                    &query,
                    &flags,
                    &opts,
                    matches.get_flag("print"),
                    matches.get_flag("fork"),
                )
            }
        }
        "preview" => preview(arg(&matches, "session_key"), arg(&matches, "query")),
        "purge" => purge(arg(&matches, "session_key")),
        "status" => status(),
        "resume" => resume_dispatch(
            arg(&matches, "session_key"),
            matches.get_flag("print"),
            matches.get_flag("fork"),
            matches.get_one::<PathBuf>("to").cloned(),
            matches.get_flag("force"),
        ),
        "ingest" => ingest_dispatch(&matches),
        "completion" => {
            let mut cmd = picker_command(false);
            for name in SUBCOMMANDS {
                cmd = cmd.subcommand(if *name == "search" {
                    picker_command(true).name("search")
                } else {
                    subcommand(name)
                });
            }
            let mut out = Vec::new();
            clap_complete::generate(clap_complete::Shell::Zsh, &mut cmd, "ccs", &mut out);
            output(&String::from_utf8_lossy(&out))?;
            Ok(ExitStatus::Success)
        }
        _ => {
            let env = crate::picker::environment();
            let params = match name {
                "_backend" => vec![("q", arg(&matches, "q"))],
                "_preview" => vec![("key", arg(&matches, "key")), ("q", arg(&matches, "q"))],
                "_toggle" => vec![("letter", arg(&matches, "letter"))],
                _ => vec![],
            };
            if name != "_fuse" {
                if let Some(reply) = crate::helper::callback(name, &params, &env) {
                    output(&reply)?;
                    return Ok(ExitStatus::Success);
                }
            }
            let reply = match name {
                "_backend" => crate::picker::backend(arg(&matches, "q"), &env, None)?,
                "_preview" => {
                    crate::picker::preview(arg(&matches, "key"), arg(&matches, "q"), &env, None)?
                }
                "_toggle" => crate::picker::toggle(arg(&matches, "letter"), &env)? + "\n",
                "_fuse" => {
                    crate::picker::fuse(arg(&matches, "seq"), arg(&matches, "q"), &env, None)?;
                    String::new()
                }
                _ => unreachable!(),
            };
            output(&reply)?;
            Ok(ExitStatus::Success)
        }
    }
}
pub fn resume_dispatch(
    key: &str,
    print: bool,
    fork: bool,
    to: Option<PathBuf>,
    force: bool,
) -> Result<ExitStatus> {
    crate::resume::resume(&crate::resume::ResumeRequest {
        session_key: key.to_owned(),
        print,
        fork,
        to_dir: to,
        force,
    })
}
fn ingest_dispatch(matches: &ArgMatches) -> Result<ExitStatus> {
    use crate::ingest::{IngestMode, IngestRequest};
    let file = matches
        .get_one::<PathBuf>("file")
        .filter(|p| !p.as_os_str().is_empty());
    let with_subagents = matches.get_flag("with-subagents");
    if with_subagents && file.is_none() {
        return Err(Error::Usage("--with-subagents needs --file".into()));
    }
    let mode = if let Some(path) = file {
        IngestMode::File(path.clone())
    } else if matches.get_flag("sweep") {
        IngestMode::Sweep
    } else {
        IngestMode::Backfill
    };
    crate::ingest::run_ingest(&IngestRequest {
        mode,
        with_subagents,
        quiet: matches.get_flag("quiet"),
    })
}

pub fn run(args: &[OsString]) -> Result<Value> {
    dispatch(args).map(|s| number(s.code()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn shared_warning_repr_preserves_lone_surrogates() {
        // Python repr(chr(0xd800) + chr(0xdc80)); OS filenames instead follow D5.
        let input = ccs_pytext::json::Value::String(vec![0xd800, 0xdc80]);
        assert_eq!(crate::resume::repr(&input), "'\\ud800\\udc80'");
    }
}
