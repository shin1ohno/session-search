//! Private Unix-socket callback server for the lifetime of a picker.
use crate::api::{PooledApi, Response};
use crate::config::Config;
use crate::errors::{Error, Result};
use crate::picker::{self, Environment};
use crate::util;
use ccs_pytext::json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

type ApiKey = (String, String, String, String);
#[derive(Default)]
pub struct SharedApi {
    slot: Mutex<Option<(ApiKey, Arc<PooledApi>)>>,
    workers: Arc<AtomicUsize>,
}
pub struct WorkerPermit(Arc<AtomicUsize>);
impl Drop for WorkerPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
impl SharedApi {
    pub fn worker(&self) -> Option<WorkerPermit> {
        self.workers
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < 32).then_some(n + 1)
            })
            .ok()?;
        Some(WorkerPermit(Arc::clone(&self.workers)))
    }
    pub fn request(
        &self,
        cfg: &Config,
        method: &str,
        path: &str,
        body: Option<&Value>,
        params: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<Response> {
        let api = {
            let mut slot = self
                .slot
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let key = (
                cfg.endpoint.clone(),
                cfg.auth_type.clone(),
                cfg.client_id.clone(),
                cfg.token_url.clone(),
            );
            if slot.as_ref().is_none_or(|(old, _)| old != &key) {
                *slot = Some((key, Arc::new(PooledApi::new(cfg)?)));
            }
            Arc::clone(&slot.as_ref().unwrap().1)
        };
        api.request(cfg, method, path, body, params, timeout)
    }
}

pub struct Helper {
    pub path: PathBuf,
    stop: Arc<AtomicBool>,
    listener: Option<JoinHandle<()>>,
}
impl Helper {
    pub fn start(env: &Environment, directory: &Path) -> Result<Self> {
        let path = directory.join("s");
        if path.as_os_str().len() > 100 {
            return Err(util::invalid("socket path too long"));
        }
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(Error::Io)?;
        let socket = UnixListener::bind(&path).map_err(Error::Io)?;
        if let Err(e) = fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .and_then(|_| socket.set_nonblocking(true))
        {
            let _ = fs::remove_file(&path);
            return Err(Error::Io(e));
        }
        let env = env.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::clone(&stop);
        let api = Arc::new(SharedApi::default());
        let listener = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                match socket.accept() {
                    Ok((mut stream, _)) => {
                        if stream.set_nonblocking(false).is_err() {
                            continue;
                        }
                        let Some(permit) = api.worker() else {
                            let _ = stream.set_write_timeout(Some(Duration::from_millis(10)));
                            let _ = reply(&mut stream, 503, "helper busy\n");
                            continue;
                        };
                        let env = env.clone();
                        let api = Arc::clone(&api);
                        std::thread::spawn(move || {
                            let _permit = permit;
                            let _ = serve(stream, &env, &api);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            path,
            stop,
            listener: Some(listener),
        })
    }
}
impl Drop for Helper {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.listener.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.path);
    }
}
fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| char::from(b).to_digit(16);
            if let (Some(a), Some(b)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((a * 16 + b) as u8);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    ccs_pytext::decode_replace(&out)
}
fn serve(mut stream: UnixStream, env: &Environment, api: &Arc<SharedApi>) -> Result<()> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(Error::Io)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(Error::Io)?;
    let mut reader = BufReader::new(stream.try_clone().map_err(Error::Io)?);
    let mut request = Vec::new();
    reader
        .by_ref()
        .take(65537)
        .read_until(b'\n', &mut request)
        .map_err(Error::Io)?;
    if request.len() > 65536 {
        return reply(&mut stream, 414, "");
    }
    let request = String::from_utf8_lossy(&request);
    let words: Vec<_> = request.split_whitespace().collect();
    if words.len() != 3 || words[0] != "GET" {
        return reply(&mut stream, 404, "");
    }
    let (path, query) = words[1].split_once('?').unwrap_or((words[1], ""));
    let params: Environment = query
        .split('&')
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .map(|(k, v)| (decode(k), decode(v)))
        .collect();
    let mut env = env.clone();
    env.insert(
        "FZF_PROMPT".into(),
        params.get("prompt").cloned().unwrap_or_default(),
    );
    let port: String = params
        .get("port")
        .cloned()
        .unwrap_or_default()
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    if port.is_empty() {
        env.remove("FZF_PORT");
    } else {
        env.insert("FZF_PORT".into(), port);
    }
    let value = |key: &str| params.get(key).map(String::as_str).unwrap_or("");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match path {
        "/backend" => picker::backend(value("q"), &env, Some(api)).map(Some),
        "/preview" => picker::preview(value("key"), value("q"), &env, Some(api)).map(Some),
        "/toggle" if ["s", "d", "a"].contains(&value("letter")) => {
            picker::toggle(value("letter"), &env).map(|s| Some(s + "\n"))
        }
        _ => Ok(None),
    }));
    match result {
        Ok(Ok(Some(body))) => reply(&mut stream, 200, &body),
        Ok(Ok(None)) => reply(&mut stream, 404, ""),
        _ => reply(&mut stream, 500, ""),
    }
}
fn reply(stream: &mut UnixStream, status: u16, body: &str) -> Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        414 => "Request-URI Too Long",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let data=format!("HTTP/1.0 {status} {reason}\r\nServer: ccs-helper\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}",body.len());
    stream.write_all(data.as_bytes()).map_err(Error::Io)
}
/// Errors fall through to the ordinary callback; only complete HTTP 200 bodies win.
pub fn callback(command: &str, params: &[(&str, &str)], env: &Environment) -> Option<String> {
    let socket = env.get("CCS_HELPER_SOCKET")?;
    let request = || -> std::io::Result<String> {
        let mut stream = UnixStream::connect(socket)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut pairs = params.to_vec();
        pairs.push((
            "prompt",
            env.get("FZF_PROMPT").map(String::as_str).unwrap_or(""),
        ));
        pairs.push((
            "port",
            env.get("FZF_PORT").map(String::as_str).unwrap_or(""),
        ));
        let path = command.strip_prefix('_').unwrap_or(command);
        let query = ccs_pytext::urlencode(&pairs);
        stream
            .write_all(format!("GET /{path}?{query} HTTP/1.0\r\nHost: ccs\r\n\r\n").as_bytes())?;
        let mut bytes = vec![];
        stream.read_to_end(&mut bytes)?;
        let contents = String::from_utf8(bytes)
            .map_err(|_| std::io::Error::other("invalid helper response"))?;
        let (headers, body) = contents
            .split_once("\r\n\r\n")
            .ok_or_else(|| std::io::Error::other("incomplete helper response"))?;
        if !headers.starts_with("HTTP/1.0 200 ") {
            return Err(std::io::Error::other("helper unavailable"));
        }
        let length = headers
            .split("\r\n")
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .and_then(|s| s.parse::<usize>().ok());
        if length != Some(body.len()) {
            return Err(std::io::Error::other("incomplete helper response"));
        }
        Ok(body.into())
    };
    request().ok()
}
pub fn run(_config: &Value, _args: &[std::ffi::OsString]) -> Result<Value> {
    Err(Error::Usage("helper is started by the picker".into()))
}
