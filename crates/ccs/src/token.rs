//! Best-effort, per-effective-user bearer cache.
//!
//! A stolen token permits reads across all hosts and writes to the named host,
//! with no purge or MCP tools, for at most its lifetime. The client secret in
//! the same protected directory can mint equivalent tokens without that limit.
//! Same-uid processes and root remain inside the accepted trust boundary.
//!
//! Cache errors never replace a successful credential grant with an error.
//! Rejected values are remembered by digest for the life of this manager; disk
//! invalidation is conditional and best effort. An unwritable cache cannot
//! provide a rejection registry across processes. Cross-process wall-clock
//! rollback cannot be fully detected; in-process lifetimes use Instant as well.
use crate::config::{encode, field, number, object, parse, string, text, Config};
use crate::errors::{Error, Result};
use ccs_pytext::json::Value;
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_CACHE: u64 = 32 * 1024;
const MAX_TOKEN: usize = 16 * 1024;
const MAX_LIFETIME: f64 = 3600.0;
const MARGIN: f64 = 60.0;

fn epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn fingerprint(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, bytes).as_ref())
}
fn warn_cache() {
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        eprintln!("ccs: token cache unavailable or unsafe; continuing without cache");
    }
}
fn invalid() -> io::Error {
    io::Error::other("unsafe token cache")
}

/// Deliberately has neither Debug nor Display.
pub(crate) struct Credential {
    pub secret: String,
    generation: String,
}
impl Credential {
    pub fn read(config: &Config) -> Result<Self> {
        let read = || -> io::Result<Self> {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(&config.secret_file)?;
            let meta = file.metadata()?;
            if !meta.is_file() || meta.len() > MAX_CACHE {
                return Err(invalid());
            }
            let mut bytes = Vec::new();
            file.take(MAX_CACHE + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_CACHE {
                return Err(invalid());
            }
            let secret = std::str::from_utf8(&bytes)
                .map_err(|_| invalid())?
                .trim()
                .to_owned();
            if secret.is_empty() {
                return Err(invalid());
            }
            // Include both content and generation metadata: replacement with the
            // same bytes still invalidates outstanding memory and disk entries.
            bytes.extend_from_slice(
                format!(
                    "\0{}:{}:{}:{}:{}:{}:{}",
                    meta.dev(),
                    meta.ino(),
                    meta.uid(),
                    meta.mtime(),
                    meta.mtime_nsec(),
                    meta.ctime(),
                    meta.ctime_nsec()
                )
                .as_bytes(),
            );
            Ok(Self {
                secret,
                generation: fingerprint(&bytes),
            })
        };
        read().map_err(|_| Error::Usage("client secret unreadable or empty".into()))
    }
}

#[derive(Clone, PartialEq)]
struct Key {
    endpoint: String,
    token_url: String,
    client_id: String,
    audience: String,
    generation: String,
    uid: u32,
}
impl Key {
    fn new(config: &Config, credential: &Credential) -> Self {
        Self {
            endpoint: config.endpoint.clone(),
            token_url: config.token_url.clone(),
            client_id: config.client_id.clone(),
            audience: config.audience.clone(),
            generation: credential.generation.clone(),
            uid: unsafe { libc::geteuid() },
        }
    }
    fn matches(&self, value: &Value) -> bool {
        [
            ("endpoint", &self.endpoint),
            ("token_url", &self.token_url),
            ("client_id", &self.client_id),
            ("audience", &self.audience),
            ("credential_generation", &self.generation),
        ]
        .iter()
        .all(|(k, v)| field(value, k).and_then(string).as_ref() == Some(v))
            && field(value, "euid").and_then(number) == Some(f64::from(self.uid))
    }
}

pub(crate) fn bearer_safe(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_TOKEN {
        return false;
    }
    let core = value.trim_end_matches('=');
    !core.is_empty()
        && core
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
}
fn jwt_shape(value: &str) -> bool {
    value.starts_with("eyJ")
        && value.split('.').count() == 3
        && value.split('.').all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// No Debug/Display: neither a diagnostic nor a panic should expose a token.
///
/// ```compile_fail
/// fn diagnostic(token: ccs::token::Token) { println!("{token:?}"); }
/// ```
/// ```compile_fail
/// fn diagnostic(token: ccs::token::Token) { println!("{token}"); }
/// ```
pub struct Token {
    value: String,
    key: Key,
    obtained: f64,
    expires: Option<f64>,
    start: Instant,
    budget: Option<Duration>,
    reusable: bool,
}
impl Token {
    fn fresh(
        value: String,
        expires_in: Option<f64>,
        key: Key,
        obtained: f64,
        start: Instant,
    ) -> Self {
        let ttl = expires_in
            .filter(|v| v.is_finite() && *v > 0.0)
            .map(|v| v.min(MAX_LIFETIME));
        let reusable = ttl.is_some_and(|v| v > MARGIN);
        Self {
            value,
            key,
            obtained,
            expires: ttl.map(|v| obtained + v),
            start,
            budget: ttl.map(|v| Duration::from_secs_f64(if reusable { v - MARGIN } else { v })),
            reusable,
        }
    }
    fn valid_at(&self, now: f64, monotonic: Instant) -> bool {
        now.is_finite()
            && self.obtained <= now + 300.0
            && self
                .expires
                .is_none_or(|v| now < v - if self.reusable { MARGIN } else { 0.0 })
            && self
                .budget
                .is_none_or(|b| monotonic.saturating_duration_since(self.start) < b)
    }
    fn decode(value: &Value, key: &Key, now: f64, start: Instant) -> Option<Self> {
        if field(value, "format").and_then(number) != Some(1.0) || !key.matches(value) {
            return None;
        }
        let token = field(value, "access_token").and_then(string)?;
        let obtained = field(value, "obtained_at").and_then(number)?;
        let expires = field(value, "expires_at").and_then(number)?;
        let lifetime = expires - obtained;
        if !now.is_finite()
            || !bearer_safe(&token)
            || !jwt_shape(&token)
            || obtained < 0.0
            || obtained > now + 300.0
            || !(lifetime > MARGIN && lifetime <= MAX_LIFETIME)
            || now >= expires - MARGIN
            || expires - now > MAX_LIFETIME
        {
            return None;
        }
        Some(Self {
            value: token,
            key: key.clone(),
            obtained,
            expires: Some(expires),
            start,
            budget: Some(Duration::from_secs_f64(
                (expires - now - MARGIN).min(lifetime - MARGIN),
            )),
            reusable: true,
        })
    }
    fn json(&self) -> Option<Value> {
        if !self.reusable || !jwt_shape(&self.value) {
            return None;
        }
        Some(object([
            ("format", Value::Number("1".into())),
            ("endpoint", text(&self.key.endpoint)),
            ("token_url", text(&self.key.token_url)),
            ("client_id", text(&self.key.client_id)),
            ("audience", text(&self.key.audience)),
            ("credential_generation", text(&self.key.generation)),
            ("euid", Value::Number(self.key.uid.to_string())),
            ("access_token", text(&self.value)),
            ("obtained_at", Value::Number(self.obtained.to_string())),
            ("expires_at", Value::Number(self.expires?.to_string())),
        ]))
    }
    pub(crate) fn value(&self) -> &str {
        &self.value
    }
}

/// Cache status never includes credential or bearer values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheStatus {
    Disabled,
    Miss,
    Memory,
    Disk,
    Refreshed,
    Rejected,
}
impl CacheStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Miss => "miss",
            Self::Memory => "memory",
            Self::Disk => "disk",
            Self::Refreshed => "refreshed",
            Self::Rejected => "rejected",
        }
    }
}

pub struct TokenManager {
    token: Option<Token>,
    rejected: Vec<String>,
    status: CacheStatus,
}
impl Default for TokenManager {
    fn default() -> Self {
        Self {
            token: None,
            rejected: Vec::new(),
            status: CacheStatus::Miss,
        }
    }
}
impl TokenManager {
    pub fn status(&self) -> CacheStatus {
        self.status
    }
    pub(crate) fn acquire<F>(&mut self, config: &Config, fresh: bool, fetch: F) -> Result<&Token>
    where
        F: FnOnce(&Credential) -> Result<(String, Option<f64>)>,
    {
        // Reading credentials precedes BOTH cache checks. Missing or rotated
        // credentials cannot leave a helper using an old in-memory bearer.
        let credential = match Credential::read(config) {
            Ok(c) => c,
            Err(e) => {
                self.token = None;
                return Err(e);
            }
        };
        let key = Key::new(config, &credential);
        if !fresh
            && self
                .token
                .as_ref()
                .is_some_and(|t| t.key == key && t.reusable && t.valid_at(epoch(), Instant::now()))
        {
            self.status = CacheStatus::Memory;
        } else {
            if let Some(stale) = self.token.take() {
                // A wall-clock rollback can leave the disk copy apparently
                // fresh after the monotonic memory budget has elapsed.
                if !stale.valid_at(epoch(), Instant::now()) {
                    let hash = fingerprint(stale.value.as_bytes());
                    if !self.rejected.contains(&hash) {
                        self.rejected.push(hash);
                    }
                }
            }
            let dir = Directory::open(config.path.parent().unwrap_or(Path::new(".")))
                .inspect_err(|_| warn_cache())
                .ok();
            if !fresh {
                self.token = dir
                    .as_ref()
                    .and_then(|d| d.read_token(&key, &self.rejected));
            }
            if self.token.is_some() {
                self.status = CacheStatus::Disk;
            } else {
                // Keeping this file alive preserves the flock inode. It is
                // never unlinked, including on process exit or lock timeout.
                let lock = dir
                    .as_ref()
                    .and_then(|d| d.lock().inspect_err(|_| warn_cache()).ok());
                if lock.is_some() {
                    if let Some(d) = &dir {
                        d.clean_orphans();
                    }
                    if !fresh {
                        self.token = dir
                            .as_ref()
                            .and_then(|d| d.read_token(&key, &self.rejected));
                    }
                }
                if self.token.is_some() {
                    self.status = CacheStatus::Disk;
                } else {
                    let obtained = epoch();
                    let start = Instant::now();
                    let (value, ttl) = fetch(&credential)?;
                    if !bearer_safe(&value)
                        || self.rejected.contains(&fingerprint(value.as_bytes()))
                    {
                        return Err(Error::Unavailable(
                            "token endpoint returned an invalid or previously rejected bearer"
                                .into(),
                        ));
                    }
                    let token = Token::fresh(value, ttl, key, obtained, start);
                    if !token.valid_at(epoch(), Instant::now()) {
                        return Err(Error::Unavailable(
                            "token expired before request could be sent".into(),
                        ));
                    }
                    if lock.is_some() {
                        if let Some(d) = &dir {
                            if d.save(&token).is_err() {
                                warn_cache();
                            }
                        }
                    }
                    self.token = Some(token);
                    self.status = CacheStatus::Refreshed;
                }
            }
        }
        self.token
            .as_ref()
            .ok_or_else(|| Error::Unavailable("token unavailable".into()))
    }
    pub(crate) fn reject(&mut self, config: &Config) {
        if let Some(token) = self.token.take() {
            let hash = fingerprint(token.value.as_bytes());
            if !self.rejected.contains(&hash) {
                self.rejected.push(hash);
            }
            if let Ok(dir) = Directory::open(config.path.parent().unwrap_or(Path::new("."))) {
                if let Ok(_lock) = dir.lock() {
                    dir.invalidate(&token.value);
                }
            }
        }
        self.status = CacheStatus::Rejected;
    }
}

/// Wave 0 metadata boundary. Bearer material is accessible only to Api.
pub fn get(config: &Value) -> Result<Value> {
    let config = Config::from_boundary(config)?;
    let status = if config.is_tailnet() {
        CacheStatus::Disabled
    } else {
        let credential = Credential::read(&config)?;
        let key = Key::new(&config, &credential);
        if Directory::open(config.path.parent().unwrap_or(Path::new(".")))
            .ok()
            .and_then(|d| d.read_token(&key, &[]))
            .is_some()
        {
            CacheStatus::Disk
        } else {
            CacheStatus::Miss
        }
    };
    Ok(object([("status", text(status.as_str()))]))
}

struct Directory(File);
impl Directory {
    fn open(path: &Path) -> io::Result<Self> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut dir = File::open("/")?;
        let uid = unsafe { libc::geteuid() };
        for part in absolute.components() {
            match part {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => {
                    let name = CString::new(name.as_bytes()).map_err(|_| invalid())?;
                    let fd = unsafe {
                        libc::openat(
                            dir.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY
                                | libc::O_DIRECTORY
                                | libc::O_NOFOLLOW
                                | libc::O_NONBLOCK
                                | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    dir = unsafe { File::from_raw_fd(fd) };
                    let meta = dir.metadata()?;
                    // Root-owned sticky ancestors (/tmp) prevent other users
                    // renaming our child. All other writable ancestors fail.
                    let sticky_root = meta.uid() == 0 && meta.mode() & 0o1000 != 0;
                    if (meta.uid() != uid && meta.uid() != 0)
                        || (meta.mode() & 0o022 != 0 && !sticky_root)
                    {
                        return Err(invalid());
                    }
                }
                _ => return Err(invalid()),
            }
        }
        let meta = dir.metadata()?;
        if meta.uid() != uid || meta.mode() & 0o777 != 0o700 {
            return Err(invalid());
        }
        Ok(Self(dir))
    }
    fn open_file(&self, name: &str, flags: i32) -> io::Result<File> {
        let name = CString::new(name).map_err(|_| invalid())?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o777 != 0o600
            || meta.nlink() != 1
        {
            return Err(invalid());
        }
        Ok(file)
    }
    fn read(&self) -> Option<Value> {
        let file = match self.open_file("token.json", libc::O_RDONLY) {
            Ok(file) => file,
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    warn_cache();
                }
                return None;
            }
        };
        if file.metadata().ok()?.len() > MAX_CACHE {
            return None;
        }
        let mut bytes = Vec::new();
        file.take(MAX_CACHE + 1).read_to_end(&mut bytes).ok()?;
        if bytes.len() as u64 > MAX_CACHE {
            return None;
        }
        parse(&bytes)
    }
    fn read_token(&self, key: &Key, rejected: &[String]) -> Option<Token> {
        let token = Token::decode(&self.read()?, key, epoch(), Instant::now())?;
        if rejected.contains(&fingerprint(token.value.as_bytes())) {
            None
        } else {
            Some(token)
        }
    }
    fn lock(&self) -> io::Result<File> {
        let file = self.open_file("token.lock", libc::O_RDWR | libc::O_CREAT)?;
        let start = Instant::now();
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(file);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::WouldBlock
                || start.elapsed() >= Duration::from_secs(2)
            {
                return Err(error);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn unlink(&self, name: &str) {
        if let Ok(name) = CString::new(name) {
            unsafe {
                libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), 0);
            }
        }
    }
    fn invalidate(&self, rejected: &str) {
        if self
            .read()
            .and_then(|v| field(&v, "access_token").and_then(string))
            .as_deref()
            == Some(rejected)
        {
            self.unlink("token.json");
        }
    }
    fn save(&self, token: &Token) -> io::Result<()> {
        let Some(value) = token.json() else {
            return Ok(());
        };
        let bytes = encode(&value).map_err(|_| invalid())?;
        if bytes.len() as u64 > MAX_CACHE {
            return Err(invalid());
        }
        let mut nonce = [0; 16];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| invalid())?;
        let name = format!(".token.{}.{}", std::process::id(), hex(&nonce));
        let source = CString::new(name.as_bytes()).map_err(|_| invalid())?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                source.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let cleanup = Temporary {
            dir: self,
            name: &name,
        };
        if file.metadata()?.mode() & 0o777 != 0o600 {
            return Err(invalid());
        }
        file.write_all(bytes.as_bytes())?;
        file.sync_all()?;
        let source = CString::new(name.as_bytes()).map_err(|_| invalid())?;
        let target = c"token.json";
        if unsafe {
            libc::renameat(
                self.0.as_raw_fd(),
                source.as_ptr(),
                self.0.as_raw_fd(),
                target.as_ptr(),
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        drop(cleanup);
        Ok(())
    }
    fn clean_orphans(&self) {
        // fdopendir owns its descriptor. A fresh openat avoids sharing the
        // directory offset with this Directory or a subsequent cleanup pass.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return;
        }
        let entries = unsafe { libc::fdopendir(fd) };
        if entries.is_null() {
            unsafe {
                libc::close(fd);
            }
            return;
        }
        loop {
            let entry = unsafe { libc::readdir(entries) };
            if entry.is_null() {
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            let Ok(name) = std::str::from_utf8(name) else {
                continue;
            };
            let parts: Vec<_> = name.split('.').collect();
            if parts.len() == 4
                && parts[0].is_empty()
                && parts[1] == "token"
                && !parts[2].is_empty()
                && parts[2].bytes().all(|b| b.is_ascii_digit())
                && parts[3].len() == 32
                && parts[3].bytes().all(|b| b.is_ascii_hexdigit())
                && self.open_file(name, libc::O_RDONLY).is_ok()
            {
                self.unlink(name);
            }
        }
        unsafe {
            libc::closedir(entries);
        }
    }
}
struct Temporary<'a> {
    dir: &'a Directory,
    name: &'a str,
}
impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        self.dir.unlink(self.name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;

    // Deliberately synthetic: not signed credentials or a real issuer's JWT.
    const SYNTHETIC: &str = "eyJtest.payload.signature";
    const REPLACEMENT: &str = "eyJtest.replacement.signature";
    struct Fixture {
        root: PathBuf,
        config: Config,
    }
    impl Fixture {
        fn new() -> Self {
            let mut nonce = [0; 16];
            SystemRandom::new().fill(&mut nonce).unwrap();
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("ccs-auth-{}", hex(&nonce)));
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let config = Config {
                path: root.join("config.json"),
                endpoint: "http://127.0.0.1/api".into(),
                token_url: "http://127.0.0.1/token".into(),
                client_id: "synthetic-client".into(),
                audience: "memory".into(),
                secret_file: root.join("client.secret"),
                host_label: "test".into(),
                auth_type: "client_credentials".into(),
                hmac_key_file: root.join("hmac.key"),
            };
            std::fs::write(&config.secret_file, "synthetic-credential").unwrap();
            Self { root, config }
        }
        fn key(&self) -> Key {
            Key::new(&self.config, &Credential::read(&self.config).unwrap())
        }
        fn token(&self) -> Token {
            Token::fresh(
                SYNTHETIC.into(),
                Some(3599.0),
                self.key(),
                epoch(),
                Instant::now(),
            )
        }
        fn save(&self) {
            Directory::open(&self.root)
                .unwrap()
                .save(&self.token())
                .unwrap();
        }
        fn no_temps(&self) {
            assert!(
                !std::fs::read_dir(&self.root).unwrap().any(|e| e
                    .unwrap()
                    .file_name()
                    .as_bytes()
                    .starts_with(b".token.")),
                "temporary token copy remains"
            );
        }
        fn get(&self) -> TokenManager {
            let mut manager = TokenManager::default();
            manager
                .acquire(&self.config, false, |_| {
                    Ok((REPLACEMENT.into(), Some(3599.0)))
                })
                .unwrap();
            manager
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    fn set(value: &mut Value, key: &'static str, replacement: Value) {
        if let Value::Object(items) = value {
            let k: Vec<_> = key.chars().map(u32::from).collect();
            items.retain(|(n, _)| *n != k);
            items.push((k, replacement));
        }
    }

    #[test]
    fn validates_types_bounds_and_bearer_grammar() {
        let f = Fixture::new();
        let key = f.key();
        let now = epoch();
        let original = f.token().json().unwrap();
        assert!(Token::decode(&original, &key, now, Instant::now()).is_some());
        let mut expired = original.clone();
        set(
            &mut expired,
            "obtained_at",
            Value::Number((now - 4000.0).to_string()),
        );
        set(
            &mut expired,
            "expires_at",
            Value::Number((now - 401.0).to_string()),
        );
        assert!(
            Token::decode(&expired, &key, now, Instant::now()).is_none(),
            "expired token accepted"
        );
        let cases = [
            ("format", text("1")),
            ("format", Value::Bool(true)),
            ("access_token", Value::Array(vec![])),
            ("access_token", text("eyJbad.\r\nvalue.sig")),
            ("access_token", text("eyJbad.a.sig=")),
            ("access_token", text("a".repeat(MAX_TOKEN + 1))),
            ("obtained_at", Value::Number("NaN".into())),
            ("obtained_at", Value::Number((now + 301.0).to_string())),
            ("expires_at", Value::Number("Infinity".into())),
            ("expires_at", text("999999999999")),
            ("expires_at", Value::Number((now + 9999.0).to_string())),
            ("expires_at", Value::Number((now + 59.0).to_string())),
            ("endpoint", text("http://127.0.0.1/other")),
            ("token_url", text("http://127.0.0.1/other")),
            ("client_id", text("other")),
            ("audience", text("other")),
            ("credential_generation", text("other")),
            ("euid", Value::Number("4294967295".into())),
        ];
        for (name, bad) in cases {
            let mut value = original.clone();
            set(&mut value, name, bad);
            assert!(
                Token::decode(&value, &key, now, Instant::now()).is_none(),
                "accepted invalid field {name}"
            );
        }
        for bad in ["", "space value", "tab\tvalue", "é", "a=b", "=", "\u{7f}"] {
            assert!(!bearer_safe(bad));
        }
        assert!(bearer_safe("abc-._~+/=="));
    }

    #[test]
    fn clock_step_does_not_extend_memory_lifetime() {
        let f = Fixture::new();
        let start = Instant::now();
        let token = Token::fresh(SYNTHETIC.into(), Some(3600.0), f.key(), 1000.0, start);
        assert!(token.valid_at(1100.0, start + Duration::from_secs(100)));
        assert!(
            !token.valid_at(1100.0, start + Duration::from_secs(3601)),
            "wall-clock rollback extended bearer lifetime"
        );
        assert!(
            !token.valid_at(4600.0, start + Duration::from_secs(1)),
            "forward clock step ignored"
        );
        assert!(!token.valid_at(699.0, start), "large rollback ignored");
    }

    #[test]
    fn cache_hit_and_memory_hit_do_not_fetch() {
        let f = Fixture::new();
        f.save();
        let mut manager = TokenManager::default();
        manager
            .acquire(&f.config, false, |_| panic!("unexpected grant"))
            .unwrap();
        assert_eq!(manager.status(), CacheStatus::Disk);
        manager
            .acquire(&f.config, false, |_| panic!("unexpected grant"))
            .unwrap();
        assert_eq!(manager.status(), CacheStatus::Memory);
        f.no_temps();
        assert_eq!(
            std::fs::metadata(f.root.join("token.json")).unwrap().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn bad_permissions_symlink_fifo_and_huge_file_miss_cache() {
        for case in [
            "mode",
            "symlink",
            "fifo",
            "directory",
            "huge",
            "json",
            "hardlink",
        ] {
            let f = Fixture::new();
            f.save();
            let cache = f.root.join("token.json");
            match case {
                "mode" => std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o644))
                    .unwrap(),
                "symlink" => {
                    std::fs::rename(&cache, f.root.join("other")).unwrap();
                    symlink(f.root.join("other"), &cache).unwrap();
                }
                "fifo" => {
                    std::fs::remove_file(&cache).unwrap();
                    let name = CString::new(cache.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                "directory" => {
                    std::fs::remove_file(&cache).unwrap();
                    std::fs::create_dir(&cache).unwrap();
                }
                "huge" => {
                    let mut bytes = encode(&f.token().json().unwrap()).unwrap().into_bytes();
                    bytes.resize(32769, b' ');
                    std::fs::write(&cache, bytes).unwrap();
                }
                "json" => std::fs::write(&cache, b"{\"format\":true,\"access_token\":[]}").unwrap(),
                "hardlink" => std::fs::hard_link(&cache, f.root.join("other")).unwrap(),
                _ => unreachable!(),
            }
            let start = Instant::now();
            assert_eq!(
                f.get().status(),
                CacheStatus::Refreshed,
                "unsafe cache accepted: {case}"
            );
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "nonregular file blocked read"
            );
            f.no_temps();
        }
    }

    #[test]
    fn expiry_rotation_and_endpoint_invalidate_memory_and_disk() {
        let mut f = Fixture::new();
        f.save();
        let mut manager = f.get();
        manager.token.as_mut().unwrap().start = Instant::now() - Duration::from_secs(3601);
        let disk = f.root.join("token.json");
        let mut value = f.token().json().unwrap();
        set(
            &mut value,
            "obtained_at",
            Value::Number((epoch() - 4000.0).to_string()),
        );
        set(
            &mut value,
            "expires_at",
            Value::Number((epoch() - 401.0).to_string()),
        );
        std::fs::write(&disk, encode(&value).unwrap()).unwrap();
        manager
            .acquire(&f.config, false, |_| Ok((REPLACEMENT.into(), Some(3600.0))))
            .unwrap();
        assert_eq!(manager.status(), CacheStatus::Refreshed);
        std::fs::write(&f.config.secret_file, "rotated-synthetic-credential").unwrap();
        manager
            .acquire(&f.config, false, |_| {
                Ok(("eyJtest.rotated.signature".into(), Some(3600.0)))
            })
            .unwrap();
        assert_eq!(manager.status(), CacheStatus::Refreshed);
        f.config.endpoint.push_str("/changed");
        manager
            .acquire(&f.config, false, |_| Ok((REPLACEMENT.into(), Some(3600.0))))
            .unwrap();
        assert_eq!(manager.status(), CacheStatus::Refreshed);
        std::fs::remove_file(&f.config.secret_file).unwrap();
        assert!(manager
            .acquire(&f.config, false, |_| panic!("unreadable credential grant"))
            .is_err());
        assert!(manager.token.is_none());
    }

    #[test]
    fn monotonic_expiry_cannot_reload_the_same_disk_value() {
        let f = Fixture::new();
        f.save();
        let mut manager = f.get();
        manager.token.as_mut().unwrap().start = Instant::now() - Duration::from_secs(3601);
        let mut fetched = false;
        manager
            .acquire(&f.config, false, |_| {
                fetched = true;
                Ok((REPLACEMENT.into(), Some(3599.0)))
            })
            .unwrap();
        assert!(
            fetched,
            "expired monotonic budget was reset by reading the disk copy"
        );
    }

    #[test]
    fn unknown_expiry_is_single_use_and_opaque_tokens_are_not_saved() {
        for ttl in [None, Some(0.0), Some(60.0), Some(f64::NAN)] {
            let f = Fixture::new();
            let mut manager = TokenManager::default();
            manager
                .acquire(&f.config, false, |_| Ok((SYNTHETIC.into(), ttl)))
                .unwrap();
            assert!(!f.root.join("token.json").exists());
            let mut fetched = false;
            manager
                .acquire(&f.config, false, |_| {
                    fetched = true;
                    Ok((REPLACEMENT.into(), Some(3599.0)))
                })
                .unwrap();
            assert!(fetched, "expiry-unknown bearer was reused");
        }
        let f = Fixture::new();
        let mut manager = TokenManager::default();
        manager
            .acquire(&f.config, false, |_| {
                Ok(("opaque-test-value".into(), Some(3599.0)))
            })
            .unwrap();
        assert!(!f.root.join("token.json").exists());
    }

    #[test]
    fn rejection_invalidates_only_matching_file_and_never_reuses_value() {
        for case in ["same", "changed", "gone", "malformed"] {
            let f = Fixture::new();
            f.save();
            let mut manager = f.get();
            let cache = f.root.join("token.json");
            match case {
                "changed" => {
                    let mut t = f.token();
                    t.value = REPLACEMENT.into();
                    Directory::open(&f.root).unwrap().save(&t).unwrap();
                }
                "gone" => std::fs::remove_file(&cache).unwrap(),
                "malformed" => std::fs::write(&cache, "[]").unwrap(),
                _ => {}
            }
            manager.reject(&f.config);
            assert!(manager.token.is_none());
            assert_eq!(
                cache.exists(),
                matches!(case, "changed" | "malformed"),
                "conditional invalidation: {case}"
            );
            assert!(
                manager
                    .acquire(&f.config, true, |_| Ok((SYNTHETIC.into(), Some(3599.0))))
                    .is_err(),
                "rejected bearer was accepted again"
            );
            assert!(manager.token.is_none());
        }
    }

    #[test]
    fn unwritable_lock_and_failed_rename_do_not_fail_grant() {
        for case in ["lock", "rename", "directory"] {
            let f = Fixture::new();
            match case {
                "lock" => {
                    std::fs::write(f.root.join("token.lock"), "").unwrap();
                    std::fs::set_permissions(
                        f.root.join("token.lock"),
                        std::fs::Permissions::from_mode(0o000),
                    )
                    .unwrap();
                }
                "rename" => std::fs::create_dir(f.root.join("token.json")).unwrap(),
                "directory" => {
                    std::fs::set_permissions(&f.root, std::fs::Permissions::from_mode(0o755))
                        .unwrap()
                }
                _ => unreachable!(),
            }
            assert_eq!(f.get().status(), CacheStatus::Refreshed);
            f.no_temps();
        }
    }

    #[test]
    fn pinned_directory_rejects_symlinks_and_survives_parent_swap() {
        let f = Fixture::new();
        let parent = f.root.join("parent");
        let leaf = parent.join("cache");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(&leaf).unwrap();
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pinned = Directory::open(&leaf).unwrap();
        std::fs::rename(&parent, f.root.join("moved")).unwrap();
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&f.root, &leaf).unwrap();
        assert!(Directory::open(&leaf).is_err());
        pinned.save(&f.token()).unwrap();
        assert!(f.root.join("moved/cache/token.json").exists());
        assert!(
            !f.root.join("token.json").exists(),
            "parent swap redirected save"
        );
    }

    #[test]
    fn orphan_cleanup_only_removes_our_safe_temporary_files() {
        let f = Fixture::new();
        let dir = Directory::open(&f.root).unwrap();
        let orphan = ".token.123.00000000000000000000000000000000";
        let unsafe_name = ".token.124.00000000000000000000000000000000";
        let mut file = dir
            .open_file(orphan, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)
            .unwrap();
        file.write_all(b"synthetic orphan").unwrap();
        drop(file);
        symlink(&f.config.secret_file, f.root.join(unsafe_name)).unwrap();
        std::fs::write(f.root.join(".token.unrelated"), b"keep").unwrap();
        let lock = dir.lock().unwrap();
        let inode = lock.metadata().unwrap().ino();
        dir.clean_orphans();
        drop(lock);
        assert!(!f.root.join(orphan).exists());
        assert!(f.root.join(unsafe_name).is_symlink());
        assert!(f.root.join(".token.unrelated").exists());
        assert_eq!(
            dir.lock().unwrap().metadata().unwrap().ino(),
            inode,
            "persistent lock inode changed"
        );
    }
}
