//! HTTP boundary. Redirects never replay credentials; API 401 retry is once.
use crate::config::{encode, field, number, object, parse, string, text, Config};
use crate::errors::{Error, Result};
use crate::token::{CacheStatus, Credential, TokenManager};
use base64::Engine;
use ccs_pytext::json::Value;
use std::io::{Read, Write};
use std::time::Duration;
use ureq::AsSendBody;

pub const USER_AGENT: &str = concat!("ccs/", env!("CARGO_PKG_VERSION"));
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Response {
    pub status: u16,
    pub headers: ureq::http::HeaderMap,
    pub body: Vec<u8>,
}
impl Response {
    pub fn json(&self) -> Option<Value> {
        if self.body.is_empty() {
            Some(Value::Null)
        } else {
            parse(&self.body)
        }
    }
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)?.to_str().ok()
    }
}

pub struct Api {
    pub config: Config,
    pub timeout: Duration,
    agent: ureq::Agent,
    tokens: TokenManager,
}
#[derive(Default)]
struct RequestOptions {
    gzip_body: bool,
    preserve_body_eof: bool,
}
struct BodyReadOptions {
    limit: Option<u64>,
    preserve_eof: bool,
}

impl Api {
    pub fn new(config: Config) -> Self {
        Self::with_timeout(config, DEFAULT_TIMEOUT)
    }
    pub fn with_timeout(config: Config, timeout: Duration) -> Self {
        let agent = agent_configuration(None, None).new_agent();
        Self {
            config,
            timeout,
            agent,
            tokens: TokenManager::default(),
        }
    }
    pub fn token_status(&self) -> CacheStatus {
        if self.config.is_tailnet() {
            CacheStatus::Disabled
        } else {
            self.tokens.status()
        }
    }
    pub fn get(
        &mut self,
        path: &str,
        params: &[(&str, &str)],
        timeout: Option<Duration>,
    ) -> Result<Response> {
        self.request("GET", path, None, params, false, timeout)
    }
    /// Archive downloads retain premature body EOF as an internal I/O error.
    /// Existing requests, including token acquisition, keep their error policy.
    pub fn get_archive(
        &mut self,
        path: &str,
        params: &[(&str, &str)],
        timeout: Option<Duration>,
    ) -> Result<Response> {
        self.request_with_options(
            "GET",
            path,
            None,
            params,
            RequestOptions {
                preserve_body_eof: true,
                ..RequestOptions::default()
            },
            timeout,
        )
    }
    pub fn post(
        &mut self,
        path: &str,
        body: &Value,
        gzip_body: bool,
        timeout: Option<Duration>,
    ) -> Result<Response> {
        self.request("POST", path, Some(body), &[], gzip_body, timeout)
    }
    pub fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        params: &[(&str, &str)],
        gzip_body: bool,
        timeout: Option<Duration>,
    ) -> Result<Response> {
        self.request_with_options(
            method,
            path,
            body,
            params,
            RequestOptions {
                gzip_body,
                ..RequestOptions::default()
            },
            timeout,
        )
    }
    fn request_with_options(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        params: &[(&str, &str)],
        options: RequestOptions,
        timeout: Option<Duration>,
    ) -> Result<Response> {
        // A path is appended to the configured origin; never accept an
        // absolute URL or a network-path reference from a caller.
        if !path.starts_with('/') || path.starts_with("//") {
            return Err(Error::Usage(
                "API path must start with a single slash".into(),
            ));
        }
        let mut url = format!("{}{}", self.config.endpoint, path);
        if !params.is_empty() {
            url.push('?');
            url.push_str(&form(params));
        }
        let mut data = body
            .map(encode)
            .transpose()?
            .unwrap_or_default()
            .into_bytes();
        if body.is_some() && options.gzip_body {
            let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
            gzip.write_all(&data)
                .map_err(|_| Error::Unavailable("gzip encoding failed".into()))?;
            data = gzip
                .finish()
                .map_err(|_| Error::Unavailable("gzip encoding failed".into()))?;
        }
        for attempt in 0..2 {
            let mut headers = Vec::new();
            if body.is_some() {
                headers.push(("Content-Type", "application/json".to_owned()));
            }
            if !self.config.is_tailnet() {
                let config = &self.config;
                let agent = &self.agent;
                // Token acquisition uses the Api default timeout, matching
                // Python. The per-request override applies to the API send.
                let token_timeout = self.timeout;
                let token = self.tokens.acquire(config, attempt == 1, |credential| {
                    fetch_token(agent, config, credential, token_timeout)
                })?;
                headers.push(("Authorization", format!("Bearer {}", token.value())));
            }
            // No Content-Encoding: the receiver recognises gzip magic bytes.
            let response = send_with_body_options(
                &self.agent,
                method,
                &url,
                &headers,
                &data,
                timeout.unwrap_or(self.timeout),
                BodyReadOptions {
                    limit: None,
                    preserve_eof: options.preserve_body_eof,
                },
            )?;
            if response.status == 401 && !self.config.is_tailnet() {
                self.tokens.reject(&self.config);
                if attempt == 0 {
                    continue;
                }
            }
            return Ok(response);
        }
        Err(Error::Unavailable("authentication retry exhausted".into()))
    }
}

fn fetch_token(
    agent: &ureq::Agent,
    config: &Config,
    credential: &Credential,
    timeout: Duration,
) -> Result<(String, Option<f64>)> {
    let basic = base64::engine::general_purpose::STANDARD.encode(format!(
        "{}:{}",
        quote(&config.client_id, false),
        quote(&credential.secret, false)
    ));
    let mut params = vec![("grant_type", "client_credentials")];
    if !config.audience.is_empty() {
        params.push(("audience", &config.audience));
    }
    let headers = [
        ("Authorization", format!("Basic {basic}")),
        ("Content-Type", "application/x-www-form-urlencoded".into()),
    ];
    let response = send(
        agent,
        "POST",
        &config.token_url,
        &headers,
        form(&params).as_bytes(),
        timeout,
        Some(32 * 1024),
    )?;
    if response.status != 200 {
        return Err(Error::Unavailable(format!(
            "token endpoint answered HTTP {}",
            response.status
        )));
    }
    let value = response.json().unwrap_or(Value::Null);
    let token = field(&value, "access_token")
        .and_then(string)
        .filter(|s| crate::token::bearer_safe(s))
        .ok_or_else(|| {
            Error::Unavailable("token endpoint answered 200 without a valid access_token".into())
        })?;
    let ttl = field(&value, "expires_in").and_then(number);
    Ok((token, ttl))
}

fn send(
    agent: &ureq::Agent,
    method: &str,
    url: &str,
    headers: &[(&str, String)],
    data: &[u8],
    timeout: Duration,
    limit: Option<u64>,
) -> Result<Response> {
    send_with_body_options(
        agent,
        method,
        url,
        headers,
        data,
        timeout,
        BodyReadOptions {
            limit,
            preserve_eof: false,
        },
    )
}
fn send_with_body_options(
    agent: &ureq::Agent,
    method: &str,
    url: &str,
    headers: &[(&str, String)],
    data: &[u8],
    timeout: Duration,
    options: BodyReadOptions,
) -> Result<Response> {
    let mut request = ureq::http::Request::builder()
        .method(method)
        .uri(url)
        .header("Accept", "application/json")
        .header("User-Agent", USER_AGENT)
        .header("Connection", "close");
    for (key, value) in headers {
        let mut value = ureq::http::HeaderValue::from_str(value)
            .map_err(|_| Error::Unavailable("invalid HTTP header".into()))?;
        if key.eq_ignore_ascii_case("authorization") {
            value.set_sensitive(true);
        }
        request = request.header(*key, value);
    }
    let mut data = data;
    let mut absent = ();
    let payload = if data.is_empty() && matches!(method, "GET" | "HEAD") {
        absent.as_body()
    } else {
        data.as_body()
    };
    let request = request
        .body(payload)
        .map_err(|_| Error::Unavailable("invalid HTTP request".into()))?;
    let proxy = proxy_for_url(url, |name| std::env::var(name).ok())?;
    let uses_tls = url.starts_with("https:")
        || proxy
            .as_ref()
            .is_some_and(|p| p.protocol() == ureq::ProxyProtocol::Https);
    let request = agent
        .configure_request(request)
        .proxy(proxy)
        .tls_config(if uses_tls {
            tls_from_env()?
        } else {
            ureq::tls::TlsConfig::default()
        })
        .timeout_global(None)
        .timeout_per_call(None)
        .timeout_resolve(Some(timeout))
        .timeout_connect(Some(timeout))
        .timeout_send_request(Some(timeout))
        .timeout_send_body(None)
        .timeout_recv_response(Some(timeout))
        .timeout_recv_body(None)
        .timeout_per_read(Some(timeout))
        .timeout_per_write(Some(timeout))
        .build();
    let mut response = agent
        .run(request)
        .map_err(|_| Error::Unavailable("HTTP transport failed".into()))?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let mut body = Vec::new();
    let read = response
        .body_mut()
        .as_reader()
        .take(options.limit.map_or(u64::MAX, |v| v + 1))
        .read_to_end(&mut body);
    if options.preserve_eof && status >= 300 && read.is_err() {
        // urllib's HTTPError path retains the HTTP status even when reading
        // its diagnostic body fails. Ordinary API callers keep their policy.
        body.clear();
    } else {
        read.map_err(|error| {
            if options.preserve_eof && error.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::Io(error)
            } else {
                Error::Unavailable("HTTP response read failed".into())
            }
        })?;
    }
    if options.limit.is_some_and(|v| body.len() as u64 > v) {
        return Err(Error::Unavailable(
            "token endpoint response too large".into(),
        ));
    }
    Ok(Response {
        status,
        headers,
        body,
    })
}

// urllib gives a present lowercase value (even empty) precedence over uppercase.
// ALL_PROXY is deliberately never consulted. CGI HTTP_PROXY is untrusted.
fn proxy_for_url(url: &str, env: impl Fn(&str) -> Option<String>) -> Result<Option<ureq::Proxy>> {
    let uri = url
        .parse::<ureq::http::Uri>()
        .map_err(|_| Error::Unavailable("invalid HTTP URL".into()))?;
    let scheme = uri.scheme_str().unwrap_or("");
    let setting = |name: &str| env(name).or_else(|| env(&name.to_ascii_uppercase()));
    if setting("no_proxy").is_some_and(|value| bypass_proxy(&uri, &value)) {
        return Ok(None);
    }
    let lower = format!("{scheme}_proxy");
    let selected = env(&lower).or_else(|| {
        if scheme == "http" && env("REQUEST_METHOD").is_some() {
            None
        } else {
            env(&lower.to_ascii_uppercase())
        }
    });
    selected
        .filter(|s| !s.is_empty())
        .map(|s| {
            ureq::Proxy::new(&s)
                .map_err(|_| Error::Unavailable("invalid proxy configuration".into()))
        })
        .transpose()
}
fn bypass_proxy(uri: &ureq::http::Uri, exclusions: &str) -> bool {
    if exclusions == "*" {
        return true;
    }
    let host = uri.host().unwrap_or("").to_ascii_lowercase();
    let authority = uri
        .authority()
        .map(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    exclusions.split(',').any(|entry| {
        let name = entry.trim().trim_start_matches('.').to_ascii_lowercase();
        !name.is_empty()
            && (host == name
                || authority == name
                || host.ends_with(&format!(".{name}"))
                || authority.ends_with(&format!(".{name}")))
    })
}
fn tls_from_env() -> Result<ureq::tls::TlsConfig> {
    tls_from_file(
        std::env::var_os("SSL_CERT_FILE")
            .as_deref()
            .map(std::path::Path::new),
    )
}
fn tls_from_file(path: Option<&std::path::Path>) -> Result<ureq::tls::TlsConfig> {
    let Some(path) = path else {
        return Ok(ureq::tls::TlsConfig::default());
    };
    let bytes =
        std::fs::read(path).map_err(|_| Error::Unavailable("SSL_CERT_FILE unreadable".into()))?;
    let mut certificates = Vec::new();
    for item in ureq::tls::parse_pem(&bytes) {
        if let ureq::tls::PemItem::Certificate(cert) =
            item.map_err(|_| Error::Unavailable("SSL_CERT_FILE invalid PEM".into()))?
        {
            certificates.push(cert);
        }
    }
    if certificates.is_empty() {
        return Err(Error::Unavailable(
            "SSL_CERT_FILE contains no certificates".into(),
        ));
    }
    // Specific replaces WebPki; it never augments the built-in roots.
    Ok(ureq::tls::TlsConfig::builder()
        .root_certs(certificates.into())
        .build())
}

fn quote(value: &str, plus: bool) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(b))
            }
            b' ' if plus => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
fn form(params: &[(&str, &str)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", quote(k, true), quote(v, true)))
        .collect::<Vec<_>>()
        .join("&")
}

/// The Wave 0 boundary returns status, parsed body and response headers.
/// Use the typed Api to retain tokens/connections in a long-lived helper.
pub fn request(config: &Value, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
    let response =
        Api::new(Config::from_boundary(config)?).request(method, path, body, &[], false, None)?;
    let headers = Value::Object(
        response
            .headers
            .iter()
            .filter_map(|(k, v)| {
                Some((
                    k.as_str().chars().map(u32::from).collect(),
                    text(v.to_str().ok()?),
                ))
            })
            .collect(),
    );
    Ok(object([
        ("status", Value::Number(response.status.to_string())),
        ("headers", headers),
        ("body", response.json().unwrap_or(Value::Null)),
    ]))
}

// Ordinary and pooled agents use the same wire policy. Only idle capacity differs.
fn agent_configuration(
    idle: Option<usize>,
    tls: Option<ureq::tls::TlsConfig>,
) -> ureq::config::Config {
    let builder = ureq::Agent::config_builder()
        .proxy(None)
        .accept_encoding("identity")
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false);
    let builder = if let Some(tls) = tls {
        builder.tls_config(tls)
    } else {
        builder
    };
    match idle {
        Some(count) => builder.max_idle_connections_per_host(count).build(),
        None => builder.build(),
    }
}
fn bearer_digest(value: &str) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, value.as_bytes());
    let mut hash = [0; 32];
    hash.copy_from_slice(digest.as_ref());
    hash
}
// Rebuilds caused by config changes must not forget a process-wide rejection.
fn rejected_bearers() -> &'static std::sync::Mutex<std::collections::HashSet<[u8; 32]>> {
    static REJECTED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<[u8; 32]>>> =
        std::sync::OnceLock::new();
    REJECTED.get_or_init(Default::default)
}
fn recover_lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // No network/file I/O happens under these locks. Preserve rejection history
    // on poison; a panicking acquisition rebuilds its private TokenManager.
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
fn rejected(hash: &[u8; 32]) -> bool {
    recover_lock(rejected_bearers()).contains(hash)
}
pub(crate) fn bearer_rejected(value: &str) -> bool {
    rejected(&bearer_digest(value))
}
pub(crate) fn remember_rejected(value: &str) {
    recover_lock(rejected_bearers()).insert(bearer_digest(value));
}
#[derive(Default)]
struct PoolTokens {
    manager: TokenManager,
    last: Option<[u8; 32]>,
}
struct FlightState {
    available: Option<PoolTokens>,
    failed_until: Option<std::time::Instant>,
}
#[cfg(test)]
type AcquireHook = Box<dyn FnOnce(&str) + Send>;
struct TokenFlight {
    state: std::sync::Mutex<FlightState>,
    changed: std::sync::Condvar,
    #[cfg(test)]
    after_acquire: std::sync::Mutex<Option<AcquireHook>>,
}
impl Default for TokenFlight {
    fn default() -> Self {
        Self {
            state: std::sync::Mutex::new(FlightState {
                available: Some(PoolTokens::default()),
                failed_until: None,
            }),
            changed: std::sync::Condvar::new(),
            #[cfg(test)]
            after_acquire: std::sync::Mutex::new(None),
        }
    }
}
fn token_failure() -> Error {
    Error::Unavailable("helper token acquisition unavailable".into())
}
impl TokenFlight {
    fn acquire(
        self: &std::sync::Arc<Self>,
        config: &Config,
        agent: &ureq::Agent,
        deadline: std::time::Instant,
    ) -> Result<String> {
        loop {
            let mut state = recover_lock(&self.state);
            let now = std::time::Instant::now();
            if now >= deadline || state.failed_until.is_some_and(|until| now < until) {
                return Err(token_failure());
            }
            if let Some(mut tokens) = state.available.take() {
                drop(state);
                let this = std::sync::Arc::clone(self);
                let config = config.clone();
                let agent = agent.clone();
                let (sender, receiver) = std::sync::mpsc::sync_channel(1);
                std::thread::spawn(move || {
                    // Credential reads, flock waits, grant I/O and rejection
                    // invalidation happen outside the coordination mutex.
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if tokens.last.is_some_and(|hash| rejected(&hash)) {
                            tokens.manager.reject(&config);
                            tokens.last = None;
                        }
                        for fresh in [false, true] {
                            let value = match tokens.manager.acquire(&config, fresh, |credential| {
                                fetch_token(&agent, &config, credential, DEFAULT_TIMEOUT)
                            }) {
                                Ok(token) => token.value().to_owned(),
                                Err(error)
                                    if !fresh && crate::token::is_rejected_token_error(&error) =>
                                {
                                    continue
                                }
                                Err(error) => return Err(error),
                            };
                            let hash = bearer_digest(&value);
                            tokens.last = Some(hash);
                            if !rejected(&hash) {
                                return Ok(value);
                            }
                            tokens.manager.reject(&config);
                            tokens.last = None;
                        }
                        Err(token_failure())
                    }));
                    let result = match result {
                        Ok(value) => value,
                        Err(_) => {
                            tokens = PoolTokens::default();
                            Err(token_failure())
                        }
                    };
                    let mut state = recover_lock(&this.state);
                    state.failed_until = result
                        .as_ref()
                        .err()
                        .map(|_| std::time::Instant::now() + Duration::from_secs(1));
                    state.available = Some(tokens);
                    drop(state);
                    this.changed.notify_all();
                    let _ = sender.send(result);
                });
                let result = receiver
                    .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                    .map_err(|_| token_failure())??;
                #[cfg(test)]
                if let Some(hook) = recover_lock(&self.after_acquire).take() {
                    hook(&result);
                }
                // Acquisition linearizes here. In-flight sends acquired before
                // rejection may complete, but no later acquisition returns it.
                if !rejected(&bearer_digest(&result)) {
                    return Ok(result);
                }
                continue;
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next, _) = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            drop(next);
        }
    }
}

pub struct PooledApi {
    agent: ureq::Agent,
    token_agent: ureq::Agent,
    tls: std::result::Result<ureq::tls::TlsConfig, String>,
    tokens: std::sync::Arc<TokenFlight>,
}
impl PooledApi {
    pub fn new(_config: &Config) -> Result<Self> {
        // Cache the Arc-containing config even when the first endpoint is HTTP.
        // An invalid certificate bundle is an error only for a TLS request.
        let tls = tls_from_env().map_err(|error| match error {
            Error::Unavailable(message) => message,
            _ => "TLS configuration unavailable".into(),
        });
        let config = agent_configuration(Some(2), tls.as_ref().ok().cloned());
        use ureq::unversioned::transport::Connector;
        let connector =
            ureq::unversioned::transport::DefaultConnector::default().chain(ObserveConnector);
        let agent = ureq::Agent::with_parts(
            config,
            connector,
            ureq::unversioned::resolver::DefaultResolver::default(),
        );
        Ok(Self {
            agent,
            token_agent: agent_configuration(None, None).new_agent(),
            tls,
            tokens: std::sync::Arc::new(TokenFlight::default()),
        })
    }
    pub fn request(
        &self,
        config: &Config,
        method: &str,
        path: &str,
        body: Option<&Value>,
        params: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<Response> {
        if !matches!((method, path), ("POST", "/search") | ("GET", "/preview")) {
            return Err(Error::Usage(
                "pooled API is limited to picker search and preview".into(),
            ));
        }
        let mut url = format!("{}{}", config.endpoint, path);
        if !params.is_empty() {
            url.push('?');
            url.push_str(&form(params));
        }
        let data = body
            .map(encode)
            .transpose()?
            .unwrap_or_default()
            .into_bytes();
        let deadline = std::time::Instant::now() + timeout;
        let mut auth_retry = false;
        let mut transport_retry = false;
        loop {
            let bearer = if config.is_tailnet() {
                None
            } else {
                Some(self.tokens.acquire(config, &self.token_agent, deadline)?)
            };
            // Only the body is replayed verbatim; every attempt acquires a
            // bearer again, including expiry and single-use policy checks.
            let response = match self.send(
                method,
                &url,
                bearer.as_deref(),
                body.is_some(),
                &data,
                timeout,
            ) {
                Ok(response) => response,
                Err(error) => {
                    let observed = ATTEMPT.with(std::cell::Cell::get);
                    if !transport_retry
                        && observed.reused
                        && observed.disconnected
                        && !observed.response_bytes
                    {
                        transport_retry = true;
                        continue;
                    }
                    return Err(error);
                }
            };
            if response.status == 401 {
                if let Some(bearer) = bearer {
                    TokenManager::reject_sent(config, &bearer);
                    if !auth_retry {
                        auth_retry = true;
                        continue;
                    }
                }
            }
            return Ok(response);
        }
    }
    fn send(
        &self,
        method: &str,
        url: &str,
        bearer: Option<&str>,
        has_body: bool,
        data: &[u8],
        timeout: Duration,
    ) -> Result<Response> {
        ATTEMPT.with(|state| state.set(AttemptObservation::default()));
        let mut request = ureq::http::Request::builder()
            .method(method)
            .uri(url)
            .header("Accept", "application/json")
            .header("User-Agent", USER_AGENT);
        if let Some(bearer) = bearer {
            let mut header = ureq::http::HeaderValue::from_str(&format!("Bearer {bearer}"))
                .map_err(|_| Error::Unavailable("invalid HTTP header".into()))?;
            header.set_sensitive(true);
            request = request.header("Authorization", header);
        }
        if has_body {
            request = request.header("Content-Type", "application/json");
        }
        let mut bytes = data;
        let mut absent = ();
        let payload = if has_body {
            bytes.as_body()
        } else {
            absent.as_body()
        };
        let request = request
            .body(payload)
            .map_err(|_| Error::Unavailable("invalid HTTP request".into()))?;
        let proxy = proxy_for_url(url, |name| std::env::var(name).ok())?;
        let uses_tls = url.starts_with("https:")
            || proxy
                .as_ref()
                .is_some_and(|p| p.protocol() == ureq::ProxyProtocol::Https);
        let mut request = self.agent.configure_request(request).proxy(proxy);
        if uses_tls {
            request = request.tls_config(self.tls.clone().map_err(Error::Unavailable)?);
        }
        let request = request
            .timeout_global(None)
            .timeout_per_call(None)
            .timeout_resolve(Some(timeout))
            .timeout_connect(Some(timeout))
            .timeout_send_request(Some(timeout))
            .timeout_send_body(None)
            .timeout_recv_response(Some(timeout))
            .timeout_recv_body(None)
            .timeout_per_read(Some(timeout))
            .timeout_per_write(Some(timeout))
            .build();
        let mut response = self
            .agent
            .run(request)
            .map_err(|_| Error::Unavailable("HTTP transport failed".into()))?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        const MAX_HELPER_BODY: u64 = 4 * 1024 * 1024;
        let mut body = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(MAX_HELPER_BODY + 1)
            .read_to_end(&mut body)
            .map_err(|_| Error::Unavailable("HTTP response read failed".into()))?;
        if body.len() as u64 > MAX_HELPER_BODY {
            return Err(Error::Unavailable("helper response too large".into()));
        }
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}

// Observations belong to the calling thread and contain no request data. The
// pinned transport wrapper distinguishes a reused disconnect from new socket,
// timeout, TLS, protocol, or partial-response failures before considering retry.
#[derive(Clone, Copy, Default)]
struct AttemptObservation {
    seen: bool,
    reused: bool,
    response_bytes: bool,
    disconnected: bool,
}
thread_local! { static ATTEMPT: std::cell::Cell<AttemptObservation> = const { std::cell::Cell::new(AttemptObservation { seen:false,reused:false,response_bytes:false,disconnected:false }) }; }
#[derive(Debug)]
struct ObserveConnector;
impl<T: ureq::unversioned::transport::Transport> ureq::unversioned::transport::Connector<T>
    for ObserveConnector
{
    type Out = ObservedTransport<T>;
    fn connect(
        &self,
        _details: &ureq::unversioned::transport::ConnectionDetails,
        chained: Option<T>,
    ) -> std::result::Result<Option<Self::Out>, ureq::Error> {
        Ok(chained.map(|inner| ObservedTransport { inner, used: false }))
    }
}
#[derive(Debug)]
struct ObservedTransport<T> {
    inner: T,
    used: bool,
}
impl<T: ureq::unversioned::transport::Transport> ureq::unversioned::transport::Transport
    for ObservedTransport<T>
{
    fn buffers(&mut self) -> &mut dyn ureq::unversioned::transport::Buffers {
        self.inner.buffers()
    }
    fn transmit_output(
        &mut self,
        amount: usize,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> std::result::Result<(), ureq::Error> {
        ATTEMPT.with(|state| {
            let mut s = state.get();
            if !s.seen {
                s.seen = true;
                s.reused = self.used;
            }
            state.set(s);
        });
        self.used = true;
        let result = self.inner.transmit_output(amount, timeout);
        observe_disconnect(&result);
        result
    }
    fn await_input(
        &mut self,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> std::result::Result<bool, ureq::Error> {
        let result = self.inner.await_input(timeout);
        ATTEMPT.with(|state| {
            let mut s = state.get();
            if matches!(result, Ok(false)) {
                s.disconnected = true;
            }
            if !self.inner.buffers().input().is_empty() {
                s.response_bytes = true;
            }
            state.set(s);
        });
        observe_disconnect(&result);
        result
    }
    fn is_open(&mut self) -> bool {
        self.inner.is_open()
    }
    fn is_tls(&self) -> bool {
        self.inner.is_tls()
    }
}
fn observe_disconnect<T>(result: &std::result::Result<T, ureq::Error>) {
    if matches!(result,Err(ureq::Error::Io(e)) if matches!(e.kind(),std::io::ErrorKind::BrokenPipe|std::io::ErrorKind::ConnectionReset|std::io::ErrorKind::ConnectionAborted|std::io::ErrorKind::UnexpectedEof))
    {
        ATTEMPT.with(|state| {
            let mut s = state.get();
            s.disconnected = true;
            state.set(s);
        });
    }
}

#[cfg(test)]
mod pooled_lock_tests {
    use super::*;

    #[test]
    fn rejection_between_grant_and_waiter_handoff_cannot_escape() {
        use std::io::BufRead;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "ccs-flight-{}-{}",
            std::process::id(),
            crate::util::now_epoch()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let secret = dir.join("secret");
        std::fs::write(&secret, "synthetic-flight-secret").unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for i in 1..=2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                }
                let body =
                    format!("{{\"access_token\":\"synthetic-handoff-{i}\",\"expires_in\":0}}");
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        let config = Config {
            path: dir.join("config.json"),
            endpoint: endpoint.clone(),
            host_label: "test".into(),
            auth_type: "client_credentials".into(),
            token_url: endpoint,
            client_id: "test".into(),
            secret_file: secret,
            audience: String::new(),
            hmac_key_file: dir.join("unused"),
        };
        let flight = std::sync::Arc::new(TokenFlight::default());
        *recover_lock(&flight.after_acquire) = Some(Box::new(remember_rejected));
        let token = flight
            .acquire(
                &config,
                &agent_configuration(None, None).new_agent(),
                std::time::Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
        assert_eq!(
            token, "synthetic-handoff-2",
            "waiter returned a bearer rejected after the worker finished"
        );
        server.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn poisoned_coordination_preserves_available_manager_and_rejections() {
        let flight = TokenFlight::default();
        let hash = bearer_digest("synthetic-poison-registry-entry");
        let _ = std::panic::catch_unwind(|| {
            let mut state = flight.state.lock().unwrap();
            state.failed_until = None;
            panic!("synthetic coordination panic");
        });
        let _ = std::panic::catch_unwind(|| {
            let mut rejected = rejected_bearers().lock().unwrap();
            rejected.insert(hash);
            panic!("synthetic rejection-registry panic");
        });
        assert!(recover_lock(&flight.state).available.is_some());
        assert!(rejected(&hash));
        // A subsequent waiter can reserve the manager and complete its handoff.
        let manager = recover_lock(&flight.state).available.take().unwrap();
        recover_lock(&flight.state).available = Some(manager);
        assert!(recover_lock(&flight.state).available.is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_use_quote_but_forms_use_plus() {
        assert_eq!(quote("a: b+é", false), "a%3A%20b%2B%C3%A9");
        assert_eq!(form(&[("audience", "a b+é")]), "audience=a+b%2B%C3%A9");
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use std::io::BufRead;
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn config(endpoint: String) -> Config {
        Config {
            endpoint,
            path: "unused".into(),
            host_label: "test".into(),
            auth_type: "tailnet".into(),
            token_url: String::new(),
            client_id: String::new(),
            secret_file: "unused".into(),
            audience: String::new(),
            hmac_key_file: "unused".into(),
        }
    }
    #[test]
    fn request_preserves_query_json_gzip_and_response_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (sender, receiver) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut lines = Vec::new();
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(n) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = n.trim().parse::<usize>().unwrap();
                }
                lines.push(line.trim_end().to_owned());
            }
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes).unwrap();
            sender.send((lines, bytes)).unwrap();
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nX-Result: value\r\nConnection: close\r\n\r\n{\"ok\":true}").unwrap();
        });
        let value = object([
            ("unicode", text("日本語")),
            ("integer", Value::Number("123".into())),
        ]);
        let response = Api::new(config(endpoint))
            .request(
                "POST",
                "/ingest",
                Some(&value),
                &[("query", "a b+é")],
                true,
                None,
            )
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.header("x-result"), Some("value"));
        assert_eq!(response.json(), Some(object([("ok", Value::Bool(true))])));
        let (lines, bytes) = receiver.recv().unwrap();
        assert_eq!(lines[0], "POST /ingest?query=a+b%2B%C3%A9 HTTP/1.1");
        assert!(lines
            .iter()
            .any(|s| s.to_ascii_lowercase() == format!("user-agent: {USER_AGENT}")));
        assert!(!lines
            .iter()
            .any(|s| s.to_ascii_lowercase().starts_with("content-encoding:")));
        assert!(!lines
            .iter()
            .any(|s| s.to_ascii_lowercase().starts_with("authorization:")));
        assert_eq!(&bytes[..2], &[0x1f, 0x8b]);
        let mut unpacked = Vec::new();
        flate2::read::GzDecoder::new(bytes.as_slice())
            .read_to_end(&mut unpacked)
            .unwrap();
        assert_eq!(parse(&unpacked), Some(value));
        server.join().unwrap();
    }
    #[test]
    fn phase_timeout_stops_a_stalled_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(150));
        });
        let result = Api::with_timeout(config(endpoint), Duration::from_millis(25)).get(
            "/status",
            &[],
            None,
        );
        assert!(result.is_err(), "stalled HTTP response did not time out");
        server.join().unwrap();
    }
    fn response_server(body: Vec<u8>, gap: Duration) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut length = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            let mut request_body = vec![0; length];
            reader.read_exact(&mut request_body).unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            if stream.write_all(header.as_bytes()).is_err() {
                return;
            }
            for chunk in body.chunks(if gap.is_zero() { body.len().max(1) } else { 10 }) {
                std::thread::sleep(gap);
                if stream.write_all(chunk).is_err() {
                    return;
                }
            }
        });
        (address, task)
    }
    #[test]
    fn progressing_body_uses_per_read_timeout() {
        let (endpoint, server) = response_server(vec![b' '; 80], Duration::from_millis(100));
        let result = Api::with_timeout(config(endpoint), Duration::from_millis(300)).get(
            "/archive",
            &[],
            None,
        );
        assert!(
            result.is_ok(),
            "whole-body timeout interrupted progressing response"
        );
        server.join().unwrap();
    }
    #[test]
    fn network_path_is_rejected_before_any_send() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_millis(500) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                            break;
                        }
                    }
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .unwrap();
                    return true;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            false
        });
        let result = Api::new(config(endpoint)).get("//other/path", &[], None);
        assert!(!server.join().unwrap(), "network path reached server");
        assert!(matches!(result, Err(Error::Usage(_))));
    }
    fn fetch_response(body: Vec<u8>) -> Result<(String, Option<f64>)> {
        let (endpoint, server) = response_server(body, Duration::ZERO);
        let mut cfg = config(endpoint.clone());
        cfg.token_url = endpoint;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("ccs-api-secret-{}-{nonce}", std::process::id()));
        std::fs::write(&path, "synthetic-client-secret").unwrap();
        cfg.secret_file = path.clone();
        let credential = Credential::read(&cfg).unwrap();
        let result = fetch_token(
            &Api::new(cfg.clone()).agent,
            &cfg,
            &credential,
            Duration::from_secs(3),
        );
        server.join().unwrap();
        std::fs::remove_file(path).unwrap();
        result
    }
    #[test]
    fn token_endpoint_response_is_size_bounded() {
        let mut body = br#"{"access_token":"synthetic-safe","expires_in":3600}"#.to_vec();
        body.resize(32769, b' ');
        let result = fetch_response(body);
        assert!(
            matches!(result, Err(Error::Unavailable(ref reason)) if reason == "token endpoint response too large"),
            "oversized token response accepted"
        );
    }
    #[test]
    fn token_fetch_validates_bearer_before_returning() {
        let result =
            fetch_response(br#"{"access_token":"invalid bearer","expires_in":3600}"#.to_vec());
        assert!(
            matches!(result, Err(Error::Unavailable(ref reason)) if reason == "token endpoint answered 200 without a valid access_token"),
            "unsafe bearer escaped fetch filter"
        );
    }
    #[test]
    fn proxy_selection_matches_urllib_environment_rules() {
        let settings = [
            ("HTTP_PROXY", "http://upper:81"),
            ("http_proxy", "http://lower:82"),
            ("https_proxy", "http://secure:83"),
            ("ALL_PROXY", "http://all:84"),
        ];
        let env = |name: &str| {
            settings
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        };
        assert_eq!(
            proxy_for_url("http://destination", env)
                .unwrap()
                .unwrap()
                .host(),
            "lower"
        );
        assert_eq!(
            proxy_for_url("https://destination", env)
                .unwrap()
                .unwrap()
                .host(),
            "secure"
        );
        assert!(
            proxy_for_url("http://destination", |name| (name == "HTTPS_PROXY")
                .then(|| "http://wrong:83".into()))
            .unwrap()
            .is_none()
        );
        assert!(
            proxy_for_url("http://destination", |name| if name == "http_proxy" {
                Some(String::new())
            } else {
                env(name)
            })
            .unwrap()
            .is_none()
        );
        assert!(proxy_for_url("http://destination", |name| match name {
            "HTTP_PROXY" => Some("http://upper".into()),
            "REQUEST_METHOD" => Some("GET".into()),
            _ => None,
        })
        .unwrap()
        .is_none());
        for (url, rule) in [
            ("http://sub.example:80", ".example"),
            ("http://localhost:99", "localhost:99"),
            ("http://[::1]:99", "[::1]"),
            ("http://example", "*"),
        ] {
            assert!(
                bypass_proxy(&url.parse().unwrap(), rule),
                "no_proxy bypass missing"
            );
        }
        assert!(!bypass_proxy(
            &"http://notexample".parse().unwrap(),
            "example"
        ));
        assert!(!bypass_proxy(
            &"http://localhost:99".parse().unwrap(),
            "localhost:98"
        ));
    }
    #[test]
    fn custom_root_set_contains_only_bundle_certificates() {
        let path = std::env::temp_dir().join(format!("ccs-ca-roots-{}", std::process::id()));
        std::fs::write(
            &path,
            b"-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let tls = tls_from_file(Some(&path)).unwrap();
        std::fs::remove_file(path).unwrap();
        let ureq::tls::RootCerts::Specific(certs) = tls.root_certs() else {
            panic!("custom bundle did not replace defaults");
        };
        assert_eq!(certs.len(), 1, "roots outside the bundle were trusted");
        assert_eq!(certs[0].der(), b"a");
    }
}
