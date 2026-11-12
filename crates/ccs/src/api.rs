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
        Self::with_timeout(config, Duration::from_secs(30))
    }
    pub fn with_timeout(config: Config, timeout: Duration) -> Self {
        let agent = ureq::Agent::config_builder()
            .proxy(None)
            .accept_encoding("identity")
            .max_redirects(0)
            .max_redirects_will_error(false)
            .http_status_as_error(false)
            .build()
            .new_agent();
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
