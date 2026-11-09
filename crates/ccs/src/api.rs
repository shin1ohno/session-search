//! HTTP boundary. Redirects never replay credentials; API 401 retry is once.
use crate::config::{encode, field, number, object, parse, string, text, Config};
use crate::errors::{Error, Result};
use crate::token::{CacheStatus, Credential, TokenManager};
use base64::Engine;
use ccs_pytext::json::Value;
use std::io::{Read, Write};
use std::time::Duration;

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

impl Api {
    pub fn new(config: Config) -> Self {
        Self::with_timeout(config, Duration::from_secs(30))
    }
    pub fn with_timeout(config: Config, timeout: Duration) -> Self {
        let agent = ureq::Agent::config_builder()
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
        if body.is_some() && gzip_body {
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
            let response = send(
                &self.agent,
                method,
                &url,
                &headers,
                &data,
                timeout.unwrap_or(self.timeout),
                None,
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
    let mut request = ureq::http::Request::builder()
        .method(method)
        .uri(url)
        .header("Accept", "application/json")
        .header("User-Agent", USER_AGENT);
    for (key, value) in headers {
        let mut value = ureq::http::HeaderValue::from_str(value)
            .map_err(|_| Error::Unavailable("invalid HTTP header".into()))?;
        if key.eq_ignore_ascii_case("authorization") {
            value.set_sensitive(true);
        }
        request = request.header(*key, value);
    }
    let request = request
        .body(data)
        .map_err(|_| Error::Unavailable("invalid HTTP request".into()))?;
    let request = agent
        .configure_request(request)
        .timeout_global(None)
        .timeout_per_call(None)
        .timeout_resolve(Some(timeout))
        .timeout_connect(Some(timeout))
        .timeout_send_request(Some(timeout))
        .timeout_send_body(Some(timeout))
        .timeout_recv_response(Some(timeout))
        .timeout_recv_body(Some(timeout))
        .timeout_per_read(Some(timeout))
        .timeout_per_write(Some(timeout))
        .build();
    let mut response = agent
        .run(request)
        .map_err(|_| Error::Unavailable("HTTP transport failed".into()))?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(limit.map_or(u64::MAX, |v| v + 1))
        .read_to_end(&mut body)
        .map_err(|_| Error::Unavailable("HTTP response read failed".into()))?;
    if limit.is_some_and(|v| body.len() as u64 > v) {
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
}
