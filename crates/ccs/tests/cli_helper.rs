//! The pooled transport is restricted to the picker's read-only routes.
use ccs::{api::PooledApi, config::Config, errors::Error, util};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

#[test]
fn pooled_transport_never_sends_to_write_or_unrelated_routes() {
    std::env::set_var("no_proxy", "*");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let worker_received = Arc::clone(&received);
    let worker_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        while !worker_stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut buffer = [0; 4096];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        let size = stream.read(&mut buffer).unwrap();
                        if size == 0 {
                            break;
                        }
                        request.extend_from_slice(&buffer[..size]);
                    }
                    let first = String::from_utf8_lossy(&request)
                        .lines()
                        .next()
                        .unwrap_or("")
                        .to_owned();
                    worker_received.lock().unwrap().push(first);
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .unwrap();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("test receiver: {e}"),
            }
        }
    });
    let cfg = Config::from_value(
        &util::object([
            ("endpoint", util::string(endpoint)),
            ("host_label", util::string("test")),
            ("auth", util::object([("type", util::string("tailnet"))])),
            ("hmac_key_file", util::string("unused")),
        ]),
        "unused.json",
    )
    .unwrap();
    let api = PooledApi::new(&cfg).unwrap();
    let body = util::object([("q", util::string("probe"))]);
    let mut rejected = Vec::new();
    for (method, path) in [
        ("POST", "/ingest"),
        ("POST", "/blob"),
        ("POST", "/state"),
        ("DELETE", "/session"),
        ("GET", "/status"),
        ("GET", "/archive"),
        ("POST", "/preview"),
        ("DELETE", "/search"),
    ] {
        rejected.push((
            method,
            path,
            matches!(
                api.request(&cfg, method, path, Some(&body), &[], Duration::from_secs(1)),
                Err(Error::Usage(_))
            ),
        ));
    }
    // Positive control: this exact receiver and API must accept the safe route.
    let response = api.request(
        &cfg,
        "POST",
        "/search",
        Some(&body),
        &[],
        Duration::from_secs(1),
    );
    stop.store(true, Ordering::Relaxed);
    thread.join().unwrap();
    assert_eq!(response.unwrap().status, 200);
    for (method, path, denied) in rejected {
        assert!(
            denied,
            "pooled transport accepted forbidden {method} {path}"
        );
    }
    assert_eq!(*received.lock().unwrap(), vec!["POST /search HTTP/1.1"]);
}
