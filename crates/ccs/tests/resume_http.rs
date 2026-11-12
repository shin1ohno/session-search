use ccs::{api::Api, config::Config, errors::Error};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::Duration;

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
fn exercise(mode: &str, checked: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let scenario = mode.to_owned();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                break;
            }
        }
        if scenario == "chunked" {
            stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nab").unwrap();
        } else {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nab")
                .unwrap();
            if scenario == "normal" {
                stream.write_all(b"cde").unwrap();
            }
            if scenario == "stalled" {
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    });
    let mut api = Api::with_timeout(config(endpoint), Duration::from_millis(150));
    let response = if checked {
        api.get_archive("/archive", &[], None)
    } else {
        api.get("/archive", &[], None)
    };
    server.join().unwrap();
    if mode == "normal" {
        let response = response.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"abcde");
    } else if checked && mode != "stalled" {
        assert!(
            matches!(response, Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof),
            "premature body must retain EOF, got {}",
            response.err().map(|e| format!("{e:?}")).unwrap_or_default()
        );
    } else {
        assert!(
            matches!(response, Err(Error::Unavailable(_))),
            "legacy/timeout must remain unavailable"
        );
    }
}
#[test]
fn normal_body() {
    exercise("normal", true);
    exercise("normal", false);
}
#[test]
fn truncated_body() {
    exercise("truncated", true);
    exercise("truncated", false);
}
#[test]
fn chunked_body() {
    exercise("chunked", true);
    exercise("chunked", false);
}
#[test]
fn stalled_body() {
    exercise("stalled", true);
    exercise("stalled", false);
}
