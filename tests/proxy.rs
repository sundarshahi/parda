//! End to end: the real `parda run` binary between a client and a fake AI provider.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::mpsc;
use std::time::Duration;

struct Parda {
    child: Child,
    port: u16,
    home: PathBuf,
}

impl Drop for Parda {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
        std::fs::remove_dir_all(&self.home).ok();
    }
}

fn start(upstream: &str, name: &str) -> Parda {
    let home = std::env::temp_dir().join(format!("parda-it-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("upstreams.json"), json!({"anthropic": upstream, "openai": upstream}).to_string())
        .unwrap();
    // Port 0: parda picks a free port and says which, so parallel tests never collide.
    let mut child = Command::new(env!("CARGO_BIN_EXE_parda"))
        .arg("run")
        .env("PARDA_HOME", &home)
        .env("PARDA_PORT", "0")
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    while err.read_line(&mut line).unwrap() > 0 {
        if let Some(p) = line.trim().strip_prefix("parda: listening on http://127.0.0.1:") {
            let port = p.parse().unwrap();
            std::thread::spawn(move || std::io::copy(&mut err, &mut std::io::sink()));
            return Parda { child, port, home };
        }
        line.clear();
    }
    child.kill().ok();
    child.wait().ok();
    panic!("parda did not start");
}

/// A fake provider: hands each request body to the test, answers with whatever `reply` builds from it.
fn fake_upstream(reply: fn(&str) -> (String, String)) -> (String, mpsc::Receiver<String>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for conn in l.incoming().flatten() {
            let mut r = BufReader::new(conn.try_clone().unwrap());
            let mut len = 0;
            let mut line = String::new();
            loop {
                line.clear();
                r.read_line(&mut line).unwrap();
                if line.trim().is_empty() {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; len];
            r.read_exact(&mut body).unwrap();
            let body = String::from_utf8(body).unwrap();
            tx.send(body.clone()).ok();
            let (ctype, text) = reply(&body);
            let mut c = conn;
            write!(
                c,
                "HTTP/1.1 200 OK\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
                text.len()
            )
            .unwrap();
        }
    });
    (url, rx)
}

fn tokens(body: &str) -> Vec<String> {
    let re =
        regex::Regex::new(r"\[PERSON_[0-9a-f]{8}\]|email_[0-9a-f]{8}@parda\.invalid|\[SECRET_[0-9a-f]{8}\]").unwrap();
    re.find_iter(body).map(|m| m.as_str().to_string()).collect()
}

/// Streams every stand-in it received back to the client, each cut in half across two events.
fn echo_split(body: &str) -> (String, String) {
    let mut sse = String::new();
    for t in tokens(body) {
        let (a, b) = t.split_at(t.len() / 2);
        for piece in [format!(" <{a}"), format!("{b}>")] {
            let ev = json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": piece}});
            sse += &format!("event: content_block_delta\ndata: {ev}\n\n");
        }
    }
    sse += "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    ("text/event-stream".into(), sse)
}

fn post(port: u16, path: &str, headers: &[(&str, &str)], body: &[u8]) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut req = format!("POST {path} HTTP/1.1\r\nhost: x\r\nconnection: close\r\ncontent-length: {}\r\n", body.len());
    for (k, v) in headers {
        req += &format!("{k}: {v}\r\n");
    }
    s.write_all(format!("{req}\r\n").as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let raw = String::from_utf8(raw).unwrap();
    let status = raw[9..12].parse().unwrap();
    let (head, rest) = raw.split_once("\r\n\r\n").unwrap();
    let body =
        if head.to_ascii_lowercase().contains("transfer-encoding: chunked") { dechunk(rest) } else { rest.into() };
    (status, body)
}

fn dechunk(mut s: &str) -> String {
    let mut out = String::new();
    loop {
        let (size, rest) = s.split_once("\r\n").unwrap();
        let n = usize::from_str_radix(size, 16).unwrap();
        if n == 0 {
            return out;
        }
        out += &rest[..n];
        s = &rest[n + 2..];
    }
}

const SECRET: &str = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123";

#[test]
fn provider_sees_stand_ins_client_sees_real_values() {
    let (url, seen) = fake_upstream(echo_split);
    let p = start(&url, "stream");
    let request = json!({"model": "m", "stream": true, "messages": [{"role": "user",
        "content": format!("Write to Ram Bahadur Thapa at ram@example.com using key {SECRET}")}]});
    let (status, body) =
        post(p.port, "/anthropic/v1/messages", &[("content-type", "application/json")], request.to_string().as_bytes());
    assert_eq!(status, 200);

    let upstream_body = seen.recv_timeout(Duration::from_secs(5)).unwrap();
    for real in ["Ram Bahadur Thapa", "ram@example.com", SECRET] {
        assert!(!upstream_body.contains(real), "{real} reached the provider: {upstream_body}");
    }
    assert_eq!(tokens(&upstream_body).len(), 3);

    let text: String = body
        .lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|d| serde_json::from_str::<Value>(d).ok())
        .filter_map(|v| v.pointer("/delta/text").and_then(Value::as_str).map(str::to_string))
        .collect();
    assert_eq!(text, format!(" <Ram Bahadur Thapa> <ram@example.com> <{SECRET}>"));
    assert!(body.contains("message_stop"));

    let log = std::fs::read_to_string(p.home.join("log.jsonl")).unwrap();
    let line: Value = serde_json::from_str(log.lines().last().unwrap()).unwrap();
    assert_eq!(line["masked"], json!({"EMAIL": 1, "PERSON": 1, "SECRET": 1}));
    assert_eq!(line["restored"], 3);
    assert_eq!(line["path"], "/v1/messages");
    for real in ["Ram", "ram@example.com", SECRET] {
        assert!(!log.contains(real), "the log must never hold values");
    }
}

#[test]
fn json_answers_are_restored_too() {
    let (url, _seen) = fake_upstream(|body| {
        let t = tokens(body).join(" ");
        ("application/json".into(), json!({"choices": [{"message": {"content": format!("Hi {t}")}}]}).to_string())
    });
    let p = start(&url, "json");
    let request = json!({"messages": [{"role": "user", "content": "I am Sita Sharma"}]});
    let (status, body) = post(
        p.port,
        "/openai/chat/completions",
        &[("content-type", "application/json")],
        request.to_string().as_bytes(),
    );
    assert_eq!(status, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["choices"][0]["message"]["content"], "Hi Sita Sharma");
}

#[test]
fn refuses_unscannable_bodies() {
    let (url, seen) = fake_upstream(echo_split);
    let p = start(&url, "refuse");
    let gz = post(p.port, "/anthropic/v1/messages", &[("content-encoding", "gzip")], b"\x1f\x8b binary");
    assert_eq!(gz.0, 415);
    let form = post(p.port, "/openai/files", &[("content-type", "text/plain")], b"name=Ram Thapa");
    assert_eq!(form.0, 415);
    assert!(form.1.contains("parda_error"));
    let ws = post(p.port, "/openai/responses", &[("upgrade", "websocket"), ("connection", "upgrade")], b"");
    assert_eq!(ws.0, 426, "Codex falls back to HTTPS only on 426");
    assert!(seen.recv_timeout(Duration::from_millis(300)).is_err(), "nothing may reach the provider");
}

#[test]
fn provider_down_is_a_clear_error() {
    let dead = "http://127.0.0.1:1"; // nothing listens on port 1
    let p = start(dead, "down");
    let (status, body) = post(p.port, "/anthropic/v1/messages", &[], b"{}");
    assert_eq!(status, 502);
    assert!(body.contains("parda could not reach"));
}
