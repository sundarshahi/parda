//! The local proxy: a small HTTP/1.1 server on 127.0.0.1. Each request body is masked before it goes
//! upstream; each answer has its stand-ins restored on the way back. Written by hand (not a framework)
//! so every streamed event is flushed to the AI tool the moment it is ready.

use crate::body;
use crate::log;
use crate::sse::SseRestorer;
use crate::vault::{Counts, Vault};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use ureq::http;

pub const PORT: u16 = 7390;
const MAX_HEAD: usize = 64 << 10;
const MAX_BODY: usize = 64 << 20;
/// Where Codex sends requests when signed in with ChatGPT rather than an API key.
const CHATGPT_CODEX: &str = "https://chatgpt.com/backend-api/codex";

/// Headers that belong to one connection, not to the request, plus ones parda sets itself.
const HOP: [&str; 11] = [
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "accept-encoding",
];

#[derive(Clone, Debug, PartialEq)]
pub struct Route {
    /// Path prefix on parda, e.g. `/anthropic`.
    pub prefix: String,
    /// Where it goes: the base URL the tool used before parda (a provider, or another proxy).
    pub upstream: String,
}

pub struct State {
    pub vault: Vault,
    pub routes: Vec<Route>,
    pub home: PathBuf,
    pub agent: ureq::Agent,
}

impl State {
    pub fn new(vault: Vault, routes: Vec<Route>, home: PathBuf) -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_connect(Some(Duration::from_secs(30)))
            .user_agent(ureq::config::AutoHeaderValue::None)
            .accept(ureq::config::AutoHeaderValue::None)
            .build();
        State { vault, routes, home, agent: config.into() }
    }
}

pub fn serve(state: Arc<State>, listener: TcpListener) {
    for conn in listener.incoming().flatten() {
        let state = state.clone();
        std::thread::spawn(move || {
            conn.set_nodelay(true).ok();
            let _ = connection(&state, conn);
        });
    }
}

struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    close: bool,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

fn connection(state: &State, conn: TcpStream) -> io::Result<()> {
    let mut reader = BufReader::new(conn.try_clone()?);
    let mut out = conn;
    loop {
        let req = match read_request(&mut reader) {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(()),
            Err(e) => {
                return error(&mut out, 400, &format!("parda could not read the request: {e}"));
            }
        };
        handle(state, &req, &mut out)?;
        if req.close {
            return Ok(());
        }
    }
}

fn read_request(r: &mut impl BufRead) -> io::Result<Option<Request>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(io::Error::other("bad request line"));
    };
    let (method, target, version) = (method.to_string(), target.to_string(), version.to_string());
    let mut headers = Vec::new();
    let mut size = line.len();
    loop {
        line.clear();
        size += r.read_line(&mut line)?;
        if size > MAX_HEAD {
            return Err(io::Error::other("headers too large"));
        }
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let get = |n: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.to_ascii_lowercase());
    let close = get("connection").is_some_and(|v| v.contains("close")) || version == "HTTP/1.0";
    let mut body = Vec::new();
    if get("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        loop {
            line.clear();
            r.read_line(&mut line)?;
            let n = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| io::Error::other("bad chunk size"))?;
            if n == 0 {
                loop {
                    line.clear();
                    if r.read_line(&mut line)? == 0 || line.trim().is_empty() {
                        break;
                    }
                }
                break;
            }
            if body.len() + n > MAX_BODY {
                return Err(io::Error::other("body too large"));
            }
            let at = body.len();
            body.resize(at + n, 0);
            r.read_exact(&mut body[at..])?;
            line.clear();
            r.read_line(&mut line)?;
        }
    } else if let Some(n) = get("content-length") {
        let n: usize = n.trim().parse().map_err(|_| io::Error::other("bad content-length"))?;
        if n > MAX_BODY {
            return Err(io::Error::other("body too large"));
        }
        body.resize(n, 0);
        r.read_exact(&mut body)?;
    }
    Ok(Some(Request { method, target, headers, body, close }))
}

fn handle(state: &State, req: &Request, out: &mut TcpStream) -> io::Result<()> {
    if req.method == "GET" && req.target == "/parda/health" {
        return respond(out, 200, &[("content-type", "text/plain")], b"parda ok\n");
    }
    let Some(route) = state.routes.iter().find(|r| {
        req.target.strip_prefix(&r.prefix).is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '?']))
    }) else {
        return error(out, 404, &format!("parda has no route for {}", req.target));
    };
    if req.header("upgrade").is_some() {
        // 426 is the answer Codex expects before it falls back to plain HTTPS; anything else costs
        // every session several seconds of retries.
        return error(out, 426, "parda can't inspect WebSocket traffic; use HTTPS");
    }
    if req.header("content-encoding").is_some_and(|v| !v.eq_ignore_ascii_case("identity")) {
        return error(out, 415, "parda can't scan a compressed request body, so it wasn't sent");
    }

    let started = Instant::now();
    let mut counts = Counts::new();
    let body = if req.body.is_empty() {
        Vec::new()
    } else {
        match body::mask_request(&state.vault, &req.body, &mut counts, route.prefix == "/anthropic") {
            Ok(b) => b,
            Err(e) => return error(out, 415, &format!("parda only forwards JSON it can scan: {e}")),
        }
    };
    let mask_us = started.elapsed().as_micros() as u64;
    let rest = &req.target[route.prefix.len()..];
    // Codex signed in with ChatGPT sends this header and talks to ChatGPT's backend instead of the API.
    let upstream = if route.upstream == crate::setup::OPENAI_DEFAULT && req.header("chatgpt-account-id").is_some() {
        CHATGPT_CODEX
    } else {
        &route.upstream
    };
    let url = format!("{}{}", upstream.trim_end_matches('/'), rest);

    let mut builder = http::Request::builder().method(req.method.as_str()).uri(&url);
    for (k, v) in &req.headers {
        if !HOP.iter().any(|h| k.eq_ignore_ascii_case(h)) {
            builder = builder.header(k, v);
        }
    }
    builder = builder.header("accept-encoding", "identity");
    let sent = if body.is_empty() && matches!(req.method.as_str(), "GET" | "HEAD" | "DELETE" | "OPTIONS") {
        builder.body(()).map(|r| state.agent.run(r))
    } else {
        builder.body(body).map(|r| state.agent.run(r))
    };
    let resp = match sent {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return error(out, 502, &format!("parda could not reach {upstream}: {e}")),
        Err(e) => return error(out, 400, &format!("parda could not build the upstream request: {e}")),
    };

    let status = resp.status().as_u16();
    let is_sse = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/event-stream"));
    let encoded = resp.headers().get("content-encoding").is_some_and(|v| v != "identity");
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter(|(k, _)| !HOP.contains(&k.as_str()))
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
        .collect();
    let mut upstream = resp.into_body().into_reader();
    let mut restored = 0;

    if is_sse && !encoded {
        write_head(out, status, &headers, None)?;
        let mut r = SseRestorer::new(&state.vault);
        let mut buf = vec![0u8; 16 << 10];
        loop {
            let n = match upstream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            chunk(out, &r.feed(&buf[..n]))?;
        }
        chunk(out, &r.finish())?;
        out.write_all(b"0\r\n\r\n")?;
        out.flush()?;
        restored = r.restored;
    } else {
        let mut data = Vec::new();
        upstream.take(MAX_BODY as u64).read_to_end(&mut data).ok();
        if !encoded {
            if let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&data) {
                body::restore_value(&state.vault, &mut v, &mut restored);
                if restored > 0 {
                    data = serde_json::to_vec(&v).unwrap_or(data);
                }
            }
        }
        write_head(out, status, &headers, Some(data.len()))?;
        out.write_all(&data)?;
        out.flush()?;
    }

    let path = rest.split('?').next().unwrap_or("");
    log::append(
        &state.home,
        &log::Record { api: &route.prefix[1..], method: &req.method, path, status, masked: &counts, restored, mask_us },
    );
    Ok(())
}

fn chunk(out: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    write!(out, "{:x}\r\n", data.len())?;
    out.write_all(data)?;
    out.write_all(b"\r\n")?;
    out.flush()
}

fn write_head(out: &mut TcpStream, status: u16, headers: &[(String, String)], len: Option<usize>) -> io::Result<()> {
    let reason = http::StatusCode::from_u16(status).ok().and_then(|s| s.canonical_reason()).unwrap_or("");
    let mut h = format!("HTTP/1.1 {status} {reason}\r\n");
    for (k, v) in headers {
        h += &format!("{k}: {v}\r\n");
    }
    match len {
        Some(n) => h += &format!("content-length: {n}\r\n\r\n"),
        None => h += "transfer-encoding: chunked\r\n\r\n",
    }
    out.write_all(h.as_bytes())
}

fn respond(out: &mut TcpStream, status: u16, headers: &[(&str, &str)], body: &[u8]) -> io::Result<()> {
    let h: Vec<_> = headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    write_head(out, status, &h, Some(body.len()))?;
    out.write_all(body)?;
    out.flush()
}

/// An error in the shape both the Anthropic and OpenAI SDKs read (`error.message`).
fn error(out: &mut TcpStream, status: u16, message: &str) -> io::Result<()> {
    let body = serde_json::json!({"type": "error", "error": {"type": "parda_error", "message": message}});
    respond(out, status, &[("content-type", "application/json")], body.to_string().as_bytes())
}
