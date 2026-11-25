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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use ureq::http;

pub const PORT: u16 = 7390;
const MAX_HEAD: usize = 64 << 10;
const MAX_BODY: usize = 64 << 20;
/// Connections served at once; more are refused so idle ones can't use up the process.
const MAX_CONNECTIONS: usize = 512;
/// A client silent this long between requests (or mid-request) is disconnected.
const IDLE: Duration = Duration::from_secs(120);
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
    let port = listener.local_addr().map_or(PORT, |a| a.port());
    raise_file_limit();
    let open = Arc::new(AtomicUsize::new(0));
    for mut conn in listener.incoming().flatten() {
        if open.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            open.fetch_sub(1, Ordering::SeqCst);
            let _ = error(&mut conn, 503, "parda has too many open connections; try again");
            continue;
        }
        let (state, done) = (state.clone(), open.clone());
        let spawned = std::thread::Builder::new().spawn(move || {
            conn.set_nodelay(true).ok();
            conn.set_read_timeout(Some(IDLE)).ok();
            let _ = connection(&state, conn, port);
            done.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            open.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// launchd starts services with a 256 open-file limit; raise it to what the system allows.
fn raise_file_limit() {
    let mut l = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit/setrlimit only read and write the struct passed in.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut l) == 0 && l.rlim_cur < 4096 {
            l.rlim_cur = l.rlim_max.min(4096);
            libc::setrlimit(libc::RLIMIT_NOFILE, &l);
        }
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

fn connection(state: &State, conn: TcpStream, port: u16) -> io::Result<()> {
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
        handle(state, &req, &mut out, port)?;
        if req.close {
            return Ok(());
        }
    }
}

/// One line, at most `MAX_HEAD` bytes: a longer one is an error, not a growing buffer.
fn read_line(r: &mut impl BufRead, buf: &mut String) -> io::Result<usize> {
    let n = r.by_ref().take(MAX_HEAD as u64).read_line(buf)?;
    if n == MAX_HEAD && !buf.ends_with('\n') {
        return Err(io::Error::other("line too long"));
    }
    Ok(n)
}

fn read_request(r: &mut impl BufRead) -> io::Result<Option<Request>> {
    let mut line = String::new();
    match read_line(r, &mut line) {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        // An idle keep-alive connection timing out: close quietly, never answer a request not made.
        Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Ok(None),
        Err(e) => return Err(e),
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
        size += read_line(r, &mut line)?;
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
            read_line(r, &mut line)?;
            let n = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| io::Error::other("bad chunk size"))?;
            if n == 0 {
                loop {
                    line.clear();
                    if read_line(r, &mut line)? == 0 || line.trim().is_empty() {
                        break;
                    }
                }
                break;
            }
            if n > MAX_BODY - body.len() {
                return Err(io::Error::other("body too large"));
            }
            let at = body.len();
            body.resize(at + n, 0);
            r.read_exact(&mut body[at..])?;
            line.clear();
            read_line(r, &mut line)?;
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

/// `%40` → `@`, `+` → space: what the server will read.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match b[i] {
            b'%' if i + 2 < b.len() => match (hex(b[i + 1]), hex(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn handle(state: &State, req: &Request, out: &mut TcpStream, port: u16) -> io::Result<()> {
    // Only programs on this computer, never a web page: a page can reach 127.0.0.1 too, and with DNS
    // rebinding read the answers. Browsers always send Origin or Sec-Fetch-Site; local tools don't.
    let host_ok = req.header("host").is_some_and(|h| {
        [format!("127.0.0.1:{port}"), format!("localhost:{port}"), format!("[::1]:{port}")]
            .iter()
            .any(|ok| h.eq_ignore_ascii_case(ok))
    });
    if !host_ok || req.header("origin").is_some() || req.header("sec-fetch-site").is_some() {
        return error(out, 403, "parda only accepts requests from programs on this computer, not from web pages");
    }
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

    let api = match route.prefix.as_str() {
        "/anthropic" => body::Api::Anthropic,
        p if p.starts_with("/gemini") => body::Api::Gemini,
        _ => body::Api::OpenAi,
    };
    // Query strings are forwarded as they are, so they must hold nothing parda would mask (checked
    // decoded: `%40` is an `@`). Gemini may carry the user's own API key as `key=`; it goes to the
    // provider it belongs to, like a header.
    if let Some((_, query)) = req.target.split_once('?') {
        let scanned = query.split('&').filter(|p| !(api == body::Api::Gemini && p.starts_with("key=")));
        if scanned.into_iter().any(|p| !crate::detect::scan(&percent_decode(p)).is_empty()) {
            return error(out, 400, "parda found sensitive data in the URL and didn't send the request");
        }
    }

    let rest = &req.target[route.prefix.len()..];
    let path = rest.split('?').next().unwrap_or("");
    // Requests that ask the model for an answer; others (embeddings, token counts) take no extra fields.
    let note = match api {
        body::Api::Anthropic => path.ends_with("/messages"),
        body::Api::OpenAi => path.ends_with("/chat/completions") || path.ends_with("/responses"),
        body::Api::Gemini => path.contains("enerateContent"),
    };
    let started = Instant::now();
    let mut counts = Counts::new();
    let body = if req.body.is_empty() {
        Vec::new()
    } else {
        match body::mask_request(&state.vault, &req.body, &mut counts, api, note) {
            Ok(b) => b,
            Err(e) => return error(out, 415, &format!("parda only forwards JSON it can scan: {e}")),
        }
    };
    let mask_us = started.elapsed().as_micros() as u64;
    // Codex signed in with ChatGPT sends this header and talks to ChatGPT's backend instead of the API.
    let upstream = if route.upstream == crate::setup::OPENAI_DEFAULT && req.header("chatgpt-account-id").is_some() {
        CHATGPT_CODEX
    } else {
        &route.upstream
    };
    let upstream_url = upstream.to_string();
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
                // Cut off upstream: drop the connection without the final chunk, so the tool sees an
                // incomplete answer instead of a clean ending.
                Err(e) => return Err(e),
            };
            chunk(out, &r.feed(&buf[..n]))?;
        }
        chunk(out, &r.finish())?;
        out.write_all(b"0\r\n\r\n")?;
        out.flush()?;
        restored = r.restored;
    } else {
        let mut data = Vec::new();
        if let Err(e) = upstream.take(MAX_BODY as u64).read_to_end(&mut data) {
            return error(out, 502, &format!("parda lost the connection to {upstream_url} mid-answer: {e}"));
        }
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

#[cfg(test)]
mod tests {
    #[test]
    fn percent_decoding() {
        assert_eq!(super::percent_decode("user=ram%40example.com&q=a+b%2Dc"), "user=ram@example.com&q=a b-c");
        assert_eq!(super::percent_decode("50%"), "50%");
        assert_eq!(super::percent_decode("%zz%4"), "%zz%4");
    }
}
