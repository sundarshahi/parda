//! Restoring stand-ins in a streamed (server-sent events) answer.
//!
//! The AI writes a stand-in in pieces: `"[PERS"` in one event, `"ON_1a2b3c4d] said"` in the next.
//! For delta events, the few characters at the end of a text field that could start a stand-in are
//! held back and put in front of the same field in the next event. Before any event that doesn't
//! continue that field, what's held is sent as a copy of the last event that had it, so nothing is lost.

use crate::body::{self, TEXT_KEYS};
use crate::vault::{self, Vault};
use serde_json::Value;

struct Carry {
    path: String,
    text: String,
    other_lines: Vec<String>,
    template: Value,
}

pub struct SseRestorer<'a> {
    vault: &'a Vault,
    buf: Vec<u8>,
    carries: Vec<Carry>,
    pub restored: u64,
}

impl<'a> SseRestorer<'a> {
    pub fn new(vault: &'a Vault) -> Self {
        SseRestorer { vault, buf: Vec::new(), carries: Vec::new(), restored: 0 }
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some((end, delim)) = event_end(&self.buf) {
            let event: Vec<u8> = self.buf.drain(..end + delim).collect();
            let text = String::from_utf8_lossy(&event[..end]).into_owned();
            let d = String::from_utf8_lossy(&event[end..]).into_owned();
            self.event(&text, &d, &mut out);
        }
        out
    }

    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.buf.is_empty() {
            let text = String::from_utf8_lossy(&std::mem::take(&mut self.buf)).into_owned();
            self.event(&text, "", &mut out);
        }
        self.flush(&mut out, "\n\n", |_| true);
        out
    }

    fn event(&mut self, raw: &str, delim: &str, out: &mut Vec<u8>) {
        let nl = if delim.starts_with("\r\n") { "\r\n" } else { "\n" };
        let mut other = Vec::new();
        let mut data = Vec::new();
        for line in raw.split(nl) {
            match line.strip_prefix("data:") {
                Some(d) => data.push(d.strip_prefix(' ').unwrap_or(d)),
                None => other.push(line.to_string()),
            }
        }
        let parsed = (!data.is_empty()).then(|| serde_json::from_str::<Value>(&data.join("\n")).ok()).flatten();
        let Some(mut v) = parsed else {
            self.flush(out, delim, |_| true);
            out.extend_from_slice(raw.as_bytes());
            out.extend_from_slice(delim.as_bytes());
            return;
        };

        let streaming = v.get("type").and_then(Value::as_str).is_some_and(|t| t.contains("delta"))
            || v.get("object").and_then(Value::as_str) == Some("chat.completion.chunk");
        let mut here = Vec::new();
        body::visit(&mut v, &mut |_, leaf| {
            if TEXT_KEYS.contains(&leaf.key) {
                here.push(leaf.path.to_string());
            }
        });
        self.flush(out, delim, |c| !streaming || !here.contains(&c.path));

        let mut new_carries = Vec::new();
        let (vault, carries, restored) = (self.vault, &mut self.carries, &mut self.restored);
        body::visit(&mut v, &mut |s, leaf| {
            let held = carries.iter().position(|c| c.path == leaf.path).map(|i| carries.remove(i).text);
            let mut text = match held {
                Some(h) => h + s.as_str(),
                None => std::mem::take(s),
            };
            if let Some(r) = vault.restore(&text, leaf.json_source, restored) {
                text = r;
            }
            if streaming && TEXT_KEYS.contains(&leaf.key) {
                let keep = text.len() - vault::pending_suffix(&text);
                if keep < text.len() {
                    new_carries.push((leaf.path.to_string(), text[keep..].to_string()));
                    text.truncate(keep);
                }
            }
            *s = text;
        });
        for (path, text) in new_carries {
            self.carries.push(Carry { path, text, other_lines: other.clone(), template: v.clone() });
        }
        write_event(out, &other, &v, nl, delim);
    }

    /// Sends what is held for every field `pick` selects, each as a copy of its last event.
    fn flush(&mut self, out: &mut Vec<u8>, delim: &str, pick: impl Fn(&Carry) -> bool) {
        let nl = if delim.starts_with("\r\n") { "\r\n" } else { "\n" };
        let delim = if delim.is_empty() { "\n\n" } else { delim };
        let (go, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.carries).into_iter().partition(|c| pick(c));
        self.carries = keep;
        for mut c in go {
            let mut restored = 0;
            let text = self.vault.restore(&c.text, false, &mut restored).unwrap_or(c.text.clone());
            self.restored += restored;
            body::visit(&mut c.template, &mut |s, leaf| {
                if leaf.path == c.path {
                    *s = text.clone();
                } else if TEXT_KEYS.contains(&leaf.key) {
                    s.clear();
                }
            });
            write_event(out, &c.other_lines, &c.template, nl, delim);
        }
    }
}

fn write_event(out: &mut Vec<u8>, other: &[String], v: &Value, nl: &str, delim: &str) {
    for l in other.iter().filter(|l| !l.is_empty()) {
        out.extend_from_slice(l.as_bytes());
        out.extend_from_slice(nl.as_bytes());
    }
    out.extend_from_slice(b"data: ");
    out.extend_from_slice(serde_json::to_string(v).unwrap_or_default().as_bytes());
    out.extend_from_slice(if delim.is_empty() { b"\n\n" } else { delim.as_bytes() });
}

/// Where the first complete event ends, and the length of the blank-line delimiter after it.
fn event_end(buf: &[u8]) -> Option<(usize, usize)> {
    let lf = buf.windows(2).position(|w| w == b"\n\n");
    let crlf = buf.windows(4).position(|w| w == b"\r\n\r\n");
    match (lf, crlf) {
        (Some(a), Some(b)) if b < a => Some((b, 4)),
        (Some(a), _) => Some((a, 2)),
        (None, Some(b)) => Some((b, 4)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Counts;

    fn setup() -> (Vault, String) {
        let v = Vault::new([5; 32]);
        let m = v.mask("Ram Bahadur Thapa", &mut Counts::new()).unwrap();
        (v, m)
    }

    fn texts(out: &str, field: &str) -> String {
        out.split("\n\n")
            .filter_map(|e| e.lines().find_map(|l| l.strip_prefix("data: ")))
            .filter_map(|d| serde_json::from_str::<Value>(d).ok())
            .filter_map(|v| v.pointer(field).and_then(Value::as_str).map(str::to_string))
            .collect()
    }

    #[test]
    fn split_token_across_events_anthropic() {
        let (v, tok) = setup();
        let (a, b) = tok.split_at(5);
        let ev = |t: &str| {
            format!(
                "event: content_block_delta\ndata: {}\n\n",
                serde_json::json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": t}})
            )
        };
        let mut r = SseRestorer::new(&v);
        let mut out = r.feed(ev(&format!("Hello {a}")).as_bytes());
        // split mid-event too: the network doesn't respect event boundaries
        let second = ev(&format!("{b}, welcome"));
        out.extend(r.feed(&second.as_bytes()[..10]));
        out.extend(r.feed(&second.as_bytes()[10..]));
        out.extend(r.feed(b"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"));
        out.extend(r.finish());
        let out = String::from_utf8(out).unwrap();
        assert_eq!(texts(&out, "/delta/text"), "Hello Ram Bahadur Thapa, welcome");
        assert!(out.contains("event: content_block_delta\ndata: "));
        assert!(out.ends_with("{\"type\":\"content_block_stop\",\"index\":0}\n\n"));
        assert_eq!(r.restored, 1);
    }

    #[test]
    fn split_token_across_events_openai_tool_call() {
        let (v, tok) = setup();
        let (a, b) = tok.split_at(9);
        let ev = |t: &str| {
            format!(
                "data: {}\n\n",
                serde_json::json!({"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": t}}]}}]})
            )
        };
        let mut r = SseRestorer::new(&v);
        let mut out = r.feed(ev(&format!("{{\"to\": \"{a}")).as_bytes());
        out.extend(r.feed(ev(&format!("{b}\"}}")).as_bytes()));
        out.extend(r.feed(b"data: [DONE]\n\n"));
        let out = String::from_utf8(out).unwrap();
        let args = texts(&out, "/choices/0/delta/tool_calls/0/function/arguments");
        assert_eq!(args, "{\"to\": \"Ram Bahadur Thapa\"}");
        assert!(out.ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn lone_bracket_is_flushed_before_the_block_ends() {
        let v = Vault::new([5; 32]);
        let mut r = SseRestorer::new(&v);
        let mut out = r.feed(b"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"arr[\"}}\n\n");
        out.extend(r.feed(b"data: {\"type\":\"content_block_stop\",\"index\":0}\n\n"));
        let out = String::from_utf8(out).unwrap();
        assert_eq!(texts(&out[..out.find("content_block_stop").unwrap()], "/delta/text"), "arr[");
    }

    #[test]
    fn crlf_events_and_done_events_without_holdback() {
        let (v, tok) = setup();
        let done = serde_json::json!({"type": "response.output_text.done", "text": format!("Hi {tok}, bye")});
        let mut r = SseRestorer::new(&v);
        let out = r.feed(format!("event: response.output_text.done\r\ndata: {done}\r\n\r\n").as_bytes());
        let out = String::from_utf8(out).unwrap();
        assert!(out.starts_with("event: response.output_text.done\r\ndata: "));
        assert!(out.ends_with("\r\n\r\n"));
        assert!(out.contains("Hi Ram Bahadur Thapa, bye"));
    }
}
