//! Restoring stand-ins in a streamed (server-sent events) answer.
//!
//! The AI writes a stand-in in pieces: `"[PERS"` in one event, `"ON_1a2b3c4d] said"` in the next.
//! When a delta event's text ends with something that could start a stand-in, the whole event is
//! held until the next one arrives. If the next event continues the same field, the held characters
//! move to its front. If the next event is a delta for another field (two tool calls streaming
//! side by side), the held event goes out without those characters and they wait for their own
//! field. Anything else (a block ending, the stream ending) sends the held event unchanged. Events
//! are never reordered. Only if a field never continues are its waiting characters sent as a copy of
//! its last event, without ids, names or roles.

use crate::body::{self, TEXT_KEYS};
use crate::vault::{self, Vault};
use serde_json::Value;

struct Held {
    other_lines: Vec<String>,
    value: Value,
    nl: String,
    delim: String,
    /// (path, characters cut from the end of that field)
    tails: Vec<(String, String)>,
}

/// Characters waiting for their field while other fields stream.
struct Waiting {
    path: String,
    text: String,
    other_lines: Vec<String>,
    template: Value,
    nl: String,
    delim: String,
}

pub struct SseRestorer<'a> {
    vault: &'a Vault,
    buf: Vec<u8>,
    held: Option<Held>,
    waiting: Vec<Waiting>,
    pub restored: u64,
}

impl<'a> SseRestorer<'a> {
    pub fn new(vault: &'a Vault) -> Self {
        SseRestorer { vault, buf: Vec::new(), held: None, waiting: Vec::new(), restored: 0 }
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
        self.release(&mut out, &[], false);
        self.send_waiting(&mut out);
        out
    }

    /// Sends what still waits for a field that never continued, each as a copy of its last event
    /// with only the position fields kept (no ids, names or roles: those were sent already).
    fn send_waiting(&mut self, out: &mut Vec<u8>) {
        for mut w in std::mem::take(&mut self.waiting) {
            body::visit(&mut w.template, &mut |s, leaf| {
                if leaf.path == w.path {
                    *s = w.text.clone();
                } else if TEXT_KEYS.contains(&leaf.key) {
                    s.clear();
                }
            });
            strip_names(&mut w.template, true);
            write_event(out, &w.other_lines, &w.template, &w.nl, &w.delim);
        }
    }

    /// Sends the held event. Tails whose path is in `continued` are dropped from it (the caller puts
    /// them in front of the next event). With `detach`, the other tails wait for their own field;
    /// otherwise they go back where they were cut.
    fn release(&mut self, out: &mut Vec<u8>, continued: &[String], detach: bool) -> Vec<(String, String)> {
        let Some(mut h) = self.held.take() else { return Vec::new() };
        let (moved, rest): (Vec<_>, Vec<_>) = h.tails.into_iter().partition(|(p, _)| continued.contains(p));
        let back = if detach {
            for (path, text) in rest {
                self.waiting.push(Waiting {
                    path,
                    text,
                    other_lines: h.other_lines.clone(),
                    template: h.value.clone(),
                    nl: h.nl.clone(),
                    delim: h.delim.clone(),
                });
            }
            Vec::new()
        } else {
            rest
        };
        body::visit(&mut h.value, &mut |s, leaf| {
            if let Some((_, t)) = back.iter().find(|(p, _)| p == leaf.path) {
                s.push_str(t);
            }
        });
        write_event(out, &h.other_lines, &h.value, &h.nl, &h.delim);
        moved
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
            self.release(out, &[], false);
            self.send_waiting(out);
            out.extend_from_slice(raw.as_bytes());
            out.extend_from_slice(delim.as_bytes());
            return;
        };

        let streaming = v.get("type").and_then(Value::as_str).is_some_and(|t| t.contains("delta"))
            || v.get("object").and_then(Value::as_str) == Some("chat.completion.chunk");
        let mut here = Vec::new();
        if streaming {
            body::visit(&mut v, &mut |_, leaf| {
                if TEXT_KEYS.contains(&leaf.key) {
                    here.push(leaf.path.to_string());
                }
            });
        }
        // Another field streaming text: held characters can wait. Anything else ends what was held.
        let other_text = streaming && !here.is_empty();
        let mut carried = self.release(out, &here, other_text);
        if other_text {
            let (mine, others): (Vec<_>, Vec<_>) =
                std::mem::take(&mut self.waiting).into_iter().partition(|w| here.contains(&w.path));
            self.waiting = others;
            carried.extend(mine.into_iter().map(|w| (w.path, w.text)));
        } else {
            self.send_waiting(out);
        }

        let mut tails = Vec::new();
        let (vault, restored) = (self.vault, &mut self.restored);
        body::visit(&mut v, &mut |s, leaf| {
            let mut text = match carried.iter().find(|(p, _)| p == leaf.path) {
                Some((_, t)) => t.clone() + s.as_str(),
                None => std::mem::take(s),
            };
            if let Some(r) = vault.restore(&text, leaf.json_source, restored) {
                text = r;
            }
            if streaming && TEXT_KEYS.contains(&leaf.key) {
                let keep = text.len() - vault::pending_suffix(&text);
                if keep < text.len() {
                    tails.push((leaf.path.to_string(), text[keep..].to_string()));
                    text.truncate(keep);
                }
            }
            *s = text;
        });
        if tails.is_empty() {
            write_event(out, &other, &v, nl, delim);
        } else {
            let delim = if delim.is_empty() { "\n\n" } else { delim };
            self.held = Some(Held { other_lines: other, value: v, nl: nl.into(), delim: delim.into(), tails });
        }
    }
}

/// Removes `id`, `name` and `role` below the top level: a continuation chunk carries only text.
fn strip_names(v: &mut Value, top: bool) {
    match v {
        Value::Object(m) => {
            if !top {
                for k in ["id", "name", "role"] {
                    m.shift_remove(k);
                }
            }
            m.values_mut().for_each(|x| strip_names(x, false));
        }
        Value::Array(a) => a.iter_mut().for_each(|x| strip_names(x, false)),
        _ => {}
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
    fn held_text_never_duplicates_ids_or_names() {
        let v = Vault::new([5; 32]);
        let first = serde_json::json!({"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"role": "assistant",
            "tool_calls": [{"index": 0, "id": "call_1", "type": "function", "function": {"name": "bash", "arguments": "{\"x\": \"[PERS"}}]}}]});
        let stop = serde_json::json!({"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]});
        let mut r = SseRestorer::new(&v);
        let mut out = r.feed(format!("data: {first}\n\n").as_bytes());
        out.extend(r.feed(format!("data: {stop}\n\n").as_bytes()));
        let out = String::from_utf8(out).unwrap();
        assert_eq!(out.matches("call_1").count(), 1);
        assert_eq!(out.matches("\"bash\"").count(), 1);
        assert_eq!(texts(&out, "/choices/0/delta/tool_calls/0/function/arguments"), "{\"x\": \"[PERS");
        assert!(out.find("call_1").unwrap() < out.find("finish_reason").unwrap(), "order kept");
    }

    #[test]
    fn interleaved_responses_calls_keep_their_own_text() {
        let (v, tok) = setup();
        let (a, b) = tok.split_at(5);
        let ev = |i: u32, d: &str| {
            format!(
                "data: {}\n\n",
                serde_json::json!({"type": "response.function_call_arguments.delta", "item_id": format!("fc_{i}"), "output_index": i, "delta": d})
            )
        };
        let mut r = SseRestorer::new(&v);
        let mut out = r.feed(ev(0, &format!("{{\"a\": \"{a}")).as_bytes());
        out.extend(r.feed(ev(1, "{\"b\":1").as_bytes()));
        out.extend(r.feed(ev(0, &format!("{b}\"}}")).as_bytes()));
        out.extend(r.finish());
        let out = String::from_utf8(out).unwrap();
        let call = |i: &str| -> String {
            out.split("\n\n")
                .filter_map(|e| e.strip_prefix("data: "))
                .filter_map(|d| serde_json::from_str::<Value>(d).ok())
                .filter(|v| v["item_id"] == i)
                .map(|v| v["delta"].as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(call("fc_0"), "{\"a\": \"Ram Bahadur Thapa\"}");
        assert_eq!(call("fc_1"), "{\"b\":1");
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
