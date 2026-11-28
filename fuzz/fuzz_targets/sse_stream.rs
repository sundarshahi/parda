//! A well-formed streamed answer, in each provider's shape, with stand-ins cut across events and
//! several fields streaming side by side: every field's text comes out exactly as if it had been
//! restored in one piece.
#![no_main]

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use parda_fuzz::sse::SseRestorer;
use parda_fuzz::{chunks, expand, seeded_vault};
use serde_json::{Value, json};

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Shape {
    AnthropicText,
    AnthropicToolJson,
    OpenAiToolArgs,
    ResponsesArgs,
    Gemini,
}

#[derive(Arbitrary, Debug)]
struct Input {
    shape: Shape,
    /// Up to three fields; the bytes 1, 2, 3 in a text become real stand-ins.
    fields: Vec<String>,
    /// (field, characters to send next). Zero characters sends a keep-alive instead.
    schedule: Vec<(u8, u8)>,
    cut: u8,
}

impl Shape {
    fn json_source(self) -> bool {
        !matches!(self, Shape::AnthropicText | Shape::Gemini)
    }

    fn event(self, field: usize, text: &str) -> String {
        let v = match self {
            Shape::AnthropicText => {
                json!({"type": "content_block_delta", "index": field, "delta": {"type": "text_delta", "text": text}})
            }
            Shape::AnthropicToolJson => {
                json!({"type": "content_block_delta", "index": field, "delta": {"type": "input_json_delta", "partial_json": text}})
            }
            Shape::OpenAiToolArgs => {
                json!({"object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"tool_calls": [{"index": field, "function": {"arguments": text}}]}}]})
            }
            Shape::ResponsesArgs => {
                json!({"type": "response.function_call_arguments.delta", "item_id": format!("fc_{field}"), "output_index": field, "delta": text})
            }
            Shape::Gemini if field == 0 => json!({"candidates": [{"content": {"role": "model", "parts": [{"text": text}]}, "index": 0}]}),
            Shape::Gemini => json!({"candidates": [{"content": {"role": "model", "parts": [{"text": text, "thought": true}]}, "index": 0}]}),
        };
        format!("data: {v}\n\n")
    }

    /// (field, text) of one event parda sent.
    fn read(self, v: &Value) -> Option<(usize, String)> {
        let text = |p: &str| v.pointer(p).and_then(Value::as_str).map(str::to_string);
        let index = |p: &str| v.pointer(p).and_then(Value::as_u64).map(|i| i as usize);
        match self {
            Shape::AnthropicText => Some((index("/index")?, text("/delta/text")?)),
            Shape::AnthropicToolJson => Some((index("/index")?, text("/delta/partial_json")?)),
            Shape::OpenAiToolArgs => Some((
                index("/choices/0/delta/tool_calls/0/index")?,
                text("/choices/0/delta/tool_calls/0/function/arguments")?,
            )),
            Shape::ResponsesArgs => Some((index("/output_index")?, text("/delta")?)),
            Shape::Gemini => {
                let part = v.pointer("/candidates/0/content/parts/0")?;
                Some((part.get("thought").is_some() as usize, part.get("text")?.as_str()?.to_string()))
            }
        }
    }
}

fuzz_target!(|input: Input| {
    let (v, tokens) = seeded_vault();
    let max_fields = if matches!(input.shape, Shape::Gemini) { 2 } else { 3 };
    let fields: Vec<Vec<char>> =
        input.fields.iter().take(max_fields).map(|t| expand(t, &tokens).chars().collect()).collect();
    if fields.is_empty() {
        return;
    }
    let mut sent = vec![String::new(); fields.len()];
    let mut at = vec![0; fields.len()];
    let mut stream = String::new();
    for &(field, n) in &input.schedule {
        let f = field as usize % fields.len();
        let end = (at[f] + n as usize).min(fields[f].len());
        if end == at[f] {
            stream.push_str(if field % 2 == 0 { ": keep-alive\n\n" } else { "event: ping\ndata: {\"type\": \"ping\"}\n\n" });
            continue;
        }
        let piece: String = fields[f][at[f]..end].iter().collect();
        stream.push_str(&input.shape.event(f, &piece));
        sent[f].push_str(&piece);
        at[f] = end;
    }

    let mut r = SseRestorer::new(&v);
    let mut out = Vec::new();
    for p in chunks(stream.as_bytes(), input.cut) {
        out.extend(r.feed(p));
    }
    out.extend(r.finish());
    let out = String::from_utf8(out).expect("parda sent text that is not UTF-8");

    let mut got = vec![String::new(); fields.len()];
    for event in out.split("\n\n") {
        let Some(data) = event.lines().find_map(|l| l.strip_prefix("data: ")) else { continue };
        let value: Value = serde_json::from_str(data).expect("parda sent an event that is not JSON");
        if let Some((f, text)) = input.shape.read(&value) {
            got[f].push_str(&text);
        }
    }
    let mut total = 0;
    for (f, text) in sent.iter().enumerate() {
        let want = v.restore(text, input.shape.json_source(), &mut total).unwrap_or_else(|| text.clone());
        assert_eq!(got[f], want, "field {f} of {:?}\nsent as: {stream}", input.shape);
    }
    assert_eq!(r.restored, total, "restored count");
});
